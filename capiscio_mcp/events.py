"""
Guard event emission for policy enforcement telemetry.

Provides a module-level singleton ``GuardEventEmitter`` that the ``@guard``
decorator uses to POST ``capiscio.policy_enforced`` events to the registry's
``/v1/events`` endpoint.

The emitter is auto-configured when ``MCPServerIdentity.connect()`` is called,
or can be set manually via ``set_event_emitter()``.  If no emitter is configured
the guard silently skips event emission (graceful degradation).
"""

from __future__ import annotations

import logging
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import requests

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_emitter: Optional["GuardEventEmitter"] = None
_emitter_lock = threading.Lock()


def get_event_emitter() -> Optional["GuardEventEmitter"]:
    """Return the configured event emitter, or ``None`` if not set."""
    return _emitter


def set_event_emitter(emitter: Optional["GuardEventEmitter"]) -> None:
    """Set (or clear) the module-level event emitter singleton."""
    global _emitter
    with _emitter_lock:
        _emitter = emitter


# ---------------------------------------------------------------------------
# Event emitter
# ---------------------------------------------------------------------------


class GuardEventEmitter:
    """Lightweight event emitter that POSTs events to ``/v1/events``.

    Uses ``requests`` (already a capiscio-mcp dependency) and fires events
    synchronously in a background thread so the guard decorator does not
    block on network I/O.

    Args:
        server_url: Registry base URL (e.g. ``https://registry.capisc.io``).
        api_key: Registry API key for ``X-Capiscio-Registry-Key`` header.
        agent_id: Agent UUID for ``agentId`` in the ``/v1/events`` payload.
            The registry requires a valid agent ID at the top level.
        server_id: MCP server UUID for ``serverId`` in the ``/v1/events``
            payload.  When set, the dashboard can attribute events to the
            MCP server's invocation counter.
        enabled: Set ``False`` to suppress emission (useful in tests).
        timeout: HTTP request timeout in seconds.
    """

    EVENT_POLICY_ENFORCED = "capiscio.policy_enforced"

    def __init__(
        self,
        server_url: str,
        api_key: str,
        agent_id: Optional[str] = None,
        *,
        server_id: Optional[str] = None,
        enabled: bool = True,
        timeout: float = 5.0,
    ) -> None:
        self.server_url = server_url.rstrip("/")
        self.api_key = api_key
        self.agent_id = agent_id
        self.server_id = server_id
        self.enabled = enabled
        self.timeout = timeout
        self._pending_threads: list[threading.Thread] = []
        self._pending_lock = threading.Lock()
        # Lazy cache: DID → agent registry UUID
        self._did_to_agent_id: Dict[str, str] = {}
        self._did_cache_lock = threading.Lock()
        self._agents_loaded = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def emit_policy_enforced(
        self,
        *,
        decision: str,
        tool_name: str,
        deny_reason: Optional[str] = None,
        deny_detail: Optional[str] = None,
        agent_did: Optional[str] = None,
        trust_level: Optional[int] = None,
        evidence_id: Optional[str] = None,
        error_code: Optional[str] = None,
        requested_capability: Optional[str] = None,
        presented_capability: Optional[str] = None,
        capability_class: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> None:
        """Emit a ``capiscio.policy_enforced`` event.

        Called by the ``@guard`` decorator on ALLOW and DENY decisions.
        Runs the HTTP POST in a background thread so the caller is not
        blocked.  Use :meth:`flush` to wait for pending emissions before
        process exit.
        """
        if not self.enabled:
            return

        # Build the payload (goes into the ``payload`` JSONB column).
        payload: Dict[str, Any] = {
            "tool_name": tool_name,
        }
        if deny_reason:
            payload["deny_reason"] = deny_reason
        if deny_detail:
            payload["deny_detail"] = deny_detail
        if agent_did:
            payload["agent_did"] = agent_did
        if trust_level is not None:
            payload["trust_level"] = trust_level
        if evidence_id:
            payload["evidence_id"] = evidence_id
        if error_code:
            payload["error_code"] = error_code
        if requested_capability:
            payload["requested_capability"] = requested_capability
        if presented_capability:
            payload["presented_capability"] = presented_capability
        if capability_class:
            payload["capability_class"] = capability_class

        # Resolve the agent UUID for the agentId field.
        effective_agent_id = self._resolve_agent_id(agent_did)

        # Build a flat event matching the registry's db.Event struct.
        # See capiscio-server internal/db/models.go for JSON field tags.
        event: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "agentId": effective_agent_id or str(uuid.UUID(int=0)),
            "traceId": str(uuid.uuid4()),
            "eventType": self.EVENT_POLICY_ENFORCED,
            "severity": severity or ("HIGH" if decision == "DENY" else "INFO"),
            "decision": decision,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "payload": payload,
        }
        if self.server_id:
            event["mcpServerId"] = self.server_id

        # Fire in a tracked background thread so flush() can join before exit
        t = threading.Thread(target=self._send_and_untrack, args=(event,), daemon=True)
        with self._pending_lock:
            self._pending_threads.append(t)
        t.start()

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def flush(self, timeout: float = 10.0) -> None:
        """Block until all pending event threads have completed.

        Call this before process exit to ensure events are delivered.

        Args:
            timeout: Maximum seconds to wait for each pending thread.
        """
        with self._pending_lock:
            threads = list(self._pending_threads)
        for t in threads:
            t.join(timeout=timeout)
        with self._pending_lock:
            self._pending_threads = [
                t for t in self._pending_threads if t.is_alive()
            ]

    def _send_and_untrack(self, event: Dict[str, Any]) -> None:
        """Send then remove ourselves from the pending list."""
        try:
            self._send(event)
        finally:
            with self._pending_lock:
                try:
                    self._pending_threads.remove(threading.current_thread())
                except ValueError:
                    pass

    def _resolve_agent_id(self, agent_did: Optional[str]) -> Optional[str]:
        """Resolve an agent DID to its registry UUID.

        On first call, eagerly fetches all agents under this API key
        and caches the DID→UUID mapping.  Subsequent calls resolve from
        cache or via ``/v1/sdk/agents?did=``.  Returns ``None`` on
        failure (best-effort).
        """
        # Eagerly load all agents once to populate the cache and set
        # a fallback agent_id for anonymous callers.
        if not self._agents_loaded:
            self._load_all_agents()

        if not agent_did:
            # Anonymous caller — use fallback agent_id if available
            return self.agent_id

        with self._did_cache_lock:
            cached = self._did_to_agent_id.get(agent_did)
        if cached is not None:
            return cached

        url = f"{self.server_url}/v1/sdk/agents"
        try:
            resp = requests.get(
                url,
                params={"did": agent_did},
                headers={"X-Capiscio-Registry-Key": self.api_key},
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                agents = resp.json().get("data", [])
                if agents:
                    agent_uuid = agents[0]["id"]
                    with self._did_cache_lock:
                        self._did_to_agent_id[agent_did] = agent_uuid
                    return agent_uuid
        except Exception:
            logger.debug("Agent DID resolution failed for %s", agent_did, exc_info=True)
        # Fall back to default agent_id
        return self.agent_id

    def _load_all_agents(self) -> None:
        """Fetch all agents under this API key and cache DID→UUID mappings."""
        self._agents_loaded = True
        url = f"{self.server_url}/v1/sdk/agents"
        try:
            resp = requests.get(
                url,
                headers={"X-Capiscio-Registry-Key": self.api_key},
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                agents = resp.json().get("data", [])
                with self._did_cache_lock:
                    for agent in agents:
                        did = agent.get("did")
                        uid = agent.get("id")
                        if did and uid:
                            self._did_to_agent_id[did] = uid
                # Set fallback agent_id to the first agent if not already set
                if not self.agent_id and agents:
                    self.agent_id = agents[0]["id"]
                    logger.debug(
                        "Event emitter: fallback agent_id set to %s",
                        self.agent_id,
                    )
        except Exception:
            logger.debug("Failed to load agents for event emitter", exc_info=True)

    def _send(self, event: Dict[str, Any]) -> None:
        """POST a single event to ``/v1/events``.  Best-effort.

        The registry decodes the POST body directly as a flat ``db.Event``
        struct (see capiscio-server ``internal/db/models.go``).  Required
        top-level JSON fields: ``agentId``, ``traceId``, ``eventType``,
        ``severity``, ``timestamp``.
        """
        url = f"{self.server_url}/v1/events"
        headers = {
            "Content-Type": "application/json",
            "X-Capiscio-Registry-Key": self.api_key,
        }
        try:
            resp = requests.post(
                url,
                json=event,
                headers=headers,
                timeout=self.timeout,
            )
            if resp.status_code >= 400:
                logger.warning(
                    "Event emission returned %s: %s",
                    resp.status_code,
                    resp.text[:200],
                )
        except Exception:
            # Best-effort — never let event emission break the guard
            logger.debug("Event emission failed", exc_info=True)
