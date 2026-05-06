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
        agent_id: Agent/server ID for event attribution.
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
        enabled: bool = True,
        timeout: float = 5.0,
    ) -> None:
        self.server_url = server_url.rstrip("/")
        self.api_key = api_key
        self.agent_id = agent_id
        self.enabled = enabled
        self.timeout = timeout

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

        Called by the ``@guard`` decorator on DENY decisions.  Runs the
        HTTP POST in a daemon thread so the caller is not blocked.
        """
        if not self.enabled:
            return

        data: Dict[str, Any] = {
            "decision": decision,
            "tool_name": tool_name,
        }
        if deny_reason:
            data["deny_reason"] = deny_reason
        if deny_detail:
            data["deny_detail"] = deny_detail
        if agent_did:
            data["agent_did"] = agent_did
        if trust_level is not None:
            data["trust_level"] = trust_level
        if evidence_id:
            data["evidence_id"] = evidence_id
        if error_code:
            data["error_code"] = error_code
        if requested_capability:
            data["requested_capability"] = requested_capability
        if presented_capability:
            data["presented_capability"] = presented_capability
        if capability_class:
            data["capability_class"] = capability_class
        if severity:
            data["severity"] = severity

        event = {
            "id": str(uuid.uuid4()),
            "type": self.EVENT_POLICY_ENFORCED,
            "agentId": self.agent_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": data,
        }

        # Fire-and-forget in a daemon thread
        t = threading.Thread(target=self._send, args=(event,), daemon=True)
        t.start()

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _send(self, event: Dict[str, Any]) -> None:
        """POST a single event to ``/v1/events``.  Best-effort."""
        url = f"{self.server_url}/v1/events"
        headers = {
            "Content-Type": "application/json",
            "X-Capiscio-Registry-Key": self.api_key,
        }
        try:
            resp = requests.post(
                url,
                json={"events": [event]},
                headers=headers,
                timeout=self.timeout,
            )
            if resp.status_code >= 400:
                logger.debug(
                    "Event emission returned %s: %s",
                    resp.status_code,
                    resp.text[:200],
                )
        except Exception:
            # Best-effort — never let event emission break the guard
            logger.debug("Event emission failed", exc_info=True)
