"""ServerBadgeKeeper — Auto-renewal for MCP server badges.

Mirrors BadgeKeeper from capiscio-sdk-python but uses the MCP server
badge API (POST /v1/sdk/servers/{id}/badge).

Example:
    keeper = ServerBadgeKeeper(
        server_id="550e8400-...",
        api_key="sk_live_...",
        initial_badge="eyJhbGc...",
        renewal_threshold=30,
    )
    keeper.start()
    badge = keeper.get_current_badge()
    keeper.stop()
"""

from __future__ import annotations

import base64
import json
import logging
import threading
import time
from typing import Callable, Optional

import requests

logger = logging.getLogger(__name__)

DEFAULT_RENEWAL_THRESHOLD = 30  # seconds before expiry to renew
DEFAULT_CHECK_INTERVAL = 10  # seconds between checks


def _decode_jwt_exp(token: str) -> Optional[int]:
    """Decode the exp claim from a JWT/JWS compact format without signature verification.

    Args:
        token: JWS/JWT compact serialization (header.payload.signature)

    Returns:
        Unix timestamp of expiry, or None if not decodable.
    """
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None
        payload_b64 = parts[1]
        # Pad to a multiple of 4 for base64url decoding
        remainder = len(payload_b64) % 4
        if remainder:
            payload_b64 += "=" * (4 - remainder)
        payload_bytes = base64.urlsafe_b64decode(payload_b64)
        payload = json.loads(payload_bytes)
        exp = payload.get("exp")
        return int(exp) if exp is not None else None
    except Exception:
        return None


class ServerBadgeKeeper:
    """Background badge renewal manager for MCP servers.

    Watches the badge ``exp`` claim and automatically renews the badge
    before it expires, ensuring the server always has a fresh badge for
    identity disclosure in the ``_meta`` of MCP initialize responses.

    Uses ``POST /v1/sdk/servers/{server_id}/badge`` for renewal — the same
    endpoint used by :func:`~capiscio_mcp.connect.MCPServerIdentity.connect`.

    Example::

        keeper = ServerBadgeKeeper(
            server_id="550e8400-...",
            api_key="sk_live_...",
            initial_badge="eyJhbGc...",
        )
        with keeper:
            badge = keeper.get_current_badge()
    """

    def __init__(
        self,
        server_id: str,
        api_key: str,
        initial_badge: str,
        ca_url: str = "https://registry.capisc.io",
        renewal_threshold: int = DEFAULT_RENEWAL_THRESHOLD,
        check_interval: int = DEFAULT_CHECK_INTERVAL,
        on_renew: Optional[Callable[[str], None]] = None,
    ) -> None:
        """Initialize ServerBadgeKeeper.

        Args:
            server_id: MCP server UUID (from the CapiscIO dashboard).
            api_key: Registry API key (``X-Capiscio-Registry-Key``).
            initial_badge: The badge JWS returned by :func:`connect`.
            ca_url: Registry base URL.
            renewal_threshold: Renew when ``exp - now <= renewal_threshold`` seconds.
            check_interval: How often (seconds) the background thread wakes to check.
            on_renew: Optional callback called with the new badge string after each renewal.
        """
        self.server_id = server_id
        self.api_key = api_key
        self.ca_url = ca_url.rstrip("/")
        self.renewal_threshold = renewal_threshold
        self.check_interval = check_interval
        self.on_renew = on_renew

        self._current_badge: Optional[str] = initial_badge
        self._badge_lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._running = False

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the background renewal thread.

        Raises:
            RuntimeError: If the keeper is already running.
        """
        if self._running:
            raise RuntimeError("ServerBadgeKeeper is already running")

        logger.info(
            "Starting ServerBadgeKeeper for server %s (threshold=%ds)",
            self.server_id,
            self.renewal_threshold,
        )
        self._stop_event.clear()
        self._running = True
        self._thread = threading.Thread(
            target=self._run,
            name=f"capiscio-badge-keeper-{self.server_id[:8]}",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        """Stop the background renewal thread (blocks until it exits)."""
        if not self._running:
            return
        logger.info("Stopping ServerBadgeKeeper for server %s...", self.server_id)
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
        self._running = False
        logger.info("ServerBadgeKeeper stopped")

    def get_current_badge(self) -> Optional[str]:
        """Return the current (most recently renewed) badge JWS."""
        with self._badge_lock:
            return self._current_badge

    def is_running(self) -> bool:
        """Whether the background renewal thread is running."""
        return self._running

    # ------------------------------------------------------------------
    # Background thread
    # ------------------------------------------------------------------

    def _run(self) -> None:
        """Background thread: periodically check expiry and renew if needed."""
        while not self._stop_event.is_set():
            try:
                self._maybe_renew()
            except Exception as exc:
                logger.warning("ServerBadgeKeeper check failed: %s", exc)
            self._stop_event.wait(timeout=self.check_interval)

        logger.debug("ServerBadgeKeeper thread exiting for server %s", self.server_id)
        self._running = False

    def _maybe_renew(self) -> None:
        """Renew the badge if it is close to expiry."""
        with self._badge_lock:
            badge = self._current_badge

        if badge is None:
            return

        exp = _decode_jwt_exp(badge)
        if exp is None:
            logger.debug("Could not decode exp from badge; skipping renewal check")
            return

        now = int(time.time())
        seconds_until_expiry = exp - now
        logger.debug(
            "Badge for server %s expires in %ds (threshold=%ds)",
            self.server_id,
            seconds_until_expiry,
            self.renewal_threshold,
        )

        if seconds_until_expiry <= self.renewal_threshold:
            logger.info(
                "Badge for server %s expires in %ds — renewing",
                self.server_id,
                seconds_until_expiry,
            )
            self._renew()

    def _renew(self) -> None:
        """Call ``POST /v1/sdk/servers/{server_id}/badge`` to get a fresh badge."""
        url = f"{self.ca_url}/v1/sdk/servers/{self.server_id}/badge"
        headers = {
            "X-Capiscio-Registry-Key": self.api_key,
            "Content-Type": "application/json",
        }
        try:
            resp = requests.post(url, headers=headers, json={}, timeout=30)
            if resp.status_code in (200, 201):
                data = resp.json()
                # Try multiple common response shapes
                new_badge = (
                    (data.get("data") or {}).get("badge")
                    or data.get("badge")
                    or data.get("token")
                )
                if new_badge:
                    with self._badge_lock:
                        self._current_badge = new_badge
                    logger.info("Badge renewed for server %s", self.server_id)
                    if self.on_renew:
                        try:
                            self.on_renew(new_badge)
                        except Exception as exc:
                            logger.warning("on_renew callback failed: %s", exc)
                else:
                    logger.warning(
                        "Badge renewal response had no badge field: %s", data
                    )
            else:
                logger.warning(
                    "Badge renewal failed for server %s: %d — %s",
                    self.server_id,
                    resp.status_code,
                    resp.text,
                )
        except requests.RequestException as exc:
            logger.warning("Badge renewal request failed: %s", exc)

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "ServerBadgeKeeper":
        self.start()
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> bool:
        self.stop()
        return False
