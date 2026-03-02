"""MCPServerIdentity — "Let's Encrypt" style MCP server identity setup.

Mirrors ``CapiscIO.connect()`` from capiscio-sdk-python but for MCP servers.
Keys are persisted in ``~/.capiscio/mcp-servers/{server_id}/``.

Usage::

    import asyncio
    import os
    from capiscio_mcp import MCPServerIdentity

    async def main():
        identity = await MCPServerIdentity.connect(
            server_id=os.environ["CAPISCIO_SERVER_ID"],
            api_key=os.environ["CAPISCIO_API_KEY"],
        )
        print(f"DID: {identity.did}")
        print(f"Badge: {identity.badge}")

        # Or with environment variables
        identity = await MCPServerIdentity.from_env()

    asyncio.run(main())
"""

from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import urlparse

import requests

from capiscio_mcp.keeper import ServerBadgeKeeper
from capiscio_mcp.registration import (
    KeyGenerationError,
    RegistrationError,
    generate_server_keypair,
    register_server_identity,
)

logger = logging.getLogger(__name__)

DEFAULT_REGISTRY = "https://registry.capisc.io"
DEFAULT_MCP_KEYS_DIR = Path.home() / ".capiscio" / "mcp-servers"


# ---------------------------------------------------------------------------
# Badge issuance helper
# ---------------------------------------------------------------------------


def _derive_domain(url: str) -> str:
    """Extract the host (and non-standard port) from a URL for use as badge domain."""
    parsed = urlparse(url)
    host = parsed.hostname or "localhost"
    port = parsed.port
    # Omit standard ports (80/443) from the domain string
    if port and port not in (80, 443):
        return f"{host}:{port}"
    return host


def _issue_badge_sync(
    server_id: str,
    api_key: str,
    ca_url: str,
    domain: Optional[str] = None,
) -> Optional[str]:
    """Call ``POST /v1/sdk/servers/{server_id}/badge`` and return the badge JWS."""
    url = f"{ca_url.rstrip('/')}/v1/sdk/servers/{server_id}/badge"
    headers = {
        "X-Capiscio-Registry-Key": api_key,
        "Content-Type": "application/json",
    }
    effective_domain = domain or _derive_domain(ca_url)
    try:
        resp = requests.post(url, headers=headers, json={"domain": effective_domain}, timeout=30)
        if resp.status_code in (200, 201):
            data = resp.json()
            # Try multiple common response shapes
            nested = data.get("data") or {}
            badge = (
                nested.get("badge")
                or nested.get("token")
                or data.get("badge")
                or data.get("token")
            )
            if badge:
                logger.info("Badge issued for server %s", server_id)
                return badge
            logger.warning("Badge issue response had no badge field: %s", data)
            return None
        logger.warning(
            "Badge issuance failed for server %s: %d — %s",
            server_id,
            resp.status_code,
            resp.text,
        )
        return None
    except requests.RequestException as exc:
        logger.warning("Badge issuance request failed: %s", exc)
        return None


async def _issue_badge(
    server_id: str,
    api_key: str,
    ca_url: str,
    domain: Optional[str] = None,
) -> Optional[str]:
    """Async wrapper for badge issuance."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None,
        _issue_badge_sync,
        server_id,
        api_key,
        ca_url,
        domain,
    )


# ---------------------------------------------------------------------------
# MCPServerIdentity dataclass
# ---------------------------------------------------------------------------


@dataclass
class MCPServerIdentity:
    """Fully-configured MCP server identity returned by :meth:`connect`.

    Attributes:
        server_id: MCP server UUID (from the CapiscIO dashboard).
        did: Server DID (``did:key:z6Mk...``).
        api_key: Registry API key.
        server_url: Registry base URL.
        keys_dir: Directory containing the server's keys.
        badge: Current trust badge JWS (auto-renewed in background when keeper is running).
        private_key_pem: PEM-encoded Ed25519 private key for PoP signing.
    """

    server_id: str
    did: str
    api_key: str
    server_url: str
    keys_dir: Path
    badge: Optional[str] = None
    private_key_pem: Optional[str] = None
    _keeper: Any = field(default=None, repr=False)

    def get_badge(self) -> Optional[str]:
        """Return the current badge, preferring the keeper's latest renewal."""
        if self._keeper is not None:
            fresh = self._keeper.get_current_badge()
            if fresh:
                return fresh
        return self.badge

    def close(self) -> None:
        """Stop badge auto-renewal and release resources."""
        if self._keeper is not None:
            try:
                self._keeper.stop()
            except Exception:
                pass
            self._keeper = None

    def __enter__(self) -> "MCPServerIdentity":
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> bool:
        self.close()
        return False

    # ------------------------------------------------------------------
    # Class-level factory methods
    # ------------------------------------------------------------------

    @classmethod
    async def connect(
        cls,
        server_id: str,
        api_key: str,
        *,
        server_url: str = DEFAULT_REGISTRY,
        domain: Optional[str] = None,
        keys_dir: Optional[Path] = None,
        auto_badge: bool = True,
        renewal_threshold: int = 30,
        on_badge_renew: Optional[Callable[[str], None]] = None,
    ) -> "MCPServerIdentity":
        """Connect to CapiscIO and get a fully-configured MCP server identity.

        This is the "Let's Encrypt" style one-liner for MCP servers:

        1. Checks ``~/.capiscio/mcp-servers/{server_id}/`` for existing keys
           (idempotent — safe to call multiple times).
        2. Generates an Ed25519 keypair via capiscio-core if none exist.
        3. Registers the DID + public key with the registry.
        4. Issues an initial badge via ``POST /v1/sdk/servers/{server_id}/badge``.
        5. Starts :class:`~capiscio_mcp.keeper.ServerBadgeKeeper` for auto-renewal.
        6. Returns :class:`MCPServerIdentity` with all credentials loaded.

        Args:
            server_id: MCP server UUID (from the CapiscIO dashboard).
            api_key: Registry API key (``X-Capiscio-Registry-Key``).
            server_url: Registry base URL (default: production).
            domain: Domain to record in the badge (e.g. ``"tools.example.com"``).
                Defaults to the hostname extracted from ``server_url``.
                Use ``CAPISCIO_SERVER_DOMAIN`` env var via :meth:`from_env`.
            keys_dir: Override for key storage directory.
            auto_badge: If ``True``, issue an initial badge and start auto-renewal.
            renewal_threshold: Renew badge this many seconds before expiry.
            on_badge_renew: Optional callback ``(badge: str) -> None`` on renewal.

        Returns:
            :class:`MCPServerIdentity` with ``.did``, ``.badge``, ``.keys_dir``,
            ``.get_badge()``, and ``.close()``.

        Example::

            identity = await MCPServerIdentity.connect(
                server_id=os.environ["CAPISCIO_SERVER_ID"],
                api_key=os.environ["CAPISCIO_API_KEY"],
            )
            print(f"Server DID: {identity.did}")

            # Use in CapiscioMCPServer
            server = CapiscioMCPServer(identity=identity)
        """
        server_url = server_url.rstrip("/")

        # Step 1: Resolve keys directory
        effective_keys_dir = Path(keys_dir) if keys_dir else (DEFAULT_MCP_KEYS_DIR / server_id)
        effective_keys_dir.mkdir(parents=True, exist_ok=True)

        private_key_path = effective_keys_dir / "private_key.pem"
        pub_key_path = effective_keys_dir / "public_key.pem"
        did_file = effective_keys_dir / "did.txt"

        did: Optional[str] = None
        private_key_pem: Optional[str] = None

        # Step 2: Check for existing keys (idempotency)
        if private_key_path.exists() and did_file.exists():
            logger.info("Found existing keys for server %s — recovering identity", server_id)
            did = did_file.read_text().strip()
            private_key_pem = private_key_path.read_text()
            logger.info("Recovered DID: %s", did)

            # Re-register (handles server resets; 409/already-exists is fine)
            if pub_key_path.exists():
                pub_key_pem = pub_key_path.read_text()
                try:
                    await register_server_identity(
                        server_id=server_id,
                        api_key=api_key,
                        did=did,
                        public_key=pub_key_pem,
                        ca_url=server_url,
                    )
                    logger.debug("Re-registered server identity (idempotent)")
                except RegistrationError as exc:
                    logger.debug("Re-registration returned: %s — continuing", exc)
        else:
            # Step 3: Generate new keypair
            logger.info("Generating Ed25519 keypair for MCP server %s...", server_id)
            keys = await generate_server_keypair(output_dir=str(effective_keys_dir))
            did = keys["did_key"]
            private_key_pem = keys["private_key_pem"]

            # Persist DID for future recovery
            did_file.write_text(did)

            # Persist public key for re-registration on recovery
            pub_pem: str = keys.get("public_key_pem", "")
            if pub_pem:
                pub_key_path.write_text(pub_pem)

            # Ensure private key is at the canonical path
            if "private_key_path" in keys:
                existing = Path(keys["private_key_path"])
                if existing.resolve() != private_key_path.resolve() and existing.exists():
                    private_key_path.write_bytes(existing.read_bytes())
                    os.chmod(private_key_path, 0o600)
            elif not private_key_path.exists():
                private_key_path.write_text(private_key_pem)
                os.chmod(private_key_path, 0o600)

            # Step 4: Register with registry
            logger.info("Registering DID %s with registry...", did)
            await register_server_identity(
                server_id=server_id,
                api_key=api_key,
                did=did,
                public_key=pub_pem,
                ca_url=server_url,
            )
            logger.info("Server identity registered: %s", did)

        # Step 5: Issue initial badge and start keeper
        badge: Optional[str] = None
        keeper: Optional[ServerBadgeKeeper] = None

        if auto_badge:
            badge = await _issue_badge(server_id, api_key, server_url, domain=domain)
            if badge:
                keeper = ServerBadgeKeeper(
                    server_id=server_id,
                    api_key=api_key,
                    initial_badge=badge,
                    ca_url=server_url,
                    renewal_threshold=renewal_threshold,
                    on_renew=on_badge_renew,
                )
                keeper.start()
            else:
                logger.warning(
                    "Badge issuance failed — server identity set up without badge"
                )

        logger.info("MCPServerIdentity ready for server %s: %s", server_id, did)
        return cls(
            server_id=server_id,
            did=did,  # type: ignore[arg-type]
            api_key=api_key,
            server_url=server_url,
            keys_dir=effective_keys_dir,
            badge=badge,
            private_key_pem=private_key_pem,
            _keeper=keeper,
        )

    @classmethod
    async def from_env(cls, **kwargs: Any) -> "MCPServerIdentity":
        """Connect using environment variables.

        Reads:
        - ``CAPISCIO_SERVER_ID`` (required)
        - ``CAPISCIO_API_KEY`` (required)
        - ``CAPISCIO_SERVER_URL`` (optional, default: production)
        - ``CAPISCIO_SERVER_DOMAIN`` (optional, default: hostname from SERVER_URL)

        Additional keyword arguments are forwarded to :meth:`connect`.

        Raises:
            ValueError: If ``CAPISCIO_SERVER_ID`` or ``CAPISCIO_API_KEY`` is unset.

        Example::

            # .env
            # CAPISCIO_SERVER_ID=550e8400-e29b-41d4-a716-446655440000
            # CAPISCIO_API_KEY=sk_live_...

            identity = await MCPServerIdentity.from_env()
        """
        server_id = os.environ.get("CAPISCIO_SERVER_ID")
        if not server_id:
            raise ValueError(
                "CAPISCIO_SERVER_ID environment variable is required. "
                "Create an MCP server at https://app.capisc.io"
            )

        api_key = os.environ.get("CAPISCIO_API_KEY")
        if not api_key:
            raise ValueError(
                "CAPISCIO_API_KEY environment variable is required. "
                "Get your API key at https://app.capisc.io"
            )

        server_url = os.environ.get("CAPISCIO_SERVER_URL", DEFAULT_REGISTRY)
        domain = os.environ.get("CAPISCIO_SERVER_DOMAIN")

        return await cls.connect(
            server_id=server_id,
            api_key=api_key,
            server_url=server_url,
            domain=domain or None,
            **kwargs,
        )
