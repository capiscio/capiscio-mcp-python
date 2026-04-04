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

import base58
import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)

from capiscio_mcp.keeper import ServerBadgeKeeper
from capiscio_mcp.registration import (
    RegistrationError,
    generate_server_keypair,
    register_server_identity,
)

logger = logging.getLogger(__name__)

DEFAULT_REGISTRY = "https://registry.capisc.io"
DEFAULT_MCP_KEYS_DIR = Path.home() / ".capiscio" / "mcp-servers"

# Env var for injecting the private key in ephemeral environments
ENV_SERVER_PRIVATE_KEY = "CAPISCIO_SERVER_PRIVATE_KEY_PEM"


# ---------------------------------------------------------------------------
# Key derivation helpers
# ---------------------------------------------------------------------------


def _did_from_ed25519_pub_raw(pub_raw: bytes) -> str:
    """Derive a did:key from raw Ed25519 public key bytes (32 bytes)."""
    # Multicodec prefix 0xed01 identifies Ed25519 public keys
    multicodec = b"\xed\x01" + pub_raw
    return "did:key:z" + base58.b58encode(multicodec).decode()


def _load_private_key_pem(pem_text: str) -> tuple[Ed25519PrivateKey, str, str, str]:
    """Load a PEM-encoded Ed25519 private key and derive all identity artefacts.

    Returns:
        (private_key, private_key_pem, public_key_pem, did)
    """
    key = load_pem_private_key(pem_text.encode(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Expected an Ed25519 private key")

    priv_pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
    pub_pem = key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
    pub_raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    did = _did_from_ed25519_pub_raw(pub_raw)
    return key, priv_pem, pub_pem, did


def _log_key_capture_hint(server_id: str, private_key_pem: str) -> None:
    """Write a one-time hint to stderr telling the user how to persist key material.

    Uses ``print(..., file=sys.stderr)`` instead of the logger so the private
    key never enters log aggregation pipelines.  The hint is only emitted on
    first-run key generation.
    """
    import sys as _sys  # local import — only needed for this hint

    escaped_pem = private_key_pem.replace("\n", "\\n")
    hint = (
        "\n"
        "  ╔══════════════════════════════════════════════════════════════╗\n"
        "  ║  New server identity generated — save key for persistence  ║\n"
        "  ╚══════════════════════════════════════════════════════════════╝\n"
        "\n"
        "  If this server runs in an ephemeral environment (containers,\n"
        "  serverless, CI) the identity will be lost on restart unless\n"
        "  you persist the private key.\n"
        "\n"
        "  Add to your secrets manager / .env:\n"
        "\n"
        f'    CAPISCIO_SERVER_PRIVATE_KEY_PEM="{escaped_pem}"\n'
        "\n"
        "  The DID will be re-derived automatically on startup.\n"
    )
    print(hint, file=_sys.stderr, flush=True)


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
            try:
                data = resp.json()
            except ValueError as exc:
                logger.warning("Badge issuance response was not valid JSON: %s", exc)
                return None
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
        pub_pem: Optional[str] = None
        is_new_identity = False

        # ------------------------------------------------------------------
        # Step 2: Resolve private key — env var → local file → generate new
        # ------------------------------------------------------------------
        env_pem = os.environ.get(ENV_SERVER_PRIVATE_KEY)

        if env_pem:
            # --- Source: environment variable ---
            env_pem = env_pem.replace("\\n", "\n")  # Handle escaped newlines
            _, private_key_pem, pub_pem, did = _load_private_key_pem(env_pem)
            logger.info("Loaded server identity from %s: %s", ENV_SERVER_PRIVATE_KEY, did)

            # Persist to disk so subsequent restarts can use local file
            private_key_path.write_text(private_key_pem)
            os.chmod(private_key_path, 0o600)
            pub_key_path.write_text(pub_pem)
            did_file.write_text(did)

        elif private_key_path.exists():
            # --- Source: local file ---
            raw_pem = private_key_path.read_text()
            _, private_key_pem, pub_pem, did = _load_private_key_pem(raw_pem)
            logger.info("Recovered server identity from local keys: %s", did)

            # Ensure public key & DID files are consistent
            pub_key_path.write_text(pub_pem)
            did_file.write_text(did)

        else:
            # --- Source: generate new keypair ---
            is_new_identity = True
            logger.info("Generating Ed25519 keypair for MCP server %s...", server_id)
            keys = await generate_server_keypair(output_dir=str(effective_keys_dir))
            did = keys["did_key"]
            private_key_pem = keys["private_key_pem"]
            pub_pem = keys.get("public_key_pem", "")

            # Persist DID for future recovery
            did_file.write_text(did)

            # Persist public key for re-registration on recovery
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

        # ------------------------------------------------------------------
        # Step 3: Register DID with registry (idempotent — safe to repeat)
        # ------------------------------------------------------------------
        assert did is not None  # narrowing for type checkers
        effective_pub_pem = pub_pem or ""

        # Check for a previously auto-created server ID (persisted after 404 → POST)
        _resolved_id_file = effective_keys_dir / ".resolved_server_id"
        if _resolved_id_file.exists():
            try:
                resolved = _resolved_id_file.read_text().strip()
            except (OSError, UnicodeDecodeError) as exc:
                logger.warning(
                    "Could not read resolved server ID from %s: %s",
                    _resolved_id_file, exc,
                )
                resolved = ""
            if resolved and resolved != server_id:
                logger.info(
                    "Using previously resolved server ID %s (env had %s)",
                    resolved, server_id,
                )
                server_id = resolved

        try:
            reg_result = await register_server_identity(
                server_id=server_id,
                api_key=api_key,
                did=did,
                public_key=effective_pub_pem,
                ca_url=server_url,
            )
            logger.info("Server identity registered: %s", did)
            # If server was auto-created, persist the new ID for subsequent runs
            if reg_result.get("created") and reg_result.get("data"):
                new_id = reg_result["data"].get("id")
                if new_id and str(new_id) != server_id:
                    logger.info(
                        "Server auto-created with new ID %s (was %s)",
                        new_id, server_id,
                    )
                    server_id = str(new_id)
                    try:
                        _resolved_id_file.write_text(server_id)
                    except OSError as write_exc:
                        logger.warning(
                            "Could not persist resolved server ID to %s: %s",
                            _resolved_id_file, write_exc,
                        )
        except RegistrationError as exc:
            status_code = getattr(exc, "status_code", None)
            if status_code in (None, 409):
                # 409 = identity already registered (idempotent), None = network error
                logger.debug("Registration returned: %s — continuing", exc)
            else:
                logger.warning(
                    "Server identity registration failed (status %s): %s",
                    status_code,
                    exc,
                )
                raise

        # ------------------------------------------------------------------
        # Step 3.5: First-run capture hint & rotation warning
        # ------------------------------------------------------------------
        if is_new_identity:
            _log_key_capture_hint(server_id, private_key_pem)

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
        - ``CAPISCIO_SERVER_PRIVATE_KEY_PEM`` (optional — PEM-encoded Ed25519
          private key for ephemeral environments; printed on first generation)

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
                "Create an MCP server at https://app.capisc.io or set to 'auto'."
            )

        # "auto" means: auto-create on the registry, persist the ID locally.
        # Uses a stable keys directory so multiple subprocesses share identity.
        if server_id.lower() == "auto":
            import uuid as _uuid
            auto_keys_dir = DEFAULT_MCP_KEYS_DIR / "_auto"
            auto_keys_dir.mkdir(parents=True, exist_ok=True)
            resolved_file = auto_keys_dir / ".resolved_server_id"
            if resolved_file.exists():
                try:
                    resolved_server_id = resolved_file.read_text().strip()
                except (OSError, UnicodeDecodeError) as exc:
                    resolved_server_id = ""
                    logger.warning(
                        "Auto mode: could not read %s: %s", resolved_file, exc,
                    )
                if resolved_server_id:
                    server_id = resolved_server_id
                    logger.info("Auto mode: reusing persisted server ID %s", server_id)
                else:
                    server_id = str(_uuid.uuid4())
                    logger.warning(
                        "Auto mode: persisted server ID was empty; "
                        "created placeholder %s", server_id,
                    )
            else:
                server_id = str(_uuid.uuid4())
                logger.info("Auto mode: created placeholder server ID %s", server_id)
            kwargs["keys_dir"] = str(auto_keys_dir)

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
