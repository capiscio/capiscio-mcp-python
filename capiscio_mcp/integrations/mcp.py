"""
MCP SDK Integration — requires ``pip install capiscio-mcp[mcp]``

Provides two integration classes:

1. **Server-side**: :class:`CapiscioMCPServer` — guard tools, disclose identity
   via ``_meta`` in the initialize response, and sign PoP challenges.
2. **Client-side**: :class:`CapiscioMCPClient` — verify server identity extracted
   from ``_meta`` on connection, enforce ``min_trust_level``.

Usage (Server)::

    from capiscio_mcp.integrations.mcp import CapiscioMCPServer
    from capiscio_mcp import MCPServerIdentity

    identity = await MCPServerIdentity.connect(
        server_id=os.environ["CAPISCIO_SERVER_ID"],
        api_key=os.environ["CAPISCIO_API_KEY"],
    )

    server = CapiscioMCPServer(identity=identity)

    @server.tool(min_trust_level=2)
    async def read_file(path: str) -> str:
        with open(path) as f:
            return f.read()

    server.run()

Usage (Client)::

    from capiscio_mcp.integrations.mcp import CapiscioMCPClient

    async with CapiscioMCPClient(
        command="python server/main.py",
        badge="eyJhbGc...",
        min_trust_level=1,
        fail_on_unverified=True,
    ) as client:
        result = await client.call_tool("list_files", {"directory": "/tmp"})
"""

from __future__ import annotations

import contextvars
import logging
import os
from dataclasses import dataclass, field
from functools import wraps
from typing import Any, Callable, Coroutine, Dict, List, Optional, TypeVar, Union

# --------------------------------------------------------------------------
# MCP server SDK (FastMCP)
# --------------------------------------------------------------------------
try:
    from mcp.server.fastmcp import FastMCP
    from mcp.types import Tool, TextContent

    MCP_AVAILABLE = True
except ImportError:
    FastMCP = None  # type: ignore
    Tool = None  # type: ignore
    TextContent = None  # type: ignore
    MCP_AVAILABLE = False

# --------------------------------------------------------------------------
# MCP client SDK
# --------------------------------------------------------------------------
try:
    from mcp.client.session import ClientSession as McpClientSession
    from mcp.client.stdio import stdio_client, StdioServerParameters

    MCP_CLIENT_AVAILABLE = True
except ImportError:
    McpClientSession = None  # type: ignore
    stdio_client = None  # type: ignore
    StdioServerParameters = None  # type: ignore
    MCP_CLIENT_AVAILABLE = False

# --------------------------------------------------------------------------
# Cryptography (PoP)
# --------------------------------------------------------------------------
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    CRYPTO_AVAILABLE = True
except ImportError:
    Ed25519PrivateKey = None  # type: ignore
    Ed25519PublicKey = None  # type: ignore
    CRYPTO_AVAILABLE = False

from capiscio_mcp.types import ServerState, ServerErrorCode, CallerCredential
from capiscio_mcp.server import (
    verify_server,
    VerifyConfig,
    VerifyResult,
    parse_http_headers,
    parse_jsonrpc_meta,
)
from capiscio_mcp.guard import guard, GuardConfig, set_credential, set_server_origin
from capiscio_mcp.errors import GuardError, ServerVerifyError
from capiscio_mcp.pop import (
    PoPRequest,
    PoPResponse,
    generate_pop_request,
    create_pop_response,
    verify_pop_response,
    load_private_key_from_pem,
    load_public_key_from_pem,
    extract_public_key_from_did_key,
    PoPError,
    PoPSignatureError,
    PoPExpiredError,
)

logger = logging.getLogger(__name__)

T = TypeVar("T")

# ---------------------------------------------------------------------------
# _meta injection machinery
# ---------------------------------------------------------------------------

# Per-run contextvar carrying the _meta dict to inject into InitializeResult.
# Set by CapiscioMCPServer.run() before starting the server; cleared on exit.
_capiscio_meta_ctx: contextvars.ContextVar[Optional[Dict[str, Any]]] = contextvars.ContextVar(
    "_capiscio_meta_ctx", default=None
)


def _install_credential_extraction(fastmcp_instance: "FastMCP") -> None:
    """Wrap the registered ``CallToolRequest`` handler to extract caller credentials from ``_meta``.

    For stdio (non-HTTP) transport, the caller's CapiscIO badge must travel in the
    JSON-RPC ``_meta`` of each tool call request under the key
    ``capiscio_caller_badge`` (API key: ``capiscio_caller_api_key``).

    This is the stdio equivalent of the ``X-Capiscio-Badge`` HTTP header (RFC-002 §9.1).
    The server-side ``@guard`` decorator reads the credential from the
    ``_current_credential`` contextvar, which this wrapper sets before dispatching.

    For HTTP-based transports, callers MUST send the badge in the
    ``X-Capiscio-Badge`` header (takes precedence over ``Authorization: Bearer``).
    """
    try:
        from mcp import types as _mcp_types
        from capiscio_mcp.types import CallerCredential
        from capiscio_mcp.guard import set_credential, _current_credential as _cred_ctx
    except ImportError:
        return

    mcp_server = getattr(fastmcp_instance, "_mcp_server", None)
    if mcp_server is None:
        return

    original_handler = mcp_server.request_handlers.get(_mcp_types.CallToolRequest)
    if original_handler is None:
        return

    async def _handler_with_credential(req: _mcp_types.CallToolRequest) -> Any:
        # Extract caller credentials from _meta (RFC-008 §Appendix-B / _meta.capiscio convention)
        badge: Optional[str] = None
        api_key: Optional[str] = None
        meta = getattr(req.params, "meta", None)
        if meta is not None:
            extra: Dict[str, Any] = getattr(meta, "model_extra", None) or {}
            badge = extra.get("capiscio_caller_badge")
            api_key = extra.get("capiscio_caller_api_key")

        if badge or api_key:
            cred = CallerCredential(badge_jws=badge, api_key=api_key)
            token = set_credential(cred)
            try:
                return await original_handler(req)
            finally:
                _cred_ctx.reset(token)
        return await original_handler(req)

    mcp_server.request_handlers[_mcp_types.CallToolRequest] = _handler_with_credential
    logger.debug("CapiscIO: installed caller credential extraction from _meta on CallToolRequest")


def _patch_server_session_once() -> bool:
    """Idempotently patch ``ServerSession._received_request`` to inject ``_meta``.

    The patch wraps ``responder.respond`` for ``InitializeRequest`` messages so
    that the ``meta`` field on the returned ``InitializeResult`` is set from the
    ``_capiscio_meta_ctx`` contextvar.  All other logic (protocol-version
    negotiation, state transitions) continues to run in the original method.

    Returns:
        ``True`` if the patch is now in place, ``False`` if the MCP SDK is not
        installed.
    """
    try:
        from mcp.server.session import ServerSession
        from mcp import types as _mcp_types
    except ImportError:
        return False

    if getattr(ServerSession, "_capiscio_meta_patched", False):
        return True

    _original_received_request = ServerSession._received_request

    @wraps(_original_received_request)
    async def _patched_received_request(
        session_self: Any,
        responder: Any,
    ) -> None:
        meta = _capiscio_meta_ctx.get()

        # Fast path: no meta to inject — delegate straight to original
        if meta is None:
            await _original_received_request(session_self, responder)
            return

        # Only intercept InitializeRequest messages
        try:
            req_root = responder.request.root
        except AttributeError:
            await _original_received_request(session_self, responder)
            return

        if not isinstance(req_root, _mcp_types.InitializeRequest):
            await _original_received_request(session_self, responder)
            return

        # Wrap responder.respond to inject _meta into the InitializeResult
        _original_respond = responder.respond

        async def _respond_with_meta(result: Any) -> None:
            try:
                # ServerResult is a RootModel; result.root is InitializeResult
                inner = getattr(result, "root", result)
                if isinstance(inner, _mcp_types.InitializeResult):
                    inner.meta = meta
            except Exception as exc:
                logger.debug("_meta injection: failed to set meta on result: %s", exc)
            await _original_respond(result)

        responder.respond = _respond_with_meta
        try:
            await _original_received_request(session_self, responder)
        finally:
            responder.respond = _original_respond

    ServerSession._received_request = _patched_received_request  # type: ignore[method-assign]
    ServerSession._capiscio_meta_patched = True  # type: ignore[attr-defined]
    logger.debug("CapiscIO: patched ServerSession._received_request for _meta injection")
    return True


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_mcp_server() -> None:
    if not MCP_AVAILABLE:
        raise ImportError(
            "MCP SDK integration requires the 'mcp' package. "
            "Install with: pip install capiscio-mcp[mcp]"
        )


def _require_mcp_client() -> None:
    if not MCP_CLIENT_AVAILABLE:
        raise ImportError(
            "MCP client integration requires the 'mcp' package. "
            "Install with: pip install capiscio-mcp[mcp]"
        )


# ---------------------------------------------------------------------------
# CapiscioMCPServer
# ---------------------------------------------------------------------------


class CapiscioMCPServer:
    """MCP Server with CapiscIO identity disclosure, PoP signing, and tool guarding.

    This class wraps FastMCP to:

    1. Automatically inject server identity (DID, badge) into the ``_meta``
       field of MCP ``initialize`` responses (RFC-007 §6.2).
    2. Sign PoP challenges from clients to prove key ownership (RFC-007).
    3. Guard registered tools with trust-level requirements (RFC-006).

    The ``_meta`` injection works by patching
    ``mcp.server.session.ServerSession._received_request`` **once** (globally,
    idempotently) at server start-time.  A per-invocation contextvar carries the
    meta dict so that only this server's responses are affected.

    Example::

        from capiscio_mcp import MCPServerIdentity
        from capiscio_mcp.integrations.mcp import CapiscioMCPServer

        identity = await MCPServerIdentity.connect(
            server_id=os.environ["CAPISCIO_SERVER_ID"],
            api_key=os.environ["CAPISCIO_API_KEY"],
        )

        server = CapiscioMCPServer(identity=identity)

        @server.tool(min_trust_level=2)
        async def read_file(path: str) -> str:
            with open(path) as f:
                return f.read()

        server.run()

    You can also supply credentials directly (without ``MCPServerIdentity``)::

        server = CapiscioMCPServer(
            name="filesystem",
            did="did:web:mcp.example.com:servers:filesystem",
            badge=os.environ.get("SERVER_BADGE"),
            private_key_path="/path/to/server.key.pem",
        )
    """

    def __init__(
        self,
        name: Optional[str] = None,
        did: Optional[str] = None,
        badge: Optional[str] = None,
        default_min_trust_level: int = 0,
        version: str = "1.0.0",
        private_key: Optional["Ed25519PrivateKey"] = None,
        private_key_path: Optional[str] = None,
        private_key_pem: Optional[Union[str, bytes]] = None,
        key_id: Optional[str] = None,
        # Convenience: pass MCPServerIdentity directly
        identity: Optional[Any] = None,
    ) -> None:
        """Initialize ``CapiscioMCPServer``.

        Args:
            name: Server name shown to clients.
            did: Server DID for identity disclosure.
            badge: Server badge JWS for client verification.
            default_min_trust_level: Default minimum trust level for tools.
            version: Server version string.
            private_key: ``Ed25519PrivateKey`` object for PoP signing (optional).
            private_key_path: Path to PEM file containing private key (optional).
            private_key_pem: PEM-encoded private key string/bytes (optional).
            key_id: Key ID for JWS header (defaults to ``{did}#keys-1``).
            identity: :class:`~capiscio_mcp.connect.MCPServerIdentity` instance.
                      When provided, ``name``, ``did``, ``badge``, and
                      ``private_key_pem`` are derived from it automatically.
        """
        _require_mcp_server()

        # Accept MCPServerIdentity as a convenience shortcut
        if identity is not None:
            name = name or getattr(identity, "server_id", "mcp-server")
            if did is None:
                did = getattr(identity, "did", None)
            if badge is None:
                badge = identity.get_badge() if callable(getattr(identity, "get_badge", None)) else getattr(identity, "badge", None)
            if private_key_pem is None and private_key is None and private_key_path is None:
                private_key_pem = getattr(identity, "private_key_pem", None)

        if not did:
            raise ValueError("'did' is required (or provide an 'identity' with a DID)")

        self.name = name or "mcp-server"
        self.did = did
        self.badge = badge
        self.default_min_trust_level = default_min_trust_level
        self.version = version

        # Load private key for PoP signing
        self._private_key: Optional["Ed25519PrivateKey"] = None
        self._key_id = key_id or f"{did}#keys-1"

        if private_key is not None:
            self._private_key = private_key
        elif private_key_path is not None:
            self._load_private_key_from_file(private_key_path)
        elif private_key_pem is not None:
            self._private_key = load_private_key_from_pem(private_key_pem)

        # Create underlying FastMCP server
        self._server = FastMCP(self.name)
        self._tools: Dict[str, Callable] = {}
        self._tool_configs: Dict[str, GuardConfig] = {}

        # Attempt to install the session patch so _meta can be injected at run-time
        if MCP_AVAILABLE:
            _patch_server_session_once()
            # Install handler wrapper that extracts caller credentials from _meta
            # for stdio transport (where HTTP headers are not available).
            _install_credential_extraction(self._server)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _load_private_key_from_file(self, path: str) -> None:
        if not CRYPTO_AVAILABLE:
            logger.warning(
                "PoP signing requires 'cryptography' package. "
                "Install with: pip install capiscio-mcp[crypto]"
            )
            return
        try:
            with open(path, "rb") as fh:
                pem_data = fh.read()
            self._private_key = load_private_key_from_pem(pem_data)
            logger.debug("Loaded private key from %s", path)
        except Exception as exc:
            logger.warning("Failed to load private key from %s: %s", path, exc)

    # ------------------------------------------------------------------
    # Public properties
    # ------------------------------------------------------------------

    @property
    def pop_enabled(self) -> bool:
        """Whether PoP signing is available (private key loaded)."""
        return self._private_key is not None

    @property
    def server(self) -> "FastMCP":
        """The underlying :class:`~mcp.server.fastmcp.FastMCP` instance."""
        return self._server

    @property
    def identity_meta(self) -> Dict[str, str]:
        """The identity ``_meta`` dict (DID + badge) used in initialize responses."""
        return self._identity_meta.copy()

    # ------------------------------------------------------------------
    # Identity meta builder
    # ------------------------------------------------------------------

    def create_initialize_response_meta(
        self,
        request_meta: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Build the ``_meta`` dict for an ``initialize`` response (RFC-007 §6.2).

        Includes server identity (DID, badge) and, if the client sent a PoP nonce
        and a private key is loaded, a PoP signature.

        Args:
            request_meta: The ``_meta`` from the ``initialize`` *request* (for PoP).

        Returns:
            Dict to be included as ``_meta`` in the ``InitializeResult``.
        """
        meta: Dict[str, Any] = {"capiscio_server_did": self.did}
        if self.badge:
            meta["capiscio_server_badge"] = self.badge

        # Attach PoP signature if client sent a nonce and we have a key
        if self._private_key is not None and request_meta is not None:
            pop_request = PoPRequest.from_meta(request_meta)
            if pop_request is not None:
                try:
                    pop_response = create_pop_response(
                        request=pop_request,
                        private_key=self._private_key,
                        key_id=self._key_id,
                    )
                    meta.update(pop_response.to_meta())
                    logger.debug("Added PoP signature to initialize response")
                except Exception as exc:
                    logger.warning("Failed to create PoP response: %s", exc)

        return meta

    # Internal alias used by _setup_identity_injection (legacy compat)
    @property
    def _identity_meta(self) -> Dict[str, Any]:
        meta: Dict[str, Any] = {"capiscio_server_did": self.did}
        if self.badge:
            meta["capiscio_server_badge"] = self.badge
        return meta

    # ------------------------------------------------------------------
    # Tool registration
    # ------------------------------------------------------------------

    def tool(
        self,
        name: Optional[str] = None,
        description: Optional[str] = None,
        min_trust_level: Optional[int] = None,
        config: Optional[GuardConfig] = None,
    ) -> Callable[[Callable[..., Coroutine[Any, Any, T]]], Callable[..., Coroutine[Any, Any, T]]]:
        """Register a tool with CapiscIO trust-level guarding.

        Wraps the function with :func:`~capiscio_mcp.guard.guard` for access
        control based on caller trust level, then registers it with FastMCP.

        Args:
            name: Tool name (defaults to function name).
            description: Tool description (defaults to docstring).
            min_trust_level: Minimum trust level (overrides server default).
            config: Full :class:`~capiscio_mcp.guard.GuardConfig`.

        Example::

            @server.tool(min_trust_level=2)
            async def execute_query(sql: str) -> list[dict]:
                ...
        """

        def decorator(
            func: Callable[..., Coroutine[Any, Any, T]]
        ) -> Callable[..., Coroutine[Any, Any, T]]:
            tool_name = name or func.__name__
            tool_description = description or func.__doc__ or f"Tool: {tool_name}"

            effective_config = config or GuardConfig()
            if min_trust_level is not None:
                effective_config.min_trust_level = min_trust_level
            elif effective_config.min_trust_level == 0:
                effective_config.min_trust_level = self.default_min_trust_level

            guarded_func = guard(config=effective_config, tool_name=tool_name)(func)

            self._tools[tool_name] = guarded_func
            self._tool_configs[tool_name] = effective_config

            self._server.tool(name=tool_name, description=tool_description)(guarded_func)

            logger.debug(
                "Registered tool '%s' with trust level %d",
                tool_name,
                effective_config.min_trust_level,
            )
            return guarded_func

        return decorator

    # ------------------------------------------------------------------
    # Run
    # ------------------------------------------------------------------

    def run(self, transport: str = "stdio") -> None:
        """Run the server with ``_meta`` identity injection enabled.

        Sets ``_capiscio_meta_ctx`` so that the patched ``ServerSession``
        injects the CapiscIO identity into every ``initialize`` response for
        the lifetime of this call.

        Args:
            transport: ``"stdio"`` (default) or ``"streamable-http"``.
        """
        meta = self.create_initialize_response_meta()
        token = _capiscio_meta_ctx.set(meta)
        try:
            self._server.run(transport=transport)
        finally:
            _capiscio_meta_ctx.reset(token)

    def run_stdio(self) -> None:
        """Run over stdio transport (deprecated — use :meth:`run` instead)."""
        self.run(transport="stdio")

    def run_sse(self, port: int = 8080) -> None:
        """Run over SSE transport (deprecated — use ``run(transport='streamable-http')``)."""
        logger.warning("SSE transport is deprecated; use streamable-http instead")
        self.run(transport="sse")


# ---------------------------------------------------------------------------
# CapiscioMCPClient
# ---------------------------------------------------------------------------


class CapiscioMCPClient:
    """MCP Client with automatic server identity and PoP verification.

    On connection this client:

    1. Calls ``session.initialize()`` to get the MCP ``InitializeResult``.
    2. Extracts ``capiscio_server_did`` and ``capiscio_server_badge`` from
       ``result.meta`` (the ``_meta`` dict in the JSON response).
    3. Calls :func:`~capiscio_mcp.server.verify_server` with those values.
    4. Enforces ``min_trust_level`` and ``fail_on_unverified`` constraints.

    Example::

        async with CapiscioMCPClient(
            command="python server/main.py",
            badge=agent.badge,
            min_trust_level=1,
            fail_on_unverified=True,
        ) as client:
            print(f"Server verified at level {client.server_trust_level}")
            files = await client.call_tool("list_files", {"directory": "/tmp"})

    For stdio transport (subprocess server)::

        async with CapiscioMCPClient(
            command="python",
            args=["my_mcp_server.py"],
            min_trust_level=1,
        ) as client:
            result = await client.call_tool("my_tool", {"arg": "value"})
    """

    def __init__(
        self,
        server_url: Optional[str] = None,
        command: Optional[str] = None,
        args: Optional[List[str]] = None,
        min_trust_level: int = 0,
        fail_on_unverified: bool = True,
        require_pop: bool = False,
        verify_config: Optional[VerifyConfig] = None,
        badge: Optional[str] = None,
        api_key: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> None:
        """Initialize ``CapiscioMCPClient``.

        Args:
            server_url: MCP server URL (HTTP transport — not yet implemented).
            command: Command to launch server process (stdio transport).
            args: Arguments for the server command.
            min_trust_level: Minimum required server trust level.
            fail_on_unverified: If ``True``, raise when server doesn't disclose identity.
            require_pop: If ``True``, require PoP verification for ``did:key`` servers.
            verify_config: Full :class:`~capiscio_mcp.server.VerifyConfig`.
            badge: Client badge JWS for authentication.
            api_key: Client API key for authentication (alternative to badge).
            env: Additional environment variables to pass to the server subprocess
                (stdio transport only). All ``CAPISCIO_*`` variables from the
                current process are forwarded automatically; use this to override
                or extend them.

        Raises:
            ValueError: If neither ``server_url`` nor ``command`` is provided.
            ImportError: If the ``mcp`` package is not installed.
        """
        _require_mcp_client()

        if server_url is None and command is None:
            raise ValueError(
                "Either server_url or command must be provided to CapiscioMCPClient "
                "to select an HTTP or stdio transport."
            )

        self.server_url = server_url
        self.command = command
        self.args = args or []
        self.min_trust_level = min_trust_level
        self.fail_on_unverified = fail_on_unverified
        self.require_pop = require_pop
        self.verify_config = verify_config or VerifyConfig(min_trust_level=min_trust_level)
        self._extra_env = env or {}

        self._credential = CallerCredential(
            badge_jws=badge,
            api_key=api_key,
        )

        self._session: Optional[McpClientSession] = None
        self._context_manager: Optional[Any] = None
        self._verify_result: Optional[VerifyResult] = None

        # PoP state
        self._pop_request: Optional[PoPRequest] = None
        self._pop_response: Optional[PoPResponse] = None
        self._pop_verified: bool = False

    # ------------------------------------------------------------------
    # Initialize request _meta (PoP nonce)
    # ------------------------------------------------------------------

    def create_initialize_request_meta(self) -> Dict[str, Any]:
        """Create the ``_meta`` dict for the ``initialize`` request (PoP nonce).

        Returns:
            Dict to include as ``_meta`` in the ``initialize`` request.
        """
        self._pop_request = generate_pop_request()
        return self._pop_request.to_meta()

    # ------------------------------------------------------------------
    # Server verification
    # ------------------------------------------------------------------

    def verify_initialize_response(
        self,
        response_meta: Optional[Dict[str, Any]],
        server_public_key: Optional["Ed25519PublicKey"] = None,
    ) -> bool:
        """Verify the ``initialize`` response including optional PoP.

        Args:
            response_meta: The ``_meta`` dict from the ``InitializeResult``.
            server_public_key: Server public key for PoP (auto-extracted from
                ``did:key`` if not provided).

        Returns:
            ``True`` if PoP verification succeeded, ``False`` otherwise.

        Raises:
            :class:`~capiscio_mcp.pop.PoPSignatureError`: If PoP is required and fails.
        """
        if response_meta is None:
            logger.debug("No _meta in initialize response")
            return False

        self._pop_response = PoPResponse.from_meta(response_meta)
        if self._pop_response is None:
            logger.debug("No PoP response in initialize response")
            return False

        if self._pop_request is None:
            logger.warning("PoP response received but no request was sent")
            return False

        if server_public_key is None:
            server_did = response_meta.get("capiscio_server_did")
            if server_did and server_did.startswith("did:key:"):
                try:
                    server_public_key = extract_public_key_from_did_key(server_did)
                except Exception as exc:
                    logger.warning("Failed to extract public key from DID: %s", exc)
                    if self.require_pop:
                        raise PoPSignatureError(
                            f"Cannot extract public key from {server_did}"
                        )
                    return False
            else:
                logger.debug("Cannot verify PoP for non-did:key DID: %s", server_did)
                return False

        try:
            verify_pop_response(
                request=self._pop_request,
                response=self._pop_response,
                public_key=server_public_key,
            )
            self._pop_verified = True
            logger.info("PoP verification succeeded")
            return True
        except PoPError as exc:
            logger.warning("PoP verification failed: %s", exc)
            if self.require_pop:
                raise
            return False

    async def _verify_server_from_meta(self, meta: Optional[Dict[str, Any]]) -> None:
        """Extract server identity from ``_meta`` and call :func:`verify_server`.

        Sets ``self._verify_result`` and enforces ``min_trust_level`` /
        ``fail_on_unverified`` constraints.

        Args:
            meta: The ``_meta`` dict from ``InitializeResult.meta``.

        Raises:
            :class:`~capiscio_mcp.errors.ServerVerifyError`: If constraints are violated.
        """
        if not meta or not isinstance(meta, dict):
            if self.fail_on_unverified:
                raise ServerVerifyError(
                    error_code=ServerErrorCode.DID_INVALID,
                    detail=(
                        "Server did not disclose identity (_meta missing)"
                        + (f" but min_trust_level={self.min_trust_level} is required"
                           if self.min_trust_level > 0 else "")
                    ),
                )
            logger.debug("Server did not disclose identity (_meta absent or non-dict)")
            return

        server_did = meta.get("capiscio_server_did")
        server_badge = meta.get("capiscio_server_badge")

        if not server_did:
            if self.fail_on_unverified:
                raise ServerVerifyError(
                    error_code=ServerErrorCode.DID_INVALID,
                    detail="Server _meta does not contain capiscio_server_did",
                )
            logger.debug("Server _meta has no capiscio_server_did")
            return

        logger.info("Verifying server identity: DID=%s", server_did)
        self._verify_result = await verify_server(
            server_did=server_did,
            server_badge=server_badge,
            config=self.verify_config,
        )

        state = self._verify_result.state
        trust_level = self._verify_result.trust_level or 0

        logger.info(
            "Server verification result: state=%s trust_level=%d",
            state,
            trust_level,
        )

        if self.fail_on_unverified and state == ServerState.UNVERIFIED_ORIGIN:
            raise ServerVerifyError(
                error_code=ServerErrorCode.DID_INVALID,
                detail=f"Server identity could not be verified (state={state.value})",
                state=state,
                server_did=server_did,
            )

        if trust_level < self.min_trust_level:
            raise ServerVerifyError(
                error_code=ServerErrorCode.TRUST_INSUFFICIENT,
                detail=(
                    f"Server trust level {trust_level} is below required "
                    f"min_trust_level={self.min_trust_level}"
                ),
                state=state,
                server_did=server_did,
            )

    # ------------------------------------------------------------------
    # Context manager / connect / close
    # ------------------------------------------------------------------

    @property
    def pop_verified(self) -> bool:
        """Whether PoP verification succeeded."""
        return self._pop_verified

    async def __aenter__(self) -> "CapiscioMCPClient":
        await self.connect()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.close()

    async def connect(self) -> None:
        """Connect to the MCP server and verify its identity.

        For stdio transport, spawns the server process.
        Extracts ``_meta`` from the ``InitializeResult`` and calls
        :func:`~capiscio_mcp.server.verify_server` to enforce
        ``min_trust_level`` and ``fail_on_unverified`` constraints.

        Raises:
            :class:`~capiscio_mcp.errors.ServerVerifyError`: If server verification fails.
            :exc:`NotImplementedError`: If HTTP transport is requested (not yet supported).
        """
        if self.command:
            # Stdio transport — spawn the server subprocess.
            # MCP's stdio_client only passes a small whitelist of env vars
            # (HOME, PATH, etc.) to the subprocess by default.  Forward all
            # CAPISCIO_* variables so the server can authenticate with the
            # registry, then apply any caller-specified overrides.
            capiscio_env = {
                k: v
                for k, v in os.environ.items()
                if k.startswith("CAPISCIO_") or k == "MCP_SERVER_COMMAND"
            }
            subprocess_env = {**capiscio_env, **self._extra_env}
            server_params = StdioServerParameters(
                command=self.command,
                args=self.args,
                env=subprocess_env if subprocess_env else None,
            )
            self._context_manager = stdio_client(server_params)
            try:
                read_stream, write_stream = await self._context_manager.__aenter__()
                self._session = McpClientSession(read_stream, write_stream)
                try:
                    await self._session.__aenter__()
                    # Initialize the session and capture the result
                    result = await self._session.initialize()
                    # Extract _meta — InitializeResult.meta is the _meta dict
                    response_meta: Optional[Dict[str, Any]] = getattr(result, "meta", None)
                    await self._verify_server_from_meta(response_meta)
                except Exception:
                    if self._session:
                        try:
                            await self._session.__aexit__(None, None, None)
                        except Exception:
                            pass
                    self._session = None
                    raise
            except Exception:
                if self._context_manager:
                    try:
                        await self._context_manager.__aexit__(None, None, None)
                    except Exception:
                        pass
                    self._context_manager = None
                raise
        else:
            logger.warning("HTTP transport not yet implemented; use stdio with command/args")
            raise NotImplementedError("HTTP transport not yet implemented")

        logger.info("Connected to MCP server: %s", self.command or self.server_url)

    async def close(self) -> None:
        """Close the connection to the MCP server."""
        if self._session:
            await self._session.__aexit__(None, None, None)
            self._session = None
        if self._context_manager:
            await self._context_manager.__aexit__(None, None, None)
            self._context_manager = None

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def server_state(self) -> Optional[ServerState]:
        """Server verification state after connection."""
        return self._verify_result.state if self._verify_result else None

    @property
    def server_trust_level(self) -> Optional[int]:
        """Server trust level if verified."""
        return self._verify_result.trust_level if self._verify_result else None

    @property
    def server_did(self) -> Optional[str]:
        """Server DID if disclosed."""
        return self._verify_result.server_did if self._verify_result else None

    @property
    def is_verified(self) -> bool:
        """Whether the server identity is cryptographically verified."""
        return (
            self._verify_result is not None
            and self._verify_result.state == ServerState.VERIFIED_PRINCIPAL
        )

    # ------------------------------------------------------------------
    # Tool calls
    # ------------------------------------------------------------------

    async def call_tool(
        self,
        name: str,
        arguments: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """Call a tool on the connected server, forwarding client credentials.

        For stdio transport the caller's badge (and/or API key) is forwarded in
        the JSON-RPC ``_meta`` of the ``tools/call`` request under the keys
        ``capiscio_caller_badge`` / ``capiscio_caller_api_key``.  The server-side
        :func:`_install_credential_extraction` wrapper picks these up and sets
        the ``_current_credential`` contextvar before the guarded tool runs.

        Args:
            name: Tool name.
            arguments: Tool arguments dict.

        Returns:
            Tool result from the server.

        Raises:
            :exc:`RuntimeError`: If not connected.
        """
        if self._session is None:
            raise RuntimeError("Client not connected. Use 'async with' context.")

        # Build _meta carrying caller credentials for stdio transport.
        meta: Optional[Dict[str, Any]] = None
        if self._credential.badge_jws or self._credential.api_key:
            meta = {}
            if self._credential.badge_jws:
                meta["capiscio_caller_badge"] = self._credential.badge_jws
            if self._credential.api_key:
                meta["capiscio_caller_api_key"] = self._credential.api_key

        return await self._session.call_tool(name, arguments or {}, meta=meta)

    async def list_tools(self) -> List[Dict[str, Any]]:
        """List tools available on the connected server.

        Returns:
            List of ``{"name": ..., "description": ...}`` dicts.

        Raises:
            :exc:`RuntimeError`: If not connected.
        """
        if self._session is None:
            raise RuntimeError("Client not connected. Use 'async with' context.")

        result = await self._session.list_tools()
        return [
            {"name": tool.name, "description": tool.description}
            for tool in result.tools
        ]
