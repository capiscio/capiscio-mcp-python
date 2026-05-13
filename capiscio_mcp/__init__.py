"""
capiscio-mcp: Trust badges for MCP tool calls.

RFC-006: MCP Tool Authority and Evidence
RFC-007: MCP Server Identity Disclosure and Verification

This package provides:
- @guard decorator for protecting MCP tools with trust-level requirements
- Server identity verification for MCP clients
- Server identity registration for MCP servers
- PoP (Proof of Possession) handshake for server key verification
- Evidence logging for audit and forensics
- One-line server identity setup via CapiscioMCPServer.connect()

Installation:
    pip install capiscio-mcp          # Standalone
    pip install capiscio-mcp[mcp]     # With MCP SDK integration
    pip install capiscio-mcp[crypto]  # With PoP signing/verification

Quickstart ("Let's Encrypt" style — recommended):
    from capiscio_mcp.integrations.mcp import CapiscioMCPServer

    server = CapiscioMCPServer.connect()

    @server.tool(min_trust_level=2)
    async def read_file(path: str) -> str:
        ...

    server.run()

Quickstart (@guard decorator):
    from capiscio_mcp import guard

    @guard(min_trust_level=2)
    async def read_database(query: str) -> list[dict]:
        ...

Quickstart (Client-side):
    from capiscio_mcp import verify_server, ServerState

    result = await verify_server(
        server_did="did:web:mcp.example.com",
        server_badge="eyJhbGc...",
    )
    if result.state == ServerState.VERIFIED_PRINCIPAL:
        print(f"Trusted at level {result.trust_level}")

Quickstart (Server Registration, manual):
    from capiscio_mcp import setup_server_identity

    result = await setup_server_identity(
        server_id="your-server-uuid",
        api_key="sk_live_...",
        output_dir="./keys",
    )
    print(f"Server DID: {result['did']}")
"""

import os as _os

# Suppress gRPC C-core stderr noise (ev_poll_posix.cc, fork_posix.cc, etc.)
# before any gRPC import.  Library users should not see low-level C-core logs.
_os.environ.setdefault("GRPC_VERBOSITY", "NONE")
_os.environ.setdefault("GRPC_TRACE", "")

from capiscio_mcp.types import (
    Decision,
    AuthLevel,
    DenyReason,
    ServerState,
    ServerErrorCode,
    TrustLevel,
)

# Eagerly register MCP proto descriptor before capiscio-sdk can register its
# simpler version.  The MCP proto is a superset (has PolicyDecision* etc.), so
# the SDK can safely fall back to it when it detects a duplicate.
import capiscio_mcp._proto.gen.capiscio.v1.mcp_pb2 as _mcp_pb2  # noqa: F401, E402

from capiscio_mcp.errors import (
    GuardError,
    ServerVerifyError,
    CoreConnectionError,
    CoreVersionError,
)
from capiscio_mcp.guard import (
    guard,
    guard_sync,
    GuardConfig,
    GuardResult,
    compute_params_hash,
    evaluate_tool_access,
)
from capiscio_mcp.server import (
    verify_server,
    verify_server_sync,
    verify_server_strict,
    VerifyConfig,
    VerifyResult,
    parse_http_headers,
    parse_jsonrpc_meta,
)
from capiscio_mcp.pop import (
    PoPRequest,
    PoPResponse,
    generate_pop_request,
    create_pop_response,
    verify_pop_response,
    PoPError,
    PoPSignatureError,
    PoPExpiredError,
)
from capiscio_mcp.registration import (
    generate_server_keypair,
    generate_server_keypair_sync,
    register_server_identity,
    register_server_identity_sync,
    setup_server_identity,
    setup_server_identity_sync,
    RegistrationError,
    KeyGenerationError,
)
from capiscio_mcp.keeper import ServerBadgeKeeper
from capiscio_mcp.connect import MCPServerIdentity
from capiscio_mcp.events import (
    GuardEventEmitter,
    get_event_emitter,
    set_event_emitter,
)
from capiscio_mcp.pip import (
    PIPConfig,
    PolicyClient,
    PolicyResult,
)
from capiscio_mcp._core.version import (
    MCP_VERSION,
    CORE_MIN_VERSION,
    PROTO_VERSION,
)

__version__ = MCP_VERSION

__all__ = [
    # Version
    "__version__",
    "MCP_VERSION",
    "CORE_MIN_VERSION",
    "PROTO_VERSION",
    # Types
    "Decision",
    "AuthLevel",
    "DenyReason",
    "ServerState",
    "ServerErrorCode",
    "TrustLevel",
    # Errors
    "GuardError",
    "ServerVerifyError",
    "CoreConnectionError",
    "CoreVersionError",
    # Guard (RFC-006)
    "guard",
    "guard_sync",
    "GuardConfig",
    "GuardResult",
    "compute_params_hash",
    "evaluate_tool_access",
    # Policy (RFC-005)
    "PIPConfig",
    "PolicyClient",
    "PolicyResult",
    # Server (RFC-007)
    "verify_server",
    "verify_server_sync",
    "verify_server_strict",
    "VerifyConfig",
    "VerifyResult",
    "parse_http_headers",
    "parse_jsonrpc_meta",
    # PoP (RFC-007 Key Verification)
    "PoPRequest",
    "PoPResponse",
    "generate_pop_request",
    "create_pop_response",
    "verify_pop_response",
    "PoPError",
    "PoPSignatureError",
    "PoPExpiredError",
    # Registration (MCP Server Identity)
    "generate_server_keypair",
    "generate_server_keypair_sync",
    "register_server_identity",
    "register_server_identity_sync",
    "setup_server_identity",
    "setup_server_identity_sync",
    "RegistrationError",
    "KeyGenerationError",
    # One-liner identity setup (MCPServerIdentity.connect())
    "MCPServerIdentity",
    "ServerBadgeKeeper",
    # Event emission (RFC-008)
    "GuardEventEmitter",
    "get_event_emitter",
    "set_event_emitter",
]
