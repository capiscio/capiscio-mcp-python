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

Installation:
    pip install capiscio-mcp          # Standalone
    pip install capiscio-mcp[mcp]     # With MCP SDK integration
    pip install capiscio-mcp[crypto]  # With PoP signing/verification

Quickstart (Server-side):
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

Quickstart (Server Registration):
    from capiscio_mcp import setup_server_identity

    result = await setup_server_identity(
        server_id="your-server-uuid",
        api_key="sk_live_...",
        output_dir="./keys",
    )
    print(f"Server DID: {result['did']}")
"""

from capiscio_mcp.types import (
    Decision,
    AuthLevel,
    DenyReason,
    ServerState,
    ServerErrorCode,
)
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
)
from capiscio_mcp.server import (
    verify_server,
    verify_server_sync,
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
    # Server (RFC-007)
    "verify_server",
    "verify_server_sync",
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
]
