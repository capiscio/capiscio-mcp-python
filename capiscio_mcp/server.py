"""
RFC-007: MCP Server Identity Verification.

This module provides functions to verify MCP server identity
before establishing trust with the server.

Key distinction from Trust Level 0:
- UNVERIFIED_ORIGIN: Server disclosed NO identity material at all
- Trust Level 0: Server disclosed a self-signed (did:key) identity

Usage:
    from capiscio_mcp import verify_server, ServerState, VerifyConfig

    result = await verify_server(
        server_did="did:web:mcp.example.com:servers:filesystem",
        server_badge="eyJhbGc...",
        transport_origin="https://mcp.example.com",
    )
    
    if result.state == ServerState.VERIFIED_PRINCIPAL:
        print(f"Server verified at trust level {result.trust_level}")
    elif result.state == ServerState.UNVERIFIED_ORIGIN:
        print("Warning: Server did not disclose identity")
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from capiscio_mcp.types import ServerState, ServerErrorCode
from capiscio_mcp.errors import ServerVerifyError

logger = logging.getLogger(__name__)


@dataclass
class VerifyConfig:
    """
    Configuration for server identity verification.
    
    Attributes:
        trusted_issuers: List of trusted issuer DIDs
        min_trust_level: Minimum trust level required (0-4)
        accept_level_zero: Accept self-signed (did:key) servers
        offline_mode: Skip revocation checks
        skip_origin_binding: Skip host/path binding checks (for trusted gateways)
    """
    trusted_issuers: Optional[List[str]] = None
    min_trust_level: int = 0
    accept_level_zero: bool = False
    offline_mode: bool = False
    skip_origin_binding: bool = False


@dataclass
class VerifyResult:
    """
    Result of server identity verification.
    
    Attributes:
        state: Server classification state (VERIFIED_PRINCIPAL, DECLARED_PRINCIPAL, UNVERIFIED_ORIGIN)
        trust_level: Trust level if verified (0-4)
        server_did: Server DID if disclosed
        badge_jti: Badge ID if present
        error_code: Error code if verification failed
        error_detail: Human-readable error detail
    """
    state: ServerState
    trust_level: Optional[int] = None
    
    # Derived identity
    server_did: Optional[str] = None
    badge_jti: Optional[str] = None
    
    # Error details
    error_code: ServerErrorCode = ServerErrorCode.NONE
    error_detail: Optional[str] = None
    
    @property
    def is_verified(self) -> bool:
        """Check if server identity is cryptographically verified."""
        return self.state == ServerState.VERIFIED_PRINCIPAL
    
    @property
    def has_identity(self) -> bool:
        """Check if server disclosed any identity."""
        return self.state != ServerState.UNVERIFIED_ORIGIN


async def verify_server(
    server_did: Optional[str],
    server_badge: Optional[str] = None,
    transport_origin: Optional[str] = None,
    endpoint_path: Optional[str] = None,
    config: Optional[VerifyConfig] = None,
) -> VerifyResult:
    """
    Verify MCP server identity per RFC-007 §7.2.
    
    This function implements the client verification algorithm:
    1. If no DID disclosed → UNVERIFIED_ORIGIN
    2. If DID but no badge → DECLARED_PRINCIPAL
    3. If DID + badge → verify badge → VERIFIED_PRINCIPAL or error
    
    Args:
        server_did: Server DID from Capiscio-Server-DID header or _meta
        server_badge: Server badge JWS from Capiscio-Server-Badge header or _meta
        transport_origin: HTTP origin (e.g., "https://mcp.example.com")
        endpoint_path: URL path for did:web binding (e.g., "/mcp/filesystem")
        config: Verification configuration
    
    Returns:
        VerifyResult with state, trust_level, and any error details
        
    Example:
        result = await verify_server(
            server_did="did:web:mcp.example.com:servers:filesystem",
            server_badge="eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...",
            transport_origin="https://mcp.example.com",
        )
        
        match result.state:
            case ServerState.VERIFIED_PRINCIPAL:
                print(f"Verified at level {result.trust_level}")
            case ServerState.DECLARED_PRINCIPAL:
                print("Identity claimed but not verified")
            case ServerState.UNVERIFIED_ORIGIN:
                print("No identity disclosed")
    """
    from capiscio_mcp._core.client import CoreClient
    
    effective_config = config or VerifyConfig()
    
    # Quick path: no DID disclosed at all
    if not server_did:
        logger.debug("Server did not disclose identity (UNVERIFIED_ORIGIN)")
        return VerifyResult(
            state=ServerState.UNVERIFIED_ORIGIN,
            error_code=ServerErrorCode.NONE,
        )
    
    # Quick path: DID disclosed but no badge → DECLARED_PRINCIPAL
    # Per RFC-007 §7.2: No badge means identity is claimed but not verified
    # This path doesn't require gRPC connection to capiscio-core
    if not server_badge:
        logger.debug(f"Server disclosed DID ({server_did}) but no badge (DECLARED_PRINCIPAL)")
        return VerifyResult(
            state=ServerState.DECLARED_PRINCIPAL,
            server_did=server_did,
            error_code=ServerErrorCode.NONE,
        )
    
    # Full verification path: DID + badge requires gRPC validation
    # Get core client
    client = await CoreClient.get_instance()
    
    # Import proto
    from capiscio_mcp._proto.capiscio.v1 import mcp_pb2
    
    # Build request
    request = mcp_pb2.VerifyServerIdentityRequest(
        server_did=server_did,
        server_badge=server_badge or "",
        transport_origin=transport_origin or "",
        endpoint_path=endpoint_path or "",
        config=mcp_pb2.VerifyConfig(
            trusted_issuers=effective_config.trusted_issuers or [],
            min_trust_level=effective_config.min_trust_level,
            accept_level_zero=effective_config.accept_level_zero,
            offline_mode=effective_config.offline_mode,
            skip_origin_binding=effective_config.skip_origin_binding,
        ),
    )
    
    # Make RPC call
    response = await client.stub.VerifyServerIdentity(request)
    
    # Map response state
    state_map = {
        mcp_pb2.VERIFIED_PRINCIPAL: ServerState.VERIFIED_PRINCIPAL,
        mcp_pb2.DECLARED_PRINCIPAL: ServerState.DECLARED_PRINCIPAL,
        mcp_pb2.UNVERIFIED_ORIGIN: ServerState.UNVERIFIED_ORIGIN,
    }
    state = state_map.get(response.state, ServerState.UNVERIFIED_ORIGIN)
    
    # Map error code
    error_code_map = {
        mcp_pb2.SERVER_ERROR_NONE: ServerErrorCode.NONE,
        mcp_pb2.SERVER_DID_INVALID: ServerErrorCode.DID_INVALID,
        mcp_pb2.SERVER_BADGE_INVALID: ServerErrorCode.BADGE_INVALID,
        mcp_pb2.SERVER_BADGE_EXPIRED: ServerErrorCode.BADGE_EXPIRED,
        mcp_pb2.SERVER_BADGE_REVOKED: ServerErrorCode.BADGE_REVOKED,
        mcp_pb2.SERVER_TRUST_INSUFFICIENT: ServerErrorCode.TRUST_INSUFFICIENT,
        mcp_pb2.SERVER_ORIGIN_MISMATCH: ServerErrorCode.ORIGIN_MISMATCH,
        mcp_pb2.SERVER_PATH_MISMATCH: ServerErrorCode.PATH_MISMATCH,
        mcp_pb2.SERVER_ISSUER_UNTRUSTED: ServerErrorCode.ISSUER_UNTRUSTED,
    }
    error_code = error_code_map.get(response.error_code, ServerErrorCode.NONE)
    
    result = VerifyResult(
        state=state,
        trust_level=response.trust_level if response.trust_level > 0 else None,
        server_did=response.server_did or None,
        badge_jti=response.badge_jti or None,
        error_code=error_code,
        error_detail=response.error_detail or None,
    )
    
    logger.debug(f"Server verification result: state={state.value}, trust_level={result.trust_level}")
    
    return result


def verify_server_sync(
    server_did: Optional[str],
    server_badge: Optional[str] = None,
    transport_origin: Optional[str] = None,
    endpoint_path: Optional[str] = None,
    config: Optional[VerifyConfig] = None,
) -> VerifyResult:
    """
    Sync wrapper for verify_server.
    
    Args:
        server_did: Server DID from Capiscio-Server-DID header or _meta
        server_badge: Server badge JWS from Capiscio-Server-Badge header or _meta
        transport_origin: HTTP origin (e.g., "https://mcp.example.com")
        endpoint_path: URL path for did:web binding
        config: Verification configuration
    
    Returns:
        VerifyResult with state, trust_level, and any error details
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    
    if loop is not None:
        import concurrent.futures
        future = asyncio.run_coroutine_threadsafe(
            verify_server(server_did, server_badge, transport_origin, endpoint_path, config),
            loop,
        )
        return future.result(timeout=30.0)
    else:
        return asyncio.run(
            verify_server(server_did, server_badge, transport_origin, endpoint_path, config)
        )


def parse_http_headers(headers: Dict[str, str]) -> Tuple[Optional[str], Optional[str]]:
    """
    Extract server identity from HTTP response headers.
    
    RFC-007 §6.1 specifies these header names:
    - Capiscio-Server-DID: Server's DID
    - Capiscio-Server-Badge: Server's badge (JWS)
    
    Args:
        headers: HTTP response headers dict (case-insensitive lookup)
    
    Returns:
        Tuple of (server_did, server_badge)
        
    Example:
        did, badge = parse_http_headers(response.headers)
        result = await verify_server(did, badge)
    """
    # Try exact case first, then case-insensitive
    def get_header(name: str) -> Optional[str]:
        if name in headers:
            return headers[name]
        # Case-insensitive lookup
        lower_name = name.lower()
        for key, value in headers.items():
            if key.lower() == lower_name:
                return value
        return None
    
    return (
        get_header("Capiscio-Server-DID"),
        get_header("Capiscio-Server-Badge"),
    )


def parse_jsonrpc_meta(meta: Optional[Dict[str, Any]]) -> Tuple[Optional[str], Optional[str]]:
    """
    Extract server identity from MCP initialize response _meta.
    
    RFC-007 §6.2 specifies these _meta keys:
    - capiscio_server_did: Server's DID
    - capiscio_server_badge: Server's badge (JWS)
    
    For PoP fields, use pop.PoPRequest.from_meta() and pop.PoPResponse.from_meta().
    
    Args:
        meta: The _meta object from InitializeResult
    
    Returns:
        Tuple of (server_did, server_badge)
        
    Example:
        # In MCP client initialization
        result = await client.initialize()
        did, badge = parse_jsonrpc_meta(result.meta)
        verify_result = await verify_server(did, badge)
        
        # For PoP verification
        from capiscio_mcp.pop import PoPResponse, verify_pop_response
        pop_response = PoPResponse.from_meta(result.meta)
    """
    if meta is None:
        return (None, None)
    
    return (
        meta.get("capiscio_server_did"),
        meta.get("capiscio_server_badge"),
    )


async def verify_server_strict(
    server_did: Optional[str],
    server_badge: Optional[str] = None,
    transport_origin: Optional[str] = None,
    endpoint_path: Optional[str] = None,
    config: Optional[VerifyConfig] = None,
) -> VerifyResult:
    """
    Verify server identity with strict requirements.
    
    Like verify_server(), but raises ServerVerifyError if:
    - No identity is disclosed (UNVERIFIED_ORIGIN)
    - Badge is missing (DECLARED_PRINCIPAL)
    - Verification fails (any error)
    
    Args:
        server_did: Server DID
        server_badge: Server badge JWS
        transport_origin: HTTP origin
        endpoint_path: URL path
        config: Verification configuration
    
    Returns:
        VerifyResult with state=VERIFIED_PRINCIPAL
        
    Raises:
        ServerVerifyError: If verification fails or identity missing
        
    Example:
        try:
            result = await verify_server_strict(did, badge, origin)
            print(f"Server verified at level {result.trust_level}")
        except ServerVerifyError as e:
            print(f"Server verification failed: {e}")
    """
    result = await verify_server(
        server_did, server_badge, transport_origin, endpoint_path, config
    )
    
    if result.state == ServerState.UNVERIFIED_ORIGIN:
        raise ServerVerifyError(
            error_code=ServerErrorCode.DID_INVALID,
            detail="Server did not disclose identity",
            state=result.state,
        )
    
    if result.state == ServerState.DECLARED_PRINCIPAL:
        raise ServerVerifyError(
            error_code=ServerErrorCode.BADGE_INVALID,
            detail="Server did not provide verifiable badge",
            state=result.state,
            server_did=result.server_did,
        )
    
    if result.error_code != ServerErrorCode.NONE:
        raise ServerVerifyError(
            error_code=result.error_code,
            detail=result.error_detail or "Server verification failed",
            state=result.state,
            server_did=result.server_did,
        )
    
    return result
