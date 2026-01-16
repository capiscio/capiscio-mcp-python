"""
Exception types for capiscio-mcp.

Provides typed exceptions for:
- Guard (RFC-006) errors
- Server verification (RFC-007) errors
- Core connection errors
"""

from __future__ import annotations

from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from capiscio_mcp.types import DenyReason, ServerErrorCode, ServerState


class CapiscioMCPError(Exception):
    """Base exception for all capiscio-mcp errors."""
    pass


# =============================================================================
# Core Connection Errors
# =============================================================================


class CoreConnectionError(CapiscioMCPError):
    """
    Raised when connection to capiscio-core fails.
    
    This includes:
    - Binary download failures
    - Process startup failures
    - gRPC connection failures
    - Health check failures
    """
    pass


class CoreVersionError(CapiscioMCPError):
    """
    Raised when capiscio-core version is incompatible.
    
    capiscio-mcp requires a specific range of capiscio-core versions.
    This error indicates the connected core is outside that range.
    """
    pass


# =============================================================================
# RFC-006: Guard Errors
# =============================================================================


class GuardError(CapiscioMCPError):
    """
    Raised when tool access is denied by the guard.
    
    Per RFC-006, all denials include:
    - reason: Specific denial reason code
    - detail: Human-readable explanation
    - evidence_id: ID of the evidence record for audit
    
    Example:
        try:
            result = await guarded_tool(params)
        except GuardError as e:
            logger.warning(f"Access denied: {e.reason} - {e.detail}")
            logger.info(f"Evidence ID: {e.evidence_id}")
    """
    
    def __init__(
        self,
        reason: "DenyReason",
        detail: str,
        evidence_id: str = "",
        agent_did: Optional[str] = None,
        trust_level: Optional[int] = None,
    ):
        self.reason = reason
        self.detail = detail
        self.evidence_id = evidence_id
        self.agent_did = agent_did
        self.trust_level = trust_level
        
        message = f"{reason.value}: {detail}"
        if evidence_id:
            message += f" (evidence_id={evidence_id})"
        
        super().__init__(message)
    
    def __repr__(self) -> str:
        return (
            f"GuardError(reason={self.reason!r}, detail={self.detail!r}, "
            f"evidence_id={self.evidence_id!r})"
        )


class GuardConfigError(CapiscioMCPError):
    """
    Raised when guard configuration is invalid.
    
    This includes:
    - Invalid trust level values
    - Invalid tool name patterns
    - Conflicting configuration options
    """
    pass


# =============================================================================
# RFC-007: Server Verification Errors
# =============================================================================


class ServerVerifyError(CapiscioMCPError):
    """
    Raised when server identity verification fails.
    
    Per RFC-007, verification can fail for various reasons including:
    - Invalid DID format
    - Badge verification failure
    - Origin/path binding mismatch
    - Trust level insufficient
    
    Example:
        try:
            result = await verify_server(server_did, server_badge)
        except ServerVerifyError as e:
            logger.warning(f"Server verification failed: {e.error_code}")
            if e.state == ServerState.UNVERIFIED_ORIGIN:
                logger.warning("Server did not disclose identity")
    """
    
    def __init__(
        self,
        error_code: "ServerErrorCode",
        detail: str,
        state: Optional["ServerState"] = None,
        server_did: Optional[str] = None,
    ):
        self.error_code = error_code
        self.detail = detail
        self.state = state
        self.server_did = server_did
        
        message = f"{error_code.value}: {detail}"
        super().__init__(message)
    
    def __repr__(self) -> str:
        return (
            f"ServerVerifyError(error_code={self.error_code!r}, "
            f"detail={self.detail!r}, state={self.state!r})"
        )


# =============================================================================
# Evidence Errors
# =============================================================================


class EvidenceError(CapiscioMCPError):
    """
    Raised when evidence logging fails.
    
    Evidence logging should not block tool execution, so this error
    is typically logged rather than raised to callers.
    """
    
    def __init__(self, message: str, evidence_id: Optional[str] = None):
        self.evidence_id = evidence_id
        super().__init__(message)
