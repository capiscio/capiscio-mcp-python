"""
Type definitions for capiscio-mcp.

Defines enums and dataclasses used across the package for:
- RFC-006: Tool authority decisions and deny reasons
- RFC-007: Server identity states and error codes
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, IntEnum
from typing import Optional, List


# =============================================================================
# RFC-006: Tool Authority Types
# =============================================================================


class Decision(str, Enum):
    """
    Tool access decision result.
    
    Per RFC-006 §6.3, every tool invocation attempt results in one of:
    - ALLOW: Tool execution is permitted
    - DENY: Tool execution is blocked with a reason
    """
    ALLOW = "allow"
    DENY = "deny"


class AuthLevel(str, Enum):
    """
    Caller authentication assurance level.
    
    Per RFC-006 §5, every evidence log records the authentication method:
    - ANONYMOUS: No identity material provided
    - API_KEY: API key authentication (reduced assurance)
    - BADGE: CapiscIO Trust Badge authentication (full assurance)
    """
    ANONYMOUS = "anonymous"
    API_KEY = "api_key"
    BADGE = "badge"


class DenyReason(str, Enum):
    """
    Reason for denying tool access.
    
    Per RFC-006 §6.4, denial must include a specific reason code.
    """
    # Badge issues
    BADGE_MISSING = "badge_missing"           # Required but not provided
    BADGE_INVALID = "badge_invalid"           # Malformed or unverifiable
    BADGE_EXPIRED = "badge_expired"           # Past expiration time
    BADGE_REVOKED = "badge_revoked"           # On revocation list
    
    # Trust issues
    TRUST_INSUFFICIENT = "trust_insufficient" # Trust level < min required
    ISSUER_UNTRUSTED = "issuer_untrusted"     # Issuer not in trusted list
    
    # Policy issues
    TOOL_NOT_ALLOWED = "tool_not_allowed"     # Tool not in allowed list
    POLICY_DENIED = "policy_denied"           # Policy evaluation failed
    
    # Other
    INTERNAL_ERROR = "internal_error"         # Unexpected error


class TrustLevel(IntEnum):
    """
    Trust levels per RFC-002 v1.4.
    
    - LEVEL_0: Self-Signed (SS) - did:key issuer, no external validation
    - LEVEL_1: Registered (REG) - Account registration with CapiscIO Registry
    - LEVEL_2: Domain Validated (DV) - DNS/HTTP challenge proving domain control
    - LEVEL_3: Organization Validated (OV) - DUNS/legal entity verification
    - LEVEL_4: Extended Validated (EV) - Manual review + legal agreement
    
    See: https://docs.capisc.io/rfcs/002-trust-badge/#5-trust-levels
    """
    LEVEL_0 = 0  # Self-Signed (SS)
    LEVEL_1 = 1  # Registered (REG)
    LEVEL_2 = 2  # Domain Validated (DV)
    LEVEL_3 = 3  # Organization Validated (OV)
    LEVEL_4 = 4  # Extended Validated (EV)


# =============================================================================
# RFC-007: Server Identity Types
# =============================================================================


class ServerState(str, Enum):
    """
    Server identity verification state.
    
    Per RFC-007 §5.2, clients classify servers into three states:
    
    - VERIFIED_PRINCIPAL: Server badge verified, trust level established.
      The server has disclosed a DID and a valid badge signed by a trusted issuer.
      
    - DECLARED_PRINCIPAL: Server DID disclosed but badge missing or invalid.
      Identity is claimed but not cryptographically verified.
      
    - UNVERIFIED_ORIGIN: Server did not disclose any identity material.
      This is distinct from Trust Level 0 (self-signed) - UNVERIFIED_ORIGIN
      means NO identity was disclosed at all.
    """
    VERIFIED_PRINCIPAL = "verified_principal"
    DECLARED_PRINCIPAL = "declared_principal"
    UNVERIFIED_ORIGIN = "unverified_origin"


class ServerErrorCode(str, Enum):
    """
    Server identity verification error codes.
    
    Per RFC-007 §8, verification failures include specific error codes.
    """
    NONE = "none"
    DID_INVALID = "did_invalid"
    BADGE_INVALID = "badge_invalid"
    BADGE_EXPIRED = "badge_expired"
    BADGE_REVOKED = "badge_revoked"
    TRUST_INSUFFICIENT = "trust_insufficient"
    ORIGIN_MISMATCH = "origin_mismatch"
    PATH_MISMATCH = "path_mismatch"
    ISSUER_UNTRUSTED = "issuer_untrusted"


# =============================================================================
# Dataclasses
# =============================================================================


@dataclass
class CallerCredential:
    """
    Caller credential for tool access evaluation.
    
    Only one of badge_jws or api_key should be set.
    If neither is set, the caller is treated as anonymous.
    """
    badge_jws: Optional[str] = None
    api_key: Optional[str] = None
    
    @property
    def auth_level(self) -> AuthLevel:
        """Derive authentication level from credential type."""
        if self.badge_jws:
            return AuthLevel.BADGE
        elif self.api_key:
            return AuthLevel.API_KEY
        return AuthLevel.ANONYMOUS


@dataclass
class EvidenceRecord:
    """
    RFC-006 §7 compliant evidence record.
    
    Every tool invocation attempt produces an evidence record,
    regardless of whether access was allowed or denied.
    """
    # Identifiers
    evidence_id: str
    timestamp: datetime
    
    # Tool context
    tool_name: str
    params_hash: str
    server_origin: str
    
    # Caller identity
    agent_did: Optional[str]
    badge_jti: Optional[str]
    auth_level: AuthLevel
    trust_level: int
    
    # Decision
    decision: Decision
    deny_reason: Optional[DenyReason] = None
    deny_detail: Optional[str] = None
    
    # Policy
    policy_version: Optional[str] = None


@dataclass
class ToolAccessResult:
    """
    Result of tool access evaluation.
    
    Contains the decision, derived identity, and evidence record.
    This is the unified response from EvaluateToolAccess RPC.
    """
    # Decision
    decision: Decision
    deny_reason: Optional[DenyReason] = None
    deny_detail: Optional[str] = None
    
    # Derived identity (core extracts from credential)
    agent_did: Optional[str] = None
    badge_jti: Optional[str] = None
    auth_level: AuthLevel = AuthLevel.ANONYMOUS
    trust_level: int = 0
    
    # Evidence (single source of truth)
    evidence_id: str = ""
    evidence_json: str = ""
    timestamp: Optional[datetime] = None


@dataclass
class ServerIdentityResult:
    """
    Result of server identity verification.
    
    Contains the server state, trust level, and any error details.
    """
    # State
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
