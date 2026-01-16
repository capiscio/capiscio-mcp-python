"""
Placeholder for generated mcp_pb2.py.

This module will be replaced by actual protobuf-generated code from
proto/capiscio/v1/mcp.proto when capiscio-core v2.5.0 is released.

For now, we define the message classes and enums as Python classes
to support development and testing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


# =============================================================================
# Enums
# =============================================================================

# Decision enum
DECISION_UNSPECIFIED = 0
ALLOW = 1
DENY = 2

# AuthLevel enum
AUTH_LEVEL_UNSPECIFIED = 0
ANONYMOUS = 1
API_KEY = 2
BADGE = 3

# DenyReason enum
DENY_REASON_UNSPECIFIED = 0
TOOL_BADGE_MISSING = 1
TOOL_BADGE_INVALID = 2
TOOL_BADGE_EXPIRED = 3
TOOL_BADGE_REVOKED = 4
TOOL_TRUST_INSUFFICIENT = 5
TOOL_NOT_ALLOWED = 6
TOOL_ISSUER_UNTRUSTED = 7
TOOL_POLICY_DENIED = 8

# ServerState enum
SERVER_STATE_UNSPECIFIED = 0
VERIFIED_PRINCIPAL = 1
DECLARED_PRINCIPAL = 2
UNVERIFIED_ORIGIN = 3

# ServerErrorCode enum
SERVER_ERROR_NONE = 0
SERVER_DID_INVALID = 1
SERVER_BADGE_INVALID = 2
SERVER_BADGE_EXPIRED = 3
SERVER_BADGE_REVOKED = 4
SERVER_TRUST_INSUFFICIENT = 5
SERVER_ORIGIN_MISMATCH = 6
SERVER_PATH_MISMATCH = 7
SERVER_ISSUER_UNTRUSTED = 8


# =============================================================================
# Messages
# =============================================================================

@dataclass
class EvaluateConfig:
    """Configuration for EvaluateToolAccess."""
    trusted_issuers: List[str] = field(default_factory=list)
    min_trust_level: int = 0
    accept_level_zero: bool = False
    allowed_tools: List[str] = field(default_factory=list)


@dataclass
class EvaluateToolAccessRequest:
    """Request message for EvaluateToolAccess RPC."""
    tool_name: str = ""
    params_hash: str = ""
    server_origin: str = ""
    badge_jws: str = ""  # oneof caller_credential
    api_key: str = ""    # oneof caller_credential
    policy_version: str = ""
    config: Optional[EvaluateConfig] = None


@dataclass
class Timestamp:
    """Protobuf Timestamp placeholder."""
    seconds: int = 0
    nanos: int = 0


@dataclass
class EvaluateToolAccessResponse:
    """Response message for EvaluateToolAccess RPC."""
    decision: int = DECISION_UNSPECIFIED
    deny_reason: int = DENY_REASON_UNSPECIFIED
    deny_detail: str = ""
    agent_did: str = ""
    badge_jti: str = ""
    auth_level: int = AUTH_LEVEL_UNSPECIFIED
    trust_level: int = 0
    evidence_json: str = ""
    evidence_id: str = ""
    timestamp: Optional[Timestamp] = None


@dataclass
class VerifyConfig:
    """Configuration for VerifyServerIdentity."""
    trusted_issuers: List[str] = field(default_factory=list)
    min_trust_level: int = 0
    accept_level_zero: bool = False
    offline_mode: bool = False
    skip_origin_binding: bool = False


@dataclass
class VerifyServerIdentityRequest:
    """Request message for VerifyServerIdentity RPC."""
    server_did: str = ""
    server_badge: str = ""
    transport_origin: str = ""
    endpoint_path: str = ""
    config: Optional[VerifyConfig] = None


@dataclass
class VerifyServerIdentityResponse:
    """Response message for VerifyServerIdentity RPC."""
    state: int = SERVER_STATE_UNSPECIFIED
    trust_level: int = 0
    server_did: str = ""
    badge_jti: str = ""
    error_code: int = SERVER_ERROR_NONE
    error_detail: str = ""


@dataclass
class HttpHeaders:
    """HTTP headers for ParseServerIdentity."""
    capiscio_server_did: str = ""
    capiscio_server_badge: str = ""


@dataclass
class JsonRpcMeta:
    """JSON-RPC _meta for ParseServerIdentity."""
    meta_json: str = ""


@dataclass
class ParseServerIdentityRequest:
    """Request message for ParseServerIdentity RPC."""
    http_headers: Optional[HttpHeaders] = None
    jsonrpc_meta: Optional[JsonRpcMeta] = None


@dataclass
class ParseServerIdentityResponse:
    """Response message for ParseServerIdentity RPC."""
    server_did: str = ""
    server_badge: str = ""
    identity_present: bool = False


@dataclass
class HealthRequest:
    """Request message for Health RPC."""
    client_version: str = ""


@dataclass
class HealthResponse:
    """Response message for Health RPC."""
    healthy: bool = True
    core_version: str = ""
    proto_version: str = ""
    version_compatible: bool = True
