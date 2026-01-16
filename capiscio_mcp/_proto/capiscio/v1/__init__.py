"""
Capiscio v1 proto package.

Re-exports generated protobuf code for MCP service.
Provides compatibility aliases for message names.
"""

# Import from generated code
from capiscio_mcp._proto.gen.capiscio.v1 import mcp_pb2
from capiscio_mcp._proto.gen.capiscio.v1 import mcp_pb2_grpc

# Add compatibility aliases for message names that changed in proto definition
# The proto uses MCP-prefixed names (MCPHealthRequest) but the SDK originally
# used shorter names (HealthRequest). We add both as attributes.
if not hasattr(mcp_pb2, 'HealthRequest'):
    mcp_pb2.HealthRequest = mcp_pb2.MCPHealthRequest
if not hasattr(mcp_pb2, 'HealthResponse'):
    mcp_pb2.HealthResponse = mcp_pb2.MCPHealthResponse
if not hasattr(mcp_pb2, 'VerifyConfig'):
    mcp_pb2.VerifyConfig = mcp_pb2.MCPVerifyConfig
if not hasattr(mcp_pb2, 'HttpHeaders'):
    mcp_pb2.HttpHeaders = mcp_pb2.MCPHttpHeaders
if not hasattr(mcp_pb2, 'JsonRpcMeta'):
    mcp_pb2.JsonRpcMeta = mcp_pb2.MCPJsonRpcMeta

# Enum value aliases - the proto uses MCP_* prefixed enum values
# Map old placeholder enum names to generated enum values
# Decision
if not hasattr(mcp_pb2, 'DECISION_UNSPECIFIED'):
    mcp_pb2.DECISION_UNSPECIFIED = mcp_pb2.MCP_DECISION_UNSPECIFIED
if not hasattr(mcp_pb2, 'ALLOW'):
    mcp_pb2.ALLOW = mcp_pb2.MCP_DECISION_ALLOW
if not hasattr(mcp_pb2, 'DENY'):
    mcp_pb2.DENY = mcp_pb2.MCP_DECISION_DENY

# AuthLevel
if not hasattr(mcp_pb2, 'AUTH_LEVEL_UNSPECIFIED'):
    mcp_pb2.AUTH_LEVEL_UNSPECIFIED = mcp_pb2.MCP_AUTH_LEVEL_UNSPECIFIED
if not hasattr(mcp_pb2, 'ANONYMOUS'):
    mcp_pb2.ANONYMOUS = mcp_pb2.MCP_AUTH_LEVEL_ANONYMOUS
if not hasattr(mcp_pb2, 'API_KEY'):
    mcp_pb2.API_KEY = mcp_pb2.MCP_AUTH_LEVEL_API_KEY
if not hasattr(mcp_pb2, 'BADGE'):
    mcp_pb2.BADGE = mcp_pb2.MCP_AUTH_LEVEL_BADGE

# DenyReason
if not hasattr(mcp_pb2, 'DENY_REASON_UNSPECIFIED'):
    mcp_pb2.DENY_REASON_UNSPECIFIED = mcp_pb2.MCP_DENY_REASON_UNSPECIFIED
if not hasattr(mcp_pb2, 'TOOL_BADGE_MISSING'):
    mcp_pb2.TOOL_BADGE_MISSING = mcp_pb2.MCP_DENY_REASON_BADGE_MISSING
if not hasattr(mcp_pb2, 'TOOL_BADGE_INVALID'):
    mcp_pb2.TOOL_BADGE_INVALID = mcp_pb2.MCP_DENY_REASON_BADGE_INVALID
if not hasattr(mcp_pb2, 'TOOL_BADGE_EXPIRED'):
    mcp_pb2.TOOL_BADGE_EXPIRED = mcp_pb2.MCP_DENY_REASON_BADGE_EXPIRED
if not hasattr(mcp_pb2, 'TOOL_BADGE_REVOKED'):
    mcp_pb2.TOOL_BADGE_REVOKED = mcp_pb2.MCP_DENY_REASON_BADGE_REVOKED
if not hasattr(mcp_pb2, 'TOOL_TRUST_INSUFFICIENT'):
    mcp_pb2.TOOL_TRUST_INSUFFICIENT = mcp_pb2.MCP_DENY_REASON_TRUST_INSUFFICIENT
if not hasattr(mcp_pb2, 'TOOL_NOT_ALLOWED'):
    mcp_pb2.TOOL_NOT_ALLOWED = mcp_pb2.MCP_DENY_REASON_TOOL_NOT_ALLOWED
if not hasattr(mcp_pb2, 'TOOL_ISSUER_UNTRUSTED'):
    mcp_pb2.TOOL_ISSUER_UNTRUSTED = mcp_pb2.MCP_DENY_REASON_ISSUER_UNTRUSTED
if not hasattr(mcp_pb2, 'TOOL_POLICY_DENIED'):
    mcp_pb2.TOOL_POLICY_DENIED = mcp_pb2.MCP_DENY_REASON_POLICY_DENIED

# ServerState
if not hasattr(mcp_pb2, 'SERVER_STATE_UNSPECIFIED'):
    mcp_pb2.SERVER_STATE_UNSPECIFIED = mcp_pb2.MCP_SERVER_STATE_UNSPECIFIED
if not hasattr(mcp_pb2, 'VERIFIED_PRINCIPAL'):
    mcp_pb2.VERIFIED_PRINCIPAL = mcp_pb2.MCP_SERVER_STATE_VERIFIED_PRINCIPAL
if not hasattr(mcp_pb2, 'DECLARED_PRINCIPAL'):
    mcp_pb2.DECLARED_PRINCIPAL = mcp_pb2.MCP_SERVER_STATE_DECLARED_PRINCIPAL
if not hasattr(mcp_pb2, 'UNVERIFIED_ORIGIN'):
    mcp_pb2.UNVERIFIED_ORIGIN = mcp_pb2.MCP_SERVER_STATE_UNVERIFIED_ORIGIN

# ServerErrorCode
if not hasattr(mcp_pb2, 'SERVER_ERROR_NONE'):
    mcp_pb2.SERVER_ERROR_NONE = mcp_pb2.MCP_SERVER_ERROR_NONE
if not hasattr(mcp_pb2, 'SERVER_DID_INVALID'):
    mcp_pb2.SERVER_DID_INVALID = mcp_pb2.MCP_SERVER_ERROR_DID_INVALID
if not hasattr(mcp_pb2, 'SERVER_BADGE_INVALID'):
    mcp_pb2.SERVER_BADGE_INVALID = mcp_pb2.MCP_SERVER_ERROR_BADGE_INVALID
if not hasattr(mcp_pb2, 'SERVER_BADGE_EXPIRED'):
    mcp_pb2.SERVER_BADGE_EXPIRED = mcp_pb2.MCP_SERVER_ERROR_BADGE_EXPIRED
if not hasattr(mcp_pb2, 'SERVER_BADGE_REVOKED'):
    mcp_pb2.SERVER_BADGE_REVOKED = mcp_pb2.MCP_SERVER_ERROR_BADGE_REVOKED
if not hasattr(mcp_pb2, 'SERVER_TRUST_INSUFFICIENT'):
    mcp_pb2.SERVER_TRUST_INSUFFICIENT = mcp_pb2.MCP_SERVER_ERROR_TRUST_INSUFFICIENT
if not hasattr(mcp_pb2, 'SERVER_ORIGIN_MISMATCH'):
    mcp_pb2.SERVER_ORIGIN_MISMATCH = mcp_pb2.MCP_SERVER_ERROR_ORIGIN_MISMATCH
if not hasattr(mcp_pb2, 'SERVER_PATH_MISMATCH'):
    mcp_pb2.SERVER_PATH_MISMATCH = mcp_pb2.MCP_SERVER_ERROR_PATH_MISMATCH
if not hasattr(mcp_pb2, 'SERVER_ISSUER_UNTRUSTED'):
    mcp_pb2.SERVER_ISSUER_UNTRUSTED = mcp_pb2.MCP_SERVER_ERROR_ISSUER_UNTRUSTED

__all__ = ["mcp_pb2", "mcp_pb2_grpc"]
