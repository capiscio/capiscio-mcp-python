"""
Tests for capiscio_mcp.types module.
"""

import pytest
from capiscio_mcp.types import (
    Decision,
    AuthLevel,
    DenyReason,
    ServerState,
    ServerErrorCode,
    TrustLevel,
    CallerCredential,
    EvidenceRecord,
    ToolAccessResult,
    ServerIdentityResult,
)
from datetime import datetime, timezone


class TestDecision:
    """Tests for Decision enum."""
    
    def test_allow_value(self):
        assert Decision.ALLOW.value == "allow"
    
    def test_deny_value(self):
        assert Decision.DENY.value == "deny"
    
    def test_string_enum(self):
        assert str(Decision.ALLOW) == "Decision.ALLOW"
        assert Decision.ALLOW == "allow"


class TestAuthLevel:
    """Tests for AuthLevel enum."""
    
    def test_anonymous_value(self):
        assert AuthLevel.ANONYMOUS.value == "anonymous"
    
    def test_api_key_value(self):
        assert AuthLevel.API_KEY.value == "api_key"
    
    def test_badge_value(self):
        assert AuthLevel.BADGE.value == "badge"


class TestDenyReason:
    """Tests for DenyReason enum."""
    
    def test_badge_missing(self):
        assert DenyReason.BADGE_MISSING.value == "badge_missing"
    
    def test_badge_invalid(self):
        assert DenyReason.BADGE_INVALID.value == "badge_invalid"
    
    def test_badge_expired(self):
        assert DenyReason.BADGE_EXPIRED.value == "badge_expired"
    
    def test_badge_revoked(self):
        assert DenyReason.BADGE_REVOKED.value == "badge_revoked"
    
    def test_trust_insufficient(self):
        assert DenyReason.TRUST_INSUFFICIENT.value == "trust_insufficient"
    
    def test_issuer_untrusted(self):
        assert DenyReason.ISSUER_UNTRUSTED.value == "issuer_untrusted"
    
    def test_tool_not_allowed(self):
        assert DenyReason.TOOL_NOT_ALLOWED.value == "tool_not_allowed"
    
    def test_policy_denied(self):
        assert DenyReason.POLICY_DENIED.value == "policy_denied"
    
    def test_internal_error(self):
        assert DenyReason.INTERNAL_ERROR.value == "internal_error"


class TestServerState:
    """Tests for ServerState enum."""
    
    def test_verified_principal(self):
        assert ServerState.VERIFIED_PRINCIPAL.value == "verified_principal"
    
    def test_declared_principal(self):
        assert ServerState.DECLARED_PRINCIPAL.value == "declared_principal"
    
    def test_unverified_origin(self):
        assert ServerState.UNVERIFIED_ORIGIN.value == "unverified_origin"


class TestServerErrorCode:
    """Tests for ServerErrorCode enum."""
    
    def test_none(self):
        assert ServerErrorCode.NONE.value == "none"
    
    def test_did_invalid(self):
        assert ServerErrorCode.DID_INVALID.value == "did_invalid"
    
    def test_badge_invalid(self):
        assert ServerErrorCode.BADGE_INVALID.value == "badge_invalid"
    
    def test_origin_mismatch(self):
        assert ServerErrorCode.ORIGIN_MISMATCH.value == "origin_mismatch"


class TestTrustLevel:
    """Tests for TrustLevel enum."""
    
    def test_level_0(self):
        assert TrustLevel.LEVEL_0 == 0
    
    def test_level_1(self):
        assert TrustLevel.LEVEL_1 == 1
    
    def test_level_2(self):
        assert TrustLevel.LEVEL_2 == 2
    
    def test_level_3(self):
        assert TrustLevel.LEVEL_3 == 3
    
    def test_level_4(self):
        assert TrustLevel.LEVEL_4 == 4
    
    def test_int_comparison(self):
        assert TrustLevel.LEVEL_2 > TrustLevel.LEVEL_1
        assert TrustLevel.LEVEL_0 < TrustLevel.LEVEL_4


class TestCallerCredential:
    """Tests for CallerCredential dataclass."""
    
    def test_default_anonymous(self):
        cred = CallerCredential()
        assert cred.badge_jws is None
        assert cred.api_key is None
        assert cred.auth_level == AuthLevel.ANONYMOUS
    
    def test_badge_credential(self):
        cred = CallerCredential(badge_jws="eyJ...")
        assert cred.badge_jws == "eyJ..."
        assert cred.api_key is None
        assert cred.auth_level == AuthLevel.BADGE
    
    def test_api_key_credential(self):
        cred = CallerCredential(api_key="sk_test_123")
        assert cred.badge_jws is None
        assert cred.api_key == "sk_test_123"
        assert cred.auth_level == AuthLevel.API_KEY
    
    def test_badge_takes_precedence(self):
        """Badge auth level takes precedence if both are set."""
        cred = CallerCredential(badge_jws="eyJ...", api_key="sk_test_123")
        assert cred.auth_level == AuthLevel.BADGE


class TestEvidenceRecord:
    """Tests for EvidenceRecord dataclass."""
    
    def test_creation(self):
        now = datetime.now(timezone.utc)
        record = EvidenceRecord(
            evidence_id="ev_123",
            timestamp=now,
            tool_name="read_file",
            params_hash="sha256:abc123",
            server_origin="https://example.com",
            agent_did="did:web:example.com:agents:test",
            badge_jti="badge_456",
            auth_level=AuthLevel.BADGE,
            trust_level=2,
            decision=Decision.ALLOW,
        )
        
        assert record.evidence_id == "ev_123"
        assert record.tool_name == "read_file"
        assert record.decision == Decision.ALLOW
        assert record.deny_reason is None
    
    def test_denied_record(self):
        record = EvidenceRecord(
            evidence_id="ev_789",
            timestamp=datetime.now(timezone.utc),
            tool_name="write_file",
            params_hash="sha256:def456",
            server_origin="https://example.com",
            agent_did="did:web:example.com:agents:test",
            badge_jti=None,
            auth_level=AuthLevel.ANONYMOUS,
            trust_level=0,
            decision=Decision.DENY,
            deny_reason=DenyReason.BADGE_MISSING,
            deny_detail="Badge required for this tool",
        )
        
        assert record.decision == Decision.DENY
        assert record.deny_reason == DenyReason.BADGE_MISSING


class TestToolAccessResult:
    """Tests for ToolAccessResult dataclass."""
    
    def test_allowed_result(self):
        result = ToolAccessResult(
            decision=Decision.ALLOW,
            agent_did="did:web:example.com:agents:test",
            badge_jti="badge_123",
            auth_level=AuthLevel.BADGE,
            trust_level=2,
            evidence_id="ev_456",
        )
        
        assert result.decision == Decision.ALLOW
        assert result.deny_reason is None
        assert result.trust_level == 2
    
    def test_denied_result(self):
        result = ToolAccessResult(
            decision=Decision.DENY,
            deny_reason=DenyReason.TRUST_INSUFFICIENT,
            deny_detail="Trust level 1 is below required 2",
            auth_level=AuthLevel.BADGE,
            trust_level=1,
            evidence_id="ev_789",
        )
        
        assert result.decision == Decision.DENY
        assert result.deny_reason == DenyReason.TRUST_INSUFFICIENT


class TestServerIdentityResult:
    """Tests for ServerIdentityResult dataclass."""
    
    def test_verified_result(self):
        result = ServerIdentityResult(
            state=ServerState.VERIFIED_PRINCIPAL,
            trust_level=2,
            server_did="did:web:mcp.example.com",
            badge_jti="badge_123",
        )
        
        assert result.state == ServerState.VERIFIED_PRINCIPAL
        assert result.is_verified is True
        assert result.has_identity is True
        assert result.trust_level == 2
    
    def test_declared_result(self):
        result = ServerIdentityResult(
            state=ServerState.DECLARED_PRINCIPAL,
            server_did="did:web:mcp.example.com",
        )
        
        assert result.state == ServerState.DECLARED_PRINCIPAL
        assert result.is_verified is False
        assert result.has_identity is True
    
    def test_unverified_result(self):
        result = ServerIdentityResult(
            state=ServerState.UNVERIFIED_ORIGIN,
        )
        
        assert result.state == ServerState.UNVERIFIED_ORIGIN
        assert result.is_verified is False
        assert result.has_identity is False
    
    def test_error_result(self):
        result = ServerIdentityResult(
            state=ServerState.DECLARED_PRINCIPAL,
            server_did="did:web:mcp.example.com",
            error_code=ServerErrorCode.BADGE_INVALID,
            error_detail="Badge signature verification failed",
        )
        
        assert result.error_code == ServerErrorCode.BADGE_INVALID
        assert result.error_detail == "Badge signature verification failed"
