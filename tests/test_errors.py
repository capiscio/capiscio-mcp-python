"""
Tests for capiscio_mcp.errors module.
"""

import pytest
from capiscio_mcp.errors import (
    CapiscioMCPError,
    CoreConnectionError,
    CoreVersionError,
    GuardError,
    GuardConfigError,
    ServerVerifyError,
    EvidenceError,
)
from capiscio_mcp.types import DenyReason, ServerErrorCode, ServerState


class TestCapiscioMCPError:
    """Tests for base CapiscioMCPError."""
    
    def test_is_exception(self):
        assert issubclass(CapiscioMCPError, Exception)
    
    def test_message(self):
        error = CapiscioMCPError("Test error message")
        assert str(error) == "Test error message"


class TestCoreConnectionError:
    """Tests for CoreConnectionError."""
    
    def test_inheritance(self):
        assert issubclass(CoreConnectionError, CapiscioMCPError)
    
    def test_message(self):
        error = CoreConnectionError("Failed to connect to core")
        assert "Failed to connect" in str(error)
    
    def test_can_be_caught_as_base(self):
        with pytest.raises(CapiscioMCPError):
            raise CoreConnectionError("connection failed")


class TestCoreVersionError:
    """Tests for CoreVersionError."""
    
    def test_inheritance(self):
        assert issubclass(CoreVersionError, CapiscioMCPError)
    
    def test_message(self):
        error = CoreVersionError("Version 1.0 is incompatible")
        assert "incompatible" in str(error)


class TestGuardError:
    """Tests for GuardError."""
    
    def test_inheritance(self):
        assert issubclass(GuardError, CapiscioMCPError)
    
    def test_basic_creation(self):
        error = GuardError(
            reason=DenyReason.BADGE_MISSING,
            detail="Badge required",
        )
        assert error.reason == DenyReason.BADGE_MISSING
        assert error.detail == "Badge required"
        assert error.evidence_id == ""
    
    def test_with_evidence_id(self):
        error = GuardError(
            reason=DenyReason.TRUST_INSUFFICIENT,
            detail="Trust level 1 < required 2",
            evidence_id="ev_12345",
        )
        assert error.evidence_id == "ev_12345"
        assert "ev_12345" in str(error)
    
    def test_with_agent_info(self):
        error = GuardError(
            reason=DenyReason.BADGE_REVOKED,
            detail="Badge has been revoked",
            evidence_id="ev_67890",
            agent_did="did:web:example.com:agents:test",
            trust_level=2,
        )
        assert error.agent_did == "did:web:example.com:agents:test"
        assert error.trust_level == 2
    
    def test_str_format(self):
        error = GuardError(
            reason=DenyReason.POLICY_DENIED,
            detail="Policy evaluation failed",
            evidence_id="ev_abc",
        )
        error_str = str(error)
        assert "policy_denied" in error_str
        assert "Policy evaluation failed" in error_str
        assert "ev_abc" in error_str
    
    def test_repr(self):
        error = GuardError(
            reason=DenyReason.BADGE_INVALID,
            detail="Invalid signature",
            evidence_id="ev_123",
        )
        repr_str = repr(error)
        assert "GuardError" in repr_str
        assert "BADGE_INVALID" in repr_str


class TestGuardConfigError:
    """Tests for GuardConfigError."""
    
    def test_inheritance(self):
        assert issubclass(GuardConfigError, CapiscioMCPError)
    
    def test_message(self):
        error = GuardConfigError("Invalid trust level: 5")
        assert "Invalid trust level" in str(error)


class TestServerVerifyError:
    """Tests for ServerVerifyError."""
    
    def test_inheritance(self):
        assert issubclass(ServerVerifyError, CapiscioMCPError)
    
    def test_basic_creation(self):
        error = ServerVerifyError(
            error_code=ServerErrorCode.DID_INVALID,
            detail="Invalid DID format",
        )
        assert error.error_code == ServerErrorCode.DID_INVALID
        assert error.detail == "Invalid DID format"
        assert error.state is None
        assert error.server_did is None
    
    def test_with_state(self):
        error = ServerVerifyError(
            error_code=ServerErrorCode.BADGE_EXPIRED,
            detail="Badge expired at 2026-01-01",
            state=ServerState.DECLARED_PRINCIPAL,
            server_did="did:web:mcp.example.com",
        )
        assert error.state == ServerState.DECLARED_PRINCIPAL
        assert error.server_did == "did:web:mcp.example.com"
    
    def test_str_format(self):
        error = ServerVerifyError(
            error_code=ServerErrorCode.ORIGIN_MISMATCH,
            detail="Origin https://evil.com does not match DID",
        )
        error_str = str(error)
        assert "origin_mismatch" in error_str
    
    def test_repr(self):
        error = ServerVerifyError(
            error_code=ServerErrorCode.TRUST_INSUFFICIENT,
            detail="Level 1 < required 2",
            state=ServerState.VERIFIED_PRINCIPAL,
        )
        repr_str = repr(error)
        assert "ServerVerifyError" in repr_str
        assert "TRUST_INSUFFICIENT" in repr_str


class TestEvidenceError:
    """Tests for EvidenceError."""
    
    def test_inheritance(self):
        assert issubclass(EvidenceError, CapiscioMCPError)
    
    def test_without_evidence_id(self):
        error = EvidenceError("Failed to log evidence")
        assert error.evidence_id is None
        assert "Failed to log" in str(error)
    
    def test_with_evidence_id(self):
        error = EvidenceError("Log destination unreachable", evidence_id="ev_partial")
        assert error.evidence_id == "ev_partial"
