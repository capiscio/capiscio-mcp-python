"""Tests for capiscio_mcp.guard module (RFC-006 implementation)."""

import asyncio
import hashlib
import base64
import json
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from capiscio_mcp.guard import (
    guard,
    guard_sync,
    compute_params_hash,
    GuardConfig,
    GuardResult,
    _caller_did,
    _caller_badge,
)
from capiscio_mcp.types import Decision, AuthLevel, DenyReason
from capiscio_mcp.errors import GuardError, GuardConfigError


class TestComputeParamsHash:
    """Tests for compute_params_hash function."""
    
    def test_empty_params(self):
        """Empty params should produce consistent hash."""
        result = compute_params_hash({})
        assert result.startswith("sha256:")
        # Verify it's valid base64url
        b64_part = result[7:]  # Strip "sha256:"
        assert len(b64_part) == 43  # SHA-256 is 32 bytes, base64url ~43 chars
    
    def test_simple_params(self):
        """Simple params should hash correctly."""
        result = compute_params_hash({"path": "/tmp/file.txt"})
        assert result.startswith("sha256:")
    
    def test_deterministic(self):
        """Same params should produce same hash."""
        params = {"a": 1, "b": "hello", "c": [1, 2, 3]}
        hash1 = compute_params_hash(params)
        hash2 = compute_params_hash(params)
        assert hash1 == hash2
    
    def test_key_order_independent(self):
        """Different key order should produce same hash (keys are sorted)."""
        params1 = {"z": 1, "a": 2, "m": 3}
        params2 = {"a": 2, "m": 3, "z": 1}
        assert compute_params_hash(params1) == compute_params_hash(params2)
    
    def test_nested_dict_sorting(self):
        """Nested dicts should also be sorted."""
        params1 = {"outer": {"z": 1, "a": 2}}
        params2 = {"outer": {"a": 2, "z": 1}}
        assert compute_params_hash(params1) == compute_params_hash(params2)
    
    def test_list_order_preserved(self):
        """List order should be preserved (not sorted)."""
        params1 = {"items": [1, 2, 3]}
        params2 = {"items": [3, 2, 1]}
        assert compute_params_hash(params1) != compute_params_hash(params2)
    
    def test_different_params_different_hash(self):
        """Different params should produce different hash."""
        hash1 = compute_params_hash({"a": 1})
        hash2 = compute_params_hash({"a": 2})
        assert hash1 != hash2
    
    def test_complex_nested_structure(self):
        """Complex nested structures should hash correctly."""
        params = {
            "query": "SELECT * FROM users",
            "options": {
                "limit": 100,
                "offset": 0,
                "filters": [
                    {"field": "status", "value": "active"},
                    {"field": "role", "value": "admin"},
                ],
            },
        }
        result = compute_params_hash(params)
        assert result.startswith("sha256:")
    
    def test_special_characters(self):
        """Special characters should be handled correctly."""
        params = {"message": "Hello, 世界! 🎉", "path": "/tmp/file with spaces.txt"}
        result = compute_params_hash(params)
        assert result.startswith("sha256:")
    
    def test_null_values(self):
        """None values should hash correctly."""
        params = {"key": None}
        result = compute_params_hash(params)
        assert result.startswith("sha256:")
    
    def test_boolean_values(self):
        """Boolean values should hash correctly."""
        params = {"enabled": True, "disabled": False}
        result = compute_params_hash(params)
        assert result.startswith("sha256:")
    
    def test_float_values(self):
        """Float values should hash correctly."""
        params = {"pi": 3.14159, "e": 2.71828}
        result = compute_params_hash(params)
        assert result.startswith("sha256:")


class TestGuardConfig:
    """Tests for GuardConfig dataclass."""
    
    def test_default_values(self):
        """Default config should have sensible defaults."""
        config = GuardConfig()
        assert config.min_trust_level == 0
        assert config.accept_level_zero is False
        assert config.trusted_issuers is None
        assert config.allowed_tools is None
        assert config.policy_version is None
    
    def test_custom_values(self):
        """Custom config values should be set correctly."""
        config = GuardConfig(
            min_trust_level=2,
            accept_level_zero=True,
            trusted_issuers=["https://registry.capisc.io"],
            allowed_tools=["read_*", "list_*"],
            policy_version="v1.0",
        )
        assert config.min_trust_level == 2
        assert config.accept_level_zero is True
        assert config.trusted_issuers == ["https://registry.capisc.io"]
        assert config.allowed_tools == ["read_*", "list_*"]
        assert config.policy_version == "v1.0"
    
    def test_validate_min_trust_level_range(self):
        """Trust level should be validated in 0-4 range."""
        # Valid levels
        for level in range(5):
            config = GuardConfig(min_trust_level=level)
            config.validate()  # Should not raise
        
        # Invalid levels
        with pytest.raises(GuardConfigError):
            config = GuardConfig(min_trust_level=-1)
            config.validate()
        
        with pytest.raises(GuardConfigError):
            config = GuardConfig(min_trust_level=5)
            config.validate()


class TestGuardResult:
    """Tests for GuardResult dataclass."""
    
    def test_allow_result(self):
        """Allow result should have correct fields."""
        result = GuardResult(
            decision=Decision.ALLOW,
            deny_reason=None,
            deny_detail=None,
            agent_did="did:web:example.com:agents:test",
            badge_jti="badge-123",
            auth_level=AuthLevel.BADGE,
            trust_level=2,
            evidence_id="ev-456",
            evidence_json='{"decision": "ALLOW"}',
        )
        assert result.decision == Decision.ALLOW
        assert result.deny_reason is None
        assert result.trust_level == 2
    
    def test_deny_result(self):
        """Deny result should have reason and detail."""
        result = GuardResult(
            decision=Decision.DENY,
            deny_reason=DenyReason.TRUST_INSUFFICIENT,
            deny_detail="Required trust level 2, got 1",
            agent_did="did:web:example.com:agents:test",
            badge_jti="badge-123",
            auth_level=AuthLevel.BADGE,
            trust_level=1,
            evidence_id="ev-456",
            evidence_json='{"decision": "DENY", "reason": "TOOL_TRUST_INSUFFICIENT"}',
        )
        assert result.decision == Decision.DENY
        assert result.deny_reason == DenyReason.TRUST_INSUFFICIENT
        assert "trust level" in result.deny_detail.lower()


class TestGuardDecorator:
    """Tests for @guard async decorator."""
    
    @pytest.mark.asyncio
    async def test_guard_allows_valid_badge(self, mock_core_client, sample_badge_jws):
        """Tool execution allowed with valid badge."""
        # Setup mock response
        mock_response = MagicMock()
        mock_response.decision = 1  # ALLOW
        mock_response.deny_reason = 0
        mock_response.agent_did = "did:web:example.com:agents:test"
        mock_response.badge_jti = "badge-123"
        mock_response.auth_level = 3  # BADGE
        mock_response.trust_level = 2
        mock_response.evidence_id = "ev-001"
        mock_response.evidence_json = "{}"
        
        mock_core_client.stub.EvaluateToolAccess = AsyncMock(return_value=mock_response)
        
        with patch("capiscio_mcp._core.client.CoreClient.get_instance", return_value=mock_core_client):
            with patch("capiscio_mcp.guard._caller_badge", return_value=sample_badge_jws):
                @guard(min_trust_level=2)
                async def read_file(path: str) -> str:
                    return f"Contents of {path}"
                
                result = await read_file(path="/tmp/test.txt")
                assert result == "Contents of /tmp/test.txt"
    
    @pytest.mark.asyncio
    async def test_guard_denies_insufficient_trust(self, mock_core_client, sample_badge_jws):
        """Tool execution denied when trust level insufficient."""
        mock_response = MagicMock()
        mock_response.decision = 2  # DENY
        mock_response.deny_reason = 5  # TOOL_TRUST_INSUFFICIENT
        mock_response.deny_detail = "Required trust level 2, got 1"
        mock_response.agent_did = "did:web:example.com:agents:test"
        mock_response.badge_jti = "badge-123"
        mock_response.auth_level = 3
        mock_response.trust_level = 1
        mock_response.evidence_id = "ev-002"
        mock_response.evidence_json = "{}"
        
        mock_core_client.stub.EvaluateToolAccess = AsyncMock(return_value=mock_response)
        
        with patch("capiscio_mcp._core.client.CoreClient.get_instance", return_value=mock_core_client):
            with patch("capiscio_mcp.guard._caller_badge", return_value=sample_badge_jws):
                @guard(min_trust_level=2)
                async def read_file(path: str) -> str:
                    return f"Contents of {path}"
                
                with pytest.raises(GuardError) as exc_info:
                    await read_file(path="/tmp/test.txt")
                
                assert exc_info.value.reason == DenyReason.TRUST_INSUFFICIENT
                assert "evidence_id" in dir(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_guard_denies_missing_badge(self, mock_core_client):
        """Tool execution denied when badge required but missing."""
        mock_response = MagicMock()
        mock_response.decision = 2  # DENY
        mock_response.deny_reason = 1  # TOOL_BADGE_MISSING
        mock_response.deny_detail = "Badge required but not provided"
        mock_response.agent_did = ""
        mock_response.badge_jti = ""
        mock_response.auth_level = 1  # ANONYMOUS
        mock_response.trust_level = 0
        mock_response.evidence_id = "ev-003"
        mock_response.evidence_json = "{}"
        
        mock_core_client.stub.EvaluateToolAccess = AsyncMock(return_value=mock_response)
        
        with patch("capiscio_mcp._core.client.CoreClient.get_instance", return_value=mock_core_client):
            with patch("capiscio_mcp.guard._caller_badge", return_value=None):
                @guard(min_trust_level=1)
                async def read_file(path: str) -> str:
                    return f"Contents of {path}"
                
                with pytest.raises(GuardError) as exc_info:
                    await read_file(path="/tmp/test.txt")
                
                assert exc_info.value.reason == DenyReason.BADGE_MISSING
    
    @pytest.mark.asyncio
    async def test_guard_uses_function_name_as_tool_name(self, mock_core_client, sample_badge_jws):
        """Tool name defaults to function name."""
        mock_response = MagicMock()
        mock_response.decision = 1  # ALLOW
        mock_response.deny_reason = 0
        mock_response.agent_did = "did:web:example.com:agents:test"
        mock_response.badge_jti = "badge-123"
        mock_response.auth_level = 3
        mock_response.trust_level = 2
        mock_response.evidence_id = "ev-004"
        mock_response.evidence_json = "{}"
        
        evaluate_mock = AsyncMock(return_value=mock_response)
        mock_core_client.stub.EvaluateToolAccess = evaluate_mock
        
        with patch("capiscio_mcp._core.client.CoreClient.get_instance", return_value=mock_core_client):
            with patch("capiscio_mcp.guard._caller_badge", return_value=sample_badge_jws):
                @guard()
                async def my_custom_tool(arg: str) -> str:
                    return arg
                
                await my_custom_tool(arg="test")
                
                # Verify tool_name was passed correctly
                call_args = evaluate_mock.call_args
                assert call_args is not None
                request = call_args[0][0]
                assert request.tool_name == "my_custom_tool"
    
    @pytest.mark.asyncio
    async def test_guard_custom_tool_name(self, mock_core_client, sample_badge_jws):
        """Custom tool name can be specified."""
        mock_response = MagicMock()
        mock_response.decision = 1
        mock_response.deny_reason = 0
        mock_response.agent_did = "did:web:example.com:agents:test"
        mock_response.badge_jti = "badge-123"
        mock_response.auth_level = 3
        mock_response.trust_level = 2
        mock_response.evidence_id = "ev-005"
        mock_response.evidence_json = "{}"
        
        evaluate_mock = AsyncMock(return_value=mock_response)
        mock_core_client.stub.EvaluateToolAccess = evaluate_mock
        
        with patch("capiscio_mcp._core.client.CoreClient.get_instance", return_value=mock_core_client):
            with patch("capiscio_mcp.guard._caller_badge", return_value=sample_badge_jws):
                @guard(tool_name="filesystem.read")
                async def read_file(path: str) -> str:
                    return f"Contents of {path}"
                
                await read_file(path="/tmp/test.txt")
                
                call_args = evaluate_mock.call_args
                request = call_args[0][0]
                assert request.tool_name == "filesystem.read"
    
    @pytest.mark.asyncio
    async def test_guard_computes_params_hash(self, mock_core_client, sample_badge_jws):
        """Guard should compute and send params_hash."""
        mock_response = MagicMock()
        mock_response.decision = 1
        mock_response.deny_reason = 0
        mock_response.agent_did = "did:web:example.com:agents:test"
        mock_response.badge_jti = "badge-123"
        mock_response.auth_level = 3
        mock_response.trust_level = 2
        mock_response.evidence_id = "ev-006"
        mock_response.evidence_json = "{}"
        
        evaluate_mock = AsyncMock(return_value=mock_response)
        mock_core_client.stub.EvaluateToolAccess = evaluate_mock
        
        with patch("capiscio_mcp._core.client.CoreClient.get_instance", return_value=mock_core_client):
            with patch("capiscio_mcp.guard._caller_badge", return_value=sample_badge_jws):
                @guard()
                async def query_db(sql: str, limit: int) -> list:
                    return []
                
                await query_db(sql="SELECT * FROM users", limit=10)
                
                call_args = evaluate_mock.call_args
                request = call_args[0][0]
                assert request.params_hash.startswith("sha256:")


class TestGuardSyncDecorator:
    """Tests for @guard_sync decorator."""
    
    def test_guard_sync_wraps_sync_function(self, mock_core_client, sample_badge_jws):
        """guard_sync should work with synchronous functions."""
        mock_response = MagicMock()
        mock_response.decision = 1
        mock_response.deny_reason = 0
        mock_response.agent_did = "did:web:example.com:agents:test"
        mock_response.badge_jti = "badge-123"
        mock_response.auth_level = 3
        mock_response.trust_level = 2
        mock_response.evidence_id = "ev-007"
        mock_response.evidence_json = "{}"
        
        async def mock_evaluate(*args, **kwargs):
            return mock_response
        
        mock_core_client.stub.EvaluateToolAccess = mock_evaluate
        
        async def mock_get_instance():
            return mock_core_client
        
        with patch("capiscio_mcp._core.client.CoreClient.get_instance", mock_get_instance):
            with patch("capiscio_mcp.guard._caller_badge", return_value=sample_badge_jws):
                @guard_sync(min_trust_level=1)
                def sync_read_file(path: str) -> str:
                    return f"Contents of {path}"
                
                # This should run without asyncio
                result = sync_read_file(path="/tmp/test.txt")
                assert result == "Contents of /tmp/test.txt"


class TestContextVariables:
    """Tests for context variable extraction."""
    
    def test_caller_did_context_var(self):
        """_caller_did context var should be accessible."""
        # Token should be set/get correctly
        token = _caller_did.set("did:web:example.com:agents:test")
        assert _caller_did.get() == "did:web:example.com:agents:test"
        _caller_did.reset(token)
    
    def test_caller_badge_context_var(self):
        """_caller_badge context var should be accessible."""
        token = _caller_badge.set("eyJhbGc...")
        assert _caller_badge.get() == "eyJhbGc..."
        _caller_badge.reset(token)
    
    def test_context_var_default_none(self):
        """Context vars should default to None."""
        assert _caller_did.get(None) is None
        assert _caller_badge.get(None) is None


class TestGuardErrorHandling:
    """Tests for guard error handling."""
    
    @pytest.mark.asyncio
    async def test_guard_connection_error(self, mock_core_client):
        """Guard should handle connection errors gracefully."""
        mock_core_client.stub.EvaluateToolAccess = AsyncMock(
            side_effect=Exception("Connection refused")
        )
        
        with patch("capiscio_mcp._core.client.CoreClient.get_instance", return_value=mock_core_client):
            @guard()
            async def test_tool() -> str:
                return "result"
            
            with pytest.raises(Exception) as exc_info:
                await test_tool()
            
            assert "Connection refused" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_guard_preserves_function_metadata(self, mock_core_client, sample_badge_jws):
        """Guard should preserve function metadata (name, docstring, etc.)."""
        mock_response = MagicMock()
        mock_response.decision = 1
        mock_response.deny_reason = 0
        mock_response.agent_did = "did:web:example.com:agents:test"
        mock_response.badge_jti = "badge-123"
        mock_response.auth_level = 3
        mock_response.trust_level = 2
        mock_response.evidence_id = "ev-008"
        mock_response.evidence_json = "{}"
        
        mock_core_client.stub.EvaluateToolAccess = AsyncMock(return_value=mock_response)
        
        with patch("capiscio_mcp._core.client.CoreClient.get_instance", return_value=mock_core_client):
            @guard()
            async def documented_tool(arg: str) -> str:
                """This is the docstring."""
                return arg
            
            assert documented_tool.__name__ == "documented_tool"
            assert documented_tool.__doc__ == "This is the docstring."
