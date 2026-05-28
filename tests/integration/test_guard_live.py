"""
Live integration tests for guard() and evaluate_tool_access().

Tests the full guard path: Python → gRPC → capiscio-core → policy evaluation.
Requires a running capiscio-core (embedded binary or external via CAPISCIO_CORE_ADDR).
"""

import os

import pytest

from capiscio_mcp.guard import evaluate_tool_access, GuardConfig, GuardResult
from capiscio_mcp.types import Decision, CallerCredential, AuthLevel

_core_available = bool(
    os.environ.get("CAPISCIO_CORE_ADDR")
    or os.environ.get("CAPISCIO_BINARY_PATH")
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not _core_available,
        reason="CAPISCIO_CORE_ADDR or CAPISCIO_BINARY_PATH not set",
    ),
]


class TestEvaluateToolAccessLive:
    """Test evaluate_tool_access against a live capiscio-core gRPC server."""

    async def test_anonymous_caller_denied(self):
        """Anonymous caller (no credential) should be denied by default."""
        result = await evaluate_tool_access(
            tool_name="read_file",
            params={"path": "/etc/passwd"},
            credential=CallerCredential(),  # anonymous
            config=GuardConfig(min_trust_level=1),
        )

        assert isinstance(result, GuardResult)
        assert result.decision == Decision.DENY
        assert result.auth_level == AuthLevel.ANONYMOUS

    async def test_api_key_credential(self):
        """API key credential should reach core and get a decision."""
        result = await evaluate_tool_access(
            tool_name="list_files",
            params={"directory": "/tmp"},
            credential=CallerCredential(api_key="test-key-12345"),
            config=GuardConfig(min_trust_level=0, accept_level_zero=True),
        )

        assert isinstance(result, GuardResult)
        assert result.decision in (Decision.ALLOW, Decision.DENY)

    async def test_params_hash_computed(self):
        """Params hash should be computed (PII never sent to core)."""
        from capiscio_mcp.guard import compute_params_hash

        params = {"query": "sensitive-data", "user_id": "12345"}
        params_hash = compute_params_hash(params)

        assert params_hash.startswith("sha256:")
        assert len(params_hash) > 10

        # Same params → same hash (deterministic)
        assert compute_params_hash(params) == params_hash

        # Different params → different hash
        different = compute_params_hash({"query": "other"})
        assert different != params_hash

    async def test_guard_result_fields_populated(self):
        """GuardResult should have all fields populated from core response."""
        result = await evaluate_tool_access(
            tool_name="write_file",
            params={"path": "/tmp/test.txt", "content": "hello"},
            credential=CallerCredential(api_key="test-key"),
            config=GuardConfig(min_trust_level=1),
        )

        assert isinstance(result, GuardResult)
        assert result.decision in (Decision.ALLOW, Decision.DENY)
        if result.decision == Decision.DENY:
            assert result.deny_reason is not None

    async def test_trusted_issuers_filter(self):
        """Trusted issuers config should be forwarded to core."""
        result = await evaluate_tool_access(
            tool_name="read_file",
            params={},
            credential=CallerCredential(api_key="test-key"),
            config=GuardConfig(
                trusted_issuers=["did:web:registry.capisc.io"],
                min_trust_level=2,
            ),
        )

        assert isinstance(result, GuardResult)

    async def test_allowed_tools_restriction(self):
        """Allowed tools config should restrict which tools are accessible."""
        result = await evaluate_tool_access(
            tool_name="dangerous_tool",
            params={},
            credential=CallerCredential(api_key="test-key"),
            config=GuardConfig(
                min_trust_level=0,
                accept_level_zero=True,
                allowed_tools=["safe_tool", "read_file"],
            ),
        )

        assert isinstance(result, GuardResult)
        assert result.decision == Decision.DENY


class TestDecisionCacheLive:
    """Test the decision cache with live core responses."""

    async def test_cache_hit_returns_same_result(self):
        """Same credential + tool should return cached result."""
        credential = CallerCredential(api_key="cache-test-key")
        config = GuardConfig(min_trust_level=0, accept_level_zero=True)

        result1 = await evaluate_tool_access(
            tool_name="cached_tool",
            params={"x": 1},
            credential=credential,
            config=config,
        )

        result2 = await evaluate_tool_access(
            tool_name="cached_tool",
            params={"x": 1},
            credential=credential,
            config=config,
        )

        assert result1.decision == result2.decision
