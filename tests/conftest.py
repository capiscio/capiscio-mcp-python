"""
Pytest configuration for capiscio-mcp tests.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

# Note: With pytest-asyncio in auto mode, no event_loop fixture needed


@pytest.fixture
def mock_core_client():
    """Mock CoreClient for unit tests."""
    with patch("capiscio_mcp._core.client.CoreClient") as mock:
        instance = AsyncMock()
        mock.get_instance = AsyncMock(return_value=instance)
        mock.return_value = instance
        yield instance


@pytest.fixture
def mock_mcp_stub():
    """Mock MCPService gRPC stub."""
    stub = AsyncMock()
    return stub


@pytest.fixture
def sample_badge_jws():
    """Sample badge JWS for testing."""
    # This is a placeholder - real badges would be properly signed
    return "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJkaWQ6d2ViOnJlZ2lzdHJ5LmNhcGlzYy5pbyIsInN1YiI6ImRpZDp3ZWI6ZXhhbXBsZS5jb206YWdlbnRzOnRlc3QiLCJleHAiOjk5OTk5OTk5OTl9.signature"


@pytest.fixture
def sample_server_did():
    """Sample server DID for testing."""
    return "did:web:mcp.example.com:servers:filesystem"


@pytest.fixture
def sample_agent_did():
    """Sample agent DID for testing."""
    return "did:web:example.com:agents:test-agent"
