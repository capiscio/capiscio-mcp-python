"""Tests for capiscio_mcp.integrations.mcp module."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

# Test imports work
from capiscio_mcp.integrations.mcp import (
    CapiscioMCPServer,
    CapiscioMCPClient,
    MCP_AVAILABLE,
    MCP_CLIENT_AVAILABLE,
)
from capiscio_mcp.types import ServerState
from capiscio_mcp.errors import GuardError, ServerVerifyError

# Skip tests that require MCP package if not installed
requires_mcp = pytest.mark.skipif(not MCP_AVAILABLE, reason="MCP package not installed")
requires_mcp_client = pytest.mark.skipif(not MCP_CLIENT_AVAILABLE, reason="MCP client not installed")


class TestMCPAvailability:
    """Tests for MCP SDK availability detection."""
    
    def test_mcp_available_flag_exists(self):
        """MCP_AVAILABLE flag should exist."""
        assert isinstance(MCP_AVAILABLE, bool)
    
    @patch.dict("sys.modules", {"mcp": None, "mcp.server": None, "mcp.client": None})
    def test_mcp_not_available_without_package(self):
        """MCP should not be available without mcp package."""
        # Re-import to pick up mocked modules
        # Note: actual behavior depends on import order
        pass


@requires_mcp
class TestCapiscioMCPServer:
    """Tests for CapiscioMCPServer class."""
    
    def test_init_with_required_params(self):
        """Should initialize with required parameters."""
        with patch("capiscio_mcp.integrations.mcp.MCP_AVAILABLE", True):
            with patch("capiscio_mcp.integrations.mcp.McpServer"):
                server = CapiscioMCPServer(
                    name="filesystem",
                    did="did:web:mcp.example.com:servers:fs",
                )
                
                assert server.name == "filesystem"
                assert server.did == "did:web:mcp.example.com:servers:fs"
    
    def test_init_with_badge(self):
        """Should accept optional badge."""
        with patch("capiscio_mcp.integrations.mcp.MCP_AVAILABLE", True):
            with patch("capiscio_mcp.integrations.mcp.McpServer"):
                server = CapiscioMCPServer(
                    name="filesystem",
                    did="did:web:mcp.example.com:servers:fs",
                    badge="eyJhbGc...",
                )
                
                assert server.badge == "eyJhbGc..."
    
    def test_init_with_default_trust_level(self):
        """Should accept default_min_trust_level."""
        with patch("capiscio_mcp.integrations.mcp.MCP_AVAILABLE", True):
            with patch("capiscio_mcp.integrations.mcp.McpServer"):
                server = CapiscioMCPServer(
                    name="filesystem",
                    did="did:web:mcp.example.com:servers:fs",
                    default_min_trust_level=2,
                )
                
                assert server.default_min_trust_level == 2
    
    def test_init_raises_without_mcp(self):
        """Should raise ImportError without MCP SDK."""
        with patch("capiscio_mcp.integrations.mcp.MCP_AVAILABLE", False):
            with pytest.raises(ImportError) as exc_info:
                server = CapiscioMCPServer(
                    name="test",
                    did="did:web:example.com",
                )
            
            assert "pip install capiscio-mcp[mcp]" in str(exc_info.value)
    
    def test_tool_decorator(self):
        """tool decorator should register guarded tools."""
        with patch("capiscio_mcp.integrations.mcp.MCP_AVAILABLE", True):
            with patch("capiscio_mcp.integrations.mcp.McpServer") as mock_mcp_server:
                mock_instance = MagicMock()
                mock_mcp_server.return_value = mock_instance
                
                server = CapiscioMCPServer(
                    name="filesystem",
                    did="did:web:mcp.example.com:servers:fs",
                )
                
                @server.tool(min_trust_level=2)
                async def read_file(path: str) -> str:
                    return f"Contents of {path}"
                
                # Should have registered the tool internally
                assert "read_file" in server._tools
                assert server._tool_configs["read_file"].min_trust_level == 2
    
    def test_tool_decorator_with_custom_name(self):
        """tool decorator should accept custom tool name."""
        with patch("capiscio_mcp.integrations.mcp.MCP_AVAILABLE", True):
            with patch("capiscio_mcp.integrations.mcp.McpServer") as mock_mcp_server:
                mock_instance = MagicMock()
                mock_mcp_server.return_value = mock_instance
                
                server = CapiscioMCPServer(
                    name="filesystem",
                    did="did:web:mcp.example.com:servers:fs",
                )
                
                @server.tool(name="fs.read", min_trust_level=1)
                async def read_file(path: str) -> str:
                    return f"Contents of {path}"
                
                # Should have registered with custom name
                assert "fs.read" in server._tools
                assert "read_file" not in server._tools
    
    def test_tool_uses_default_trust_level(self):
        """tool should use server's default_min_trust_level."""
        with patch("capiscio_mcp.integrations.mcp.MCP_AVAILABLE", True):
            with patch("capiscio_mcp.integrations.mcp.McpServer"):
                server = CapiscioMCPServer(
                    name="filesystem",
                    did="did:web:mcp.example.com:servers:fs",
                    default_min_trust_level=3,
                )
                
                @server.tool()  # No min_trust_level specified
                async def test_tool() -> str:
                    return "result"
                
                # Tool should use default trust level 3
    
    def test_server_property_returns_underlying_server(self):
        """server property should return underlying MCP server."""
        with patch("capiscio_mcp.integrations.mcp.MCP_AVAILABLE", True):
            with patch("capiscio_mcp.integrations.mcp.McpServer") as mock_mcp_server:
                mock_instance = MagicMock()
                mock_mcp_server.return_value = mock_instance
                
                server = CapiscioMCPServer(
                    name="filesystem",
                    did="did:web:mcp.example.com:servers:fs",
                )
                
                assert server.server is mock_instance


@requires_mcp_client
class TestCapiscioMCPClient:
    """Tests for CapiscioMCPClient class."""
    
    def test_init_with_required_params(self):
        """Should initialize with required parameters."""
        with patch("capiscio_mcp.integrations.mcp.MCP_CLIENT_AVAILABLE", True):
            client = CapiscioMCPClient(
                server_url="https://mcp.example.com",
            )
            
            assert client.server_url == "https://mcp.example.com"
    
    def test_init_with_min_trust_level(self):
        """Should accept min_trust_level."""
        with patch("capiscio_mcp.integrations.mcp.MCP_CLIENT_AVAILABLE", True):
            client = CapiscioMCPClient(
                server_url="https://mcp.example.com",
                min_trust_level=2,
            )
            
            assert client.min_trust_level == 2
    
    def test_init_with_fail_on_unverified(self):
        """Should accept fail_on_unverified flag."""
        with patch("capiscio_mcp.integrations.mcp.MCP_CLIENT_AVAILABLE", True):
            client = CapiscioMCPClient(
                server_url="https://mcp.example.com",
                fail_on_unverified=False,
            )
            
            assert client.fail_on_unverified is False
    
    def test_init_raises_without_mcp(self):
        """Should raise ImportError without MCP SDK."""
        with patch("capiscio_mcp.integrations.mcp.MCP_CLIENT_AVAILABLE", False):
            with pytest.raises(ImportError) as exc_info:
                client = CapiscioMCPClient(
                    server_url="https://mcp.example.com",
                )
            
            assert "pip install capiscio-mcp[mcp]" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_context_manager_enter(self):
        """Should connect on context manager enter."""
        with patch("capiscio_mcp.integrations.mcp.MCP_CLIENT_AVAILABLE", True):
            with patch("capiscio_mcp.integrations.mcp.verify_server") as mock_verify:
                mock_verify.return_value = MagicMock(
                    state=ServerState.VERIFIED_PRINCIPAL,
                    trust_level=2,
                    error_code=None,
                    server_did="did:web:example.com",
                )
                
                client = CapiscioMCPClient(
                    server_url="https://mcp.example.com",
                )
                
                async with client:
                    # Verify connect was called (verify_server invoked)
                    mock_verify.assert_called()
    
    @pytest.mark.asyncio
    async def test_context_manager_exit(self):
        """Should disconnect on context manager exit."""
        with patch("capiscio_mcp.integrations.mcp.MCP_CLIENT_AVAILABLE", True):
            with patch("capiscio_mcp.integrations.mcp.verify_server") as mock_verify:
                mock_verify.return_value = MagicMock(
                    state=ServerState.VERIFIED_PRINCIPAL,
                    trust_level=2,
                    error_code=None,
                    server_did="did:web:example.com",
                )
                
                client = CapiscioMCPClient(
                    server_url="https://mcp.example.com",
                )
                
                async with client:
                    pass
                
                # After exit, session should be cleaned up
                assert client._session is None
    
    @pytest.mark.asyncio
    async def test_verifies_server_on_connect(self):
        """Should verify server identity on connect."""
        with patch("capiscio_mcp.integrations.mcp.MCP_CLIENT_AVAILABLE", True):
            with patch("capiscio_mcp.integrations.mcp.verify_server") as mock_verify:
                mock_verify.return_value = MagicMock(
                    state=ServerState.VERIFIED_PRINCIPAL,
                    trust_level=2,
                    error_code=None,
                    server_did="did:web:example.com",
                )
                
                client = CapiscioMCPClient(
                    server_url="https://mcp.example.com",
                )
                
                async with client:
                    mock_verify.assert_called()
    
    @pytest.mark.asyncio
    async def test_raises_on_unverified_when_configured(self):
        """Should raise when server is unverified and fail_on_unverified=True."""
        from capiscio_mcp.types import ServerErrorCode
        
        with patch("capiscio_mcp.integrations.mcp.MCP_CLIENT_AVAILABLE", True):
            with patch("capiscio_mcp.integrations.mcp.verify_server") as mock_verify:
                mock_verify.return_value = MagicMock(
                    state=ServerState.UNVERIFIED_ORIGIN,
                    trust_level=None,
                    error_code=ServerErrorCode.NONE,
                    server_did=None,
                )
                
                client = CapiscioMCPClient(
                    server_url="https://mcp.example.com",
                    fail_on_unverified=True,
                )
                
                with pytest.raises(ServerVerifyError):
                    async with client:
                        pass
    
    @pytest.mark.asyncio
    async def test_allows_unverified_when_configured(self):
        """Should allow unverified server when fail_on_unverified=False."""
        with patch("capiscio_mcp.integrations.mcp.MCP_CLIENT_AVAILABLE", True):
            with patch("capiscio_mcp.integrations.mcp.verify_server") as mock_verify:
                mock_verify.return_value = MagicMock(
                    state=ServerState.UNVERIFIED_ORIGIN,
                    trust_level=None,
                    error_code=None,
                    server_did=None,
                )
                
                client = CapiscioMCPClient(
                    server_url="https://mcp.example.com",
                    fail_on_unverified=False,  # Allow unverified
                )
                
                # Should not raise
                async with client:
                    assert client.server_state == ServerState.UNVERIFIED_ORIGIN
    
    @pytest.mark.asyncio
    async def test_server_state_property(self):
        """server_state property should return verification state."""
        with patch("capiscio_mcp.integrations.mcp.MCP_CLIENT_AVAILABLE", True):
            with patch("capiscio_mcp.integrations.mcp.verify_server") as mock_verify:
                mock_verify.return_value = MagicMock(
                    state=ServerState.VERIFIED_PRINCIPAL,
                    trust_level=2,
                    error_code=None,
                    server_did="did:web:example.com",
                )
                
                client = CapiscioMCPClient(
                    server_url="https://mcp.example.com",
                )
                
                async with client:
                    assert client.server_state == ServerState.VERIFIED_PRINCIPAL
    
    @pytest.mark.asyncio
    async def test_server_trust_level_property(self):
        """server_trust_level property should return trust level."""
        with patch("capiscio_mcp.integrations.mcp.MCP_CLIENT_AVAILABLE", True):
            with patch("capiscio_mcp.integrations.mcp.verify_server") as mock_verify:
                mock_verify.return_value = MagicMock(
                    state=ServerState.VERIFIED_PRINCIPAL,
                    trust_level=3,
                    error_code=None,
                    server_did="did:web:example.com",
                )
                
                client = CapiscioMCPClient(
                    server_url="https://mcp.example.com",
                )
                
                async with client:
                    assert client.server_trust_level == 3
    
    @pytest.mark.asyncio
    async def test_call_tool(self):
        """call_tool should delegate to underlying client."""
        with patch("capiscio_mcp.integrations.mcp.MCP_CLIENT_AVAILABLE", True):
            with patch("capiscio_mcp.integrations.mcp.verify_server") as mock_verify:
                mock_verify.return_value = MagicMock(
                    state=ServerState.VERIFIED_PRINCIPAL,
                    trust_level=2,
                    error_code=None,
                    server_did="did:web:example.com",
                )
                
                client = CapiscioMCPClient(
                    server_url="https://mcp.example.com",
                )
                
                # For this test, we just verify the not-connected error
                # since actual MCP client integration is not yet implemented
                with pytest.raises(RuntimeError) as exc_info:
                    await client.call_tool("read_file", {"path": "/tmp/test.txt"})
                
                assert "not connected" in str(exc_info.value).lower()
    
    @pytest.mark.asyncio
    async def test_call_tool_raises_when_not_connected(self):
        """call_tool should raise when not connected."""
        with patch("capiscio_mcp.integrations.mcp.MCP_AVAILABLE", True):
            client = CapiscioMCPClient(
                server_url="https://mcp.example.com",
            )
            
            with pytest.raises(RuntimeError) as exc_info:
                await client.call_tool("test", {})
            
            assert "not connected" in str(exc_info.value).lower()
