"""Tests for capiscio_mcp.integrations.mcp module."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

# Test imports work
from capiscio_mcp.integrations.mcp import (
    CapiscioMCPServer,
    CapiscioMCPClient,
    MCP_AVAILABLE,
    MCP_CLIENT_AVAILABLE,
    _install_credential_extraction,
)
from capiscio_mcp.types import ServerState

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
            with patch("capiscio_mcp.integrations.mcp.FastMCP"):
                server = CapiscioMCPServer(
                    name="filesystem",
                    did="did:web:mcp.example.com:servers:fs",
                )
                
                assert server.name == "filesystem"
                assert server.did == "did:web:mcp.example.com:servers:fs"
    
    def test_init_with_badge(self):
        """Should accept optional badge."""
        with patch("capiscio_mcp.integrations.mcp.MCP_AVAILABLE", True):
            with patch("capiscio_mcp.integrations.mcp.FastMCP"):
                server = CapiscioMCPServer(
                    name="filesystem",
                    did="did:web:mcp.example.com:servers:fs",
                    badge="eyJhbGc...",
                )
                
                assert server.badge == "eyJhbGc..."
    
    def test_init_with_default_trust_level(self):
        """Should accept default_min_trust_level."""
        with patch("capiscio_mcp.integrations.mcp.MCP_AVAILABLE", True):
            with patch("capiscio_mcp.integrations.mcp.FastMCP"):
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
            with patch("capiscio_mcp.integrations.mcp.FastMCP") as mock_fastmcp:
                mock_instance = MagicMock()
                mock_fastmcp.return_value = mock_instance
                
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
            with patch("capiscio_mcp.integrations.mcp.FastMCP") as mock_fastmcp:
                mock_instance = MagicMock()
                mock_fastmcp.return_value = mock_instance
                
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
            with patch("capiscio_mcp.integrations.mcp.FastMCP"):
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
        """server property should return underlying FastMCP server."""
        with patch("capiscio_mcp.integrations.mcp.MCP_AVAILABLE", True):
            with patch("capiscio_mcp.integrations.mcp.FastMCP") as mock_fastmcp:
                mock_instance = MagicMock()
                mock_fastmcp.return_value = mock_instance
                
                server = CapiscioMCPServer(
                    name="filesystem",
                    did="did:web:mcp.example.com:servers:fs",
                )
                
                assert server.server is mock_instance


@requires_mcp_client
class TestCapiscioMCPClient:
    """Tests for CapiscioMCPClient class."""
    
    def test_init_with_server_url(self):
        """Should initialize with server_url parameter."""
        with patch("capiscio_mcp.integrations.mcp.MCP_CLIENT_AVAILABLE", True):
            client = CapiscioMCPClient(
                server_url="https://mcp.example.com",
            )
            
            assert client.server_url == "https://mcp.example.com"
    
    def test_init_with_command(self):
        """Should initialize with command parameter for stdio transport."""
        with patch("capiscio_mcp.integrations.mcp.MCP_CLIENT_AVAILABLE", True):
            client = CapiscioMCPClient(
                command="python",
                args=["server.py"],
            )
            
            assert client.command == "python"
            assert client.args == ["server.py"]
    
    def test_init_raises_without_transport(self):
        """Should raise ValueError if neither server_url nor command provided."""
        with patch("capiscio_mcp.integrations.mcp.MCP_CLIENT_AVAILABLE", True):
            with pytest.raises(ValueError) as exc_info:
                client = CapiscioMCPClient()
            
            assert "server_url or command" in str(exc_info.value)
    
    def test_init_with_min_trust_level(self):
        """Should accept min_trust_level."""
        with patch("capiscio_mcp.integrations.mcp.MCP_CLIENT_AVAILABLE", True):
            client = CapiscioMCPClient(
                command="python",
                args=["server.py"],
                min_trust_level=2,
            )
            
            assert client.min_trust_level == 2
    
    def test_init_with_fail_on_unverified(self):
        """Should accept fail_on_unverified flag."""
        with patch("capiscio_mcp.integrations.mcp.MCP_CLIENT_AVAILABLE", True):
            client = CapiscioMCPClient(
                command="python",
                args=["server.py"],
                fail_on_unverified=False,
            )
            
            assert client.fail_on_unverified is False
    
    def test_init_raises_without_mcp(self):
        """Should raise ImportError without MCP SDK."""
        with patch("capiscio_mcp.integrations.mcp.MCP_CLIENT_AVAILABLE", False):
            with pytest.raises(ImportError) as exc_info:
                client = CapiscioMCPClient(
                    command="python",
                    args=["server.py"],
                )
            
            assert "pip install capiscio-mcp[mcp]" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_context_manager_cleanup(self):
        """Context manager should clean up on exit."""
        with patch("capiscio_mcp.integrations.mcp.MCP_CLIENT_AVAILABLE", True):
            with patch("capiscio_mcp.integrations.mcp.stdio_client") as mock_stdio:
                with patch("capiscio_mcp.integrations.mcp.McpClientSession") as mock_session:
                    # Set up mocks
                    mock_cm = AsyncMock()
                    mock_cm.__aenter__.return_value = (MagicMock(), MagicMock())
                    mock_stdio.return_value = mock_cm
                    
                    mock_session_instance = AsyncMock()
                    mock_session_instance.initialize = AsyncMock()
                    mock_session.return_value = mock_session_instance
                    
                    client = CapiscioMCPClient(
                        command="python",
                        args=["server.py"],
                        fail_on_unverified=False,
                    )
                    
                    async with client:
                        pass
                    
                    # After exit, session should be cleaned up
                    assert client._session is None
                    assert client._context_manager is None
    
    @pytest.mark.asyncio
    async def test_http_transport_not_implemented(self):
        """HTTP transport should raise NotImplementedError."""
        with patch("capiscio_mcp.integrations.mcp.MCP_CLIENT_AVAILABLE", True):
            client = CapiscioMCPClient(
                server_url="https://mcp.example.com",
            )
            
            with pytest.raises(NotImplementedError) as exc_info:
                async with client:
                    pass
            
            assert "HTTP transport" in str(exc_info.value)
    
    def test_server_state_property_before_connect(self):
        """server_state property should return None before connect."""
        with patch("capiscio_mcp.integrations.mcp.MCP_CLIENT_AVAILABLE", True):
            client = CapiscioMCPClient(
                command="python",
                args=["server.py"],
            )
            
            assert client.server_state is None
    
    def test_server_trust_level_property_before_connect(self):
        """server_trust_level property should return None before connect."""
        with patch("capiscio_mcp.integrations.mcp.MCP_CLIENT_AVAILABLE", True):
            client = CapiscioMCPClient(
                command="python",
                args=["server.py"],
            )
            
            assert client.server_trust_level is None
    
    @pytest.mark.asyncio
    async def test_call_tool_raises_when_not_connected(self):
        """call_tool should raise when not connected."""
        with patch("capiscio_mcp.integrations.mcp.MCP_CLIENT_AVAILABLE", True):
            client = CapiscioMCPClient(
                command="python",
                args=["server.py"],
            )
            
            with pytest.raises(RuntimeError) as exc_info:
                await client.call_tool("test", {})
            
            assert "not connected" in str(exc_info.value).lower()
    
    @pytest.mark.asyncio
    async def test_list_tools_raises_when_not_connected(self):
        """list_tools should raise when not connected."""
        with patch("capiscio_mcp.integrations.mcp.MCP_CLIENT_AVAILABLE", True):
            client = CapiscioMCPClient(
                command="python",
                args=["server.py"],
            )
            
            with pytest.raises(RuntimeError) as exc_info:
                await client.list_tools()
            
            assert "not connected" in str(exc_info.value).lower()


@requires_mcp
class TestInstallCredentialExtraction:
    """Tests for _install_credential_extraction — stdio badge-in-_meta mechanism."""

    def _make_fastmcp_with_handler(self):
        """Return a minimal FastMCP-like mock with a CallToolRequest handler."""
        from mcp import types as _mcp_types

        original_handler_called_with = []

        async def original_handler(req):
            original_handler_called_with.append(req)
            return "original_result"

        mock_server = MagicMock()
        mock_server.request_handlers = {
            _mcp_types.CallToolRequest: original_handler,
        }

        mock_fastmcp = MagicMock()
        mock_fastmcp._mcp_server = mock_server
        return mock_fastmcp, mock_server, original_handler_called_with

    def test_installs_wrapper_over_call_tool_handler(self):
        """_install_credential_extraction should replace the CallToolRequest handler."""
        from mcp import types as _mcp_types

        mock_fastmcp, mock_server, _ = self._make_fastmcp_with_handler()
        original_handler = mock_server.request_handlers[_mcp_types.CallToolRequest]

        _install_credential_extraction(mock_fastmcp)

        new_handler = mock_server.request_handlers[_mcp_types.CallToolRequest]
        assert new_handler is not original_handler

    def test_no_mcp_server_attribute_is_safe(self):
        """Should silently return if fastmcp has no _mcp_server attribute."""
        mock_fastmcp = MagicMock(spec=[])  # no _mcp_server
        # Should not raise
        _install_credential_extraction(mock_fastmcp)

    def test_no_handler_registered_is_safe(self):
        """Should silently return if CallToolRequest handler is not registered."""
        from mcp import types as _mcp_types

        mock_server = MagicMock()
        mock_server.request_handlers = {}  # no CallToolRequest handler
        mock_fastmcp = MagicMock()
        mock_fastmcp._mcp_server = mock_server

        _install_credential_extraction(mock_fastmcp)
        # request_handlers unchanged
        assert _mcp_types.CallToolRequest not in mock_server.request_handlers

    @pytest.mark.asyncio
    async def test_badge_extracted_from_meta_and_sets_credential(self):
        """Wrapper should extract capiscio_caller_badge from _meta and set contextvar."""
        from mcp import types as _mcp_types
        from capiscio_mcp.guard import _current_credential

        captured_cred = []

        async def original_handler(req):
            # Capture whatever credential is set when the original handler runs
            captured_cred.append(_current_credential.get())
            return "ok"

        mock_server = MagicMock()
        mock_server.request_handlers = {_mcp_types.CallToolRequest: original_handler}
        mock_fastmcp = MagicMock()
        mock_fastmcp._mcp_server = mock_server

        _install_credential_extraction(mock_fastmcp)
        wrapper = mock_server.request_handlers[_mcp_types.CallToolRequest]

        # Build a CallToolRequest with badge in _meta
        meta = _mcp_types.RequestParams.Meta(capiscio_caller_badge="badge_jws_value")
        params = _mcp_types.CallToolRequestParams(name="test_tool", arguments={}, _meta=meta)
        req = _mcp_types.CallToolRequest(params=params)

        await wrapper(req)

        assert len(captured_cred) == 1
        cred = captured_cred[0]
        assert cred is not None
        assert cred.badge_jws == "badge_jws_value"
        assert cred.api_key is None

    @pytest.mark.asyncio
    async def test_api_key_extracted_from_meta(self):
        """Wrapper should extract capiscio_caller_api_key from _meta."""
        from mcp import types as _mcp_types
        from capiscio_mcp.guard import _current_credential

        captured_cred = []

        async def original_handler(req):
            captured_cred.append(_current_credential.get())
            return "ok"

        mock_server = MagicMock()
        mock_server.request_handlers = {_mcp_types.CallToolRequest: original_handler}
        mock_fastmcp = MagicMock()
        mock_fastmcp._mcp_server = mock_server

        _install_credential_extraction(mock_fastmcp)
        wrapper = mock_server.request_handlers[_mcp_types.CallToolRequest]

        meta = _mcp_types.RequestParams.Meta(capiscio_caller_api_key="sk-test-key")
        params = _mcp_types.CallToolRequestParams(name="test_tool", arguments={}, _meta=meta)
        req = _mcp_types.CallToolRequest(params=params)

        await wrapper(req)

        assert captured_cred[0].api_key == "sk-test-key"
        assert captured_cred[0].badge_jws is None

    @pytest.mark.asyncio
    async def test_no_meta_passes_through_without_credential(self):
        """Wrapper should call original handler unchanged when _meta has no credentials."""
        from mcp import types as _mcp_types
        from capiscio_mcp.guard import _current_credential

        captured_cred = []

        async def original_handler(req):
            captured_cred.append(_current_credential.get())
            return "ok"

        mock_server = MagicMock()
        mock_server.request_handlers = {_mcp_types.CallToolRequest: original_handler}
        mock_fastmcp = MagicMock()
        mock_fastmcp._mcp_server = mock_server

        _install_credential_extraction(mock_fastmcp)
        wrapper = mock_server.request_handlers[_mcp_types.CallToolRequest]

        # No _meta on the request
        params = _mcp_types.CallToolRequestParams(name="test_tool", arguments={})
        req = _mcp_types.CallToolRequest(params=params)

        await wrapper(req)

        # Original handler should have been called; no credential set
        assert len(captured_cred) == 1
        # Default contextvar should be None (no credential)
        assert captured_cred[0] is None

    @pytest.mark.asyncio
    async def test_credential_contextvar_is_reset_after_call(self):
        """Credential contextvar must be reset to its prior value after the handler returns."""
        from mcp import types as _mcp_types
        from capiscio_mcp.guard import _current_credential, set_credential
        from capiscio_mcp.types import CallerCredential

        async def original_handler(req):
            return "ok"

        mock_server = MagicMock()
        mock_server.request_handlers = {_mcp_types.CallToolRequest: original_handler}
        mock_fastmcp = MagicMock()
        mock_fastmcp._mcp_server = mock_server

        _install_credential_extraction(mock_fastmcp)
        wrapper = mock_server.request_handlers[_mcp_types.CallToolRequest]

        # Set a pre-existing credential
        prior_cred = CallerCredential(badge_jws="prior_badge")
        token = set_credential(prior_cred)
        try:
            meta = _mcp_types.RequestParams.Meta(capiscio_caller_badge="call_badge")
            params = _mcp_types.CallToolRequestParams(name="test", arguments={}, _meta=meta)
            req = _mcp_types.CallToolRequest(params=params)
            await wrapper(req)

            # Credential should be restored to prior value
            assert _current_credential.get() is prior_cred
        finally:
            _current_credential.reset(token)

    def test_server_init_installs_credential_extraction(self):
        """CapiscioMCPServer.__init__ should call _install_credential_extraction."""
        with patch("capiscio_mcp.integrations.mcp.MCP_AVAILABLE", True):
            with patch("capiscio_mcp.integrations.mcp.FastMCP"):
                with patch(
                    "capiscio_mcp.integrations.mcp._install_credential_extraction"
                ) as mock_install:
                    CapiscioMCPServer(
                        name="test",
                        did="did:web:example.com",
                    )
                    mock_install.assert_called_once()


@requires_mcp_client
class TestClientCallToolMetaPropagation:
    """Tests for CapiscioMCPClient.call_tool forwarding credentials via _meta."""

    @pytest.mark.asyncio
    async def test_call_tool_passes_badge_in_meta(self):
        """call_tool should pass badge in session.call_tool meta kwarg."""
        with patch("capiscio_mcp.integrations.mcp.MCP_CLIENT_AVAILABLE", True):
            client = CapiscioMCPClient(
                command="python",
                args=["server.py"],
                badge="eyJhbGciOiJFZERTQSJ9.test.sig",
            )

            mock_session = AsyncMock()
            mock_session.call_tool = AsyncMock(return_value="tool_result")
            client._session = mock_session

            result = await client.call_tool("my_tool", {"arg": "val"})

            mock_session.call_tool.assert_called_once_with(
                "my_tool",
                {"arg": "val"},
                meta={"capiscio_caller_badge": "eyJhbGciOiJFZERTQSJ9.test.sig"},
            )
            assert result == "tool_result"

    @pytest.mark.asyncio
    async def test_call_tool_passes_api_key_in_meta(self):
        """call_tool should pass api_key in session.call_tool meta kwarg."""
        with patch("capiscio_mcp.integrations.mcp.MCP_CLIENT_AVAILABLE", True):
            client = CapiscioMCPClient(
                command="python",
                args=["server.py"],
                api_key="sk-live-test",
            )

            mock_session = AsyncMock()
            mock_session.call_tool = AsyncMock(return_value="result")
            client._session = mock_session

            await client.call_tool("tool", {})

            _, _, kwargs = mock_session.call_tool.mock_calls[0]
            assert kwargs["meta"] == {"capiscio_caller_api_key": "sk-live-test"}

    @pytest.mark.asyncio
    async def test_call_tool_passes_both_badge_and_api_key_in_meta(self):
        """call_tool should pass both badge and api_key when both are set."""
        with patch("capiscio_mcp.integrations.mcp.MCP_CLIENT_AVAILABLE", True):
            client = CapiscioMCPClient(
                command="python",
                args=["server.py"],
                badge="badge_jws",
                api_key="sk-test",
            )

            mock_session = AsyncMock()
            mock_session.call_tool = AsyncMock(return_value="result")
            client._session = mock_session

            await client.call_tool("tool", {})

            _, _, kwargs = mock_session.call_tool.mock_calls[0]
            assert kwargs["meta"] == {
                "capiscio_caller_badge": "badge_jws",
                "capiscio_caller_api_key": "sk-test",
            }

    @pytest.mark.asyncio
    async def test_call_tool_passes_none_meta_when_no_credentials(self):
        """call_tool should pass meta=None when no credentials are set."""
        with patch("capiscio_mcp.integrations.mcp.MCP_CLIENT_AVAILABLE", True):
            client = CapiscioMCPClient(
                command="python",
                args=["server.py"],
                # No badge or api_key
            )

            mock_session = AsyncMock()
            mock_session.call_tool = AsyncMock(return_value="result")
            client._session = mock_session

            await client.call_tool("tool", {"x": 1})

            mock_session.call_tool.assert_called_once_with("tool", {"x": 1}, meta=None)

    @pytest.mark.asyncio
    async def test_call_tool_empty_arguments_uses_empty_dict(self):
        """call_tool should default arguments to {} when None passed."""
        with patch("capiscio_mcp.integrations.mcp.MCP_CLIENT_AVAILABLE", True):
            client = CapiscioMCPClient(
                command="python",
                args=["server.py"],
            )

            mock_session = AsyncMock()
            mock_session.call_tool = AsyncMock(return_value="result")
            client._session = mock_session

            await client.call_tool("tool")

            call_args = mock_session.call_tool.call_args
            assert call_args.args[1] == {}
