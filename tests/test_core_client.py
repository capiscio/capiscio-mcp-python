"""Tests for capiscio_mcp._core.client module."""

import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from capiscio_mcp._core.client import CoreClient


@pytest.fixture(autouse=True)
def reset_singleton():
    """Reset CoreClient singleton before and after each test."""
    # Reset class-level state for new per-loop-instance pattern
    CoreClient._instances.clear()
    CoreClient._lock = None
    yield
    CoreClient._instances.clear()
    CoreClient._lock = None


class TestCoreClientSingleton:
    """Tests for CoreClient singleton pattern."""
    
    @pytest.mark.asyncio
    async def test_get_instance_returns_same_instance(self):
        """get_instance should return same instance within same event loop."""
        with patch.object(CoreClient, "connect", new_callable=AsyncMock):
            # Mark as connected so connect isn't called again
            instance1 = await CoreClient.get_instance()
            instance1._connected = True
            instance2 = await CoreClient.get_instance()
            
            assert instance1 is instance2
    
    @pytest.mark.asyncio
    async def test_get_instance_calls_connect_once(self):
        """get_instance should only call connect once when already connected."""
        with patch.object(CoreClient, "connect", new_callable=AsyncMock) as mock_connect:
            # First call creates and connects
            instance = await CoreClient.get_instance()
            # Mark as connected to prevent reconnection
            instance._connected = True
            
            await CoreClient.get_instance()
            await CoreClient.get_instance()
            
            # Should only connect once since _connected is True
            mock_connect.assert_called_once()
    
    def test_reset_singleton(self):
        """Should be able to reset singleton for testing."""
        # Add a mock instance to _instances
        loop_id = 12345
        CoreClient._instances[loop_id] = MagicMock()
        assert len(CoreClient._instances) > 0
        
        # Clear it
        CoreClient._instances.clear()
        assert len(CoreClient._instances) == 0


class TestCoreClientEmbeddedMode:
    """Tests for embedded mode (auto-start binary)."""
    
    @pytest.mark.asyncio
    async def test_embedded_mode_when_no_addr(self):
        """Should use embedded mode when CAPISCIO_CORE_ADDR not set."""
        # Clear environment variable
        env_without_addr = {k: v for k, v in os.environ.items() if k != "CAPISCIO_CORE_ADDR"}
        
        with patch.dict(os.environ, env_without_addr, clear=True):
            # Mock the imports in client.py - need to patch where they're used
            with patch("capiscio_mcp._core.client.ensure_binary", new_callable=AsyncMock) as mock_ensure:
                mock_ensure.return_value = "/usr/local/bin/capiscio"
                
                with patch("capiscio_mcp._core.client.ProcessSupervisor") as mock_supervisor_cls:
                    mock_supervisor = MagicMock()
                    mock_supervisor.start = AsyncMock()
                    mock_supervisor.stop = AsyncMock()
                    mock_supervisor_cls.return_value = mock_supervisor
                    
                    with patch("capiscio_mcp._core.client.grpc.aio.insecure_channel") as mock_channel:
                        mock_channel_instance = MagicMock()
                        mock_channel_instance.close = AsyncMock()
                        mock_channel.return_value = mock_channel_instance
                        
                        with patch("capiscio_mcp._core.client.wait_healthy", new_callable=AsyncMock):
                            with patch("capiscio_mcp._core.client.check_version_compatibility", new_callable=AsyncMock):
                                with patch("capiscio_mcp._proto.capiscio.v1.mcp_pb2_grpc.MCPServiceStub"):
                                    client = CoreClient()
                                    await client.connect()
                                    
                                    # Should have downloaded/ensured binary
                                    mock_ensure.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_embedded_mode_finds_free_port(self):
        """Embedded mode should find an available port."""
        client = CoreClient()
        port = await client._find_free_port()
        
        assert isinstance(port, int)
        assert port > 0
        assert port < 65536


class TestCoreClientExternalMode:
    """Tests for external mode (user-managed core)."""
    
    @pytest.mark.asyncio
    async def test_external_mode_when_addr_set(self):
        """Should use external mode when CAPISCIO_CORE_ADDR is set."""
        with patch.dict(os.environ, {"CAPISCIO_CORE_ADDR": "localhost:50051"}):
            with patch("capiscio_mcp._core.client.grpc.aio.insecure_channel") as mock_channel:
                mock_channel_instance = MagicMock()
                mock_channel_instance.close = AsyncMock()
                mock_channel.return_value = mock_channel_instance
                
                with patch("capiscio_mcp._core.client.wait_healthy", new_callable=AsyncMock):
                    with patch("capiscio_mcp._core.client.check_version_compatibility", new_callable=AsyncMock):
                        with patch("capiscio_mcp._proto.capiscio.v1.mcp_pb2_grpc.MCPServiceStub"):
                            client = CoreClient()
                            await client.connect()
                            
                            # Should connect to specified address
                            mock_channel.assert_called_once_with("localhost:50051")
    
    @pytest.mark.asyncio
    async def test_external_mode_custom_port(self):
        """External mode should use custom port from env."""
        with patch.dict(os.environ, {"CAPISCIO_CORE_ADDR": "core.example.com:9999"}):
            with patch("capiscio_mcp._core.client.grpc.aio.insecure_channel") as mock_channel:
                mock_channel_instance = MagicMock()
                mock_channel_instance.close = AsyncMock()
                mock_channel.return_value = mock_channel_instance
                
                with patch("capiscio_mcp._core.client.wait_healthy", new_callable=AsyncMock):
                    with patch("capiscio_mcp._core.client.check_version_compatibility", new_callable=AsyncMock):
                        with patch("capiscio_mcp._proto.capiscio.v1.mcp_pb2_grpc.MCPServiceStub"):
                            client = CoreClient()
                            await client.connect()
                            
                            mock_channel.assert_called_once_with("core.example.com:9999")


class TestCoreClientVersionHandshake:
    """Tests for version compatibility handshake."""
    
    @pytest.mark.asyncio
    async def test_incompatible_version_raises(self):
        """Should raise error when core version is incompatible."""
        with patch.dict(os.environ, {"CAPISCIO_CORE_ADDR": "localhost:50051"}):
            with patch("capiscio_mcp._core.client.grpc.aio.insecure_channel") as mock_channel:
                mock_channel_instance = MagicMock()
                mock_channel_instance.close = AsyncMock()
                mock_channel.return_value = mock_channel_instance
                
                with patch("capiscio_mcp._core.client.wait_healthy", new_callable=AsyncMock):
                    with patch("capiscio_mcp._core.client.check_version_compatibility", new_callable=AsyncMock) as mock_compat:
                        mock_compat.side_effect = RuntimeError("version mismatch")
                        
                        with patch("capiscio_mcp._proto.capiscio.v1.mcp_pb2_grpc.MCPServiceStub"):
                            client = CoreClient()
                            
                            from capiscio_mcp.errors import CoreConnectionError
                            with pytest.raises(CoreConnectionError) as exc_info:
                                await client.connect()
                            
                            assert "version" in str(exc_info.value).lower()
    
    @pytest.mark.asyncio
    async def test_compatible_version_continues(self):
        """Should continue when core version is compatible."""
        with patch.dict(os.environ, {"CAPISCIO_CORE_ADDR": "localhost:50051"}):
            with patch("capiscio_mcp._core.client.grpc.aio.insecure_channel") as mock_channel:
                mock_channel_instance = MagicMock()
                mock_channel_instance.close = AsyncMock()
                mock_channel.return_value = mock_channel_instance
                
                with patch("capiscio_mcp._core.client.wait_healthy", new_callable=AsyncMock):
                    with patch("capiscio_mcp._core.client.check_version_compatibility", new_callable=AsyncMock):
                        with patch("capiscio_mcp._proto.capiscio.v1.mcp_pb2_grpc.MCPServiceStub"):
                            client = CoreClient()
                            await client.connect()
                            
                            # Should not raise
                            assert client._connected


class TestCoreClientHealthCheck:
    """Tests for health check on connect."""
    
    @pytest.mark.asyncio
    async def test_waits_for_healthy(self):
        """Should wait for core to be healthy."""
        with patch.dict(os.environ, {"CAPISCIO_CORE_ADDR": "localhost:50051"}):
            with patch("capiscio_mcp._core.client.grpc.aio.insecure_channel") as mock_channel:
                mock_channel_instance = MagicMock()
                mock_channel_instance.close = AsyncMock()
                mock_channel.return_value = mock_channel_instance
                
                with patch("capiscio_mcp._core.client.wait_healthy", new_callable=AsyncMock) as mock_health:
                    with patch("capiscio_mcp._core.client.check_version_compatibility", new_callable=AsyncMock):
                        with patch("capiscio_mcp._proto.capiscio.v1.mcp_pb2_grpc.MCPServiceStub"):
                            client = CoreClient()
                            await client.connect()
                            
                            mock_health.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_health_timeout_raises(self):
        """Should raise error if health check times out."""
        with patch.dict(os.environ, {"CAPISCIO_CORE_ADDR": "localhost:50051"}):
            with patch("capiscio_mcp._core.client.grpc.aio.insecure_channel") as mock_channel:
                mock_channel_instance = MagicMock()
                mock_channel_instance.close = AsyncMock()
                mock_channel.return_value = mock_channel_instance
                
                with patch("capiscio_mcp._core.client.wait_healthy", new_callable=AsyncMock) as mock_health:
                    mock_health.side_effect = asyncio.TimeoutError()
                    
                    with patch("capiscio_mcp._proto.capiscio.v1.mcp_pb2_grpc.MCPServiceStub"):
                        client = CoreClient()
                        
                        from capiscio_mcp.errors import CoreConnectionError
                        with pytest.raises(CoreConnectionError):
                            await client.connect()


class TestCoreClientClose:
    """Tests for closing connection."""
    
    @pytest.mark.asyncio
    async def test_close_channel(self):
        """Should close gRPC channel."""
        client = CoreClient()
        
        mock_channel = MagicMock()
        mock_channel.close = AsyncMock()
        client._channel = mock_channel
        
        await client.close()
        
        mock_channel.close.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_close_stops_supervisor(self):
        """Should stop supervisor on close."""
        client = CoreClient()
        
        mock_channel = MagicMock()
        mock_channel.close = AsyncMock()
        client._channel = mock_channel
        
        mock_supervisor = MagicMock()
        mock_supervisor.stop = AsyncMock()
        client._supervisor = mock_supervisor
        
        await client.close()
        
        mock_supervisor.stop.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_close_without_supervisor(self):
        """Should handle close when no supervisor."""
        client = CoreClient()
        
        mock_channel = MagicMock()
        mock_channel.close = AsyncMock()
        client._channel = mock_channel
        client._supervisor = None
        
        # Should not raise
        await client.close()


class TestCoreClientStub:
    """Tests for gRPC stub property."""
    
    def test_stub_property(self):
        """stub property should return the gRPC stub."""
        client = CoreClient()
        
        mock_stub = MagicMock()
        client._stub = mock_stub
        
        assert client.stub is mock_stub
    
    def test_stub_raises_when_not_connected(self):
        """stub should raise when not connected."""
        client = CoreClient()
        
        from capiscio_mcp.errors import CoreConnectionError
        with pytest.raises(CoreConnectionError):
            _ = client.stub


class TestCoreClientContextManager:
    """Tests for async context manager."""
    
    @pytest.mark.asyncio
    async def test_context_manager_connects_and_closes(self):
        """Context manager should connect on enter and close on exit."""
        with patch.dict(os.environ, {"CAPISCIO_CORE_ADDR": "localhost:50051"}):
            with patch("capiscio_mcp._core.client.grpc.aio.insecure_channel") as mock_channel:
                mock_channel_instance = MagicMock()
                mock_channel_instance.close = AsyncMock()
                mock_channel.return_value = mock_channel_instance
                
                with patch("capiscio_mcp._core.client.wait_healthy", new_callable=AsyncMock):
                    with patch("capiscio_mcp._core.client.check_version_compatibility", new_callable=AsyncMock):
                        with patch("capiscio_mcp._proto.capiscio.v1.mcp_pb2_grpc.MCPServiceStub"):
                            async with CoreClient() as client:
                                assert client._connected
                            
                            # After exit, should be closed
                            assert not client._connected


class TestCoreClientIsConnected:
    """Tests for is_connected property."""
    
    def test_is_connected_false_initially(self):
        """is_connected should be False initially."""
        client = CoreClient()
        assert not client.is_connected
    
    @pytest.mark.asyncio
    async def test_is_connected_true_after_connect(self):
        """is_connected should be True after connect."""
        with patch.dict(os.environ, {"CAPISCIO_CORE_ADDR": "localhost:50051"}):
            with patch("capiscio_mcp._core.client.grpc.aio.insecure_channel") as mock_channel:
                mock_channel_instance = MagicMock()
                mock_channel_instance.close = AsyncMock()
                mock_channel.return_value = mock_channel_instance
                
                with patch("capiscio_mcp._core.client.wait_healthy", new_callable=AsyncMock):
                    with patch("capiscio_mcp._core.client.check_version_compatibility", new_callable=AsyncMock):
                        with patch("capiscio_mcp._proto.capiscio.v1.mcp_pb2_grpc.MCPServiceStub"):
                            client = CoreClient()
                            await client.connect()
                            
                            assert client.is_connected
