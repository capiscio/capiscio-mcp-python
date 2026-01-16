"""Tests for capiscio_mcp._core.health module."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from capiscio_mcp._core.health import (
    check_version_compatibility,
    wait_healthy,
    HealthCheckError,
)
from capiscio_mcp._core.version import MCP_VERSION


class TestCheckVersionCompatibility:
    """Tests for check_version_compatibility function."""
    
    @pytest.mark.asyncio
    async def test_compatible_version(self):
        """Should return True for compatible core version."""
        mock_stub = MagicMock()
        mock_response = MagicMock()
        mock_response.healthy = True
        mock_response.core_version = "2.5.0"
        mock_response.proto_version = "1.0"
        mock_response.version_compatible = True
        
        mock_stub.Health = AsyncMock(return_value=mock_response)
        
        result = await check_version_compatibility(mock_stub, MCP_VERSION)
        
        assert result is True
    
    @pytest.mark.asyncio
    async def test_incompatible_version(self):
        """Should raise for incompatible core version."""
        mock_stub = MagicMock()
        mock_response = MagicMock()
        mock_response.healthy = True
        mock_response.core_version = "3.0.0"  # Above max
        mock_response.proto_version = "2.0"
        mock_response.version_compatible = False
        
        mock_stub.Health = AsyncMock(return_value=mock_response)
        
        from capiscio_mcp.errors import CoreVersionError
        with pytest.raises(CoreVersionError):
            await check_version_compatibility(mock_stub, MCP_VERSION)
    
    @pytest.mark.asyncio
    async def test_sends_client_version(self):
        """Should send client version in request."""
        mock_stub = MagicMock()
        mock_response = MagicMock()
        mock_response.healthy = True
        mock_response.core_version = "2.5.0"
        mock_response.version_compatible = True
        
        mock_stub.Health = AsyncMock(return_value=mock_response)
        
        await check_version_compatibility(mock_stub, "1.2.3")
        
        # Verify client_version was sent
        call_args = mock_stub.Health.call_args
        assert call_args is not None
        request = call_args[0][0]
        assert request.client_version == "1.2.3"
    
    @pytest.mark.asyncio
    async def test_handles_grpc_error(self):
        """Should handle gRPC errors gracefully."""
        mock_stub = MagicMock()
        mock_stub.Health = AsyncMock(side_effect=Exception("Connection refused"))
        
        with pytest.raises(Exception) as exc_info:
            await check_version_compatibility(mock_stub, MCP_VERSION)
        
        assert "Connection refused" in str(exc_info.value)


class TestWaitHealthy:
    """Tests for wait_healthy function."""
    
    @pytest.mark.asyncio
    async def test_returns_when_healthy(self):
        """Should return when core becomes healthy."""
        mock_stub = MagicMock()
        mock_response = MagicMock()
        mock_response.healthy = True
        
        mock_stub.Health = AsyncMock(return_value=mock_response)
        
        # wait_healthy returns None on success (doesn't raise)
        await wait_healthy(mock_stub, timeout=5.0)
        # If we get here without exception, test passes
    
    @pytest.mark.asyncio
    async def test_retries_until_healthy(self):
        """Should retry until core becomes healthy."""
        mock_stub = MagicMock()
        
        # First two calls return unhealthy, third returns healthy
        unhealthy_response = MagicMock()
        unhealthy_response.healthy = False
        
        healthy_response = MagicMock()
        healthy_response.healthy = True
        
        mock_stub.Health = AsyncMock(side_effect=[
            unhealthy_response,
            unhealthy_response,
            healthy_response,
        ])
        
        # wait_healthy returns None on success
        await wait_healthy(mock_stub, timeout=10.0, interval=0.01)
        
        assert mock_stub.Health.call_count == 3
    
    @pytest.mark.asyncio
    async def test_timeout_raises_error(self):
        """Should raise error on timeout."""
        mock_stub = MagicMock()
        mock_response = MagicMock()
        mock_response.healthy = False
        
        mock_stub.Health = AsyncMock(return_value=mock_response)
        
        with pytest.raises((asyncio.TimeoutError, HealthCheckError)):
            await wait_healthy(mock_stub, timeout=0.1, interval=0.02)
    
    @pytest.mark.asyncio
    async def test_handles_connection_error_during_wait(self):
        """Should handle connection errors while waiting."""
        mock_stub = MagicMock()
        
        # First call fails, second succeeds
        healthy_response = MagicMock()
        healthy_response.healthy = True
        
        mock_stub.Health = AsyncMock(side_effect=[
            ConnectionError("Not ready yet"),
            healthy_response,
        ])
        
        # wait_healthy returns None on success
        await wait_healthy(mock_stub, timeout=5.0, interval=0.01)
    
    @pytest.mark.asyncio
    async def test_default_timeout(self):
        """Should use default timeout if not specified."""
        mock_stub = MagicMock()
        mock_response = MagicMock()
        mock_response.healthy = True
        
        mock_stub.Health = AsyncMock(return_value=mock_response)
        
        # Should work with default timeout
        await wait_healthy(mock_stub)
    
    @pytest.mark.asyncio
    async def test_custom_interval(self):
        """Should use custom check interval."""
        mock_stub = MagicMock()
        
        # Track call timestamps to verify interval
        call_times = []
        
        async def track_calls(*args, **kwargs):
            call_times.append(asyncio.get_event_loop().time())
            response = MagicMock()
            response.healthy = len(call_times) >= 3
            return response
        
        mock_stub.Health = track_calls
        
        await wait_healthy(mock_stub, timeout=5.0, interval=0.05)
        
        # Verify interval between calls
        if len(call_times) >= 2:
            interval = call_times[1] - call_times[0]
            assert interval >= 0.04  # Allow some tolerance


class TestHealthCheckError:
    """Tests for HealthCheckError exception."""
    
    def test_error_message(self):
        """Error should have descriptive message."""
        error = HealthCheckError("Core not healthy after 10s")
        assert "healthy" in str(error).lower()
        assert "10" in str(error)
    
    def test_is_exception(self):
        """Should be a proper exception."""
        error = HealthCheckError("test")
        assert isinstance(error, Exception)
        
        with pytest.raises(HealthCheckError):
            raise error
    
    def test_with_cause(self):
        """Should support exception chaining."""
        cause = ConnectionError("Connection refused")
        error = HealthCheckError("Health check failed")
        error.__cause__ = cause
        
        assert error.__cause__ is cause


class TestHealthCheckIntegration:
    """Integration tests for health check flow."""
    
    @pytest.mark.asyncio
    async def test_full_health_check_flow(self):
        """Test complete health check and version compatibility flow."""
        mock_stub = MagicMock()
        
        # Health response with version info
        mock_response = MagicMock()
        mock_response.healthy = True
        mock_response.core_version = "2.5.0"
        mock_response.proto_version = "1.0"
        mock_response.version_compatible = True
        
        mock_stub.Health = AsyncMock(return_value=mock_response)
        
        # Check version first
        compat = await check_version_compatibility(mock_stub, MCP_VERSION)
        assert compat is True
        
        # Then wait for healthy (returns None)
        await wait_healthy(mock_stub, timeout=5.0)
    
    @pytest.mark.asyncio
    async def test_graceful_startup(self):
        """Test handling slow core startup."""
        mock_stub = MagicMock()
        
        call_count = 0
        
        async def slow_startup(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            
            response = MagicMock()
            # Simulate slow startup - healthy after 5 calls
            response.healthy = call_count >= 5
            response.core_version = "2.5.0"
            response.version_compatible = True
            return response
        
        mock_stub.Health = slow_startup
        
        # wait_healthy returns None on success
        await wait_healthy(mock_stub, timeout=5.0, interval=0.01)
        
        assert call_count >= 5
