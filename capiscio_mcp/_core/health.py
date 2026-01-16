"""
Health check and version compatibility for capiscio-core connection.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from capiscio_mcp._core.version import is_core_compatible, PROTO_VERSION
from capiscio_mcp.errors import CoreConnectionError, CoreVersionError

if TYPE_CHECKING:
    from typing import Any

logger = logging.getLogger(__name__)


# Alias for backward compatibility
HealthCheckError = CoreConnectionError


async def check_version_compatibility(
    stub: "Any",
    client_version: str,
) -> bool:
    """
    Check if the connected capiscio-core is compatible with this SDK.
    
    Performs a Health RPC call and validates version compatibility.
    
    Args:
        stub: MCPService gRPC stub
        client_version: This SDK's version string
        
    Returns:
        True if compatible
        
    Raises:
        CoreVersionError: If versions are incompatible
    """
    try:
        # Import proto here to avoid circular imports
        from capiscio_mcp._proto.capiscio.v1 import mcp_pb2
        
        request = mcp_pb2.HealthRequest(client_version=client_version)
        response = await stub.Health(request)
        
        if not response.healthy:
            raise CoreConnectionError("capiscio-core reported unhealthy status")
        
        # Check core version compatibility
        if not is_core_compatible(response.core_version):
            raise CoreVersionError(
                f"capiscio-core version {response.core_version} is not compatible. "
                f"This SDK requires core version >= 2.5.0 and < 3.0.0"
            )
        
        # Check proto version
        if response.proto_version != PROTO_VERSION:
            logger.warning(
                f"Proto version mismatch: core={response.proto_version}, "
                f"sdk={PROTO_VERSION}. This may cause issues."
            )
        
        # Check bidirectional compatibility
        if not response.version_compatible:
            raise CoreVersionError(
                f"capiscio-core reports this SDK version ({client_version}) "
                "is not compatible"
            )
        
        logger.debug(
            f"Version check passed: core={response.core_version}, "
            f"proto={response.proto_version}"
        )
        return True
        
    except CoreVersionError:
        raise
    except Exception as e:
        raise CoreConnectionError(f"Health check failed: {e}") from e


async def wait_healthy(
    stub: "Any",
    timeout: float = 10.0,
    interval: float = 0.5,
) -> None:
    """
    Wait for capiscio-core to become healthy.
    
    Polls the Health RPC until successful or timeout.
    
    Args:
        stub: MCPService gRPC stub
        timeout: Maximum time to wait in seconds
        interval: Time between health checks in seconds
        
    Raises:
        CoreConnectionError: If timeout expires before core becomes healthy
    """
    from capiscio_mcp._proto.capiscio.v1 import mcp_pb2
    
    start_time = asyncio.get_event_loop().time()
    last_error = None
    
    while (asyncio.get_event_loop().time() - start_time) < timeout:
        try:
            request = mcp_pb2.HealthRequest(client_version="")
            response = await asyncio.wait_for(
                stub.Health(request),
                timeout=interval,
            )
            
            if response.healthy:
                logger.debug("capiscio-core is healthy")
                return
            
            last_error = "Core reported unhealthy"
            
        except asyncio.TimeoutError:
            last_error = "Health check timed out"
        except Exception as e:
            last_error = str(e)
        
        await asyncio.sleep(interval)
    
    raise CoreConnectionError(
        f"capiscio-core did not become healthy within {timeout}s. "
        f"Last error: {last_error}"
    )
