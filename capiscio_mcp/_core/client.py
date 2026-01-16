"""
gRPC client for capiscio-core MCPService.

Supports two connection modes:
- Embedded: Auto-downloads binary, starts locally, connects localhost
- External: Connects to user-provided CAPISCIO_CORE_ADDR

Usage:
    # Singleton pattern (recommended)
    client = await CoreClient.get_instance()
    response = await client.stub.EvaluateToolAccess(request)
    
    # Manual lifecycle
    client = CoreClient()
    await client.connect()
    # ... use client ...
    await client.close()
"""

from __future__ import annotations

import asyncio
import logging
import os
import socket
from pathlib import Path
from typing import Optional, TYPE_CHECKING

import grpc

from capiscio_mcp._core.version import MCP_VERSION
from capiscio_mcp._core.lifecycle import (
    ensure_binary,
    ProcessSupervisor,
)
from capiscio_mcp._core.health import wait_healthy, check_version_compatibility
from capiscio_mcp.errors import CoreConnectionError

if TYPE_CHECKING:
    from capiscio_mcp._proto.capiscio.v1 import mcp_pb2_grpc

logger = logging.getLogger(__name__)


def _get_running_loop_id() -> int:
    """Get the ID of the currently running event loop, or 0 if none."""
    try:
        loop = asyncio.get_running_loop()
        return id(loop)
    except RuntimeError:
        return 0


class CoreClient:
    """
    Async gRPC client to capiscio-core MCPService.
    
    Supports two modes:
    - Embedded: Auto-downloads binary, starts locally, connects localhost
    - External: Connects to user-provided CAPISCIO_CORE_ADDR
    
    The singleton pattern is event-loop aware: each event loop gets its own
    client instance. This ensures gRPC channels aren't shared across loops.
    
    Attributes:
        stub: The MCPService gRPC stub for making RPC calls
    """
    
    # Per-loop instances: {loop_id: CoreClient}
    _instances: dict[int, "CoreClient"] = {}
    _lock: Optional[asyncio.Lock] = None
    
    def __init__(self) -> None:
        """Initialize the client (not connected yet)."""
        self._channel: Optional[grpc.aio.Channel] = None
        self._stub: Optional["mcp_pb2_grpc.MCPServiceStub"] = None
        self._supervisor: Optional[ProcessSupervisor] = None
        self._port: Optional[int] = None
        self._connected = False
        self._loop_id: int = 0
    
    @classmethod
    def _get_lock(cls) -> asyncio.Lock:
        """Get or create the lock for the current event loop."""
        # Create lock lazily in the current event loop
        if cls._lock is None:
            cls._lock = asyncio.Lock()
        return cls._lock
    
    @classmethod
    async def get_instance(cls) -> "CoreClient":
        """
        Get or create the singleton client instance for the current event loop.
        
        Each event loop gets its own client instance. This prevents issues
        with gRPC channels being used across different event loops.
        
        Returns:
            Connected CoreClient instance
        """
        loop_id = _get_running_loop_id()
        
        async with cls._get_lock():
            # Check if we have a valid instance for this loop
            instance = cls._instances.get(loop_id)
            
            if instance is None or not instance._connected:
                # Create new instance for this loop
                instance = CoreClient()
                instance._loop_id = loop_id
                await instance.connect()
                cls._instances[loop_id] = instance
            
            return instance
    
    @classmethod
    async def reset(cls) -> None:
        """
        Reset the client instance for the current event loop.
        
        Call this to clean up resources. Safe to call multiple times.
        """
        loop_id = _get_running_loop_id()
        
        try:
            async with cls._get_lock():
                instance = cls._instances.pop(loop_id, None)
                if instance is not None:
                    await instance.close()
        except RuntimeError:
            # Lock may be invalid if loop is closing
            pass
    
    @classmethod
    async def reset_all(cls) -> None:
        """
        Reset all client instances (for testing/cleanup).
        """
        for loop_id, instance in list(cls._instances.items()):
            try:
                await instance.close()
            except Exception:
                pass
        cls._instances.clear()
        cls._lock = None
    
    # Backward compatibility alias
    @classmethod
    async def reset_instance(cls) -> None:
        """
        Reset the singleton instance (for testing).
        
        DEPRECATED: Use reset() instead.
        """
        await cls.reset()
    
    # Backward compatibility property for tests that directly set _instance
    @property
    def _instance(self) -> Optional["CoreClient"]:
        """Backward compatibility: get current loop's instance."""
        loop_id = _get_running_loop_id()
        return self._instances.get(loop_id)
    
    @_instance.setter
    def _instance(self, value: Optional["CoreClient"]) -> None:
        """Backward compatibility: set/clear current loop's instance."""
        loop_id = _get_running_loop_id() or id(asyncio.new_event_loop())
        if value is None:
            self._instances.pop(loop_id, None)
        else:
            self._instances[loop_id] = value
    
    async def connect(self, timeout: float = 30.0) -> None:
        """
        Connect to capiscio-core (embedded or external mode).
        
        Mode is determined by CAPISCIO_CORE_ADDR environment variable:
        - If set: External mode, connect to specified address
        - If not set: Embedded mode, download binary and start locally
        
        Args:
            timeout: Connection timeout in seconds
            
        Raises:
            CoreConnectionError: If connection fails
        """
        if self._connected:
            return
        
        addr = os.environ.get("CAPISCIO_CORE_ADDR")
        
        if addr:
            # External mode: user manages core process
            logger.info(f"Connecting to external capiscio-core at {addr}")
            self._channel = grpc.aio.insecure_channel(addr)
        else:
            # Embedded mode: download binary and start locally
            logger.info("Starting embedded capiscio-core")
            binary = await ensure_binary()
            self._port = await self._find_free_port()
            
            self._supervisor = ProcessSupervisor(binary, self._port)
            await self._supervisor.start()
            
            self._channel = grpc.aio.insecure_channel(f"localhost:{self._port}")
        
        # Import and create stub
        from capiscio_mcp._proto.capiscio.v1 import mcp_pb2_grpc
        self._stub = mcp_pb2_grpc.MCPServiceStub(self._channel)
        
        # Wait for healthy and check version
        try:
            await wait_healthy(self._stub, timeout=timeout)
            await check_version_compatibility(self._stub, MCP_VERSION)
        except Exception as e:
            await self.close()
            raise CoreConnectionError(f"Failed to connect to capiscio-core: {e}") from e
        
        self._connected = True
        logger.info("Successfully connected to capiscio-core")
    
    async def close(self) -> None:
        """Close connection and terminate embedded core if running."""
        self._connected = False
        
        if self._channel:
            await self._channel.close()
            self._channel = None
        
        if self._supervisor:
            await self._supervisor.stop()
            self._supervisor = None
        
        self._stub = None
        logger.debug("CoreClient closed")
    
    async def _find_free_port(self) -> int:
        """Find an available port for embedded core."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("", 0))
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            return s.getsockname()[1]
    
    @property
    def stub(self) -> "mcp_pb2_grpc.MCPServiceStub":
        """
        Get the gRPC stub for MCPService.
        
        Raises:
            CoreConnectionError: If not connected
        """
        if self._stub is None:
            raise CoreConnectionError(
                "CoreClient not connected. Call connect() first or use get_instance()."
            )
        return self._stub
    
    @property
    def is_connected(self) -> bool:
        """Check if client is connected."""
        return self._connected
    
    async def __aenter__(self) -> "CoreClient":
        """Async context manager entry."""
        await self.connect()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self.close()
