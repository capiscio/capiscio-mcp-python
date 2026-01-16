"""
Placeholder for generated mcp_pb2_grpc.py.

This module will be replaced by actual protobuf-generated code from
proto/capiscio/v1/mcp.proto when capiscio-core v2.5.0 is released.

For now, we define stub classes that can be mocked in tests.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import grpc
    from capiscio_mcp._proto.capiscio.v1 import mcp_pb2


class MCPServiceStub:
    """
    Stub for MCPService gRPC client.
    
    This is a placeholder that will be replaced by actual generated code.
    The stub provides async methods for all MCP RPCs.
    """
    
    def __init__(self, channel: "grpc.aio.Channel") -> None:
        """
        Initialize stub with gRPC channel.
        
        Args:
            channel: Async gRPC channel
        """
        self._channel = channel
    
    async def EvaluateToolAccess(
        self,
        request: "mcp_pb2.EvaluateToolAccessRequest",
    ) -> "mcp_pb2.EvaluateToolAccessResponse":
        """
        Evaluate tool access (RFC-006).
        
        Single RPC returns decision + evidence atomically.
        """
        raise NotImplementedError("Stub - replace with generated code")
    
    async def VerifyServerIdentity(
        self,
        request: "mcp_pb2.VerifyServerIdentityRequest",
    ) -> "mcp_pb2.VerifyServerIdentityResponse":
        """
        Verify server identity (RFC-007).
        """
        raise NotImplementedError("Stub - replace with generated code")
    
    async def ParseServerIdentity(
        self,
        request: "mcp_pb2.ParseServerIdentityRequest",
    ) -> "mcp_pb2.ParseServerIdentityResponse":
        """
        Parse server identity from headers/meta.
        """
        raise NotImplementedError("Stub - replace with generated code")
    
    async def Health(
        self,
        request: "mcp_pb2.HealthRequest",
    ) -> "mcp_pb2.HealthResponse":
        """
        Health check for client supervision.
        """
        raise NotImplementedError("Stub - replace with generated code")


class MCPServiceServicer:
    """
    Servicer base class for MCPService gRPC server.
    
    This is a placeholder that will be replaced by actual generated code.
    """
    
    async def EvaluateToolAccess(
        self,
        request: "mcp_pb2.EvaluateToolAccessRequest",
        context: "grpc.aio.ServicerContext",
    ) -> "mcp_pb2.EvaluateToolAccessResponse":
        """Evaluate tool access (RFC-006)."""
        raise NotImplementedError("Method not implemented!")
    
    async def VerifyServerIdentity(
        self,
        request: "mcp_pb2.VerifyServerIdentityRequest",
        context: "grpc.aio.ServicerContext",
    ) -> "mcp_pb2.VerifyServerIdentityResponse":
        """Verify server identity (RFC-007)."""
        raise NotImplementedError("Method not implemented!")
    
    async def ParseServerIdentity(
        self,
        request: "mcp_pb2.ParseServerIdentityRequest",
        context: "grpc.aio.ServicerContext",
    ) -> "mcp_pb2.ParseServerIdentityResponse":
        """Parse server identity from headers/meta."""
        raise NotImplementedError("Method not implemented!")
    
    async def Health(
        self,
        request: "mcp_pb2.HealthRequest",
        context: "grpc.aio.ServicerContext",
    ) -> "mcp_pb2.HealthResponse":
        """Health check."""
        raise NotImplementedError("Method not implemented!")


def add_MCPServiceServicer_to_server(
    servicer: MCPServiceServicer,
    server: "grpc.aio.Server",
) -> None:
    """Add MCPServiceServicer to a gRPC server."""
    raise NotImplementedError("Stub - replace with generated code")
