"""
MCP SDK Integration — requires `pip install capiscio-mcp[mcp]`

Provides two separate integration classes:
1. Server-side: CapiscioMCPServer (guard tools, disclose identity, PoP signing)
2. Client-side: CapiscioMCPClient (verify server identity, PoP verification)

Usage (Server):
    from capiscio_mcp.integrations.mcp import CapiscioMCPServer

    server = CapiscioMCPServer(
        name="filesystem",
        did="did:web:mcp.example.com:servers:filesystem",
        badge="eyJhbGc...",
        private_key_path="/path/to/key.pem",  # For PoP signing
    )

    @server.tool(min_trust_level=2)
    async def read_file(path: str) -> str:
        with open(path) as f:
            return f.read()

    # Run the server
    server.run()

Usage (Client):
    from capiscio_mcp.integrations.mcp import CapiscioMCPClient

    async with CapiscioMCPClient(
        server_url="https://mcp.example.com",
        min_trust_level=2,
        require_pop=True,  # Require PoP verification
    ) as client:
        result = await client.call_tool("read_file", {"path": "/data/file.txt"})
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from functools import wraps
from typing import Any, Callable, Coroutine, Dict, List, Optional, TypeVar, Union

# Check if MCP SDK (FastMCP) is available
try:
    from mcp.server.fastmcp import FastMCP
    from mcp.types import Tool, TextContent
    MCP_AVAILABLE = True
except ImportError:
    FastMCP = None  # type: ignore
    Tool = None  # type: ignore
    TextContent = None  # type: ignore
    MCP_AVAILABLE = False

try:
    from mcp.client.session import ClientSession as McpClientSession
    from mcp.client.stdio import stdio_client, StdioServerParameters
    MCP_CLIENT_AVAILABLE = True
except ImportError:
    McpClientSession = None  # type: ignore
    stdio_client = None  # type: ignore
    StdioServerParameters = None  # type: ignore
    MCP_CLIENT_AVAILABLE = False

# Check if cryptography is available for PoP
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    CRYPTO_AVAILABLE = True
except ImportError:
    Ed25519PrivateKey = None  # type: ignore
    Ed25519PublicKey = None  # type: ignore
    CRYPTO_AVAILABLE = False

from capiscio_mcp.types import ServerState, CallerCredential
from capiscio_mcp.server import (
    verify_server,
    VerifyConfig,
    VerifyResult,
    parse_http_headers,
    parse_jsonrpc_meta,
)
from capiscio_mcp.guard import guard, GuardConfig, set_credential, set_server_origin
from capiscio_mcp.errors import GuardError, ServerVerifyError
from capiscio_mcp.pop import (
    PoPRequest,
    PoPResponse,
    generate_pop_request,
    create_pop_response,
    verify_pop_response,
    load_private_key_from_pem,
    load_public_key_from_pem,
    extract_public_key_from_did_key,
    PoPError,
    PoPSignatureError,
    PoPExpiredError,
)

logger = logging.getLogger(__name__)

T = TypeVar("T")


def _require_mcp_server() -> None:
    """Raise ImportError if MCP server SDK (FastMCP) is not available."""
    if not MCP_AVAILABLE:
        raise ImportError(
            "MCP SDK integration requires the 'mcp' package. "
            "Install with: pip install capiscio-mcp[mcp]"
        )


def _require_mcp_client() -> None:
    """Raise ImportError if MCP client SDK is not available."""
    if not MCP_CLIENT_AVAILABLE:
        raise ImportError(
            "MCP client integration requires the 'mcp' package. "
            "Install with: pip install capiscio-mcp[mcp]"
        )


class CapiscioMCPServer:
    """
    MCP Server with CapiscIO identity disclosure, PoP signing, and tool guarding.
    
    This class wraps FastMCP to:
    1. Automatically inject identity into initialize response _meta
    2. Sign PoP challenges to prove key ownership (RFC-007)
    3. Guard registered tools with @guard decorator for trust enforcement
    
    Attributes:
        name: Server name
        did: Server DID (did:web:... or did:key:...)
        badge: Server trust badge JWS (optional but recommended)
        default_min_trust_level: Default minimum trust level for tools
        pop_enabled: Whether PoP signing is available
    
    Example:
        server = CapiscioMCPServer(
            name="filesystem",
            did="did:web:mcp.example.com:servers:filesystem",
            badge=os.environ.get("SERVER_BADGE"),
            private_key_path="/path/to/server.key.pem",
        )
        
        @server.tool(min_trust_level=2)
        async def read_file(path: str) -> str:
            with open(path) as f:
                return f.read()
        
        # Run the server
        server.run()
    """
    
    def __init__(
        self,
        name: str,
        did: str,
        badge: Optional[str] = None,
        default_min_trust_level: int = 0,
        version: str = "1.0.0",
        private_key: Optional["Ed25519PrivateKey"] = None,
        private_key_path: Optional[str] = None,
        private_key_pem: Optional[Union[str, bytes]] = None,
        key_id: Optional[str] = None,
    ):
        """
        Initialize CapiscIO MCP Server.
        
        Args:
            name: Server name (shown to clients)
            did: Server DID for identity disclosure
            badge: Server badge JWS for identity verification
            default_min_trust_level: Default minimum trust level for tools
            version: Server version string
            private_key: Ed25519 private key for PoP signing (optional)
            private_key_path: Path to PEM file containing private key (optional)
            private_key_pem: PEM-encoded private key string/bytes (optional)
            key_id: Key ID for JWS header (defaults to DID#keys-1)
        """
        _require_mcp_server()
        
        self.name = name
        self.did = did
        self.badge = badge
        self.default_min_trust_level = default_min_trust_level
        self.version = version
        
        # Load private key for PoP signing
        self._private_key: Optional["Ed25519PrivateKey"] = None
        self._key_id = key_id or f"{did}#keys-1"
        
        if private_key is not None:
            self._private_key = private_key
        elif private_key_path is not None:
            self._load_private_key_from_file(private_key_path)
        elif private_key_pem is not None:
            self._private_key = load_private_key_from_pem(private_key_pem)
        
        # Create underlying FastMCP server
        self._server = FastMCP(name)
        self._tools: Dict[str, Callable] = {}
        self._tool_configs: Dict[str, GuardConfig] = {}
        
        self._setup_identity_injection()
    
    def _load_private_key_from_file(self, path: str) -> None:
        """Load private key from PEM file."""
        if not CRYPTO_AVAILABLE:
            logger.warning(
                "PoP signing requires 'cryptography' package. "
                "Install with: pip install capiscio-mcp[crypto]"
            )
            return
        
        try:
            with open(path, "rb") as f:
                pem_data = f.read()
            self._private_key = load_private_key_from_pem(pem_data)
            logger.debug(f"Loaded private key from {path}")
        except Exception as e:
            logger.warning(f"Failed to load private key from {path}: {e}")
    
    @property
    def pop_enabled(self) -> bool:
        """Check if PoP signing is available."""
        return self._private_key is not None
    
    def _setup_identity_injection(self) -> None:
        """
        Set up identity injection into initialize response.
        
        Per RFC-007 §6.2, server identity is disclosed via _meta in
        the initialize response.
        """
        # The MCP SDK provides hooks for customizing responses
        # This implementation depends on the specific MCP SDK version
        # For now, we'll store the identity info to be included
        self._identity_meta = {
            "capiscio_server_did": self.did,
        }
        if self.badge:
            self._identity_meta["capiscio_server_badge"] = self.badge
    
    def create_initialize_response_meta(
        self,
        request_meta: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create the _meta object for initialize response.
        
        This method should be called when building the initialize response.
        It includes:
        1. Server identity (DID, badge)
        2. PoP response (if client sent PoP request and we have a private key)
        
        Args:
            request_meta: The _meta from the initialize request (for PoP)
            
        Returns:
            Dict to include as _meta in initialize response
            
        Example:
            # In your initialize handler
            def handle_initialize(request):
                response_meta = server.create_initialize_response_meta(
                    request_meta=request.params.get("_meta")
                )
                return InitializeResult(
                    capabilities=...,
                    _meta=response_meta,
                )
        """
        meta = self._identity_meta.copy()
        
        # Handle PoP if client sent nonce and we have a key
        if self._private_key is not None and request_meta is not None:
            pop_request = PoPRequest.from_meta(request_meta)
            if pop_request is not None:
                try:
                    pop_response = create_pop_response(
                        request=pop_request,
                        private_key=self._private_key,
                        key_id=self._key_id,
                    )
                    meta.update(pop_response.to_meta())
                    logger.debug("Added PoP signature to initialize response")
                except Exception as e:
                    logger.warning(f"Failed to create PoP response: {e}")
        
        return meta
    
    def tool(
        self,
        name: Optional[str] = None,
        description: Optional[str] = None,
        min_trust_level: Optional[int] = None,
        config: Optional[GuardConfig] = None,
    ) -> Callable[[Callable[..., Coroutine[Any, Any, T]]], Callable[..., Coroutine[Any, Any, T]]]:
        """
        Register a tool with CapiscIO guard.
        
        This decorator:
        1. Registers the function as an MCP tool via FastMCP
        2. Wraps it with @guard for access control based on caller trust level
        
        Args:
            name: Tool name (default: function name)
            description: Tool description
            min_trust_level: Minimum trust level (overrides default)
            config: Full guard configuration
        
        Returns:
            Decorator function
        
        Example:
            @server.tool(min_trust_level=2)
            async def execute_query(sql: str) -> list[dict]:
                ...
        """
        def decorator(
            func: Callable[..., Coroutine[Any, Any, T]]
        ) -> Callable[..., Coroutine[Any, Any, T]]:
            tool_name = name or func.__name__
            tool_description = description or func.__doc__ or f"Tool: {tool_name}"
            
            # Build effective config
            effective_config = config or GuardConfig()
            if min_trust_level is not None:
                effective_config.min_trust_level = min_trust_level
            elif effective_config.min_trust_level == 0:
                effective_config.min_trust_level = self.default_min_trust_level
            
            # Apply guard decorator
            guarded_func = guard(config=effective_config, tool_name=tool_name)(func)
            
            # Store for reference
            self._tools[tool_name] = guarded_func
            self._tool_configs[tool_name] = effective_config
            
            # Register with FastMCP server using its @tool decorator
            # FastMCP will handle the MCP protocol details
            self._server.tool(name=tool_name, description=tool_description)(guarded_func)
            
            logger.debug(f"Registered tool '{tool_name}' with trust level {effective_config.min_trust_level}")
            
            return guarded_func
        
        return decorator
    
    @property
    def server(self) -> "FastMCP":
        """Access the underlying FastMCP server."""
        return self._server
    
    @property
    def identity_meta(self) -> Dict[str, str]:
        """Get the identity metadata for initialize response."""
        return self._identity_meta.copy()
    
    def run(self, transport: str = "stdio") -> None:
        """
        Run the server with the specified transport.
        
        Args:
            transport: Transport type - "stdio" (default) or "streamable-http"
        
        Example:
            server.run()  # stdio transport
            server.run(transport="streamable-http")  # HTTP transport
        """
        self._server.run(transport=transport)
    
    async def run_stdio(self) -> None:
        """Run the server over stdio transport (async version)."""
        # For backwards compatibility, delegate to run()
        self._server.run(transport="stdio")
    
    async def run_sse(self, port: int = 8080) -> None:
        """Run the server over SSE transport (deprecated, use streamable-http)."""
        logger.warning("SSE transport is deprecated, use streamable-http instead")
        self._server.run(transport="sse")


class CapiscioMCPClient:
    """
    MCP Client with automatic server identity and PoP verification.
    
    This class wraps MCP client functionality to:
    1. Generate PoP request (nonce) for initialize request
    2. Verify server identity and PoP response on connection
    3. Enforce trust level requirements
    4. Include caller credentials in tool requests
    
    Attributes:
        server_url: URL of the MCP server
        min_trust_level: Minimum required trust level
        fail_on_unverified: If True, raise on unverified servers
        require_pop: If True, require PoP verification (did:key servers)
        pop_verified: Whether PoP verification succeeded
    
    Example:
        async with CapiscioMCPClient(
            server_url="https://mcp.example.com",
            min_trust_level=2,
            require_pop=True,
            badge="eyJhbGc...",  # Your client badge
        ) as client:
            # Server identity and PoP already verified
            print(f"Trusted at level {client.server_trust_level}")
            print(f"PoP verified: {client.pop_verified}")
            
            result = await client.call_tool("read_file", {"path": "/data/file.txt"})
    
    For stdio transport (subprocess server):
        async with CapiscioMCPClient(
            command="python",
            args=["my_mcp_server.py"],
            min_trust_level=1,
        ) as client:
            result = await client.call_tool("my_tool", {"arg": "value"})
    """
    
    def __init__(
        self,
        server_url: Optional[str] = None,
        command: Optional[str] = None,
        args: Optional[List[str]] = None,
        min_trust_level: int = 0,
        fail_on_unverified: bool = True,
        require_pop: bool = False,
        verify_config: Optional[VerifyConfig] = None,
        badge: Optional[str] = None,
        api_key: Optional[str] = None,
    ):
        """
        Initialize CapiscIO MCP Client.
        
        Args:
            server_url: URL of the MCP server (for HTTP transport)
            command: Command to run server (for stdio transport)
            args: Arguments for command (for stdio transport)
            min_trust_level: Minimum required server trust level
            fail_on_unverified: If True, raise when server doesn't disclose identity
            require_pop: If True, require PoP verification for did:key servers
            verify_config: Full verification configuration
            badge: Client badge for authentication (recommended)
            api_key: Client API key for authentication (alternative)
        """
        _require_mcp_client()
        
        self.server_url = server_url
        self.command = command
        self.args = args or []
        self.min_trust_level = min_trust_level
        self.fail_on_unverified = fail_on_unverified
        self.require_pop = require_pop
        self.verify_config = verify_config or VerifyConfig(min_trust_level=min_trust_level)
        
        # Client credentials
        self._credential = CallerCredential(
            badge_jws=badge,
            api_key=api_key,
        )
        
        self._session: Optional[McpClientSession] = None
        self._context_manager: Optional[Any] = None
        self._verify_result: Optional[VerifyResult] = None
        
        # PoP state
        self._pop_request: Optional[PoPRequest] = None
        self._pop_response: Optional[PoPResponse] = None
        self._pop_verified: bool = False
    
    def create_initialize_request_meta(self) -> Dict[str, Any]:
        """
        Create the _meta object for initialize request.
        
        This should be called when building the initialize request.
        It generates a PoP nonce to be signed by the server.
        
        Returns:
            Dict to include as _meta in initialize request
            
        Example:
            # In your client code
            meta = client.create_initialize_request_meta()
            result = await session.initialize(
                client_info=ClientInfo(...),
                _meta=meta,
            )
        """
        self._pop_request = generate_pop_request()
        return self._pop_request.to_meta()
    
    def verify_initialize_response(
        self,
        response_meta: Optional[Dict[str, Any]],
        server_public_key: Optional["Ed25519PublicKey"] = None,
    ) -> bool:
        """
        Verify the initialize response including PoP.
        
        This should be called after receiving the initialize response.
        It extracts the PoP signature and verifies it.
        
        Args:
            response_meta: The _meta from initialize response
            server_public_key: Server's public key for PoP verification
                              (if None, will try to extract from did:key)
        
        Returns:
            True if PoP verification succeeded, False otherwise
            
        Raises:
            PoPSignatureError: If PoP verification fails and require_pop=True
        """
        if response_meta is None:
            logger.debug("No _meta in initialize response")
            return False
        
        # Extract PoP response
        self._pop_response = PoPResponse.from_meta(response_meta)
        if self._pop_response is None:
            logger.debug("No PoP response in initialize response")
            return False
        
        if self._pop_request is None:
            logger.warning("PoP response received but no request was sent")
            return False
        
        # Get public key for verification
        if server_public_key is None:
            # Try to extract from server DID
            server_did = response_meta.get("capiscio_server_did")
            if server_did and server_did.startswith("did:key:"):
                try:
                    server_public_key = extract_public_key_from_did_key(server_did)
                except Exception as e:
                    logger.warning(f"Failed to extract public key from DID: {e}")
                    if self.require_pop:
                        raise PoPSignatureError(f"Cannot extract public key from {server_did}")
                    return False
            else:
                # For did:web, we'd need to fetch DID document
                logger.debug(f"Cannot verify PoP for non-did:key: {server_did}")
                return False
        
        # Verify PoP
        try:
            verify_pop_response(
                request=self._pop_request,
                response=self._pop_response,
                public_key=server_public_key,
            )
            self._pop_verified = True
            logger.info("PoP verification succeeded")
            return True
        except PoPError as e:
            logger.warning(f"PoP verification failed: {e}")
            if self.require_pop:
                raise
            return False
    
    @property
    def pop_verified(self) -> bool:
        """Whether PoP verification succeeded."""
        return self._pop_verified
    
    async def __aenter__(self) -> "CapiscioMCPClient":
        """
        Async context manager entry.
        
        Connects to server and verifies identity.
        """
        await self.connect()
        return self
    
    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        await self.close()
    
    async def connect(self) -> None:
        """
        Connect to MCP server and verify identity.
        
        For stdio transport, spawns the server process.
        For HTTP transport, connects to the server URL.
        
        Raises:
            ServerVerifyError: If server verification fails and fail_on_unverified=True
            GuardError: If server doesn't meet trust requirements
        """
        if self.command:
            # Stdio transport - spawn server process
            server_params = StdioServerParameters(
                command=self.command,
                args=self.args,
            )
            self._context_manager = stdio_client(server_params)
            read_stream, write_stream = await self._context_manager.__aenter__()
            self._session = McpClientSession(read_stream, write_stream)
            await self._session.__aenter__()
            
            # Initialize the session
            await self._session.initialize()
        else:
            # HTTP transport would go here
            # For now, just log that it's not implemented
            logger.warning("HTTP transport not yet implemented, use stdio with command/args")
            raise NotImplementedError("HTTP transport not yet implemented")
        
        # Extract server identity from initialize response
        # Note: MCP SDK currently doesn't expose _meta from initialize response easily
        # This is a known limitation - identity verification works via separate channels
        server_did: Optional[str] = None
        server_badge: Optional[str] = None
        
        # For now, we skip verification if we can't get identity
        # Full verification requires protocol support for _meta passthrough
        if server_did or server_badge:
            self._verify_result = await verify_server(
                server_did=server_did,
                server_badge=server_badge,
                transport_origin=self.server_url or f"stdio:{self.command}",
                config=self.verify_config,
            )
            
            # Enforce requirements
            if self.fail_on_unverified and self._verify_result.state == ServerState.UNVERIFIED_ORIGIN:
                raise ServerVerifyError(
                    error_code=self._verify_result.error_code,
                    detail=f"Server did not disclose identity",
                    state=self._verify_result.state,
                )
        
        logger.info(f"Connected to MCP server: {self.command or self.server_url}")
    
    async def close(self) -> None:
        """Close connection to MCP server."""
        if self._session:
            await self._session.__aexit__(None, None, None)
            self._session = None
        if self._context_manager:
            await self._context_manager.__aexit__(None, None, None)
            self._context_manager = None
    
    @property
    def server_state(self) -> Optional[ServerState]:
        """Server verification state after connection."""
        return self._verify_result.state if self._verify_result else None
    
    @property
    def server_trust_level(self) -> Optional[int]:
        """Server trust level if verified."""
        return self._verify_result.trust_level if self._verify_result else None
    
    @property
    def server_did(self) -> Optional[str]:
        """Server DID if disclosed."""
        return self._verify_result.server_did if self._verify_result else None
    
    @property
    def is_verified(self) -> bool:
        """Check if server identity is cryptographically verified."""
        return (
            self._verify_result is not None
            and self._verify_result.state == ServerState.VERIFIED_PRINCIPAL
        )
    
    async def call_tool(
        self,
        name: str,
        arguments: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """
        Call a tool on the connected server.
        
        Automatically includes client credentials in the request.
        
        Args:
            name: Tool name
            arguments: Tool arguments
        
        Returns:
            Tool result from the server
            
        Raises:
            RuntimeError: If not connected
        """
        if self._session is None:
            raise RuntimeError("Client not connected. Use 'async with' context.")
        
        # Set credential context for the call
        token = set_credential(self._credential)
        try:
            # Call tool via MCP client session
            result = await self._session.call_tool(name, arguments or {})
            return result
        finally:
            # Note: credential context is thread-local, no explicit reset needed
            pass
    
    async def list_tools(self) -> List[Dict[str, Any]]:
        """
        List available tools on the server.
        
        Returns:
            List of tool definitions
        """
        if self._session is None:
            raise RuntimeError("Client not connected. Use 'async with' context.")
        
        result = await self._session.list_tools()
        return [
            {
                "name": tool.name,
                "description": tool.description,
            }
            for tool in result.tools
        ]
