# MCP SDK Integration

Use capiscio-mcp with the official MCP Python SDK.

## Installation

```bash
pip install capiscio-mcp[mcp]
```

## Server Integration

### CapiscioMCPServer

The `CapiscioMCPServer` wraps the MCP SDK server with automatic identity disclosure:

```python
from capiscio_mcp.integrations.mcp import CapiscioMCPServer

server = CapiscioMCPServer(
    name="filesystem",
    did="did:web:mcp.example.com:servers:filesystem",
    badge="eyJhbGc...",  # Server's trust badge
)

@server.tool(min_trust_level=2)
async def read_file(path: str) -> str:
    """Read a file (requires Trust Level 2+)."""
    with open(path) as f:
        return f.read()

@server.tool(min_trust_level=3)
async def write_file(path: str, content: str) -> None:
    """Write a file (requires Trust Level 3+)."""
    with open(path, "w") as f:
        f.write(content)

# Run the server
if __name__ == "__main__":
    server.run()
```

### Features

- **Automatic identity headers**: Adds `Capiscio-Server-DID` and `Capiscio-Server-Badge` to responses
- **Trust-level enforcement**: Uses `@guard` under the hood
- **Evidence logging**: All tool calls logged automatically

## Client Integration

### CapiscioMCPClient

The `CapiscioMCPClient` wraps the MCP SDK client with automatic server verification:

```python
from capiscio_mcp.integrations.mcp import CapiscioMCPClient

async with CapiscioMCPClient(
    server_url="https://mcp.example.com",
    min_trust_level=2,  # Require verified identity
    badge="eyJhbGc...",  # Your client badge
) as client:
    # Server identity already verified on connect
    print(f"Connected at trust level {client.server_trust_level}")
    
    result = await client.call_tool("read_file", {"path": "/data/file.txt"})
```

### Features

- **Automatic verification**: Verifies server identity on connection
- **Badge attachment**: Attaches your badge to tool calls
- **Error on untrusted**: Raises exception if server not verified

## Manual Integration

If you're using a custom MCP setup, use the core functions directly:

### Server Side

```python
from mcp.server import Server
from capiscio_mcp import guard

server = Server("my-server")

@server.tool()
@guard(min_trust_level=2)  # Apply guard to MCP tool
async def my_tool(param: str) -> str:
    return f"Result: {param}"
```

### Client Side

```python
from mcp.client import Client
from capiscio_mcp import verify_server, parse_http_headers

async def connect_and_verify(url: str):
    # Connect to MCP server
    async with Client(url) as client:
        # Get server info
        info = await client.get_server_info()
        
        # Parse identity from response headers
        identity = parse_http_headers(client.last_response_headers)
        
        if identity.has_identity:
            result = await verify_server(
                server_did=identity.server_did,
                server_badge=identity.server_badge,
                transport_origin=url,
            )
            
            if not result.is_verified:
                raise RuntimeError(f"Server not verified: {result.error_detail}")
        
        # Proceed with verified server
        return client
```

## Stdio Transport

For stdio-based MCP servers, identity is passed via JSON-RPC `_meta`:

```python
from capiscio_mcp import parse_jsonrpc_meta, verify_server

# Server adds identity to _meta
response = {
    "jsonrpc": "2.0",
    "id": 1,
    "result": {...},
    "_meta": {
        "serverDid": "did:web:example.com",
        "serverBadge": "eyJhbGc...",
    }
}

# Client extracts and verifies
identity = parse_jsonrpc_meta(response["_meta"])
result = await verify_server(
    server_did=identity.server_did,
    server_badge=identity.server_badge,
)
```
