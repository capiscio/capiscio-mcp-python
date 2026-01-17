````markdown
# Server Identity Registration

This guide covers setting up a verifiable identity for your MCP server.

## Why Server Identity?

MCP servers expose powerful tools—file systems, databases, APIs. But how do clients know they're connecting to the **real** server and not an imposter?

Server identity registration solves this by:

- **Generating a keypair** for cryptographic signing
- **Creating a DID** (Decentralized Identifier) for the server
- **Registering with the CapiscIO Registry** for discoverability

## Quick Start

```python
from capiscio_mcp import setup_server_identity

# One-step setup: generate keys + register with registry
result = await setup_server_identity(
    server_id="550e8400-e29b-41d4-a716-446655440000",  # From dashboard
    api_key="sk_live_...",  # Registry API key
    output_dir="./keys",
)

print(f"Server DID: {result['did']}")
# did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
```

## Prerequisites

1. **Create your MCP server in the CapiscIO Dashboard**
   - Go to [dashboard.capisc.io](https://dashboard.capisc.io)
   - Navigate to Servers → Create Server
   - Copy the server UUID

2. **Get an API key**
   - In the dashboard, go to Settings → API Keys
   - Create a key with `servers:write` permission

3. **capiscio-core must be running**
   - Either embedded (auto-downloaded) or external

## Step-by-Step Registration

### Step 1: Generate Keypair

Generate an Ed25519 keypair for your server:

```python
from capiscio_mcp import generate_server_keypair

keys = await generate_server_keypair(output_dir="./keys")

print(f"DID: {keys['did_key']}")
print(f"Private key: {keys['private_key_path']}")
```

Returns:

| Key | Description |
|-----|-------------|
| `key_id` | Unique key identifier |
| `did_key` | The derived `did:key:z6Mk...` URI |
| `public_key_pem` | PEM-encoded public key |
| `private_key_pem` | PEM-encoded private key |
| `private_key_path` | Path to saved key file (if `output_dir` provided) |

### Step 2: Register with Registry

Register the DID with the CapiscIO registry:

```python
from capiscio_mcp import register_server_identity

await register_server_identity(
    server_id="550e8400-e29b-41d4-a716-446655440000",
    api_key="sk_live_...",
    did=keys["did_key"],
    public_key=keys["public_key_pem"],
)
```

### Combined: setup_server_identity

For convenience, use the combined function:

```python
from capiscio_mcp import setup_server_identity

result = await setup_server_identity(
    server_id="550e8400-e29b-41d4-a716-446655440000",
    api_key="sk_live_...",
    output_dir="./keys",
)

# Returns everything you need
print(f"DID: {result['did']}")
print(f"Private key: {result['private_key_path']}")
```

## Synchronous API

All functions have sync wrappers:

```python
from capiscio_mcp import (
    generate_server_keypair_sync,
    register_server_identity_sync,
    setup_server_identity_sync,
)

# Sync version
result = setup_server_identity_sync(
    server_id="550e8400-e29b-41d4-a716-446655440000",
    api_key="sk_live_...",
    output_dir="./keys",
)
```

## Using the Identity

After registration, use the DID and private key for server identity disclosure:

### With CapiscioMCPServer

```python
from capiscio_mcp.integrations.mcp import CapiscioMCPServer

server = CapiscioMCPServer(
    name="filesystem",
    did=result["did"],
    private_key_path=result["private_key_path"],
)

@server.tool(min_trust_level=2)
async def read_file(path: str) -> str:
    """Server identity is automatically disclosed."""
    with open(path) as f:
        return f.read()
```

### Manual Disclosure

Add identity headers to responses:

```python
from fastapi import FastAPI, Response

app = FastAPI()

@app.middleware("http")
async def add_server_identity(request, call_next):
    response = await call_next(request)
    response.headers["Capiscio-Server-DID"] = SERVER_DID
    response.headers["Capiscio-Server-Badge"] = SERVER_BADGE
    return response
```

## Error Handling

```python
from capiscio_mcp import (
    setup_server_identity,
    RegistrationError,
    KeyGenerationError,
)
from capiscio_mcp.errors import CoreConnectionError

try:
    result = await setup_server_identity(
        server_id="550e8400-e29b-41d4-a716-446655440000",
        api_key="sk_live_...",
    )
except CoreConnectionError as e:
    print("Could not connect to capiscio-core")
    print("Ensure it's running: capiscio mcp serve")
except KeyGenerationError as e:
    print(f"Key generation failed: {e}")
except RegistrationError as e:
    print(f"Registration failed: {e}")
    if e.status_code == 401:
        print("Invalid API key")
    elif e.status_code == 404:
        print("Server not found - create it in the dashboard first")
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `CAPISCIO_CORE_ADDR` | External core address (default: embedded) |
| `CAPISCIO_SERVER_DID` | Pre-configured server DID |
| `CAPISCIO_SERVER_PRIVATE_KEY` | Path to private key PEM |

## Security Best Practices

1. **Never commit private keys**
   ```gitignore
   # .gitignore
   *.pem
   keys/
   capiscio_keys/
   ```

2. **Use restrictive permissions**
   ```bash
   chmod 600 ./keys/*.pem
   ```

3. **Rotate keys periodically**
   - Generate new keypair
   - Update registry with new DID
   - Keep old key for transition period

4. **Store API keys securely**
   ```bash
   # Use environment variables
   export CAPISCIO_REGISTRY_API_KEY="sk_live_..."
   ```

## Next Steps

- [Protect MCP Tools](server-side.md) - Add trust-level requirements
- [Client-Side Verification](client-side.md) - Verify servers before connecting
- [Evidence Logging](evidence.md) - Audit trail for all tool calls

````