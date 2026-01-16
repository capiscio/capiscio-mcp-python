# Client-Side: Verifying MCP Servers

This guide covers verifying MCP server identity per RFC-007.

## Basic Usage

```python
from capiscio_mcp import verify_server, ServerState

result = await verify_server(
    server_did="did:web:mcp.example.com:servers:filesystem",
    server_badge="eyJhbGc...",
    transport_origin="https://mcp.example.com",
)

if result.state == ServerState.VERIFIED_PRINCIPAL:
    print(f"✅ Server verified at trust level {result.trust_level}")
elif result.state == ServerState.DECLARED_PRINCIPAL:
    print("⚠️ Identity declared but verification failed")
    print(f"   Error: {result.error_detail}")
elif result.state == ServerState.UNVERIFIED_ORIGIN:
    print("❌ Server did not disclose any identity")
```

## VerifyConfig Options

```python
from capiscio_mcp import verify_server, VerifyConfig

config = VerifyConfig(
    # List of trusted issuer DIDs
    trusted_issuers=[
        "did:web:registry.capisc.io",
    ],
    
    # Minimum trust level required (0-4)
    min_trust_level=2,
    
    # Accept self-signed (did:key) servers?
    accept_level_zero=False,
    
    # Skip revocation checks (offline mode)?
    offline_mode=False,
    
    # Skip host/path binding checks (for trusted gateways)
    skip_origin_binding=False,
)

result = await verify_server(
    server_did="did:web:mcp.example.com",
    server_badge="eyJhbGc...",
    transport_origin="https://mcp.example.com",
    config=config,
)
```

## Extracting Identity from Transport

### From HTTP Headers

```python
from capiscio_mcp import parse_http_headers, verify_server

# Extract from HTTP response
headers = {
    "Capiscio-Server-DID": "did:web:mcp.example.com",
    "Capiscio-Server-Badge": "eyJhbGc...",
}

identity = parse_http_headers(headers)

if identity.has_identity:
    result = await verify_server(
        server_did=identity.server_did,
        server_badge=identity.server_badge,
        transport_origin="https://mcp.example.com",
    )
```

### From JSON-RPC _meta

```python
from capiscio_mcp import parse_jsonrpc_meta, verify_server

# Extract from MCP JSON-RPC response
response = {
    "jsonrpc": "2.0",
    "id": 1,
    "result": {...},
    "_meta": {
        "serverDid": "did:web:mcp.example.com",
        "serverBadge": "eyJhbGc...",
    }
}

identity = parse_jsonrpc_meta(response.get("_meta", {}))

if identity.has_identity:
    result = await verify_server(
        server_did=identity.server_did,
        server_badge=identity.server_badge,
    )
```

## Server States Explained

| State | RFC-007 Definition | Recommended Action |
|-------|-------------------|-------------------|
| `VERIFIED_PRINCIPAL` | DID verified via badge chain | ✅ Safe to proceed |
| `DECLARED_PRINCIPAL` | DID provided but verification failed | ⚠️ Warn user, consider blocking |
| `UNVERIFIED_ORIGIN` | No identity material provided | ❌ Treat as untrusted |

## Error Handling

```python
from capiscio_mcp import verify_server, ServerVerifyError

try:
    result = await verify_server(
        server_did="did:web:mcp.example.com",
        server_badge="eyJhbGc...",
        transport_origin="https://mcp.example.com",
    )
except ServerVerifyError as e:
    print(f"Verification error: {e.error_code}")
    print(f"Detail: {e.message}")
```

## Error Codes

| Code | Meaning |
|------|---------|
| `DID_INVALID` | Server DID is malformed |
| `BADGE_INVALID` | Badge signature invalid |
| `BADGE_EXPIRED` | Badge has expired |
| `BADGE_REVOKED` | Badge has been revoked |
| `TRUST_INSUFFICIENT` | Trust level below minimum |
| `ORIGIN_MISMATCH` | Transport origin doesn't match DID domain |
| `PATH_MISMATCH` | Endpoint path doesn't match DID path |
| `ISSUER_UNTRUSTED` | Badge issuer not in trusted list |

## Synchronous Version

```python
from capiscio_mcp import verify_server_sync

result = verify_server_sync(
    server_did="did:web:mcp.example.com",
    server_badge="eyJhbGc...",
    transport_origin="https://mcp.example.com",
)
```

## Strict Mode

Raises an exception if verification fails:

```python
from capiscio_mcp.server import verify_server_strict

# Raises ServerVerifyError if not VERIFIED_PRINCIPAL
result = await verify_server_strict(
    server_did="did:web:mcp.example.com",
    server_badge="eyJhbGc...",
    transport_origin="https://mcp.example.com",
)
# If we get here, server is verified
print(f"Server trust level: {result.trust_level}")
```
