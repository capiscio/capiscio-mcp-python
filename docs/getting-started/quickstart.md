# Quickstart

Get started with capiscio-mcp in under 5 minutes.

## Server-Side: Protect Your Tools

The `@guard` decorator protects MCP tools with trust-level requirements:

```python
from capiscio_mcp import guard

@guard(min_trust_level=2)
async def read_database(query: str) -> list[dict]:
    """Only agents with Trust Level 2+ can execute this tool."""
    # Your database query logic here
    return [{"id": 1, "name": "Example"}]
```

### With Configuration

```python
from capiscio_mcp import guard, GuardConfig

config = GuardConfig(
    min_trust_level=2,
    trusted_issuers=["did:web:registry.capisc.io"],
    allowed_tools=["read_*", "list_*"],
    require_badge=True,  # Deny anonymous access
)

@guard(config=config)
async def execute_query(sql: str) -> list[dict]:
    """Execute a SQL query with full policy enforcement."""
    pass
```

### Sync Version

```python
from capiscio_mcp import guard_sync

@guard_sync(min_trust_level=2)
def read_database_sync(query: str) -> list[dict]:
    """Synchronous version for non-async code."""
    pass
```

## Client-Side: Verify Servers

Before connecting to an MCP server, verify its identity:

```python
from capiscio_mcp import verify_server, ServerState

result = await verify_server(
    server_did="did:web:mcp.example.com",
    server_badge="eyJhbGc...",
    transport_origin="https://mcp.example.com",
)

if result.state == ServerState.VERIFIED_PRINCIPAL:
    print(f"✅ Trusted server at Level {result.trust_level}")
elif result.state == ServerState.DECLARED_PRINCIPAL:
    print("⚠️ Server identity declared but not verified")
elif result.state == ServerState.UNVERIFIED_ORIGIN:
    print("❌ Server did not disclose identity")
```

## Understanding Server States

| State | Meaning | Action |
|-------|---------|--------|
| `VERIFIED_PRINCIPAL` | Identity cryptographically verified | Safe to proceed |
| `DECLARED_PRINCIPAL` | Identity declared but verification failed | Proceed with caution |
| `UNVERIFIED_ORIGIN` | No identity disclosed | High risk |

## Trust Levels

Per RFC-002 v1.4:

| Level | Name | Validation | Use Case |
|-------|------|------------|----------|
| 0 | Self-Signed (SS) | None, `did:key` issuer | Local dev, testing, demos |
| 1 | Registered (REG) | Account registration | Development, internal agents |
| 2 | Domain Validated (DV) | DNS/HTTP challenge | Production, B2B agents |
| 3 | Organization Validated (OV) | DUNS/legal entity | High-trust production |
| 4 | Extended Validated (EV) | Manual review + legal | Regulated industries |

## Next Steps

- [Server-Side Guide](../guides/server-side.md) - Full @guard configuration
- [Client-Side Guide](../guides/client-side.md) - Server verification patterns
- [Evidence Logging](../guides/evidence.md) - Audit trail configuration
- [MCP SDK Integration](../guides/mcp-integration.md) - Use with official MCP SDK
