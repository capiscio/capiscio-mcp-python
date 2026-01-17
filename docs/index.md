# MCP Guard

**Tool-level security for Model Context Protocol servers.**

MCP Guard provides trust badges and identity verification for [Model Context Protocol (MCP)](https://modelcontextprotocol.io) tool calls, implementing:

- **RFC-006**: MCP Tool Authority and Evidence
- **RFC-007**: MCP Server Identity Disclosure and Verification

## Why MCP Guard?

MCP servers expose powerful tools to autonomous agents—file systems, databases, APIs. But MCP itself doesn't define how to:

- **Authenticate** which agent is calling a tool
- **Authorize** whether that agent should have access
- **Audit** what happened for post-incident review

MCP Guard solves this with:

| Feature | Description |
|---------|-------------|
| **@guard decorator** | Protect tools with trust-level requirements |
| **Evidence logging** | Cryptographic audit trail for every invocation |
| **Server identity** | Verify MCP servers before connecting |
| **Trust levels** | 0 (self-signed) → 4 (extended validation) |

## Quick Example

### Server-Side (Protect Your Tools)

```python
from capiscio_mcp import guard

@guard(min_trust_level=2)
async def read_database(query: str) -> list[dict]:
    """Only agents with Trust Level 2+ can execute this tool."""
    pass
```

### Client-Side (Verify Servers)

```python
from capiscio_mcp import verify_server, ServerState

result = await verify_server(
    server_did="did:web:mcp.example.com",
    server_badge="eyJhbGc...",
    transport_origin="https://mcp.example.com",
)

if result.state == ServerState.VERIFIED_PRINCIPAL:
    print(f"Trusted server at Level {result.trust_level}")
```

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

<div class="grid cards" markdown>

-   :material-download:{ .lg .middle } **Installation**

    ---

    Install capiscio-mcp and configure your environment.

    [:octicons-arrow-right-24: Installation](getting-started/installation.md)

-   :material-rocket-launch:{ .lg .middle } **Quickstart**

    ---

    Get started in 5 minutes with the @guard decorator.

    [:octicons-arrow-right-24: Quickstart](getting-started/quickstart.md)

-   :material-shield-check:{ .lg .middle } **Server-Side Guide**

    ---

    Protect your MCP tools with trust-level requirements.

    [:octicons-arrow-right-24: Server-Side](guides/server-side.md)

-   :material-check-decagram:{ .lg .middle } **Client-Side Guide**

    ---

    Verify MCP server identity before connecting.

    [:octicons-arrow-right-24: Client-Side](guides/client-side.md)

</div>

## Documentation

- [RFC-006: MCP Tool Authority and Evidence](../rfcs/006-mcp-tool-authority-evidence.md)
- [RFC-007: MCP Server Identity Disclosure](../rfcs/007-mcp-server-identity-discovery.md)
