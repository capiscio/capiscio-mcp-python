# CapiscIO MCP Guard

Tool-level security for Model Context Protocol servers.

[![PyPI version](https://badge.fury.io/py/capiscio-mcp.svg)](https://badge.fury.io/py/capiscio-mcp)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**MCP Guard** provides trust badges and identity verification for [Model Context Protocol (MCP)](https://modelcontextprotocol.io) tool calls. It implements:

- **RFC-006**: MCP Tool Authority and Evidence
- **RFC-007**: MCP Server Identity Disclosure and Verification

## Installation

```bash
# Standalone (no MCP SDK dependency)
pip install capiscio-mcp

# With MCP SDK integration
pip install capiscio-mcp[mcp]
```

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
| **Trust levels** | 0 (self-signed) → 4 (continuous validation) |

## Quickstart 1: Server-Side (Tool Guarding)

Protect your MCP tools with trust-level requirements:

```python
from capiscio_mcp import guard

@guard(min_trust_level=2)
async def read_database(query: str) -> list[dict]:
    """Only agents with Trust Level 2+ can execute this tool."""
    # ... database query logic
    pass

# Sync version available
from capiscio_mcp import guard_sync

@guard_sync(min_trust_level=2)
def read_database_sync(query: str) -> list[dict]:
    pass
```

### With Full Configuration

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
    pass
```

### With MCP SDK Integration

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
```

## Quickstart 2: Client-Side (Server Verification)

Verify the identity of MCP servers you connect to:

```python
from capiscio_mcp import verify_server, ServerState

result = await verify_server(
    server_did="did:web:mcp.example.com",
    server_badge="eyJhbGc...",
    transport_origin="https://mcp.example.com",
)

if result.state == ServerState.VERIFIED_PRINCIPAL:
    print(f"Trusted server at Level {result.trust_level}")
elif result.state == ServerState.DECLARED_PRINCIPAL:
    print("Server identity declared but not verified")
elif result.state == ServerState.UNVERIFIED_ORIGIN:
    print("Warning: Server did not disclose identity")
```

### With MCP SDK Integration

```python
from capiscio_mcp.integrations.mcp import CapiscioMCPClient

async with CapiscioMCPClient(
    server_url="https://mcp.example.com",
    min_trust_level=2,  # Require verified identity
    badge="eyJhbGc...",  # Your client badge
) as client:
    # Server identity already verified
    print(f"Connected at trust level {client.server_trust_level}")
    
    result = await client.call_tool("read_file", {"path": "/data/file.txt"})
```

## Core Connection Modes

MCP Guard connects to capiscio-core for cryptographic operations:

### Embedded Mode (Default)

SDK automatically downloads and manages the core binary:

```bash
pip install capiscio-mcp
# Just works! Binary downloaded on first use.
```

### External Mode

Connect to a separately managed core service:

```bash
# Start core in another terminal
capiscio mcp serve --listen localhost:50051

# SDK connects to external core
export CAPISCIO_CORE_ADDR="localhost:50051"
```

## Trust Levels

| Level | Name | Description |
|-------|------|-------------|
| 0 | Self-Signed | `did:key` issuer, cryptographic identity only |
| 1 | Domain Validated (DV) | Domain ownership verified |
| 2 | Organization Validated (OV) | Organization identity verified |
| 3 | Extended Validation (EV) | Legal entity verification |
| 4 | Continuous Validation (CV) | Runtime attestation |

## Evidence Logging

Every tool invocation—allowed or denied—produces an evidence record:

```python
from capiscio_mcp import guard, GuardError

@guard(min_trust_level=2)
async def sensitive_operation(data: dict) -> dict:
    pass

try:
    result = await sensitive_operation(data={"key": "value"})
except GuardError as e:
    # Evidence logged even on denial
    print(f"Denied: {e.reason}")
    print(f"Evidence ID: {e.evidence_id}")  # For audit trail
```

Evidence includes:
- Tool name and parameters hash (not raw params—PII safe)
- Caller identity (agent DID, badge JTI, auth level)
- Decision and reason
- Timestamp and unique evidence ID

## Configuration Reference

### GuardConfig

```python
from capiscio_mcp import GuardConfig

config = GuardConfig(
    min_trust_level=2,        # Minimum trust level (0-4)
    accept_level_zero=False,  # Accept self-signed badges?
    trusted_issuers=[         # List of trusted issuer DIDs
        "did:web:registry.capisc.io",
    ],
    allowed_tools=[           # Glob patterns for allowed tools
        "read_*",
        "list_*",
    ],
    require_badge=True,       # Deny anonymous/API key access
    policy_version="v1.0",    # Policy version for tracking
)
```

### VerifyConfig

```python
from capiscio_mcp import VerifyConfig

config = VerifyConfig(
    trusted_issuers=[...],    # Trusted issuer DIDs
    min_trust_level=2,        # Minimum required level
    accept_level_zero=False,  # Accept self-signed servers?
    offline_mode=False,       # Skip revocation checks?
    skip_origin_binding=False,  # Skip host/path binding?
)
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `CAPISCIO_CORE_ADDR` | External core address | (embedded mode) |
| `CAPISCIO_SERVER_ORIGIN` | Server origin for guard | (auto-detect) |
| `CAPISCIO_LOG_LEVEL` | Logging verbosity | `info` |

## API Reference

### Guard (RFC-006)

- `guard(config=None, min_trust_level=None, tool_name=None)` — Async decorator
- `guard_sync(...)` — Sync decorator
- `evaluate_tool_access(tool_name, params, credential, config)` — Low-level API
- `compute_params_hash(params)` — Deterministic parameter hashing
- `GuardConfig` — Configuration dataclass
- `GuardResult` — Evaluation result dataclass
- `GuardError` — Exception for denied access

### Server (RFC-007)

- `verify_server(server_did, server_badge, transport_origin, endpoint_path, config)` — Async verification
- `verify_server_sync(...)` — Sync verification
- `verify_server_strict(...)` — Raises on any verification failure
- `parse_http_headers(headers)` — Extract identity from HTTP headers
- `parse_jsonrpc_meta(meta)` — Extract identity from MCP _meta
- `VerifyConfig` — Configuration dataclass
- `VerifyResult` — Verification result dataclass
- `ServerVerifyError` — Exception for verification failures

### Types

- `Decision` — ALLOW / DENY
- `AuthLevel` — ANONYMOUS / API_KEY / BADGE
- `DenyReason` — Enumeration of denial reasons
- `ServerState` — VERIFIED_PRINCIPAL / DECLARED_PRINCIPAL / UNVERIFIED_ORIGIN
- `ServerErrorCode` — Enumeration of verification error codes
- `TrustLevel` — 0-4 trust level enum

## Documentation

- [RFC-006: MCP Tool Authority and Evidence](https://docs.capisc.io/rfcs/006)
- [RFC-007: MCP Server Identity Disclosure](https://docs.capisc.io/rfcs/007)
- [Server-Side Guide](https://docs.capisc.io/mcp/server-side)
- [Client-Side Guide](https://docs.capisc.io/mcp/client-side)
- [Evidence Logging Guide](https://docs.capisc.io/mcp/evidence)

## Development

```bash
# Clone repository
git clone https://github.com/capiscio/capiscio-mcp-python.git
cd capiscio-mcp-python

# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest -v

# Run tests with coverage
pytest --cov=capiscio_mcp --cov-report=html

# Type checking
mypy capiscio_mcp

# Linting
ruff check capiscio_mcp
```

## License

Apache License 2.0

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
