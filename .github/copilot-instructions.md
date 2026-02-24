# capiscio-mcp-python - GitHub Copilot Instructions

## ⛔ ABSOLUTE RULES - NO EXCEPTIONS

### 1. ALL WORK VIA PULL REQUESTS
- **NEVER commit directly to `main`.** All changes MUST go through PRs.
- Create feature branches: `feature/`, `fix/`, `chore/`

### 2. RUN TESTS LOCALLY BEFORE PUSH
- `pytest -v` must pass before pushing

### 3. NO WATCH/BLOCKING COMMANDS
- **NEVER run blocking commands** without timeout

---

## 🚨 CRITICAL: Read First

**Before starting work, check the repo's README.md and existing code patterns.**

---

## Repository Purpose

**capiscio-mcp-python** (PyPI: `capiscio-mcp`) is the MCP Guard — tool-level security for Model Context Protocol servers. It implements:

- **RFC-006**: MCP Tool Authority and Evidence
- **RFC-007**: MCP Server Identity Disclosure and Verification

**Current Version**: v2.4.0

## Architecture

```
capiscio-mcp-python/
├── capiscio_mcp/
│   ├── __init__.py          # Public API exports
│   ├── guard.py             # @guard decorator — core trust enforcement
│   ├── server.py            # Server verification utilities
│   ├── registration.py      # Server DID generation & registration
│   ├── pop.py               # Proof-of-possession and evidence handling
│   ├── integrations/        # MCP framework integrations
│   │   └── mcp.py           # CapiscioMCPServer/Client wrappers
│   ├── types.py             # Shared type definitions
│   └── errors.py            # Error classes
├── docs/                    # MkDocs documentation
├── tests/                   # Test suite
└── pyproject.toml           # Package configuration
```

## Key Concepts

### @guard Decorator

The primary API surface. Wraps MCP tool handlers with trust-level enforcement:

```python
from capiscio_mcp import guard

@guard(min_trust_level=2)
async def sensitive_tool(query: str, badge: str) -> str:
    """Only agents with trust level ≥ 2 can call this."""
    ...
```

### FastMCP Integration

For use with the MCP SDK's FastMCP server:

```python
from capiscio_mcp.integrations.mcp import CapiscioMCPServer

server = CapiscioMCPServer("my-server", default_trust_level=1)

@server.tool()
@guard(min_trust_level=2)
async def protected_tool(query: str) -> str:
    ...
```

### Server Identity

MCP servers register their own identity (DID) with CapiscIO:

```python
from capiscio_mcp import setup_server_identity, register_server_identity, verify_server

# Set up this server's identity (generates keys, prepares DID document)
await setup_server_identity(name="my-mcp-server", url="https://...")

# Register this server's identity with the CapiscIO registry
identity = await register_server_identity()

# Verify another server
result = await verify_server("did:web:other-server.example.com")
```

### Evidence Logging

Every guarded tool call produces a cryptographic evidence record:

```python
# Evidence is automatically collected by @guard
# Contains: caller DID, tool name, timestamp, badge JTI, trust level
```

## Critical Rules

### 1. RFC Compliance
- RFC-006 defines the evidence format — don't change the schema
- RFC-007 defines server identity — follow the DID document structure

### 2. gRPC Dependency
Badge verification calls capiscio-core via gRPC. The `CAPISCIO_CORE_ADDR` environment variable must point to the core service:
```bash
CAPISCIO_CORE_ADDR=localhost:50051  # Local development
```

### 3. Trust Level Semantics
- Level 0: Self-signed (no verification)
- Level 1: Domain validated (DV)
- Level 2: Organization validated (OV)
- Level 3: Extended validated (EV)
- Level 4: Reserved (not yet implemented)

### 4. Async-First APIs
Public APIs are **async-first** — prefer async interfaces. Synchronous wrappers (e.g., `*_sync`) exist for compatibility; do not add new sync wrappers or change existing ones without discussion and clear documentation.

## Environment Variables

```bash
# Optional: Point to a running capiscio-core gRPC server (default: auto-start local)
CAPISCIO_CORE_ADDR=localhost:50051

# Optional: Filesystem path to capiscio-core binary
CAPISCIO_BINARY_PATH=/path/to/capiscio-core
# or set CAPISCIO_BINARY if the binary is on your PATH:
# CAPISCIO_BINARY=capiscio-core

# Server origin for evidence logging
CAPISCIO_SERVER_ORIGIN=http://localhost:8000
```

## Common Commands

```bash
# Install for development
pip install -e ".[dev,mcp]"

# Run tests
pytest -v

# Build docs
mkdocs build

# Type checking
mypy capiscio_mcp/
```
