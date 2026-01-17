# Server-Side: Guarding MCP Tools

This guide covers protecting MCP tools with the `@guard` decorator per RFC-006.

## Basic Usage

```python
from capiscio_mcp import guard

@guard(min_trust_level=2)
async def read_file(path: str) -> str:
    """Read a file (requires Trust Level 2+)."""
    with open(path) as f:
        return f.read()
```

## GuardConfig Options

```python
from capiscio_mcp import guard, GuardConfig

config = GuardConfig(
    # Minimum trust level required (0-4)
    min_trust_level=2,
    
    # Accept self-signed (did:key) badges?
    accept_level_zero=False,
    
    # List of trusted issuer DIDs
    trusted_issuers=[
        "did:web:registry.capisc.io",
        "did:web:internal.example.com",
    ],
    
    # Glob patterns for allowed tool names
    allowed_tools=[
        "read_*",
        "list_*",
    ],
    
    # If True, deny anonymous/API key access
    require_badge=True,
    
    # Policy version for tracking
    policy_version="v1.0",
)

@guard(config=config)
async def execute_query(sql: str) -> list[dict]:
    pass
```

## Handling Denials

```python
from capiscio_mcp import guard, GuardError

@guard(min_trust_level=2)
async def sensitive_operation(data: dict) -> dict:
    pass

try:
    result = await sensitive_operation(data={"key": "value"})
except GuardError as e:
    print(f"Access denied: {e.reason}")
    print(f"Evidence ID: {e.evidence_id}")  # For audit trail
    print(f"Caller DID: {e.agent_did}")
```

## Deny Reasons

| Reason | Meaning |
|--------|---------|
| `BADGE_MISSING` | No badge provided |
| `BADGE_INVALID` | Badge signature invalid |
| `BADGE_EXPIRED` | Badge has expired |
| `BADGE_REVOKED` | Badge has been revoked |
| `TRUST_INSUFFICIENT` | Trust level too low |
| `TOOL_NOT_ALLOWED` | Tool not in allowed_tools |
| `ISSUER_UNTRUSTED` | Badge issuer not trusted |
| `POLICY_DENIED` | Custom policy denied access |

## Different Trust Levels for Different Tools

```python
from capiscio_mcp import guard

@guard(min_trust_level=1)
async def list_files(directory: str) -> list[str]:
    """Low-risk: List files (DV sufficient)."""
    pass

@guard(min_trust_level=2)
async def read_file(path: str) -> str:
    """Medium-risk: Read file contents (OV required)."""
    pass

@guard(min_trust_level=3)
async def write_file(path: str, content: str) -> None:
    """High-risk: Write files (OV required)."""
    pass

@guard(min_trust_level=4)
async def execute_command(cmd: str) -> str:
    """Critical: Execute shell commands (EV required)."""
    pass
```

## Context Access

Access caller information within guarded functions:

```python
from capiscio_mcp import guard
from capiscio_mcp.guard import get_caller_credential

@guard(min_trust_level=2)
async def audit_operation(data: dict) -> dict:
    credential = get_caller_credential()
    
    if credential:
        print(f"Caller DID: {credential.agent_did}")
        print(f"Trust Level: {credential.trust_level}")
        print(f"Badge JTI: {credential.badge_jti}")
    
    return {"status": "ok"}
```

## MCP SDK Integration

See [MCP SDK Integration](mcp-integration.md) for using `@guard` with the official MCP SDK.
