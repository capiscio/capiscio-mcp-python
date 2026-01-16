# Evidence Logging

Every tool invocation—allowed or denied—produces an evidence record for audit and forensics.

## What Gets Logged

Evidence records include:

| Field | Description |
|-------|-------------|
| `evidence_id` | Unique ID for this record |
| `timestamp` | When the evaluation occurred |
| `tool_name` | Tool that was invoked |
| `params_hash` | SHA-256 hash of parameters (not raw params—PII safe) |
| `decision` | ALLOW or DENY |
| `deny_reason` | Why access was denied (if applicable) |
| `agent_did` | Caller's DID (if authenticated) |
| `badge_jti` | Badge ID (if badge was used) |
| `auth_level` | ANONYMOUS, API_KEY, or BADGE |
| `trust_level` | Caller's trust level (0-4) |
| `server_origin` | Server that processed the request |

## Accessing Evidence on Denial

```python
from capiscio_mcp import guard, GuardError

@guard(min_trust_level=2)
async def sensitive_operation(data: dict) -> dict:
    pass

try:
    result = await sensitive_operation(data={"key": "value"})
except GuardError as e:
    print(f"Denied: {e.reason}")
    print(f"Evidence ID: {e.evidence_id}")
    print(f"Agent DID: {e.agent_did}")
    print(f"Trust Level: {e.trust_level}")
```

## Evidence Storage

Evidence can be stored in multiple backends:

### Local Storage (Default)

Evidence stored in `~/.capiscio/evidence/`:

```bash
export CAPISCIO_EVIDENCE_DIR="$HOME/.capiscio/evidence"
```

### Registry Storage

Forward evidence to the CapiscIO Registry:

```bash
export CAPISCIO_EVIDENCE_MODE="registry"
export CAPISCIO_REGISTRY_ENDPOINT="https://registry.capisc.io/events"
export CAPISCIO_REGISTRY_API_KEY="sk_live_..."
```

### Hybrid Storage

Store locally AND forward to registry:

```bash
export CAPISCIO_EVIDENCE_MODE="hybrid"
```

## Parameters Hash

Tool parameters are **never** sent to the core or logged directly. Instead, a deterministic hash is computed:

```python
from capiscio_mcp import compute_params_hash

params = {"query": "SELECT * FROM users", "limit": 10}
hash_value = compute_params_hash(params)

print(hash_value)
# SHA-256 of canonical JSON: "a1b2c3d4..."
```

This keeps PII out of evidence records while allowing correlation.

## Querying Evidence

Evidence records can be queried via:

1. **Local files**: JSON files in the evidence directory
2. **Registry API**: Query via CapiscIO Registry (requires API key)

### Local Evidence Example

```python
import json
from pathlib import Path

evidence_dir = Path.home() / ".capiscio" / "evidence"

for evidence_file in evidence_dir.glob("*.json"):
    with open(evidence_file) as f:
        record = json.load(f)
        if record["decision"] == "deny":
            print(f"Denial: {record['tool_name']} by {record['agent_did']}")
```

## Evidence Retention

Configure retention via environment:

```bash
# Keep evidence for 90 days
export CAPISCIO_EVIDENCE_RETENTION_DAYS="90"

# Disable auto-cleanup
export CAPISCIO_EVIDENCE_RETENTION_DAYS="0"
```

## Compliance Considerations

Evidence logging helps with:

- **SOC 2**: Audit trail of access decisions
- **GDPR**: Parameters are hashed, not stored raw
- **HIPAA**: Track who accessed what tools
- **PCI DSS**: Monitor privileged operations
