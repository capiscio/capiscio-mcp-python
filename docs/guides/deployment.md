# Deploying MCP Servers

This guide covers deploying MCP servers with CapiscIO identity to production environments — especially ephemeral ones like Docker, AWS Lambda, and Cloud Run where local storage doesn't persist between restarts.

---

## Identity Persistence Challenge

When you call `MCPServerIdentity.connect()`, the SDK:

1. Generates an Ed25519 keypair
2. Registers the public key with the CapiscIO registry
3. Receives a `did:web` DID from the registry (e.g. `did:web:registry.capisc.io:servers:...`)
4. Stores keys under `~/.capiscio/servers/{server_id}/`

> **Note:** A `did:key` is only used in local dev mode when no registry is involved. In production with an API key, the registry assigns a `did:web` identity.

In persistent environments (VMs, bare metal) this works automatically — the keys survive restarts. In **ephemeral environments** (containers, serverless, CI runners) the filesystem is recreated on every deploy, which would silently generate a new identity each time.

---

## Key Injection via Environment Variable

Set `CAPISCIO_SERVER_PRIVATE_KEY_PEM` to inject the server's Ed25519 private key from your secrets manager. The SDK will recover the same DID on every start without generating a new keypair.

### First-Run Capture

On the very first run (when no key exists anywhere), the SDK generates a keypair and logs a capture hint to stderr:

```
╔══════════════════════════════════════════════════════════════════╗
║  New server identity generated — save key for persistence        ║
╚══════════════════════════════════════════════════════════════════╝

  Add to your secrets manager / .env:

    CAPISCIO_SERVER_PRIVATE_KEY_PEM='-----BEGIN PRIVATE KEY-----\nMC4CAQ...xYz\n-----END PRIVATE KEY-----\n'

  The DID will be recovered automatically from the key on startup.
```

Copy the entire PEM string (including `\n` line breaks) and store it in your secrets manager.

### Key Resolution Priority

The SDK resolves the server identity in this order:

| Priority | Source | When Used |
|----------|--------|-----------|
| 1 | `CAPISCIO_SERVER_PRIVATE_KEY_PEM` env var | Containers, serverless, CI |
| 2 | Local key file (`~/.capiscio/servers/{id}/private_key.pem`) | Persistent environments |
| 3 | Generate new keypair | First run only |

!!! warning "DID Changes on New Key Generation"
    If neither the env var nor local files are available, the SDK generates a **new** keypair
    with a **different** DID. Any badges issued to the old DID will no longer be valid.
    Always persist the key in ephemeral environments.

---

## Environment Variables Reference

All variables used by `CapiscioMCPServer.connect()`:

| Variable | Required | Description |
|----------|----------|-------------|
| `CAPISCIO_SERVER_ID` | Yes | Server UUID from the dashboard |
| `CAPISCIO_API_KEY` | Yes | Registry API key |
| `CAPISCIO_SERVER_URL` | No | Registry URL (default: `https://registry.capisc.io`) |
| `CAPISCIO_SERVER_DOMAIN` | No | Domain for badge issuance (default: derived from server URL) |
| `CAPISCIO_SERVER_PRIVATE_KEY_PEM` | No | PEM-encoded Ed25519 private key for identity persistence |

---

## Docker

### docker-compose.yml

```yaml
services:
  mcp-server:
    build: .
    environment:
      CAPISCIO_SERVER_ID: "550e8400-e29b-41d4-a716-446655440000"
      CAPISCIO_API_KEY: "${CAPISCIO_API_KEY}"
      CAPISCIO_SERVER_PRIVATE_KEY_PEM: "${MCP_SERVER_KEY}"
```

### Dockerfile

```dockerfile
FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

# Identity recovered from CAPISCIO_SERVER_PRIVATE_KEY_PEM at runtime
CMD ["python", "server.py"]
```

### Server Code

```python
from capiscio_mcp.integrations.mcp import CapiscioMCPServer

async def main():
    # Reads CAPISCIO_SERVER_ID, CAPISCIO_API_KEY, and
    # CAPISCIO_SERVER_PRIVATE_KEY_PEM from environment
    server = CapiscioMCPServer.connect()

    @server.tool(min_trust_level=2)
    async def my_tool(param: str) -> str:
        return f"Result: {param}"

    server.run()
```

---

## AWS Lambda

```python
import json
from capiscio_mcp.integrations.mcp import CapiscioMCPServer

async def handler(event, context):
    # Key injected via Lambda environment variables or Secrets Manager
    server = CapiscioMCPServer.connect()

    return {
        "statusCode": 200,
        "body": json.dumps({
            "server_did": server.did,
            "badge_valid": server.badge is not None,
        }),
    }
```

Configure the Lambda environment:

```bash
aws lambda update-function-configuration \
  --function-name my-mcp-server \
  --environment "Variables={
    CAPISCIO_SERVER_ID=550e8400-...,
    CAPISCIO_API_KEY=sk_live_...,
    CAPISCIO_SERVER_PRIVATE_KEY_PEM=$(cat private_key.pem | tr '\n' '\\n')
  }"
```

!!! tip "Use AWS Secrets Manager"
    For production, store the PEM in AWS Secrets Manager and reference it
    via a Lambda layer or the Secrets Manager SDK rather than inline env vars.

---

## Google Cloud Run

```yaml
# cloud-run-service.yaml
apiVersion: serving.knative.dev/v1
kind: Service
metadata:
  name: mcp-server
spec:
  template:
    spec:
      containers:
        - image: gcr.io/my-project/mcp-server
          env:
            - name: CAPISCIO_SERVER_ID
              value: "550e8400-..."
            - name: CAPISCIO_API_KEY
              valueFrom:
                secretKeyRef:
                  name: capiscio-api-key
                  key: latest
            - name: CAPISCIO_SERVER_PRIVATE_KEY_PEM
              valueFrom:
                secretKeyRef:
                  name: mcp-server-key
                  key: latest
```

---

## Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mcp-server
spec:
  template:
    spec:
      containers:
        - name: mcp-server
          image: my-registry/mcp-server:latest
          env:
            - name: CAPISCIO_SERVER_ID
              value: "550e8400-..."
            - name: CAPISCIO_API_KEY
              valueFrom:
                secretKeyRef:
                  name: capiscio-secrets
                  key: api-key
            - name: CAPISCIO_SERVER_PRIVATE_KEY_PEM
              valueFrom:
                secretKeyRef:
                  name: capiscio-secrets
                  key: server-private-key
```

Create the secret:

```bash
kubectl create secret generic capiscio-secrets \
  --from-literal=api-key="sk_live_..." \
  --from-file=server-private-key=private_key.pem
```

---

## Key Rotation

To rotate the server identity:

1. Delete (or unset) `CAPISCIO_SERVER_PRIVATE_KEY_PEM`
2. Remove local key files if present (`~/.capiscio/servers/{id}/`)
3. Restart the server — a new keypair and DID will be generated
4. Capture the new key from the log hint
5. Store the new key in your secrets manager

!!! danger "Badge Invalidation"
    Rotating keys changes the server's DID. Any existing badges issued to the
    old DID are no longer valid. The server will automatically request a new badge
    on the next `connect()` call.

---

## Next Steps

- [Server Registration](server-registration.md) — Manual step-by-step registration
- [Server-Side (Guarding Tools)](server-side.md) — Protect tools with trust levels
- [MCP SDK Integration](mcp-integration.md) — CapiscioMCPServer wrapper
