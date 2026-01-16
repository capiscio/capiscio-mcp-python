# Installation

## PyPI Installation

```bash
# Standalone (no MCP SDK dependency)
pip install capiscio-mcp

# With MCP SDK integration
pip install capiscio-mcp[mcp]

# With PoP signing/verification (requires cryptography)
pip install capiscio-mcp[crypto]

# Full installation
pip install capiscio-mcp[mcp,crypto]
```

## Using uv

```bash
uv add capiscio-mcp
uv add capiscio-mcp --extra mcp
```

## Requirements

- Python 3.10+
- capiscio-core (auto-downloaded on first use)

## Core Connection Modes

capiscio-mcp connects to capiscio-core for cryptographic operations:

### Embedded Mode (Default)

The SDK automatically downloads and manages the core binary:

```bash
pip install capiscio-mcp
# Just works! Binary downloaded on first use.
```

The binary is cached at `~/.capiscio/bin/capiscio`.

### External Mode

Connect to a separately managed core service:

```bash
# Start core in another terminal
capiscio mcp serve --listen localhost:50051

# SDK connects to external core
export CAPISCIO_CORE_ADDR="localhost:50051"
```

## Verify Installation

```python
from capiscio_mcp import MCP_VERSION, CORE_MIN_VERSION

print(f"capiscio-mcp version: {MCP_VERSION}")
print(f"Required core version: {CORE_MIN_VERSION}")
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `CAPISCIO_CORE_ADDR` | External core address | (embedded mode) |
| `CAPISCIO_SERVER_ORIGIN` | Server origin for guard | (auto-detect) |
| `CAPISCIO_LOG_LEVEL` | Logging verbosity | `info` |
