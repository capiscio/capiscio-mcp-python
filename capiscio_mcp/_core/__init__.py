"""
Core connection management for capiscio-mcp.

This module handles:
- Binary download and lifecycle management
- gRPC client connection (embedded and external modes)
- Health checks and version compatibility
"""

from capiscio_mcp._core.version import (
    MCP_VERSION,
    CORE_MIN_VERSION,
    CORE_MAX_VERSION,
    PROTO_VERSION,
    is_core_compatible,
)
from capiscio_mcp._core.client import CoreClient
from capiscio_mcp._core.lifecycle import (
    ensure_binary,
    get_binary_path,
    download_binary,
)
from capiscio_mcp._core.health import (
    wait_healthy,
    check_version_compatibility,
)

__all__ = [
    # Version
    "MCP_VERSION",
    "CORE_MIN_VERSION",
    "CORE_MAX_VERSION",
    "PROTO_VERSION",
    "is_core_compatible",
    # Client
    "CoreClient",
    # Lifecycle
    "ensure_binary",
    "get_binary_path",
    "download_binary",
    # Health
    "wait_healthy",
    "check_version_compatibility",
]
