"""
Version constants and compatibility checking for capiscio-mcp.

capiscio-mcp has decoupled versioning from capiscio-core:
- MCP_VERSION: User-facing SDK version (0.1.0+)
- CORE_MIN_VERSION / CORE_MAX_VERSION: Compatible core range
- PROTO_VERSION: Proto schema version for wire compatibility
"""

from __future__ import annotations

import re
from typing import Tuple

# capiscio-mcp version (user-facing, independent semver)
MCP_VERSION = "0.1.0"

# Compatible capiscio-core versions (internal constraint)
# Note: MCP integration was added in 2.3.1
CORE_MIN_VERSION = "2.3.0"
CORE_MAX_VERSION = "3.0.0"  # exclusive

# Proto schema version for wire compatibility
PROTO_VERSION = "1.0"

# GitHub repository for binary downloads
GITHUB_REPO = "capiscio/capiscio-core"
BINARY_NAME = "capiscio"


def parse_version(version: str) -> Tuple[int, int, int]:
    """
    Parse a semver version string into (major, minor, patch) tuple.
    
    Args:
        version: Version string like "2.5.0" or "v2.5.0"
        
    Returns:
        Tuple of (major, minor, patch)
        
    Raises:
        ValueError: If version string is invalid
    """
    # Strip leading 'v' if present
    version = version.lstrip("v")
    
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)", version)
    if not match:
        raise ValueError(f"Invalid version string: {version}")
    
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


def is_core_compatible(core_version: str) -> bool:
    """
    Check if a capiscio-core version is compatible with this SDK.
    
    Args:
        core_version: Core version string (e.g., "2.5.0")
        
    Returns:
        True if compatible, False otherwise
    """
    try:
        core = parse_version(core_version)
        min_ver = parse_version(CORE_MIN_VERSION)
        max_ver = parse_version(CORE_MAX_VERSION)
        
        return min_ver <= core < max_ver
    except ValueError:
        return False


def get_download_url(version: str, os_name: str, arch_name: str) -> str:
    """
    Get the download URL for a specific core version and platform.
    
    Args:
        version: Core version (e.g., "2.5.0")
        os_name: OS name (darwin, linux, windows)
        arch_name: Architecture (amd64, arm64)
        
    Returns:
        GitHub release download URL
    """
    ext = ".exe" if os_name == "windows" else ""
    filename = f"{BINARY_NAME}-{os_name}-{arch_name}{ext}"
    return f"https://github.com/{GITHUB_REPO}/releases/download/v{version}/{filename}"
