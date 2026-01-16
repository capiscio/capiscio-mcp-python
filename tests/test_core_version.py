"""Tests for capiscio_mcp._core.version module."""

import pytest

from capiscio_mcp._core.version import (
    MCP_VERSION,
    CORE_MIN_VERSION,
    CORE_MAX_VERSION,
    PROTO_VERSION,
    parse_version,
    is_core_compatible,
    get_download_url,
)


class TestVersionConstants:
    """Tests for version constants."""
    
    def test_mcp_version_format(self):
        """MCP version should be valid semver."""
        parts = MCP_VERSION.split(".")
        assert len(parts) == 3
        for part in parts:
            assert part.isdigit()
    
    def test_core_min_version_format(self):
        """Core min version should be valid semver."""
        parts = CORE_MIN_VERSION.split(".")
        assert len(parts) == 3
        for part in parts:
            assert part.isdigit()
    
    def test_core_max_version_format(self):
        """Core max version should be valid semver."""
        parts = CORE_MAX_VERSION.split(".")
        assert len(parts) == 3
        for part in parts:
            assert part.isdigit()
    
    def test_proto_version_format(self):
        """Proto version should be valid."""
        assert PROTO_VERSION is not None
        assert len(PROTO_VERSION) > 0
    
    def test_version_ordering(self):
        """Core min < max version."""
        min_tuple = parse_version(CORE_MIN_VERSION)
        max_tuple = parse_version(CORE_MAX_VERSION)
        assert min_tuple < max_tuple


class TestParseVersion:
    """Tests for parse_version function."""
    
    def test_parse_simple_version(self):
        """Parse simple semver string."""
        result = parse_version("1.2.3")
        assert result == (1, 2, 3)
    
    def test_parse_zero_version(self):
        """Parse version with zeros."""
        result = parse_version("0.0.0")
        assert result == (0, 0, 0)
    
    def test_parse_large_numbers(self):
        """Parse version with large numbers."""
        result = parse_version("10.20.30")
        assert result == (10, 20, 30)
    
    def test_parse_real_versions(self):
        """Parse actual version strings from constants."""
        min_v = parse_version(CORE_MIN_VERSION)
        max_v = parse_version(CORE_MAX_VERSION)
        mcp_v = parse_version(MCP_VERSION)
        
        assert all(isinstance(v, tuple) for v in [min_v, max_v, mcp_v])
        assert all(len(v) == 3 for v in [min_v, max_v, mcp_v])
    
    def test_parse_invalid_format(self):
        """Invalid format should raise ValueError."""
        with pytest.raises(ValueError):
            parse_version("1.2")
        
        with pytest.raises(ValueError):
            parse_version("not.a.version")
    
    def test_parse_with_extra_parts(self):
        """Version with extra parts extracts first 3."""
        # The regex only extracts first 3 components
        result = parse_version("1.2.3.4")
        assert result == (1, 2, 3)
    
    def test_parse_with_v_prefix(self):
        """Version with 'v' prefix should work."""
        result = parse_version("v1.2.3")
        assert result == (1, 2, 3)
    
    def test_parse_with_prerelease(self):
        """Prerelease suffix should be handled."""
        result = parse_version("1.2.3-alpha")
        assert result == (1, 2, 3)
        
        result = parse_version("1.2.3-beta.1")
        assert result == (1, 2, 3)


class TestIsCoreCompatible:
    """Tests for is_core_compatible function."""
    
    def test_compatible_exact_min(self):
        """Exact minimum version is compatible."""
        assert is_core_compatible(CORE_MIN_VERSION) is True
    
    def test_compatible_between_min_max(self):
        """Version between min and max is compatible."""
        # Create a version between min and max
        min_tuple = parse_version(CORE_MIN_VERSION)
        between = f"{min_tuple[0]}.{min_tuple[1]}.{min_tuple[2] + 1}"
        assert is_core_compatible(between) is True
    
    def test_incompatible_below_min(self):
        """Version below minimum is incompatible."""
        min_tuple = parse_version(CORE_MIN_VERSION)
        # Create a version below min
        if min_tuple[2] > 0:
            below = f"{min_tuple[0]}.{min_tuple[1]}.{min_tuple[2] - 1}"
        elif min_tuple[1] > 0:
            below = f"{min_tuple[0]}.{min_tuple[1] - 1}.0"
        else:
            below = f"{min_tuple[0] - 1}.0.0" if min_tuple[0] > 0 else None
        
        if below:
            assert is_core_compatible(below) is False
    
    def test_incompatible_at_max(self):
        """Exact maximum version is incompatible (exclusive)."""
        assert is_core_compatible(CORE_MAX_VERSION) is False
    
    def test_incompatible_above_max(self):
        """Version above maximum is incompatible."""
        max_tuple = parse_version(CORE_MAX_VERSION)
        above = f"{max_tuple[0]}.{max_tuple[1]}.{max_tuple[2] + 1}"
        assert is_core_compatible(above) is False
    
    def test_handles_v_prefix(self):
        """Version with 'v' prefix should work."""
        assert is_core_compatible(f"v{CORE_MIN_VERSION}") is True
    
    def test_handles_prerelease(self):
        """Prerelease versions should work."""
        # Prerelease of min version should be compatible
        assert is_core_compatible(f"{CORE_MIN_VERSION}-alpha") is True


class TestGetDownloadUrl:
    """Tests for get_download_url function."""
    
    def test_linux_amd64(self):
        """Linux AMD64 URL should be correct."""
        url = get_download_url(CORE_MIN_VERSION, "linux", "amd64")
        assert "linux" in url.lower()
        assert "amd64" in url.lower() or "x86_64" in url.lower()
        assert url.startswith("https://")
    
    def test_linux_arm64(self):
        """Linux ARM64 URL should be correct."""
        url = get_download_url(CORE_MIN_VERSION, "linux", "arm64")
        assert "linux" in url.lower()
        assert "arm64" in url.lower() or "aarch64" in url.lower()
    
    def test_darwin_amd64(self):
        """macOS AMD64 URL should be correct."""
        url = get_download_url(CORE_MIN_VERSION, "darwin", "amd64")
        assert "darwin" in url.lower() or "macos" in url.lower()
        assert "amd64" in url.lower() or "x86_64" in url.lower()
    
    def test_darwin_arm64(self):
        """macOS ARM64 (Apple Silicon) URL should be correct."""
        url = get_download_url(CORE_MIN_VERSION, "darwin", "arm64")
        assert "darwin" in url.lower() or "macos" in url.lower()
        assert "arm64" in url.lower() or "aarch64" in url.lower()
    
    def test_windows_amd64(self):
        """Windows AMD64 URL should be correct."""
        url = get_download_url(CORE_MIN_VERSION, "windows", "amd64")
        assert "windows" in url.lower()
        assert url.endswith(".exe") or "amd64" in url.lower()
    
    def test_unsupported_os(self):
        """Unsupported OS generates URL anyway (no validation)."""
        # The implementation doesn't validate - it just generates URLs
        url = get_download_url(CORE_MIN_VERSION, "freebsd", "amd64")
        assert "freebsd" in url
    
    def test_unsupported_arch(self):
        """Unsupported arch generates URL anyway (no validation)."""
        # The implementation doesn't validate - it just generates URLs
        url = get_download_url(CORE_MIN_VERSION, "linux", "mips")
        assert "mips" in url
    
    def test_url_contains_version(self):
        """Download URL should contain version."""
        url = get_download_url(CORE_MIN_VERSION, "linux", "amd64")
        # Should contain the version we passed
        assert CORE_MIN_VERSION in url
