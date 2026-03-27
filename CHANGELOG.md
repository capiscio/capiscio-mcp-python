# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.6.0] - 2026-03-27

### Added
- **PolicyClient**: RFC-005 PDP integration via Option B for embedded policy evaluation (#10)

### Fixed
- **Proto Descriptor Collision**: Hardened `AddSerializedFile` error handling with eager registration to win descriptor pool race (#11)
- **PyPI Wheel Packaging**: Force-include nested proto files in wheel and sdist builds (#11)

## [2.5.0] - 2026-03-16

### Added
- **`MCPServerIdentity.connect()`**: Zero-config server identity setup with `ServerBadgeKeeper` (#7)
- **Stdio Credential Passing**: Badge credentials passed in `_meta` for stdio transports (#7)

### Fixed
- Improve binary install experience with better error messages (#8)

## [2.4.0] - 2026-02-04

### Changed
- **Version Alignment**: Synchronized version with capiscio-core v2.4.0

## [0.1.0] - 2026-01-15

### Added

- Initial release of capiscio-mcp
- RFC-006: MCP Tool Authority and Evidence implementation
  - `@guard` and `@guard_sync` decorators for tool protection
  - `GuardConfig` for configuration
  - `compute_params_hash()` for deterministic parameter hashing
  - `evaluate_tool_access()` low-level API
- RFC-007: MCP Server Identity Verification implementation
  - `verify_server()` and `verify_server_sync()` functions
  - `verify_server_strict()` for strict verification
  - `parse_http_headers()` and `parse_jsonrpc_meta()` helpers
  - `VerifyConfig` for configuration
- Core connection management
  - Embedded mode: automatic binary download and management
  - External mode: connect to user-managed core via `CAPISCIO_CORE_ADDR`
  - Process supervision with automatic restart
  - Health checks and version compatibility
- MCP SDK integration (optional)
  - `CapiscioMCPServer` for server-side integration
  - `CapiscioMCPClient` for client-side integration
- Type definitions
  - `Decision`, `AuthLevel`, `DenyReason` enums
  - `ServerState`, `ServerErrorCode` enums
  - `TrustLevel` enum (0-4)
- Error types
  - `GuardError` for denied tool access
  - `ServerVerifyError` for verification failures
  - `CoreConnectionError` for connection issues
  - `CoreVersionError` for version mismatches
- Comprehensive test suite with 80%+ coverage target

### Dependencies

- Requires capiscio-core >= 2.5.0, < 3.0.0
- Python 3.10+
- Optional: mcp >= 1.0 for MCP SDK integration

[Unreleased]: https://github.com/capiscio/capiscio-mcp-python/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/capiscio/capiscio-mcp-python/releases/tag/v0.1.0
