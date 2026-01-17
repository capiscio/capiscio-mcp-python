# API Reference

This section provides detailed API documentation for all public modules in capiscio-mcp.

## Core Exports

::: capiscio_mcp
    options:
      members:
        - guard
        - guard_sync
        - GuardConfig
        - GuardResult
        - GuardError
        - verify_server
        - verify_server_sync
        - VerifyConfig
        - VerifyResult
        - Decision
        - AuthLevel
        - DenyReason
        - ServerState
        - ServerErrorCode
        - generate_server_keypair
        - generate_server_keypair_sync
        - register_server_identity
        - register_server_identity_sync
        - setup_server_identity
        - setup_server_identity_sync
        - RegistrationError
        - KeyGenerationError
      show_root_heading: false

## Guard Module (RFC-006)

::: capiscio_mcp.guard
    options:
      members:
        - guard
        - guard_sync
        - GuardConfig
        - GuardResult
        - compute_params_hash
        - get_caller_credential
      show_root_heading: false

## Server Module (RFC-007)

::: capiscio_mcp.server
    options:
      members:
        - verify_server
        - verify_server_sync
        - VerifyConfig
        - VerifyResult
        - parse_http_headers
        - parse_jsonrpc_meta
      show_root_heading: false

## PoP Module (Key Verification)

::: capiscio_mcp.pop
    options:
      members:
        - PoPRequest
        - PoPResponse
        - generate_pop_request
        - create_pop_response
        - verify_pop_response
        - PoPError
        - PoPSignatureError
        - PoPExpiredError
      show_root_heading: false

## Types

::: capiscio_mcp.types
    options:
      members:
        - Decision
        - AuthLevel
        - DenyReason
        - ServerState
        - ServerErrorCode
        - TrustLevel
        - CallerCredential
        - ServerIdentity
      show_root_heading: false

## Errors

::: capiscio_mcp.errors
    options:
      members:
        - GuardError
        - GuardConfigError
        - ServerVerifyError
        - CoreConnectionError
        - CoreVersionError
      show_root_heading: false

## Registration Module (Server Identity)

::: capiscio_mcp.registration
    options:
      members:
        - generate_server_keypair
        - generate_server_keypair_sync
        - register_server_identity
        - register_server_identity_sync
        - setup_server_identity
        - setup_server_identity_sync
        - RegistrationError
        - KeyGenerationError
      show_root_heading: false

## MCP SDK Integration

::: capiscio_mcp.integrations.mcp
    options:
      show_root_heading: false
