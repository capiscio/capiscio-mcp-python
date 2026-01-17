"""
MCP Server Identity Registration.

This module provides functions for MCP servers to:
1. Generate Ed25519 keypairs (deriving did:key)
2. Register their DID with the CapiscIO registry

This follows the same pattern as agent identity registration in capiscio-sdk-python.

Usage:
    from capiscio_mcp.registration import setup_server_identity

    # One-step setup: generate keys + register with registry
    result = await setup_server_identity(
        server_id="your-server-uuid",
        api_key="sk_live_...",
        ca_url="https://registry.capisc.io",
        output_dir="./keys",
    )
    print(f"Server DID: {result['did']}")
    print(f"Private key saved to: {result['private_key_path']}")

    # Or step-by-step:
    from capiscio_mcp.registration import generate_server_keypair, register_server_identity

    # Step 1: Generate keypair
    keys = await generate_server_keypair(output_dir="./keys")

    # Step 2: Register with registry
    await register_server_identity(
        server_id="your-server-uuid",
        api_key="sk_live_...",
        did=keys["did_key"],
        public_key=keys["public_key_pem"],
    )
"""

from __future__ import annotations

import asyncio
import base64
import logging
import os
from pathlib import Path
from typing import Optional

import requests

from capiscio_mcp.errors import CoreConnectionError

logger = logging.getLogger(__name__)


# =============================================================================
# Errors
# =============================================================================


class RegistrationError(Exception):
    """Error during server identity registration."""

    def __init__(self, message: str, status_code: Optional[int] = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class KeyGenerationError(Exception):
    """Error generating keypair."""

    pass


# =============================================================================
# Key Generation (via capiscio-core gRPC)
# =============================================================================


async def generate_server_keypair(
    key_id: str = "",
    output_dir: Optional[str] = None,
) -> dict:
    """
    Generate Ed25519 keypair for MCP server identity.

    Uses capiscio-core's SimpleGuardService.GenerateKeyPair via gRPC.
    The keypair is used for PoP (Proof of Possession) verification.

    Args:
        key_id: Optional specific key ID. If empty, one is generated.
        output_dir: Optional directory to save private key PEM file.
                   If provided, saves as {key_id}.pem

    Returns:
        dict with:
            - key_id: The key identifier
            - did_key: The derived did:key URI (e.g., did:key:z6Mk...)
            - public_key_pem: PEM-encoded public key
            - private_key_pem: PEM-encoded private key
            - private_key_path: Path to saved key file (if output_dir provided)

    Raises:
        KeyGenerationError: If key generation fails
        CoreConnectionError: If connection to capiscio-core fails

    Example:
        keys = await generate_server_keypair(output_dir="./keys")
        print(f"DID: {keys['did_key']}")
        # did:key:z6MkhaXgBZD...
    """
    from capiscio_mcp._core.client import CoreClient
    from capiscio_mcp._proto.gen.capiscio.v1 import simpleguard_pb2, simpleguard_pb2_grpc
    from capiscio_mcp._proto.gen.capiscio.v1 import trust_pb2

    try:
        # Get core client (auto-downloads binary if needed)
        client = await CoreClient.get_instance()

        # Create SimpleGuard stub
        simpleguard_stub = simpleguard_pb2_grpc.SimpleGuardServiceStub(client._channel)

        # Build request
        request = simpleguard_pb2.GenerateKeyPairRequest(
            algorithm=trust_pb2.KEY_ALGORITHM_ED25519,
            key_id=key_id,
            metadata={},
        )

        # Make RPC call
        response = await simpleguard_stub.GenerateKeyPair(request)

        if response.error_message:
            raise KeyGenerationError(f"Key generation failed: {response.error_message}")

        result = {
            "key_id": response.key_id,
            "did_key": response.did_key,
            "public_key_pem": response.public_key_pem,
            "private_key_pem": response.private_key_pem,
        }

        # Save private key to file if output_dir provided
        if output_dir:
            output_path = Path(output_dir)
            output_path.mkdir(parents=True, exist_ok=True)

            key_filename = f"{response.key_id}.pem"
            key_path = output_path / key_filename

            with open(key_path, "w") as f:
                f.write(response.private_key_pem)

            # Set restrictive permissions (owner read/write only)
            os.chmod(key_path, 0o600)

            result["private_key_path"] = str(key_path)
            logger.info(f"Private key saved to {key_path}")

        logger.info(f"Generated keypair with DID: {response.did_key}")
        return result

    except CoreConnectionError:
        raise
    except Exception as e:
        raise KeyGenerationError(f"Failed to generate keypair: {e}") from e


def generate_server_keypair_sync(
    key_id: str = "",
    output_dir: Optional[str] = None,
) -> dict:
    """
    Sync wrapper for generate_server_keypair.

    See generate_server_keypair() for full documentation.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop is not None:
        import concurrent.futures

        future = asyncio.run_coroutine_threadsafe(
            generate_server_keypair(key_id, output_dir),
            loop,
        )
        return future.result(timeout=60.0)
    else:
        return asyncio.run(generate_server_keypair(key_id, output_dir))


# =============================================================================
# Registry Registration (via HTTP)
# =============================================================================


async def register_server_identity(
    server_id: str,
    api_key: str,
    did: str,
    public_key: str,
    ca_url: str = "https://registry.capisc.io",
) -> dict:
    """
    Register MCP server DID with the CapiscIO registry.

    Uses PUT /v1/sdk/servers/{id} to update the server's DID and public key.
    This follows the same pattern as agent identity registration.

    Args:
        server_id: The MCP server's UUID (from dashboard creation)
        api_key: Registry API key (X-Capiscio-Registry-Key)
        did: The server's DID (e.g., did:key:z6Mk...)
        public_key: PEM-encoded public key
        ca_url: Registry URL (default: https://registry.capisc.io)

    Returns:
        dict with:
            - success: True if registration succeeded
            - message: Status message
            - data: Updated server object (if successful)

    Raises:
        RegistrationError: If registration fails

    Example:
        result = await register_server_identity(
            server_id="550e8400-e29b-41d4-a716-446655440000",
            api_key="sk_live_abc123...",
            did="did:key:z6MkhaXgBZD...",
            public_key="-----BEGIN PUBLIC KEY-----...",
        )
    """
    # Run in thread pool to avoid blocking async loop
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None,
        _register_server_identity_sync,
        server_id,
        api_key,
        did,
        public_key,
        ca_url,
    )


def _register_server_identity_sync(
    server_id: str,
    api_key: str,
    did: str,
    public_key: str,
    ca_url: str,
) -> dict:
    """Sync implementation of register_server_identity."""
    url = f"{ca_url.rstrip('/')}/v1/sdk/servers/{server_id}"

    headers = {
        "Content-Type": "application/json",
        "X-Capiscio-Registry-Key": api_key,
    }

    payload = {
        "did": did,
        "publicKey": public_key,
    }

    try:
        response = requests.put(url, json=payload, headers=headers, timeout=30)

        if response.status_code == 200:
            data = response.json()
            logger.info(f"Successfully registered server identity: {did}")
            return {
                "success": True,
                "message": "Server identity registered successfully",
                "data": data.get("data"),
            }
        elif response.status_code == 400:
            error_data = response.json()
            error_msg = error_data.get("message", "Invalid request")
            raise RegistrationError(f"Bad request: {error_msg}", status_code=400)
        elif response.status_code == 401:
            raise RegistrationError("Invalid API key", status_code=401)
        elif response.status_code == 404:
            raise RegistrationError(f"Server not found: {server_id}", status_code=404)
        else:
            raise RegistrationError(
                f"Registration failed with status {response.status_code}",
                status_code=response.status_code,
            )

    except requests.RequestException as e:
        raise RegistrationError(f"Network error: {e}") from e


def register_server_identity_sync(
    server_id: str,
    api_key: str,
    did: str,
    public_key: str,
    ca_url: str = "https://registry.capisc.io",
) -> dict:
    """
    Sync wrapper for register_server_identity.

    See register_server_identity() for full documentation.
    """
    return _register_server_identity_sync(server_id, api_key, did, public_key, ca_url)


# =============================================================================
# Convenience: Combined Setup
# =============================================================================


async def setup_server_identity(
    server_id: str,
    api_key: str,
    ca_url: str = "https://registry.capisc.io",
    output_dir: Optional[str] = None,
    key_id: str = "",
) -> dict:
    """
    Generate keypair and register server identity in one call.

    This is the recommended way to set up MCP server identity:
    1. Generates Ed25519 keypair via capiscio-core
    2. Registers the DID with the CapiscIO registry
    3. Optionally saves the private key to disk

    Args:
        server_id: The MCP server's UUID (from dashboard creation)
        api_key: Registry API key (X-Capiscio-Registry-Key)
        ca_url: Registry URL (default: https://registry.capisc.io)
        output_dir: Optional directory to save private key PEM file
        key_id: Optional specific key ID. If empty, one is generated.

    Returns:
        dict with:
            - did: The server's DID (did:key:z6Mk...)
            - public_key_pem: PEM-encoded public key
            - private_key_pem: PEM-encoded private key
            - private_key_path: Path to saved key (if output_dir provided)
            - key_id: The key identifier

    Raises:
        KeyGenerationError: If key generation fails
        RegistrationError: If registry registration fails
        CoreConnectionError: If connection to capiscio-core fails

    Example:
        result = await setup_server_identity(
            server_id="550e8400-e29b-41d4-a716-446655440000",
            api_key="sk_live_abc123...",
            output_dir="./keys",
        )

        # Use result['private_key_pem'] for PoP signing
        # Save result['did'] for server identity disclosure
    """
    # Step 1: Generate keypair
    logger.info(f"Generating keypair for server {server_id}...")
    keys = await generate_server_keypair(key_id=key_id, output_dir=output_dir)

    # Step 2: Register with registry
    logger.info(f"Registering DID {keys['did_key']} with registry...")
    await register_server_identity(
        server_id=server_id,
        api_key=api_key,
        did=keys["did_key"],
        public_key=keys["public_key_pem"],
        ca_url=ca_url,
    )

    result = {
        "did": keys["did_key"],
        "public_key_pem": keys["public_key_pem"],
        "private_key_pem": keys["private_key_pem"],
        "key_id": keys["key_id"],
    }

    if "private_key_path" in keys:
        result["private_key_path"] = keys["private_key_path"]

    logger.info(f"Server identity setup complete: {keys['did_key']}")
    return result


def setup_server_identity_sync(
    server_id: str,
    api_key: str,
    ca_url: str = "https://registry.capisc.io",
    output_dir: Optional[str] = None,
    key_id: str = "",
) -> dict:
    """
    Sync wrapper for setup_server_identity.

    See setup_server_identity() for full documentation.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop is not None:
        import concurrent.futures

        future = asyncio.run_coroutine_threadsafe(
            setup_server_identity(server_id, api_key, ca_url, output_dir, key_id),
            loop,
        )
        return future.result(timeout=120.0)
    else:
        return asyncio.run(
            setup_server_identity(server_id, api_key, ca_url, output_dir, key_id)
        )
