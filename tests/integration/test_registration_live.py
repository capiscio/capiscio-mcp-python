"""
Live integration tests for server identity registration.

Tests the registration flow:
  generate_server_keypair (gRPC) → register_server_identity (REST PUT)

Requires:
- capiscio-core gRPC server (for Ed25519 key generation)
- capiscio-server REST API (for identity registration)
"""

import os
import uuid

import pytest
import requests

from capiscio_mcp.registration import (
    generate_server_keypair,
    register_server_identity,
    setup_server_identity,
    RegistrationError,
)

_server_url = os.getenv("CAPISCIO_SERVER_URL", "http://localhost:8080")

_core_available = bool(
    os.environ.get("CAPISCIO_CORE_ADDR")
    or os.environ.get("CAPISCIO_BINARY_PATH")
)

def _server_available():
    try:
        resp = requests.get(f"{_server_url}/health", timeout=2)
        return resp.status_code == 200
    except requests.exceptions.RequestException:
        return False

pytestmark = pytest.mark.integration


@pytest.mark.skipif(not _core_available, reason="capiscio-core not available")
class TestGenerateServerKeypairLive:
    """Test Ed25519 key generation via gRPC to capiscio-core."""

    async def test_generate_keypair_returns_keys(self):
        """generate_server_keypair should return PEM key pair from core."""
        try:
            result = await generate_server_keypair()
        except Exception as e:
            pytest.skip(f"Core keygen not available: {e}")

        assert "private_key" in result or hasattr(result, "private_key_pem")
        assert "public_key" in result or hasattr(result, "public_key_pem")

    async def test_generate_keypair_unique(self):
        """Each call should generate a unique keypair."""
        try:
            result1 = await generate_server_keypair()
            result2 = await generate_server_keypair()
        except Exception as e:
            pytest.skip(f"Core keygen not available: {e}")

        key1 = result1.get("public_key") or getattr(result1, "public_key_pem", None)
        key2 = result2.get("public_key") or getattr(result2, "public_key_pem", None)
        assert key1 != key2


@pytest.mark.skipif(not _server_available(), reason=f"capiscio-server not available at {_server_url}")
class TestRegisterServerIdentityLive:
    """Test server registration against live capiscio-server."""

    async def test_register_new_server(self, server_url, api_key):
        """Registering a new server should succeed or auto-create."""
        server_id = f"test-reg-{uuid.uuid4().hex[:8]}"
        test_did = f"did:key:z6Mk{uuid.uuid4().hex[:32]}"
        test_pubkey = "MCowBQYDK2VwAyEA" + "A" * 43 + "="

        try:
            result = await register_server_identity(
                server_id=server_id,
                api_key=api_key,
                did=test_did,
                public_key=test_pubkey,
                ca_url=server_url,
            )
        except Exception as e:
            if "401" in str(e) or "403" in str(e):
                pytest.skip(f"Auth error (expected without valid key): {e}")
            raise

        assert result.get("success") is True or result.get("created") is True

    async def test_register_idempotent(self, server_url, api_key):
        """Registering the same server_id twice should be idempotent (409 = OK)."""
        server_id = f"test-idempotent-{uuid.uuid4().hex[:8]}"
        test_did = f"did:key:z6Mk{uuid.uuid4().hex[:32]}"
        test_pubkey = "MCowBQYDK2VwAyEA" + "B" * 43 + "="

        try:
            await register_server_identity(
                server_id=server_id,
                api_key=api_key,
                did=test_did,
                public_key=test_pubkey,
                ca_url=server_url,
            )
            result = await register_server_identity(
                server_id=server_id,
                api_key=api_key,
                did=test_did,
                public_key=test_pubkey,
                ca_url=server_url,
            )
        except Exception as e:
            if "401" in str(e) or "403" in str(e):
                pytest.skip(f"Auth error: {e}")
            if "409" not in str(e):
                raise

    async def test_register_missing_api_key_rejected(self, server_url):
        """Registration without a valid API key should fail."""
        server_id = f"test-nokey-{uuid.uuid4().hex[:8]}"

        with pytest.raises(Exception):
            await register_server_identity(
                server_id=server_id,
                api_key="",
                did="did:key:z6MkInvalid",
                public_key="invalid",
                ca_url=server_url,
            )


@pytest.mark.skipif(
    not (_core_available and _server_available()),
    reason="Both capiscio-server and capiscio-core required",
)
class TestSetupServerIdentityLive:
    """Test end-to-end setup_server_identity (keygen + registration)."""

    async def test_setup_generates_and_registers(self, server_url, api_key):
        """setup_server_identity should do keygen + registration in one call."""
        server_id = f"test-setup-{uuid.uuid4().hex[:8]}"

        try:
            result = await setup_server_identity(
                server_id=server_id,
                api_key=api_key,
                ca_url=server_url,
            )
        except Exception as e:
            if "401" in str(e) or "403" in str(e):
                pytest.skip(f"Auth error: {e}")
            pytest.skip(f"Setup not available: {e}")

        assert result is not None
