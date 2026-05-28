"""
Live integration tests for MCPServerIdentity.connect().

Tests the full "Let's Encrypt"-style server identity flow:
  connect() → generate keypair (gRPC) → register (REST) → issue badge → keeper

Requires:
- capiscio-core gRPC server (for key generation)
- capiscio-server REST API (for registration + badge issuance)
"""

import os
import tempfile

import pytest
import requests

from capiscio_mcp.connect import MCPServerIdentity
from capiscio_mcp.errors import CoreConnectionError

_server_url = os.getenv("CAPISCIO_SERVER_URL", "http://localhost:8080")

def _infra_available():
    core = bool(
        os.environ.get("CAPISCIO_CORE_ADDR")
        or os.environ.get("CAPISCIO_BINARY_PATH")
    )
    try:
        resp = requests.get(f"{_server_url}/health", timeout=2)
        server = resp.status_code == 200
    except requests.exceptions.RequestException:
        server = False
    return core and server

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not _infra_available(),
        reason="Both capiscio-server and capiscio-core required",
    ),
]


class TestMCPServerIdentityConnect:
    """Test MCPServerIdentity.connect() against live infrastructure."""

    async def test_connect_generates_keypair(self, server_url, api_key):
        """connect() should generate an Ed25519 keypair via gRPC."""
        with tempfile.TemporaryDirectory() as keys_dir:
            try:
                identity = await MCPServerIdentity.connect(
                    server_id="test-integration-connect",
                    api_key=api_key,
                    server_url=server_url,
                    keys_dir=keys_dir,
                    auto_badge=False,
                )

                assert os.path.exists(os.path.join(keys_dir, "private_key.pem"))
                assert os.path.exists(os.path.join(keys_dir, "public_key.pem"))
                assert os.path.exists(os.path.join(keys_dir, "did.txt"))
                assert identity.did is not None
                assert identity.did.startswith("did:")

                identity.close()
            except CoreConnectionError:
                pytest.skip("Core connection failed — binary may not support this flow")

    async def test_connect_full_flow(self, server_url, api_key):
        """Full connect flow: keygen → register → badge → keeper."""
        with tempfile.TemporaryDirectory() as keys_dir:
            try:
                identity = await MCPServerIdentity.connect(
                    server_id="test-integration-full",
                    api_key=api_key,
                    server_url=server_url,
                    keys_dir=keys_dir,
                    auto_badge=True,
                )

                badge = identity.get_badge()
                assert badge is not None
                assert isinstance(badge, str)
                assert len(badge.split(".")) == 3  # JWS compact

                assert identity.did is not None

                identity.close()
            except CoreConnectionError:
                pytest.skip("Core connection failed")
            except Exception as e:
                if "401" in str(e) or "403" in str(e):
                    pytest.skip(f"Auth error (expected in CI without valid key): {e}")
                raise

    async def test_connect_idempotent_registration(self, server_url, api_key):
        """Calling connect() twice with same server_id should be idempotent."""
        with tempfile.TemporaryDirectory() as keys_dir:
            try:
                identity1 = await MCPServerIdentity.connect(
                    server_id="test-integration-idempotent",
                    api_key=api_key,
                    server_url=server_url,
                    keys_dir=keys_dir,
                    auto_badge=False,
                )
                did1 = identity1.did
                identity1.close()

                identity2 = await MCPServerIdentity.connect(
                    server_id="test-integration-idempotent",
                    api_key=api_key,
                    server_url=server_url,
                    keys_dir=keys_dir,
                    auto_badge=False,
                )
                did2 = identity2.did
                identity2.close()

                assert did1 == did2
            except CoreConnectionError:
                pytest.skip("Core connection failed")
            except Exception as e:
                if "401" in str(e) or "403" in str(e):
                    pytest.skip(f"Auth error: {e}")
                raise

    async def test_connect_context_manager(self, server_url, api_key):
        """MCPServerIdentity should work as a context manager."""
        with tempfile.TemporaryDirectory() as keys_dir:
            try:
                identity = await MCPServerIdentity.connect(
                    server_id="test-integration-ctx",
                    api_key=api_key,
                    server_url=server_url,
                    keys_dir=keys_dir,
                    auto_badge=False,
                )
                with identity:
                    assert identity.did is not None
            except CoreConnectionError:
                pytest.skip("Core connection failed")
            except Exception as e:
                if "401" in str(e) or "403" in str(e):
                    pytest.skip(f"Auth error: {e}")
                raise

    async def test_connect_invalid_api_key_rejected(self, server_url):
        """Invalid API key should be rejected by the server."""
        with tempfile.TemporaryDirectory() as keys_dir:
            with pytest.raises(Exception):
                await MCPServerIdentity.connect(
                    server_id="test-integration-badkey",
                    api_key="invalid-key-that-should-fail",
                    server_url=server_url,
                    keys_dir=keys_dir,
                    auto_badge=True,
                )
