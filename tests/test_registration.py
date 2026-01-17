"""
Tests for capiscio_mcp.registration module.

Tests MCP server identity registration following the agent DID pattern.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import json


class TestKeyGenerationErrors:
    """Tests for key generation error handling."""

    @pytest.mark.asyncio
    async def test_generate_keypair_grpc_error(self):
        """Raise KeyGenerationError on gRPC failure."""
        from capiscio_mcp.registration import (
            generate_server_keypair,
            KeyGenerationError,
        )

        with patch("capiscio_mcp._core.client.CoreClient") as mock_client_class:
            mock_instance = AsyncMock()
            mock_instance._channel = MagicMock()
            mock_client_class.get_instance = AsyncMock(return_value=mock_instance)
            
            # Simulate gRPC error via async stub
            mock_stub = AsyncMock()
            mock_stub.GenerateKeyPair.side_effect = Exception("gRPC error")
            
            with patch.dict("sys.modules", {
                "capiscio_mcp._proto.gen.capiscio.v1.simpleguard_pb2": MagicMock(),
                "capiscio_mcp._proto.gen.capiscio.v1.simpleguard_pb2_grpc": MagicMock(
                    SimpleGuardServiceStub=MagicMock(return_value=mock_stub)
                ),
                "capiscio_mcp._proto.gen.capiscio.v1.trust_pb2": MagicMock(),
            }):
                with pytest.raises(KeyGenerationError):
                    await generate_server_keypair()


class TestKeyGenerationSuccess:
    """Tests for successful key generation."""

    @pytest.mark.asyncio
    async def test_generate_keypair_success(self):
        """Successfully generate a keypair."""
        from capiscio_mcp.registration import generate_server_keypair

        # Create mock response
        mock_response = MagicMock()
        mock_response.key_id = "test-key-id-123"
        mock_response.public_key_pem = "-----BEGIN PUBLIC KEY-----\nMCowBQ..."
        mock_response.private_key_pem = "-----BEGIN PRIVATE KEY-----\nMC4CA..."
        mock_response.did_key = "did:key:z6MkTestKeyHere"
        mock_response.error_message = ""
        
        mock_stub = AsyncMock()
        mock_stub.GenerateKeyPair.return_value = mock_response

        with patch("capiscio_mcp._core.client.CoreClient") as mock_client_class:
            mock_instance = AsyncMock()
            mock_instance._channel = MagicMock()
            mock_client_class.get_instance = AsyncMock(return_value=mock_instance)

            with patch.dict("sys.modules", {
                "capiscio_mcp._proto.gen.capiscio.v1.simpleguard_pb2": MagicMock(),
                "capiscio_mcp._proto.gen.capiscio.v1.simpleguard_pb2_grpc": MagicMock(
                    SimpleGuardServiceStub=MagicMock(return_value=mock_stub)
                ),
                "capiscio_mcp._proto.gen.capiscio.v1.trust_pb2": MagicMock(),
            }):
                result = await generate_server_keypair()

                assert result["key_id"] == "test-key-id-123"
                assert result["public_key_pem"] == mock_response.public_key_pem
                assert result["private_key_pem"] == mock_response.private_key_pem
                assert result["did_key"] == "did:key:z6MkTestKeyHere"


class TestRegistrationErrors:
    """Tests for registration error handling."""

    @pytest.mark.asyncio
    async def test_register_missing_params(self):
        """Test registration with empty params."""
        from capiscio_mcp.registration import (
            register_server_identity,
            RegistrationError,
        )

        # Test with a mock that returns 400
        with patch("capiscio_mcp.registration.requests.put") as mock_put:
            mock_response = MagicMock()
            mock_response.status_code = 400
            mock_response.json.return_value = {"message": "Bad request"}
            mock_put.return_value = mock_response

            with pytest.raises(RegistrationError, match="Bad request"):
                await register_server_identity(
                    server_id="test-server",
                    did="did:key:z6MkTest",
                    public_key="-----BEGIN PUBLIC KEY-----\ntest",
                    api_key="test-key",
                    ca_url="https://api.capisc.io",
                )

    @pytest.mark.asyncio
    async def test_register_unauthorized(self):
        """Raise RegistrationError on 401."""
        from capiscio_mcp.registration import (
            register_server_identity,
            RegistrationError,
        )

        with patch("capiscio_mcp.registration.requests.put") as mock_put:
            mock_response = MagicMock()
            mock_response.status_code = 401
            mock_put.return_value = mock_response

            with pytest.raises(RegistrationError, match="Invalid API key"):
                await register_server_identity(
                    server_id="test-server",
                    did="did:key:z6MkTest",
                    public_key="-----BEGIN PUBLIC KEY-----\ntest",
                    api_key="invalid-key",
                    ca_url="https://api.capisc.io",
                )


class TestRegistrationSuccess:
    """Tests for successful registration."""

    @pytest.mark.asyncio
    async def test_register_server_identity_success(self):
        """Successfully register server identity."""
        from capiscio_mcp.registration import register_server_identity

        with patch("capiscio_mcp.registration.requests.put") as mock_put:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "data": {
                    "id": "test-server",
                    "did": "did:key:z6MkTest",
                    "publicKey": "-----BEGIN PUBLIC KEY-----\ntest",
                }
            }
            mock_put.return_value = mock_response

            result = await register_server_identity(
                server_id="test-server",
                did="did:key:z6MkTest",
                public_key="-----BEGIN PUBLIC KEY-----\ntest",
                api_key="valid-key",
                ca_url="https://api.capisc.io",
            )

            assert result["success"] is True
            assert result["data"]["did"] == "did:key:z6MkTest"

            # Verify the PUT was called correctly
            mock_put.assert_called_once()
            call_args = mock_put.call_args
            assert "/v1/sdk/servers/test-server" in call_args[0][0]
            assert call_args[1]["headers"]["X-Capiscio-Registry-Key"] == "valid-key"

    def test_register_server_identity_sync(self):
        """Test synchronous registration wrapper."""
        from capiscio_mcp.registration import register_server_identity_sync

        with patch("capiscio_mcp.registration.requests.put") as mock_put:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"data": {"id": "sync-server"}}
            mock_put.return_value = mock_response

            result = register_server_identity_sync(
                server_id="sync-server",
                did="did:key:z6MkSync",
                public_key="-----BEGIN PUBLIC KEY-----\ntest",
                api_key="test-key",
                ca_url="https://api.capisc.io",
            )

            assert result["success"] is True


class TestSetupServerIdentity:
    """Tests for the combined setup_server_identity function."""

    @pytest.mark.asyncio
    async def test_setup_server_identity_success(self):
        """Successfully setup server identity end-to-end."""
        from capiscio_mcp.registration import setup_server_identity

        # Mock key generation response
        mock_key_response = MagicMock()
        mock_key_response.key_id = "generated-key-id"
        mock_key_response.public_key_pem = "-----BEGIN PUBLIC KEY-----\ngenerated"
        mock_key_response.private_key_pem = "-----BEGIN PRIVATE KEY-----\ngenerated"
        mock_key_response.did_key = "did:key:z6MkGenerated"
        mock_key_response.error_message = ""
        
        mock_stub = AsyncMock()
        mock_stub.GenerateKeyPair.return_value = mock_key_response

        with patch("capiscio_mcp._core.client.CoreClient") as mock_client_class:
            mock_instance = AsyncMock()
            mock_instance._channel = MagicMock()
            mock_client_class.get_instance = AsyncMock(return_value=mock_instance)

            with patch.dict("sys.modules", {
                "capiscio_mcp._proto.gen.capiscio.v1.simpleguard_pb2": MagicMock(),
                "capiscio_mcp._proto.gen.capiscio.v1.simpleguard_pb2_grpc": MagicMock(
                    SimpleGuardServiceStub=MagicMock(return_value=mock_stub)
                ),
                "capiscio_mcp._proto.gen.capiscio.v1.trust_pb2": MagicMock(),
            }):
                with patch("capiscio_mcp.registration.requests.put") as mock_put:
                    mock_reg_response = MagicMock()
                    mock_reg_response.status_code = 200
                    mock_reg_response.json.return_value = {
                        "data": {
                            "id": "my-server",
                            "did": "did:key:z6MkGenerated",
                        }
                    }
                    mock_put.return_value = mock_reg_response

                    result = await setup_server_identity(
                        server_id="my-server",
                        api_key="my-api-key",
                        ca_url="https://api.capisc.io",
                    )

                    # Check result contains keypair and registration info
                    assert result["did"] == "did:key:z6MkGenerated"
                    assert result["private_key_pem"] == "-----BEGIN PRIVATE KEY-----\ngenerated"
                    assert result["key_id"] == "generated-key-id"


class TestRegistrationIdempotency:
    """Tests for idempotent registration behavior."""

    @pytest.mark.asyncio
    async def test_register_twice_same_identity(self):
        """Registering the same identity twice should succeed (PUT is idempotent)."""
        from capiscio_mcp.registration import register_server_identity

        with patch("capiscio_mcp.registration.requests.put") as mock_put:
            # Both calls return success
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "data": {
                    "id": "idempotent-server",
                    "did": "did:key:z6MkSame",
                }
            }
            mock_put.return_value = mock_response

            # First registration
            result1 = await register_server_identity(
                server_id="idempotent-server",
                did="did:key:z6MkSame",
                public_key="-----BEGIN PUBLIC KEY-----\ntest",
                api_key="key",
                ca_url="https://api.capisc.io",
            )

            # Second registration with same data
            result2 = await register_server_identity(
                server_id="idempotent-server",
                did="did:key:z6MkSame",
                public_key="-----BEGIN PUBLIC KEY-----\ntest",
                api_key="key",
                ca_url="https://api.capisc.io",
            )

            assert result1["success"] == result2["success"]
            assert mock_put.call_count == 2


class TestExceptionTypes:
    """Tests for exception type handling."""

    def test_registration_error_inheritance(self):
        """RegistrationError should be a proper Exception."""
        from capiscio_mcp.registration import RegistrationError

        error = RegistrationError("test message")
        assert isinstance(error, Exception)
        assert str(error) == "test message"

    def test_key_generation_error_inheritance(self):
        """KeyGenerationError should be a proper Exception."""
        from capiscio_mcp.registration import KeyGenerationError

        error = KeyGenerationError("key gen failed")
        assert isinstance(error, Exception)
        assert str(error) == "key gen failed"

    def test_registration_error_has_status_code(self):
        """RegistrationError should accept status_code."""
        from capiscio_mcp.registration import RegistrationError

        error = RegistrationError("test", status_code=401)
        assert error.status_code == 401


class TestRequestPayload:
    """Tests for the correct request payload format."""

    @pytest.mark.asyncio
    async def test_request_payload_structure(self):
        """Verify the PUT request payload has correct structure."""
        from capiscio_mcp.registration import register_server_identity

        with patch("capiscio_mcp.registration.requests.put") as mock_put:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"data": {"id": "test"}}
            mock_put.return_value = mock_response

            await register_server_identity(
                server_id="payload-test",
                did="did:key:z6MkPayload",
                public_key="-----BEGIN PUBLIC KEY-----\npayload",
                api_key="test-key",
                ca_url="https://api.capisc.io",
            )

            # Check the JSON payload
            call_args = mock_put.call_args
            json_payload = call_args[1]["json"]

            assert json_payload["did"] == "did:key:z6MkPayload"
            assert json_payload["publicKey"] == "-----BEGIN PUBLIC KEY-----\npayload"

    @pytest.mark.asyncio
    async def test_request_headers(self):
        """Verify the request headers are correct."""
        from capiscio_mcp.registration import register_server_identity

        with patch("capiscio_mcp.registration.requests.put") as mock_put:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"data": {"id": "test"}}
            mock_put.return_value = mock_response

            await register_server_identity(
                server_id="header-test",
                did="did:key:z6MkHeader",
                public_key="-----BEGIN PUBLIC KEY-----\nheader",
                api_key="my-special-key",
                ca_url="https://api.capisc.io",
            )

            call_args = mock_put.call_args
            headers = call_args[1]["headers"]

            assert headers["X-Capiscio-Registry-Key"] == "my-special-key"
            assert headers["Content-Type"] == "application/json"

    @pytest.mark.asyncio
    async def test_request_url_construction(self):
        """Verify URL is constructed correctly."""
        from capiscio_mcp.registration import register_server_identity

        with patch("capiscio_mcp.registration.requests.put") as mock_put:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"data": {"id": "test"}}
            mock_put.return_value = mock_response

            await register_server_identity(
                server_id="url-test-server",
                did="did:key:z6MkUrl",
                public_key="-----BEGIN PUBLIC KEY-----\nurl",
                api_key="key",
                ca_url="https://api.capisc.io",
            )

            call_args = mock_put.call_args
            url = call_args[0][0]

            assert url == "https://api.capisc.io/v1/sdk/servers/url-test-server"

    @pytest.mark.asyncio
    async def test_ca_url_trailing_slash(self):
        """Handle ca_url with trailing slash."""
        from capiscio_mcp.registration import register_server_identity

        with patch("capiscio_mcp.registration.requests.put") as mock_put:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"data": {"id": "test"}}
            mock_put.return_value = mock_response

            await register_server_identity(
                server_id="slash-test",
                did="did:key:z6MkSlash",
                public_key="-----BEGIN PUBLIC KEY-----\nslash",
                api_key="key",
                ca_url="https://api.capisc.io/",  # Note trailing slash
            )

            call_args = mock_put.call_args
            url = call_args[0][0]

            # Should not have double slash
            assert "//" not in url.replace("https://", "")


class TestNetworkErrors:
    """Tests for network error handling."""

    @pytest.mark.asyncio
    async def test_register_network_timeout(self):
        """Raise RegistrationError on network timeout."""
        from capiscio_mcp.registration import (
            register_server_identity,
            RegistrationError,
        )

        with patch("capiscio_mcp.registration.requests.put") as mock_put:
            import requests as req_lib
            mock_put.side_effect = req_lib.exceptions.Timeout("Connection timed out")

            with pytest.raises(RegistrationError, match="Network error"):
                await register_server_identity(
                    server_id="timeout-test",
                    did="did:key:z6MkTimeout",
                    public_key="-----BEGIN PUBLIC KEY-----\ntest",
                    api_key="key",
                    ca_url="https://api.capisc.io",
                )

    @pytest.mark.asyncio
    async def test_register_connection_error(self):
        """Raise RegistrationError on connection failure."""
        from capiscio_mcp.registration import (
            register_server_identity,
            RegistrationError,
        )

        with patch("capiscio_mcp.registration.requests.put") as mock_put:
            import requests as req_lib
            mock_put.side_effect = req_lib.exceptions.ConnectionError("Connection refused")

            with pytest.raises(RegistrationError, match="Network error"):
                await register_server_identity(
                    server_id="conn-error-test",
                    did="did:key:z6MkConnError",
                    public_key="-----BEGIN PUBLIC KEY-----\ntest",
                    api_key="key",
                    ca_url="https://api.capisc.io",
                )


class TestServerNotFound:
    """Tests for server not found handling."""

    @pytest.mark.asyncio
    async def test_register_server_not_found(self):
        """Raise RegistrationError when server ID doesn't exist."""
        from capiscio_mcp.registration import (
            register_server_identity,
            RegistrationError,
        )

        with patch("capiscio_mcp.registration.requests.put") as mock_put:
            mock_response = MagicMock()
            mock_response.status_code = 404
            mock_put.return_value = mock_response

            with pytest.raises(RegistrationError, match="not found"):
                await register_server_identity(
                    server_id="nonexistent-server",
                    did="did:key:z6MkNotFound",
                    public_key="-----BEGIN PUBLIC KEY-----\ntest",
                    api_key="key",
                    ca_url="https://api.capisc.io",
                )


class TestKeyGenerationWithErrorMessage:
    """Tests for key generation when server returns error message."""

    @pytest.mark.asyncio
    async def test_generate_keypair_server_error_message(self):
        """Raise KeyGenerationError when server returns error_message."""
        from capiscio_mcp.registration import (
            generate_server_keypair,
            KeyGenerationError,
        )

        # Create mock response with error_message
        mock_response = MagicMock()
        mock_response.key_id = ""
        mock_response.public_key_pem = ""
        mock_response.private_key_pem = ""
        mock_response.did_key = ""
        mock_response.error_message = "Key generation failed: invalid algorithm"
        
        mock_stub = AsyncMock()
        mock_stub.GenerateKeyPair.return_value = mock_response

        with patch("capiscio_mcp._core.client.CoreClient") as mock_client_class:
            mock_instance = AsyncMock()
            mock_instance._channel = MagicMock()
            mock_client_class.get_instance = AsyncMock(return_value=mock_instance)

            with patch.dict("sys.modules", {
                "capiscio_mcp._proto.gen.capiscio.v1.simpleguard_pb2": MagicMock(),
                "capiscio_mcp._proto.gen.capiscio.v1.simpleguard_pb2_grpc": MagicMock(
                    SimpleGuardServiceStub=MagicMock(return_value=mock_stub)
                ),
                "capiscio_mcp._proto.gen.capiscio.v1.trust_pb2": MagicMock(),
            }):
                with pytest.raises(KeyGenerationError, match="Key generation failed"):
                    await generate_server_keypair()


class TestOutputDirSaving:
    """Tests for saving private key to output directory."""

    @pytest.mark.asyncio
    async def test_generate_keypair_saves_to_output_dir(self, tmp_path):
        """Successfully save private key to output directory."""
        from capiscio_mcp.registration import generate_server_keypair

        # Create mock response
        mock_response = MagicMock()
        mock_response.key_id = "saved-key-id"
        mock_response.public_key_pem = "-----BEGIN PUBLIC KEY-----\ntest"
        mock_response.private_key_pem = "-----BEGIN PRIVATE KEY-----\nsecret"
        mock_response.did_key = "did:key:z6MkSaved"
        mock_response.error_message = ""
        
        mock_stub = AsyncMock()
        mock_stub.GenerateKeyPair.return_value = mock_response

        with patch("capiscio_mcp._core.client.CoreClient") as mock_client_class:
            mock_instance = AsyncMock()
            mock_instance._channel = MagicMock()
            mock_client_class.get_instance = AsyncMock(return_value=mock_instance)

            with patch.dict("sys.modules", {
                "capiscio_mcp._proto.gen.capiscio.v1.simpleguard_pb2": MagicMock(),
                "capiscio_mcp._proto.gen.capiscio.v1.simpleguard_pb2_grpc": MagicMock(
                    SimpleGuardServiceStub=MagicMock(return_value=mock_stub)
                ),
                "capiscio_mcp._proto.gen.capiscio.v1.trust_pb2": MagicMock(),
            }):
                result = await generate_server_keypair(output_dir=str(tmp_path))

                # Check result includes path
                assert "private_key_path" in result
                
                # Verify file was created (mocked, but path should exist in result)
                assert result["private_key_path"].endswith(".pem")


class TestSetupServerIdentityErrors:
    """Tests for setup_server_identity error scenarios."""

    @pytest.mark.asyncio
    async def test_setup_fails_on_key_generation_error(self):
        """setup_server_identity should fail if key generation fails."""
        from capiscio_mcp.registration import (
            setup_server_identity,
            KeyGenerationError,
        )

        mock_stub = AsyncMock()
        mock_stub.GenerateKeyPair.side_effect = Exception("gRPC unavailable")

        with patch("capiscio_mcp._core.client.CoreClient") as mock_client_class:
            mock_instance = AsyncMock()
            mock_instance._channel = MagicMock()
            mock_client_class.get_instance = AsyncMock(return_value=mock_instance)

            with patch.dict("sys.modules", {
                "capiscio_mcp._proto.gen.capiscio.v1.simpleguard_pb2": MagicMock(),
                "capiscio_mcp._proto.gen.capiscio.v1.simpleguard_pb2_grpc": MagicMock(
                    SimpleGuardServiceStub=MagicMock(return_value=mock_stub)
                ),
                "capiscio_mcp._proto.gen.capiscio.v1.trust_pb2": MagicMock(),
            }):
                with pytest.raises(KeyGenerationError):
                    await setup_server_identity(
                        server_id="fail-test",
                        api_key="key",
                        ca_url="https://api.capisc.io",
                    )

    @pytest.mark.asyncio
    async def test_setup_fails_on_registration_error(self):
        """setup_server_identity should fail if registration fails."""
        from capiscio_mcp.registration import (
            setup_server_identity,
            RegistrationError,
        )

        # Mock successful key generation
        mock_key_response = MagicMock()
        mock_key_response.key_id = "gen-key"
        mock_key_response.public_key_pem = "-----BEGIN PUBLIC KEY-----\ntest"
        mock_key_response.private_key_pem = "-----BEGIN PRIVATE KEY-----\ntest"
        mock_key_response.did_key = "did:key:z6MkGenKey"
        mock_key_response.error_message = ""
        
        mock_stub = AsyncMock()
        mock_stub.GenerateKeyPair.return_value = mock_key_response

        with patch("capiscio_mcp._core.client.CoreClient") as mock_client_class:
            mock_instance = AsyncMock()
            mock_instance._channel = MagicMock()
            mock_client_class.get_instance = AsyncMock(return_value=mock_instance)

            with patch.dict("sys.modules", {
                "capiscio_mcp._proto.gen.capiscio.v1.simpleguard_pb2": MagicMock(),
                "capiscio_mcp._proto.gen.capiscio.v1.simpleguard_pb2_grpc": MagicMock(
                    SimpleGuardServiceStub=MagicMock(return_value=mock_stub)
                ),
                "capiscio_mcp._proto.gen.capiscio.v1.trust_pb2": MagicMock(),
            }):
                # Mock failing registration
                with patch("capiscio_mcp.registration.requests.put") as mock_put:
                    mock_response = MagicMock()
                    mock_response.status_code = 500
                    mock_put.return_value = mock_response

                    with pytest.raises(RegistrationError):
                        await setup_server_identity(
                            server_id="fail-reg-test",
                            api_key="key",
                            ca_url="https://api.capisc.io",
                        )
