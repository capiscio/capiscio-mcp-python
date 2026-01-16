"""Tests for capiscio_mcp.server module (RFC-007 implementation)."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from capiscio_mcp.server import (
    verify_server,
    verify_server_sync,
    verify_server_strict,
    parse_http_headers,
    parse_jsonrpc_meta,
    VerifyConfig,
    VerifyResult,
)
from capiscio_mcp.types import ServerState, ServerErrorCode, TrustLevel
from capiscio_mcp.errors import ServerVerifyError


class TestVerifyConfig:
    """Tests for VerifyConfig dataclass."""
    
    def test_default_values(self):
        """Default config should have sensible defaults."""
        config = VerifyConfig()
        assert config.min_trust_level == 0
        assert config.accept_level_zero is False
        assert config.trusted_issuers is None
        assert config.offline_mode is False
        assert config.skip_origin_binding is False
    
    def test_custom_values(self):
        """Custom config values should be set correctly."""
        config = VerifyConfig(
            min_trust_level=2,
            accept_level_zero=True,
            trusted_issuers=["https://registry.capisc.io"],
            offline_mode=True,
            skip_origin_binding=True,
        )
        assert config.min_trust_level == 2
        assert config.accept_level_zero is True
        assert config.trusted_issuers == ["https://registry.capisc.io"]
        assert config.offline_mode is True
        assert config.skip_origin_binding is True


class TestVerifyResult:
    """Tests for VerifyResult dataclass."""
    
    def test_verified_principal_result(self):
        """Verified principal result should have trust level."""
        result = VerifyResult(
            state=ServerState.VERIFIED_PRINCIPAL,
            trust_level=2,
            server_did="did:web:mcp.example.com:servers:filesystem",
            badge_jti="badge-123",
            error_code=None,
            error_detail=None,
        )
        assert result.state == ServerState.VERIFIED_PRINCIPAL
        assert result.trust_level == 2
        assert result.server_did is not None
    
    def test_declared_principal_result(self):
        """Declared principal result should have DID but optional trust level."""
        result = VerifyResult(
            state=ServerState.DECLARED_PRINCIPAL,
            trust_level=None,
            server_did="did:web:mcp.example.com:servers:filesystem",
            badge_jti=None,
            error_code=None,
            error_detail=None,
        )
        assert result.state == ServerState.DECLARED_PRINCIPAL
        assert result.trust_level is None
        assert result.server_did is not None
    
    def test_unverified_origin_result(self):
        """Unverified origin result should have no identity info."""
        result = VerifyResult(
            state=ServerState.UNVERIFIED_ORIGIN,
            trust_level=None,
            server_did=None,
            badge_jti=None,
            error_code=None,
            error_detail=None,
        )
        assert result.state == ServerState.UNVERIFIED_ORIGIN
        assert result.trust_level is None
        assert result.server_did is None
    
    def test_error_result(self):
        """Error result should have error code and detail."""
        result = VerifyResult(
            state=ServerState.DECLARED_PRINCIPAL,
            trust_level=None,
            server_did="did:web:mcp.example.com:servers:filesystem",
            badge_jti=None,
            error_code=ServerErrorCode.BADGE_INVALID,
            error_detail="Badge signature verification failed",
        )
        assert result.error_code == ServerErrorCode.BADGE_INVALID
        assert "signature" in result.error_detail.lower()


class TestVerifyServer:
    """Tests for verify_server async function."""
    
    @pytest.mark.asyncio
    async def test_verified_principal_with_valid_badge(
        self, mock_core_client, sample_server_did, sample_badge_jws
    ):
        """Server with valid badge returns VERIFIED_PRINCIPAL."""
        mock_response = MagicMock()
        mock_response.state = 1  # VERIFIED_PRINCIPAL
        mock_response.trust_level = 2
        mock_response.server_did = sample_server_did
        mock_response.badge_jti = "badge-123"
        mock_response.error_code = 0
        mock_response.error_detail = ""
        
        mock_core_client.stub.VerifyServerIdentity = AsyncMock(return_value=mock_response)
        
        with patch("capiscio_mcp._core.client.CoreClient.get_instance", return_value=mock_core_client):
            result = await verify_server(
                server_did=sample_server_did,
                server_badge=sample_badge_jws,
                transport_origin="https://mcp.example.com",
            )
            
            assert result.state == ServerState.VERIFIED_PRINCIPAL
            assert result.trust_level == 2
            assert result.server_did == sample_server_did
    
    @pytest.mark.asyncio
    async def test_declared_principal_without_badge(
        self, mock_core_client, sample_server_did
    ):
        """Server with DID but no badge returns DECLARED_PRINCIPAL."""
        mock_response = MagicMock()
        mock_response.state = 2  # DECLARED_PRINCIPAL
        mock_response.trust_level = 0
        mock_response.server_did = sample_server_did
        mock_response.badge_jti = ""
        mock_response.error_code = 0
        mock_response.error_detail = ""
        
        mock_core_client.stub.VerifyServerIdentity = AsyncMock(return_value=mock_response)
        
        with patch("capiscio_mcp._core.client.CoreClient.get_instance", return_value=mock_core_client):
            result = await verify_server(
                server_did=sample_server_did,
                server_badge=None,
                transport_origin="https://mcp.example.com",
            )
            
            assert result.state == ServerState.DECLARED_PRINCIPAL
            assert result.trust_level is None
    
    @pytest.mark.asyncio
    async def test_unverified_origin_no_identity(self, mock_core_client):
        """Server with no identity returns UNVERIFIED_ORIGIN."""
        mock_response = MagicMock()
        mock_response.state = 3  # UNVERIFIED_ORIGIN
        mock_response.trust_level = 0
        mock_response.server_did = ""
        mock_response.badge_jti = ""
        mock_response.error_code = 0
        mock_response.error_detail = ""
        
        mock_core_client.stub.VerifyServerIdentity = AsyncMock(return_value=mock_response)
        
        with patch("capiscio_mcp._core.client.CoreClient.get_instance", return_value=mock_core_client):
            result = await verify_server(
                server_did=None,
                server_badge=None,
            )
            
            assert result.state == ServerState.UNVERIFIED_ORIGIN
            assert result.trust_level is None
            assert result.server_did is None
    
    @pytest.mark.asyncio
    async def test_unverified_origin_is_not_trust_level_zero(self, mock_core_client):
        """UNVERIFIED_ORIGIN is distinct from Trust Level 0 (RFC-007 §5.2)."""
        # This is an important distinction per RFC-007:
        # - Trust Level 0 = self-signed badge with did:key
        # - UNVERIFIED_ORIGIN = no identity disclosed at all
        mock_response = MagicMock()
        mock_response.state = 3  # UNVERIFIED_ORIGIN
        mock_response.trust_level = 0
        mock_response.server_did = ""
        mock_response.badge_jti = ""
        mock_response.error_code = 0
        mock_response.error_detail = ""
        
        mock_core_client.stub.VerifyServerIdentity = AsyncMock(return_value=mock_response)
        
        with patch("capiscio_mcp._core.client.CoreClient.get_instance", return_value=mock_core_client):
            result = await verify_server(server_did=None, server_badge=None)
            
            # UNVERIFIED_ORIGIN means no identity was disclosed
            # This is NOT the same as having Trust Level 0
            assert result.state == ServerState.UNVERIFIED_ORIGIN
            # trust_level should be None (not 0) for unverified origins
            assert result.trust_level is None
    
    @pytest.mark.asyncio
    async def test_origin_binding_host_match(
        self, mock_core_client, sample_badge_jws
    ):
        """did:web host must match HTTP origin."""
        mock_response = MagicMock()
        mock_response.state = 1  # VERIFIED_PRINCIPAL
        mock_response.trust_level = 2
        mock_response.server_did = "did:web:mcp.example.com:servers:filesystem"
        mock_response.badge_jti = "badge-123"
        mock_response.error_code = 0
        mock_response.error_detail = ""
        
        mock_core_client.stub.VerifyServerIdentity = AsyncMock(return_value=mock_response)
        
        with patch("capiscio_mcp._core.client.CoreClient.get_instance", return_value=mock_core_client):
            result = await verify_server(
                server_did="did:web:mcp.example.com:servers:filesystem",
                server_badge=sample_badge_jws,
                transport_origin="https://mcp.example.com",
                endpoint_path="/servers/filesystem",
            )
            
            # Should succeed - host matches
            assert result.state == ServerState.VERIFIED_PRINCIPAL
    
    @pytest.mark.asyncio
    async def test_origin_binding_host_mismatch(
        self, mock_core_client, sample_badge_jws
    ):
        """did:web host mismatch should return error."""
        mock_response = MagicMock()
        mock_response.state = 2  # DECLARED_PRINCIPAL (downgraded due to mismatch)
        mock_response.trust_level = 0
        mock_response.server_did = "did:web:mcp.example.com:servers:filesystem"
        mock_response.badge_jti = ""
        mock_response.error_code = 6  # SERVER_ORIGIN_MISMATCH
        mock_response.error_detail = "Origin mismatch: expected mcp.example.com, got other.example.com"
        
        mock_core_client.stub.VerifyServerIdentity = AsyncMock(return_value=mock_response)
        
        with patch("capiscio_mcp._core.client.CoreClient.get_instance", return_value=mock_core_client):
            result = await verify_server(
                server_did="did:web:mcp.example.com:servers:filesystem",
                server_badge=sample_badge_jws,
                transport_origin="https://other.example.com",  # Mismatch!
            )
            
            assert result.error_code == ServerErrorCode.ORIGIN_MISMATCH
    
    @pytest.mark.asyncio
    async def test_origin_binding_skipped_for_stdio(self, mock_core_client, sample_badge_jws):
        """Origin binding not applied for stdio transport."""
        mock_response = MagicMock()
        mock_response.state = 1  # VERIFIED_PRINCIPAL
        mock_response.trust_level = 2
        mock_response.server_did = "did:web:mcp.example.com:servers:filesystem"
        mock_response.badge_jti = "badge-123"
        mock_response.error_code = 0
        mock_response.error_detail = ""
        
        mock_core_client.stub.VerifyServerIdentity = AsyncMock(return_value=mock_response)
        
        with patch("capiscio_mcp._core.client.CoreClient.get_instance", return_value=mock_core_client):
            result = await verify_server(
                server_did="did:web:mcp.example.com:servers:filesystem",
                server_badge=sample_badge_jws,
                transport_origin=None,  # stdio - no origin
            )
            
            # Should still verify badge, just skip origin binding
            assert result.state == ServerState.VERIFIED_PRINCIPAL
    
    @pytest.mark.asyncio
    async def test_origin_binding_skipped_when_configured(
        self, mock_core_client, sample_badge_jws
    ):
        """Origin binding skipped with skip_origin_binding=true."""
        mock_response = MagicMock()
        mock_response.state = 1  # VERIFIED_PRINCIPAL
        mock_response.trust_level = 2
        mock_response.server_did = "did:web:mcp.example.com:servers:filesystem"
        mock_response.badge_jti = "badge-123"
        mock_response.error_code = 0
        mock_response.error_detail = ""
        
        mock_core_client.stub.VerifyServerIdentity = AsyncMock(return_value=mock_response)
        
        with patch("capiscio_mcp._core.client.CoreClient.get_instance", return_value=mock_core_client):
            result = await verify_server(
                server_did="did:web:mcp.example.com:servers:filesystem",
                server_badge=sample_badge_jws,
                transport_origin="https://gateway.example.com",  # Different origin
                config=VerifyConfig(skip_origin_binding=True),  # Skip check
            )
            
            # Should pass even with different origin
            assert result.state == ServerState.VERIFIED_PRINCIPAL
    
    @pytest.mark.asyncio
    async def test_expired_badge_error(self, mock_core_client, sample_server_did):
        """Expired badge should return error."""
        mock_response = MagicMock()
        mock_response.state = 2  # DECLARED_PRINCIPAL
        mock_response.trust_level = 0
        mock_response.server_did = sample_server_did
        mock_response.badge_jti = ""
        mock_response.error_code = 3  # SERVER_BADGE_EXPIRED
        mock_response.error_detail = "Badge expired at 2026-01-14T12:00:00Z"
        
        mock_core_client.stub.VerifyServerIdentity = AsyncMock(return_value=mock_response)
        
        with patch("capiscio_mcp._core.client.CoreClient.get_instance", return_value=mock_core_client):
            result = await verify_server(
                server_did=sample_server_did,
                server_badge="eyJhbGc..expired...",
            )
            
            assert result.error_code == ServerErrorCode.BADGE_EXPIRED
    
    @pytest.mark.asyncio
    async def test_revoked_badge_error(self, mock_core_client, sample_server_did):
        """Revoked badge should return error."""
        mock_response = MagicMock()
        mock_response.state = 2  # DECLARED_PRINCIPAL
        mock_response.trust_level = 0
        mock_response.server_did = sample_server_did
        mock_response.badge_jti = "badge-123"
        mock_response.error_code = 4  # SERVER_BADGE_REVOKED
        mock_response.error_detail = "Badge revoked"
        
        mock_core_client.stub.VerifyServerIdentity = AsyncMock(return_value=mock_response)
        
        with patch("capiscio_mcp._core.client.CoreClient.get_instance", return_value=mock_core_client):
            result = await verify_server(
                server_did=sample_server_did,
                server_badge="eyJhbGc..revoked...",
            )
            
            assert result.error_code == ServerErrorCode.BADGE_REVOKED
    
    @pytest.mark.asyncio
    async def test_trust_insufficient_error(
        self, mock_core_client, sample_server_did, sample_badge_jws
    ):
        """Insufficient trust level should return error."""
        mock_response = MagicMock()
        mock_response.state = 1  # VERIFIED_PRINCIPAL but low trust
        mock_response.trust_level = 1
        mock_response.server_did = sample_server_did
        mock_response.badge_jti = "badge-123"
        mock_response.error_code = 5  # SERVER_TRUST_INSUFFICIENT
        mock_response.error_detail = "Required trust level 2, got 1"
        
        mock_core_client.stub.VerifyServerIdentity = AsyncMock(return_value=mock_response)
        
        with patch("capiscio_mcp._core.client.CoreClient.get_instance", return_value=mock_core_client):
            result = await verify_server(
                server_did=sample_server_did,
                server_badge=sample_badge_jws,
                config=VerifyConfig(min_trust_level=2),
            )
            
            assert result.error_code == ServerErrorCode.TRUST_INSUFFICIENT


class TestVerifyServerStrict:
    """Tests for verify_server_strict function."""
    
    @pytest.mark.asyncio
    async def test_strict_raises_on_unverified(self, mock_core_client):
        """Strict mode raises exception for unverified origin."""
        mock_response = MagicMock()
        mock_response.state = 3  # UNVERIFIED_ORIGIN
        mock_response.trust_level = 0
        mock_response.server_did = ""
        mock_response.badge_jti = ""
        mock_response.error_code = 0
        mock_response.error_detail = ""
        
        mock_core_client.stub.VerifyServerIdentity = AsyncMock(return_value=mock_response)
        
        with patch("capiscio_mcp._core.client.CoreClient.get_instance", return_value=mock_core_client):
            with pytest.raises(ServerVerifyError) as exc_info:
                await verify_server_strict(
                    server_did=None,
                    server_badge=None,
                )
            
            assert "identity" in str(exc_info.value).lower()
    
    @pytest.mark.asyncio
    async def test_strict_raises_on_declared_only(
        self, mock_core_client, sample_server_did
    ):
        """Strict mode raises exception for declared-only principal."""
        mock_response = MagicMock()
        mock_response.state = 2  # DECLARED_PRINCIPAL
        mock_response.trust_level = 0
        mock_response.server_did = sample_server_did
        mock_response.badge_jti = ""
        mock_response.error_code = 0
        mock_response.error_detail = ""
        
        mock_core_client.stub.VerifyServerIdentity = AsyncMock(return_value=mock_response)
        
        with patch("capiscio_mcp._core.client.CoreClient.get_instance", return_value=mock_core_client):
            with pytest.raises(ServerVerifyError) as exc_info:
                await verify_server_strict(
                    server_did=sample_server_did,
                    server_badge=None,
                )
            
            assert "badge" in str(exc_info.value).lower()
    
    @pytest.mark.asyncio
    async def test_strict_passes_on_verified(
        self, mock_core_client, sample_server_did, sample_badge_jws
    ):
        """Strict mode passes for verified principal."""
        mock_response = MagicMock()
        mock_response.state = 1  # VERIFIED_PRINCIPAL
        mock_response.trust_level = 2
        mock_response.server_did = sample_server_did
        mock_response.badge_jti = "badge-123"
        mock_response.error_code = 0
        mock_response.error_detail = ""
        
        mock_core_client.stub.VerifyServerIdentity = AsyncMock(return_value=mock_response)
        
        with patch("capiscio_mcp._core.client.CoreClient.get_instance", return_value=mock_core_client):
            result = await verify_server_strict(
                server_did=sample_server_did,
                server_badge=sample_badge_jws,
            )
            
            assert result.state == ServerState.VERIFIED_PRINCIPAL


class TestVerifyServerSync:
    """Tests for verify_server_sync function."""
    
    def test_sync_wrapper_works(self, mock_core_client, sample_server_did, sample_badge_jws):
        """Sync wrapper should execute async function."""
        mock_response = MagicMock()
        mock_response.state = 1
        mock_response.trust_level = 2
        mock_response.server_did = sample_server_did
        mock_response.badge_jti = "badge-123"
        mock_response.error_code = 0
        mock_response.error_detail = ""
        
        async def mock_verify(*args, **kwargs):
            return mock_response
        
        mock_core_client.stub.VerifyServerIdentity = mock_verify
        
        async def mock_get_instance():
            return mock_core_client
        
        with patch("capiscio_mcp._core.client.CoreClient.get_instance", mock_get_instance):
            result = verify_server_sync(
                server_did=sample_server_did,
                server_badge=sample_badge_jws,
            )
            
            assert result.state == ServerState.VERIFIED_PRINCIPAL


class TestParseHttpHeaders:
    """Tests for parse_http_headers function."""
    
    def test_parse_both_headers(self):
        """Should extract both DID and badge from headers."""
        headers = {
            "Capiscio-Server-DID": "did:web:mcp.example.com:servers:fs",
            "Capiscio-Server-Badge": "eyJhbGc...",
        }
        
        server_did, server_badge = parse_http_headers(headers)
        
        assert server_did == "did:web:mcp.example.com:servers:fs"
        assert server_badge == "eyJhbGc..."
    
    def test_parse_did_only(self):
        """Should extract DID when badge not present."""
        headers = {
            "Capiscio-Server-DID": "did:web:mcp.example.com:servers:fs",
        }
        
        server_did, server_badge = parse_http_headers(headers)
        
        assert server_did == "did:web:mcp.example.com:servers:fs"
        assert server_badge is None
    
    def test_parse_no_headers(self):
        """Should return None for both when headers missing."""
        headers = {}
        
        server_did, server_badge = parse_http_headers(headers)
        
        assert server_did is None
        assert server_badge is None
    
    def test_case_insensitivity(self):
        """Headers should be case-insensitive per HTTP spec."""
        headers = {
            "capiscio-server-did": "did:web:lowercase.example.com",
        }
        
        server_did, server_badge = parse_http_headers(headers)
        
        # Case-insensitive lookup should find it
        assert server_did == "did:web:lowercase.example.com"
    
    def test_ignore_other_headers(self):
        """Should ignore unrelated headers."""
        headers = {
            "Content-Type": "application/json",
            "Capiscio-Server-DID": "did:web:mcp.example.com",
            "X-Custom-Header": "value",
        }
        
        server_did, server_badge = parse_http_headers(headers)
        
        assert server_did == "did:web:mcp.example.com"


class TestParseJsonrpcMeta:
    """Tests for parse_jsonrpc_meta function."""
    
    def test_parse_both_fields(self):
        """Should extract both DID and badge from _meta."""
        meta = {
            "capiscio_server_did": "did:web:mcp.example.com:servers:fs",
            "capiscio_server_badge": "eyJhbGc...",
        }
        
        server_did, server_badge = parse_jsonrpc_meta(meta)
        
        assert server_did == "did:web:mcp.example.com:servers:fs"
        assert server_badge == "eyJhbGc..."
    
    def test_parse_did_only(self):
        """Should extract DID when badge not present."""
        meta = {
            "capiscio_server_did": "did:web:mcp.example.com:servers:fs",
        }
        
        server_did, server_badge = parse_jsonrpc_meta(meta)
        
        assert server_did == "did:web:mcp.example.com:servers:fs"
        assert server_badge is None
    
    def test_parse_empty_meta(self):
        """Should return None for both when meta is empty."""
        meta = {}
        
        server_did, server_badge = parse_jsonrpc_meta(meta)
        
        assert server_did is None
        assert server_badge is None
    
    def test_parse_with_other_fields(self):
        """Should ignore unrelated fields."""
        meta = {
            "capiscio_server_did": "did:web:mcp.example.com",
            "other_field": "value",
            "nested": {"key": "value"},
        }
        
        server_did, server_badge = parse_jsonrpc_meta(meta)
        
        assert server_did == "did:web:mcp.example.com"
        assert server_badge is None
