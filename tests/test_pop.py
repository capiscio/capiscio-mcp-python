"""
Tests for capiscio_mcp.pop module.

Tests PoP (Proof of Possession) primitives for RFC-007 MCP server identity.
"""

import time
import pytest

# Skip all tests if cryptography is not available
pytest.importorskip("cryptography")

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from capiscio_mcp.pop import (
    PoPRequest,
    PoPResponse,
    generate_nonce,
    generate_pop_request,
    sign_nonce,
    create_pop_response,
    verify_pop_signature,
    verify_pop_response,
    extract_public_key_from_did_key,
    public_key_to_did_key,
    load_private_key_from_pem,
    load_public_key_from_pem,
    PoPError,
    PoPNonceError,
    PoPSignatureError,
    PoPExpiredError,
    _base58_encode,
    _base58_decode,
)


class TestNonceGeneration:
    """Tests for nonce generation."""
    
    def test_generate_nonce_default_size(self):
        """Generate nonce with default size."""
        nonce = generate_nonce()
        # 32 bytes = 256 bits, base64url encoded ~ 43 chars without padding
        assert len(nonce) >= 40
        assert len(nonce) <= 50
        # Should be base64url (no padding)
        assert "=" not in nonce
    
    def test_generate_nonce_custom_size(self):
        """Generate nonce with custom size."""
        nonce = generate_nonce(16)  # 128 bits
        assert len(nonce) >= 20
        assert len(nonce) <= 25
    
    def test_generate_nonce_uniqueness(self):
        """Each nonce should be unique."""
        nonces = [generate_nonce() for _ in range(100)]
        assert len(set(nonces)) == 100


class TestPoPRequest:
    """Tests for PoPRequest dataclass."""
    
    def test_generate_pop_request(self):
        """Generate a PoP request."""
        req = generate_pop_request()
        assert req.client_nonce
        assert req.created_at > 0
        assert req.created_at <= time.time()
    
    def test_pop_request_to_meta(self):
        """Convert PoP request to _meta format."""
        req = PoPRequest(
            client_nonce="test-nonce-abc123",
            created_at=1700000000.0,
        )
        meta = req.to_meta()
        assert meta["capiscio_pop_nonce"] == "test-nonce-abc123"
        assert meta["capiscio_pop_created_at"] == 1700000000
    
    def test_pop_request_from_meta(self):
        """Parse PoP request from _meta."""
        meta = {
            "capiscio_pop_nonce": "test-nonce-xyz789",
            "capiscio_pop_created_at": 1700000000,
        }
        req = PoPRequest.from_meta(meta)
        assert req is not None
        assert req.client_nonce == "test-nonce-xyz789"
        assert req.created_at == 1700000000.0
    
    def test_pop_request_from_meta_missing_nonce(self):
        """Return None if nonce is missing."""
        assert PoPRequest.from_meta({}) is None
        assert PoPRequest.from_meta({"other": "field"}) is None
    
    def test_pop_request_from_meta_none(self):
        """Return None for None input."""
        assert PoPRequest.from_meta(None) is None
    
    def test_pop_request_is_expired(self):
        """Check expiry detection."""
        old_req = PoPRequest(
            client_nonce="old",
            created_at=time.time() - 400,  # 400 seconds ago
        )
        assert old_req.is_expired(max_age=300)  # 5 minute limit
        
        new_req = PoPRequest(
            client_nonce="new",
            created_at=time.time(),
        )
        assert not new_req.is_expired(max_age=300)


class TestPoPResponse:
    """Tests for PoPResponse dataclass."""
    
    def test_pop_response_to_meta(self):
        """Convert PoP response to _meta format."""
        resp = PoPResponse(
            nonce_signature="eyJ...signature...",
            signed_at=1700000100.0,
        )
        meta = resp.to_meta()
        assert meta["capiscio_pop_signature"] == "eyJ...signature..."
        assert meta["capiscio_pop_signed_at"] == 1700000100
    
    def test_pop_response_from_meta(self):
        """Parse PoP response from _meta."""
        meta = {
            "capiscio_pop_signature": "eyJ...sig...",
            "capiscio_pop_signed_at": 1700000100,
        }
        resp = PoPResponse.from_meta(meta)
        assert resp is not None
        assert resp.nonce_signature == "eyJ...sig..."
        assert resp.signed_at == 1700000100.0
    
    def test_pop_response_from_meta_missing(self):
        """Return None if signature is missing."""
        assert PoPResponse.from_meta({}) is None
        assert PoPResponse.from_meta({"other": "field"}) is None


class TestPoPSigning:
    """Tests for PoP signing functions."""
    
    @pytest.fixture
    def key_pair(self):
        """Generate a test Ed25519 key pair."""
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key
    
    def test_sign_nonce(self, key_pair):
        """Sign a nonce and get JWS."""
        private_key, _ = key_pair
        nonce = "test-nonce-123"
        key_id = "did:key:z6Mk...#keys-1"
        
        jws = sign_nonce(nonce, private_key, key_id)
        
        # JWS compact format: header.payload.signature
        parts = jws.split(".")
        assert len(parts) == 3
        # Each part should be base64url encoded
        assert all(p for p in parts)
    
    def test_create_pop_response(self, key_pair):
        """Create a full PoP response."""
        private_key, _ = key_pair
        
        request = PoPRequest(
            client_nonce="challenge-nonce",
            created_at=time.time(),
        )
        
        response = create_pop_response(
            request=request,
            private_key=private_key,
            key_id="did:key:z6Mk...#keys-1",
        )
        
        assert response.nonce_signature
        assert response.signed_at > 0


class TestPoPVerification:
    """Tests for PoP verification functions."""
    
    @pytest.fixture
    def key_pair(self):
        """Generate a test Ed25519 key pair."""
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key
    
    def test_verify_pop_signature(self, key_pair):
        """Verify a valid PoP signature."""
        private_key, public_key = key_pair
        nonce = "verify-test-nonce"
        
        jws = sign_nonce(nonce, private_key, "test-key-id")
        
        # Should not raise
        verify_pop_signature(jws, nonce, public_key)
    
    def test_verify_pop_signature_wrong_key(self, key_pair):
        """Verification fails with wrong public key."""
        private_key, _ = key_pair
        wrong_private = Ed25519PrivateKey.generate()
        wrong_public = wrong_private.public_key()
        
        nonce = "nonce-123"
        jws = sign_nonce(nonce, private_key, "key-id")
        
        with pytest.raises(PoPSignatureError):
            verify_pop_signature(jws, nonce, wrong_public)
    
    def test_verify_pop_signature_wrong_nonce(self, key_pair):
        """Verification fails with wrong expected nonce."""
        private_key, public_key = key_pair
        
        jws = sign_nonce("original-nonce", private_key, "key-id")
        
        with pytest.raises(PoPSignatureError, match="mismatch"):
            verify_pop_signature(jws, "different-nonce", public_key)
    
    def test_verify_pop_response_full_flow(self, key_pair):
        """Full PoP request/response verification flow."""
        private_key, public_key = key_pair
        
        # Client generates request
        request = generate_pop_request()
        
        # Server signs response
        response = create_pop_response(
            request=request,
            private_key=private_key,
            key_id="test-server#keys-1",
        )
        
        # Client verifies response
        verify_pop_response(request, response, public_key)
    
    def test_verify_pop_response_expired(self, key_pair):
        """Verification fails if request expired."""
        private_key, public_key = key_pair
        
        # Old request
        request = PoPRequest(
            client_nonce="old-nonce",
            created_at=time.time() - 600,  # 10 minutes ago
        )
        
        response = create_pop_response(request, private_key, "key-id")
        
        with pytest.raises(PoPExpiredError):
            verify_pop_response(request, response, public_key, max_age=300)


class TestDIDKeyConversion:
    """Tests for DID:key conversion utilities."""
    
    @pytest.fixture
    def key_pair(self):
        """Generate a test Ed25519 key pair."""
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key
    
    def test_public_key_to_did_key(self, key_pair):
        """Convert public key to did:key."""
        _, public_key = key_pair
        did = public_key_to_did_key(public_key)
        
        assert did.startswith("did:key:z6Mk")
    
    def test_extract_public_key_from_did_key(self, key_pair):
        """Extract public key from did:key."""
        _, public_key = key_pair
        did = public_key_to_did_key(public_key)
        
        extracted = extract_public_key_from_did_key(did)
        
        # Should be able to use for verification
        from cryptography.hazmat.primitives import serialization
        
        original_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        extracted_bytes = extracted.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        assert original_bytes == extracted_bytes
    
    def test_did_key_roundtrip(self, key_pair):
        """Roundtrip conversion preserves key."""
        _, public_key = key_pair
        
        did = public_key_to_did_key(public_key)
        extracted = extract_public_key_from_did_key(did)
        did2 = public_key_to_did_key(extracted)
        
        assert did == did2
    
    def test_extract_invalid_did_key(self):
        """Raise on invalid did:key format."""
        with pytest.raises(ValueError):
            extract_public_key_from_did_key("did:web:example.com")
        
        with pytest.raises(ValueError):
            extract_public_key_from_did_key("not-a-did")


class TestBase58:
    """Tests for base58btc encoding."""
    
    def test_base58_roundtrip(self):
        """Roundtrip encoding preserves data."""
        import os
        data = os.urandom(32)
        encoded = _base58_encode(data)
        decoded = _base58_decode(encoded)
        assert data == decoded
    
    def test_base58_leading_zeros(self):
        """Handle leading zeros correctly."""
        data = b"\x00\x00\x01\x02\x03"
        encoded = _base58_encode(data)
        assert encoded.startswith("11")  # Leading zeros become '1's
        decoded = _base58_decode(encoded)
        assert data == decoded
    
    def test_base58_empty(self):
        """Handle empty input."""
        assert _base58_encode(b"") == ""
        assert _base58_decode("") == b""


class TestMetaRoundtrip:
    """Tests for _meta field roundtrip."""
    
    @pytest.fixture
    def key_pair(self):
        """Generate a test Ed25519 key pair."""
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key
    
    def test_full_meta_roundtrip(self, key_pair):
        """Full _meta roundtrip between client and server."""
        private_key, public_key = key_pair
        
        # Client creates request and puts in _meta
        client_request = generate_pop_request()
        request_meta = client_request.to_meta()
        
        # Server parses request from _meta
        server_request = PoPRequest.from_meta(request_meta)
        assert server_request is not None
        assert server_request.client_nonce == client_request.client_nonce
        
        # Server creates response
        server_response = create_pop_response(server_request, private_key, "key-id")
        response_meta = {
            "capiscio_server_did": "did:key:z6MkTest...",
            **server_response.to_meta(),
        }
        
        # Client parses response from _meta
        client_response = PoPResponse.from_meta(response_meta)
        assert client_response is not None
        
        # Client verifies PoP
        verify_pop_response(client_request, client_response, public_key)


class TestPEMLoading:
    """Tests for PEM key loading."""
    
    @pytest.fixture
    def key_pair_pem(self):
        """Generate key pair and PEM representation."""
        from cryptography.hazmat.primitives import serialization
        
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        
        return private_pem, public_pem
    
    def test_load_private_key_from_pem(self, key_pair_pem):
        """Load private key from PEM."""
        private_pem, _ = key_pair_pem
        key = load_private_key_from_pem(private_pem)
        assert key is not None
    
    def test_load_public_key_from_pem(self, key_pair_pem):
        """Load public key from PEM."""
        _, public_pem = key_pair_pem
        key = load_public_key_from_pem(public_pem)
        assert key is not None
    
    def test_load_key_from_pem_string(self, key_pair_pem):
        """Load key from PEM string (not bytes)."""
        private_pem, _ = key_pair_pem
        key = load_private_key_from_pem(private_pem.decode("utf-8"))
        assert key is not None
