"""
Proof of Possession (PoP) primitives for RFC-007 MCP server identity.

This module implements the PoP handshake for MCP server identity verification:
1. Client generates a nonce and includes it in initialize request _meta
2. Server signs the nonce with its DID key and returns signature in response _meta
3. Client verifies the signature to prove server controls the DID key

The PoP handshake upgrades server state from DECLARED_PRINCIPAL to VERIFIED_PRINCIPAL.

Usage (Client):
    # Generate PoP request
    pop_request = generate_pop_request()
    
    # Include in initialize request _meta
    meta = {
        **pop_request.to_meta(),
        "capiscio_server_did": server_did,  # If available
    }
    
    # After receiving response, verify PoP
    pop_response = PoPResponse.from_meta(response._meta)
    if pop_response:
        verify_pop_response(pop_request, pop_response, server_public_key)

Usage (Server):
    # Parse PoP request from client
    pop_request = PoPRequest.from_meta(request._meta)
    
    # Create signed response
    if pop_request and private_key:
        pop_response = create_pop_response(pop_request, private_key, key_id)
        
        # Include in initialize response _meta
        meta = {
            **identity_meta,
            **pop_response.to_meta(),
        }
"""

from __future__ import annotations

import base64
import json
import os
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Dict, Any, Union

# Optional cryptography import - only needed for server-side signing
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature
    CRYPTO_AVAILABLE = True
except ImportError:
    Ed25519PrivateKey = None  # type: ignore
    Ed25519PublicKey = None  # type: ignore
    CRYPTO_AVAILABLE = False


# =============================================================================
# Constants
# =============================================================================

DEFAULT_NONCE_SIZE = 32  # 256 bits of entropy
POP_MAX_AGE_SECONDS = 300  # 5 minutes


# =============================================================================
# Errors
# =============================================================================


class PoPError(Exception):
    """Base exception for PoP errors."""
    pass


class PoPNonceError(PoPError):
    """Error generating nonce."""
    pass


class PoPSignatureError(PoPError):
    """Error signing or verifying PoP."""
    pass


class PoPExpiredError(PoPError):
    """PoP request has expired."""
    pass


class PoPMissingCrypto(PoPError):
    """Cryptography package not installed."""
    def __init__(self) -> None:
        super().__init__(
            "PoP signing/verification requires 'cryptography' package. "
            "Install with: pip install capiscio-mcp[crypto]"
        )


# =============================================================================
# PoP Request (Client → Server)
# =============================================================================


@dataclass
class PoPRequest:
    """
    PoP request sent by client in initialize request _meta.
    
    Per RFC-007, the client generates a random nonce and includes it
    in the initialize request. The server must sign this nonce to
    prove possession of the DID key.
    
    Attributes:
        client_nonce: Base64url-encoded random nonce (32 bytes)
        created_at: Timestamp when nonce was generated
    """
    client_nonce: str
    created_at: float  # Unix timestamp
    
    def to_meta(self) -> Dict[str, Any]:
        """
        Convert to _meta format for MCP initialize request.
        
        Returns:
            Dict with capiscio_pop_nonce and capiscio_pop_created_at
        """
        return {
            "capiscio_pop_nonce": self.client_nonce,
            "capiscio_pop_created_at": int(self.created_at),
        }
    
    @classmethod
    def from_meta(cls, meta: Optional[Dict[str, Any]]) -> Optional["PoPRequest"]:
        """
        Parse PoP request from MCP _meta object.
        
        Args:
            meta: The _meta dict from initialize request
            
        Returns:
            PoPRequest if present, None otherwise
        """
        if not meta:
            return None
        
        nonce = meta.get("capiscio_pop_nonce")
        if not nonce or not isinstance(nonce, str):
            return None
        
        # Parse created_at with fallback to current time
        created_at = meta.get("capiscio_pop_created_at")
        if isinstance(created_at, (int, float)):
            ts = float(created_at)
        else:
            ts = time.time()
        
        return cls(client_nonce=nonce, created_at=ts)
    
    def is_expired(self, max_age: float = POP_MAX_AGE_SECONDS) -> bool:
        """Check if the PoP request has expired."""
        return (time.time() - self.created_at) > max_age
    
    @property
    def created_datetime(self) -> datetime:
        """Get created_at as datetime."""
        return datetime.fromtimestamp(self.created_at)


@dataclass
class PoPResponse:
    """
    PoP response sent by server in initialize response _meta.
    
    Per RFC-007, the server signs the client's nonce with its DID key
    and returns the signature. The client verifies this signature to
    prove the server controls the private key for the disclosed DID.
    
    Attributes:
        nonce_signature: JWS compact serialization of signed nonce
        signed_at: Timestamp when signature was created
    """
    nonce_signature: str
    signed_at: float  # Unix timestamp
    
    def to_meta(self) -> Dict[str, Any]:
        """
        Convert to _meta format for MCP initialize response.
        
        Returns:
            Dict with capiscio_pop_signature and capiscio_pop_signed_at
        """
        return {
            "capiscio_pop_signature": self.nonce_signature,
            "capiscio_pop_signed_at": int(self.signed_at),
        }
    
    @classmethod
    def from_meta(cls, meta: Optional[Dict[str, Any]]) -> Optional["PoPResponse"]:
        """
        Parse PoP response from MCP _meta object.
        
        Args:
            meta: The _meta dict from initialize response
            
        Returns:
            PoPResponse if present, None otherwise
        """
        if not meta:
            return None
        
        signature = meta.get("capiscio_pop_signature")
        if not signature or not isinstance(signature, str):
            return None
        
        # Parse signed_at with fallback to current time
        signed_at = meta.get("capiscio_pop_signed_at")
        if isinstance(signed_at, (int, float)):
            ts = float(signed_at)
        else:
            ts = time.time()
        
        return cls(nonce_signature=signature, signed_at=ts)
    
    @property
    def signed_datetime(self) -> datetime:
        """Get signed_at as datetime."""
        return datetime.fromtimestamp(self.signed_at)


# =============================================================================
# PoP Generation Functions
# =============================================================================


def generate_nonce(size: int = DEFAULT_NONCE_SIZE) -> str:
    """
    Generate a cryptographically secure random nonce.
    
    Args:
        size: Number of random bytes (default 32 = 256 bits)
        
    Returns:
        Base64url-encoded nonce (no padding, per RFC-003)
        
    Raises:
        PoPNonceError: If nonce generation fails
    """
    try:
        random_bytes = os.urandom(size)
        # Base64url encoding without padding (per RFC-003 §6.2)
        return base64.urlsafe_b64encode(random_bytes).rstrip(b"=").decode("ascii")
    except Exception as e:
        raise PoPNonceError(f"Failed to generate nonce: {e}") from e


def generate_pop_request() -> PoPRequest:
    """
    Generate a new PoP request for MCP initialize.
    
    Creates a request with a fresh nonce and current timestamp.
    
    Returns:
        PoPRequest ready to include in _meta
        
    Raises:
        PoPNonceError: If nonce generation fails
    """
    return PoPRequest(
        client_nonce=generate_nonce(),
        created_at=time.time(),
    )


# =============================================================================
# PoP Signing Functions (Server-side)
# =============================================================================


def _require_crypto() -> None:
    """Raise if cryptography package is not available."""
    if not CRYPTO_AVAILABLE:
        raise PoPMissingCrypto()


def _create_jws_header(key_id: str) -> str:
    """Create JWS header for PoP signature."""
    header = {
        "alg": "EdDSA",
        "typ": "pop+jws",
        "kid": key_id,
    }
    header_json = json.dumps(header, separators=(",", ":"), sort_keys=True)
    return base64.urlsafe_b64encode(header_json.encode()).rstrip(b"=").decode("ascii")


def _parse_jws_parts(jws: str) -> tuple[dict, bytes, bytes]:
    """Parse JWS compact serialization into (header, payload, signature)."""
    parts = jws.split(".")
    if len(parts) != 3:
        raise PoPSignatureError(f"Invalid JWS format: expected 3 parts, got {len(parts)}")
    
    # Decode header
    header_b64 = parts[0]
    # Add padding if needed
    padding = 4 - len(header_b64) % 4
    if padding != 4:
        header_b64 += "=" * padding
    header_json = base64.urlsafe_b64decode(header_b64)
    header = json.loads(header_json)
    
    # Decode payload
    payload_b64 = parts[1]
    padding = 4 - len(payload_b64) % 4
    if padding != 4:
        payload_b64 += "=" * padding
    payload = base64.urlsafe_b64decode(payload_b64)
    
    # Decode signature
    sig_b64 = parts[2]
    padding = 4 - len(sig_b64) % 4
    if padding != 4:
        sig_b64 += "=" * padding
    signature = base64.urlsafe_b64decode(sig_b64)
    
    return header, payload, signature


def sign_nonce(
    nonce: str,
    private_key: "Ed25519PrivateKey",
    key_id: str,
) -> str:
    """
    Sign a nonce with Ed25519 private key, returning JWS compact serialization.
    
    Args:
        nonce: The nonce to sign (base64url-encoded)
        private_key: Ed25519 private key for signing
        key_id: Key ID to include in JWS header (e.g., DID key reference)
        
    Returns:
        JWS compact serialization (header.payload.signature)
        
    Raises:
        PoPMissingCrypto: If cryptography package not available
        PoPSignatureError: If signing fails
    """
    _require_crypto()
    
    try:
        # Create header
        header_b64 = _create_jws_header(key_id)
        
        # Payload is the nonce itself
        payload_b64 = base64.urlsafe_b64encode(nonce.encode()).rstrip(b"=").decode("ascii")
        
        # Signing input per RFC 7515
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        
        # Sign with Ed25519
        signature = private_key.sign(signing_input)
        signature_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
        
        return f"{header_b64}.{payload_b64}.{signature_b64}"
    except Exception as e:
        raise PoPSignatureError(f"Failed to sign nonce: {e}") from e


def create_pop_response(
    request: PoPRequest,
    private_key: "Ed25519PrivateKey",
    key_id: str,
) -> PoPResponse:
    """
    Create a PoP response by signing the client's nonce.
    
    Args:
        request: The PoP request containing client nonce
        private_key: Server's Ed25519 private key
        key_id: Key ID for JWS header (e.g., DID key reference)
        
    Returns:
        PoPResponse ready to include in _meta
        
    Raises:
        PoPMissingCrypto: If cryptography package not available
        PoPSignatureError: If signing fails
    """
    signature = sign_nonce(request.client_nonce, private_key, key_id)
    return PoPResponse(
        nonce_signature=signature,
        signed_at=time.time(),
    )


# =============================================================================
# PoP Verification Functions (Client-side)
# =============================================================================


def verify_pop_signature(
    jws: str,
    expected_nonce: str,
    public_key: "Ed25519PublicKey",
) -> None:
    """
    Verify a PoP signature.
    
    Args:
        jws: JWS compact serialization to verify
        expected_nonce: The nonce that should have been signed
        public_key: Server's Ed25519 public key
        
    Raises:
        PoPMissingCrypto: If cryptography package not available
        PoPSignatureError: If verification fails
    """
    _require_crypto()
    
    try:
        # Parse JWS
        header, payload, signature = _parse_jws_parts(jws)
        
        # Verify algorithm
        alg = header.get("alg")
        if alg != "EdDSA":
            raise PoPSignatureError(f"Unsupported algorithm: {alg}")
        
        # Verify payload matches expected nonce
        payload_nonce = payload.decode("utf-8")
        if payload_nonce != expected_nonce:
            raise PoPSignatureError("Nonce mismatch in PoP signature")
        
        # Reconstruct signing input
        parts = jws.split(".")
        signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
        
        # Verify signature
        try:
            public_key.verify(signature, signing_input)
        except InvalidSignature:
            raise PoPSignatureError("Invalid PoP signature")
            
    except PoPSignatureError:
        raise
    except Exception as e:
        raise PoPSignatureError(f"Failed to verify PoP signature: {e}") from e


def verify_pop_response(
    request: PoPRequest,
    response: PoPResponse,
    public_key: "Ed25519PublicKey",
    max_age: float = POP_MAX_AGE_SECONDS,
) -> None:
    """
    Verify a complete PoP response.
    
    Args:
        request: The original PoP request
        response: The PoP response from server
        public_key: Server's Ed25519 public key
        max_age: Maximum age of request in seconds
        
    Raises:
        PoPMissingCrypto: If cryptography package not available
        PoPExpiredError: If request has expired
        PoPSignatureError: If signature verification fails
    """
    # Check expiry
    if request.is_expired(max_age):
        raise PoPExpiredError(
            f"PoP request expired (age: {time.time() - request.created_at:.1f}s, "
            f"max: {max_age}s)"
        )
    
    # Verify signature
    verify_pop_signature(
        jws=response.nonce_signature,
        expected_nonce=request.client_nonce,
        public_key=public_key,
    )


# =============================================================================
# DID Key Utilities
# =============================================================================


def extract_public_key_from_did_key(did: str) -> "Ed25519PublicKey":
    """
    Extract Ed25519 public key from did:key.
    
    Per RFC-002 §6.1, did:key format for Ed25519:
    did:key:z6Mk... where the multibase-encoded value contains
    the multicodec prefix 0xed01 followed by the raw public key.
    
    Args:
        did: A did:key URI (e.g., "did:key:z6Mk...")
        
    Returns:
        Ed25519 public key
        
    Raises:
        PoPMissingCrypto: If cryptography package not available
        ValueError: If DID format is invalid
    """
    _require_crypto()
    
    if not did.startswith("did:key:z"):
        raise ValueError(f"Invalid did:key format: {did}")
    
    # Extract multibase value (after 'z' prefix for base58btc)
    multibase = did[8:]  # Remove "did:key:"
    if not multibase.startswith("z"):
        raise ValueError(f"Expected base58btc multibase (z prefix): {multibase}")
    
    # Decode base58btc
    raw = _base58_decode(multibase[1:])  # Remove 'z' prefix
    
    # Check for Ed25519 multicodec prefix (0xed01)
    if len(raw) < 2:
        raise ValueError("Multibase value too short")
    
    if raw[0] == 0xed and raw[1] == 0x01:
        # Has multicodec prefix
        key_bytes = raw[2:]
    elif len(raw) == 32:
        # Raw key without prefix
        key_bytes = raw
    else:
        raise ValueError(f"Unexpected multibase content: length {len(raw)}")
    
    if len(key_bytes) != 32:
        raise ValueError(f"Invalid Ed25519 key size: {len(key_bytes)}")
    
    return Ed25519PublicKey.from_public_bytes(bytes(key_bytes))


def public_key_to_did_key(public_key: "Ed25519PublicKey") -> str:
    """
    Convert Ed25519 public key to did:key.
    
    Args:
        public_key: Ed25519 public key
        
    Returns:
        did:key URI
        
    Raises:
        PoPMissingCrypto: If cryptography package not available
    """
    _require_crypto()
    
    # Get raw public key bytes
    key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    
    # Add Ed25519 multicodec prefix (0xed01)
    prefixed = bytes([0xed, 0x01]) + key_bytes
    
    # Encode as base58btc with 'z' prefix
    return "did:key:z" + _base58_encode(prefixed)


# =============================================================================
# Base58 Utilities (Bitcoin alphabet)
# =============================================================================

_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BASE58_MAP = {c: i for i, c in enumerate(_BASE58_ALPHABET)}


def _base58_encode(data: bytes) -> str:
    """Encode bytes as base58btc (Bitcoin alphabet)."""
    if not data:
        return ""
    
    # Count leading zeros
    leading_zeros = 0
    for b in data:
        if b == 0:
            leading_zeros += 1
        else:
            break
    
    # Convert to integer
    num = int.from_bytes(data, "big")
    
    # Convert to base58
    result = []
    while num > 0:
        num, remainder = divmod(num, 58)
        result.append(_BASE58_ALPHABET[remainder])
    
    # Add leading '1's for leading zeros
    result.extend("1" * leading_zeros)
    
    return "".join(reversed(result))


def _base58_decode(encoded: str) -> bytes:
    """Decode base58btc (Bitcoin alphabet) to bytes."""
    if not encoded:
        return b""
    
    # Count leading '1's (zeros)
    leading_ones = 0
    for c in encoded:
        if c == "1":
            leading_ones += 1
        else:
            break
    
    # Convert from base58
    num = 0
    for c in encoded:
        if c not in _BASE58_MAP:
            raise ValueError(f"Invalid base58 character: {c}")
        num = num * 58 + _BASE58_MAP[c]
    
    # Convert to bytes
    if num == 0:
        return b"\x00" * leading_ones
    
    result = []
    while num > 0:
        result.append(num & 0xff)
        num >>= 8
    
    # Add leading zeros
    result.extend([0] * leading_ones)
    
    return bytes(reversed(result))


# =============================================================================
# Key Loading Utilities
# =============================================================================


def load_private_key_from_pem(pem_data: Union[str, bytes]) -> "Ed25519PrivateKey":
    """
    Load Ed25519 private key from PEM format.
    
    Args:
        pem_data: PEM-encoded private key (string or bytes)
        
    Returns:
        Ed25519 private key
        
    Raises:
        PoPMissingCrypto: If cryptography package not available
        ValueError: If key format is invalid
    """
    _require_crypto()
    
    if isinstance(pem_data, str):
        pem_data = pem_data.encode()
    
    key = serialization.load_pem_private_key(pem_data, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"Expected Ed25519 private key, got {type(key).__name__}")
    return key


def load_public_key_from_pem(pem_data: Union[str, bytes]) -> "Ed25519PublicKey":
    """
    Load Ed25519 public key from PEM format.
    
    Args:
        pem_data: PEM-encoded public key (string or bytes)
        
    Returns:
        Ed25519 public key
        
    Raises:
        PoPMissingCrypto: If cryptography package not available
        ValueError: If key format is invalid
    """
    _require_crypto()
    
    if isinstance(pem_data, str):
        pem_data = pem_data.encode()
    
    key = serialization.load_pem_public_key(pem_data)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError(f"Expected Ed25519 public key, got {type(key).__name__}")
    return key
