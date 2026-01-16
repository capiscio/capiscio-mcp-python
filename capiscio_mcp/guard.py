"""
RFC-006: MCP Tool Authority Guard.

This module provides the @guard decorator for protecting MCP tool execution
with identity verification and policy enforcement.

Key design principle: params_hash is computed in Python, never sent raw to core.
This keeps PII out of the gRPC boundary and avoids cross-language canonicalization.

Usage:
    from capiscio_mcp import guard, GuardConfig

    @guard(min_trust_level=2)
    async def read_file(path: str) -> str:
        ...

    # With full configuration
    config = GuardConfig(
        min_trust_level=2,
        trusted_issuers=["did:web:registry.capisc.io"],
        allowed_tools=["read_*", "list_*"],
    )

    @guard(config=config)
    async def execute_query(sql: str) -> list[dict]:
        ...
"""

from __future__ import annotations

import asyncio
import base64
import contextvars
import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import wraps
from typing import (
    Any,
    Callable,
    Coroutine,
    List,
    Optional,
    ParamSpec,
    TypeVar,
    Union,
    overload,
)

from capiscio_mcp.types import (
    AuthLevel,
    CallerCredential,
    Decision,
    DenyReason,
    TrustLevel,
)
from capiscio_mcp.errors import GuardError, GuardConfigError

logger = logging.getLogger(__name__)

# Type variables for decorator
P = ParamSpec("P")
R = TypeVar("R")

# Context variable for passing credentials to guarded functions
_current_credential: contextvars.ContextVar[Optional[CallerCredential]] = (
    contextvars.ContextVar("current_credential", default=None)
)

# Context variable for server origin
_current_origin: contextvars.ContextVar[Optional[str]] = (
    contextvars.ContextVar("current_origin", default=None)
)

# Context variables for backward compatibility / test access
_caller_did: contextvars.ContextVar[Optional[str]] = (
    contextvars.ContextVar("caller_did", default=None)
)

_caller_badge: contextvars.ContextVar[Optional[str]] = (
    contextvars.ContextVar("caller_badge", default=None)
)


@dataclass
class GuardConfig:
    """
    Configuration for the @guard decorator.
    
    Attributes:
        min_trust_level: Minimum trust level required (0-4, default 0)
        accept_level_zero: Accept self-signed (did:key) badges
        trusted_issuers: List of trusted issuer DIDs
        allowed_tools: Glob patterns for allowed tool names
        policy_version: Policy version string for tracking
        require_badge: If True, deny anonymous/API key access
    """
    min_trust_level: int = 0
    accept_level_zero: bool = False
    trusted_issuers: Optional[List[str]] = None
    allowed_tools: Optional[List[str]] = None
    policy_version: Optional[str] = None
    require_badge: bool = False
    
    def __post_init__(self) -> None:
        """Validate configuration on creation."""
        self.validate()
    
    def validate(self) -> None:
        """Validate configuration values."""
        if not 0 <= self.min_trust_level <= 4:
            raise GuardConfigError(
                f"min_trust_level must be 0-4, got {self.min_trust_level}"
            )
        
        if self.min_trust_level == 0 and not self.accept_level_zero:
            # Level 0 is self-signed, must explicitly opt-in
            pass  # This is fine, will deny Level 0 badges


@dataclass
class GuardResult:
    """
    Result from tool access evaluation.
    
    Attributes:
        decision: ALLOW or DENY
        deny_reason: Reason for denial (if decision is DENY)
        deny_detail: Human-readable detail (if decision is DENY)
        agent_did: Extracted agent DID from credential
        badge_jti: Badge ID if present
        auth_level: Authentication level (ANONYMOUS, API_KEY, BADGE)
        trust_level: Verified trust level (0-4)
        evidence_id: Unique evidence record ID
        evidence_json: RFC-006 §7 compliant JSON
    """
    decision: Decision
    deny_reason: Optional[DenyReason] = None
    deny_detail: Optional[str] = None
    
    # Derived identity
    agent_did: Optional[str] = None
    badge_jti: Optional[str] = None
    auth_level: AuthLevel = AuthLevel.ANONYMOUS
    trust_level: int = 0
    
    # Evidence
    evidence_id: str = ""
    evidence_json: str = ""


def compute_params_hash(params: dict[str, Any]) -> str:
    """
    Compute deterministic hash of tool parameters.
    
    CRITICAL: This stays in Python. Core never sees raw params.
    
    Canonicalization rules (JCS-like):
    1. Sort keys recursively (lexicographic)
    2. Compact JSON (no whitespace)
    3. SHA-256 hash
    4. Base64url encode (no padding)
    
    Args:
        params: Tool parameters dictionary
        
    Returns:
        String in format "sha256:<base64url>"
        
    Example:
        >>> compute_params_hash({"b": 2, "a": 1})
        'sha256:...'  # Same as compute_params_hash({"a": 1, "b": 2})
    """
    def sort_recursive(obj: Any) -> Any:
        if isinstance(obj, dict):
            return {k: sort_recursive(v) for k, v in sorted(obj.items())}
        if isinstance(obj, list):
            return [sort_recursive(item) for item in obj]
        return obj
    
    canonical = json.dumps(
        sort_recursive(params),
        separators=(",", ":"),
        ensure_ascii=True,
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).digest()
    b64 = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return f"sha256:{b64}"


def set_credential(credential: CallerCredential) -> contextvars.Token:
    """
    Set the caller credential for the current context.
    
    Use this to provide credentials to @guard decorated functions.
    
    Args:
        credential: The caller's credential (badge or API key)
        
    Returns:
        Token that can be used to reset the credential
        
    Example:
        token = set_credential(CallerCredential(badge_jws=badge_token))
        try:
            result = await guarded_tool(param="value")
        finally:
            _current_credential.reset(token)
    """
    return _current_credential.set(credential)


def set_server_origin(origin: str) -> contextvars.Token:
    """
    Set the server origin for the current context.
    
    Args:
        origin: HTTP origin (e.g., "https://api.example.com")
        
    Returns:
        Token that can be used to reset the origin
    """
    return _current_origin.set(origin)


def get_credential() -> Optional[CallerCredential]:
    """Get the current caller credential from context."""
    return _current_credential.get()


def get_server_origin() -> str:
    """Get the current server origin from context or environment."""
    import os
    origin = _current_origin.get()
    if origin:
        return origin
    return os.environ.get("CAPISCIO_SERVER_ORIGIN", "")


async def evaluate_tool_access(
    tool_name: str,
    params: dict[str, Any],
    credential: Optional[CallerCredential] = None,
    config: Optional[GuardConfig] = None,
) -> GuardResult:
    """
    Evaluate tool access via capiscio-core.
    
    This is the low-level API. Most users should use the @guard decorator.
    
    Args:
        tool_name: Name of the tool being invoked
        params: Tool parameters (will be hashed, never sent raw)
        credential: Caller credential (default: from context)
        config: Guard configuration
        
    Returns:
        GuardResult with decision and evidence
    """
    from capiscio_mcp._core.client import CoreClient
    
    effective_config = config or GuardConfig()
    effective_credential = credential or get_credential() or CallerCredential()
    
    # Compute params hash locally (PII never leaves Python)
    params_hash = compute_params_hash(params)
    server_origin = get_server_origin()
    
    # Get core client
    client = await CoreClient.get_instance()
    
    # Import proto
    from capiscio_mcp._proto.capiscio.v1 import mcp_pb2
    
    # Build request
    request = mcp_pb2.EvaluateToolAccessRequest(
        tool_name=tool_name,
        params_hash=params_hash,
        server_origin=server_origin,
        policy_version=effective_config.policy_version or "",
        config=mcp_pb2.EvaluateConfig(
            trusted_issuers=effective_config.trusted_issuers or [],
            min_trust_level=effective_config.min_trust_level,
            accept_level_zero=effective_config.accept_level_zero,
            allowed_tools=effective_config.allowed_tools or [],
        ),
    )
    
    # Set credential (oneof in proto)
    if effective_credential.badge_jws:
        request.badge_jws = effective_credential.badge_jws
    elif effective_credential.api_key:
        request.api_key = effective_credential.api_key
    # If neither: anonymous (implicit)
    
    # Make RPC call
    response = await client.stub.EvaluateToolAccess(request)
    
    # Map response to GuardResult
    decision = Decision.ALLOW if response.decision == mcp_pb2.ALLOW else Decision.DENY
    
    deny_reason = None
    if response.deny_reason:
        deny_reason_map = {
            mcp_pb2.TOOL_BADGE_MISSING: DenyReason.BADGE_MISSING,
            mcp_pb2.TOOL_BADGE_INVALID: DenyReason.BADGE_INVALID,
            mcp_pb2.TOOL_BADGE_EXPIRED: DenyReason.BADGE_EXPIRED,
            mcp_pb2.TOOL_BADGE_REVOKED: DenyReason.BADGE_REVOKED,
            mcp_pb2.TOOL_TRUST_INSUFFICIENT: DenyReason.TRUST_INSUFFICIENT,
            mcp_pb2.TOOL_NOT_ALLOWED: DenyReason.TOOL_NOT_ALLOWED,
            mcp_pb2.TOOL_ISSUER_UNTRUSTED: DenyReason.ISSUER_UNTRUSTED,
            mcp_pb2.TOOL_POLICY_DENIED: DenyReason.POLICY_DENIED,
        }
        deny_reason = deny_reason_map.get(response.deny_reason, DenyReason.INTERNAL_ERROR)
    
    auth_level_map = {
        mcp_pb2.ANONYMOUS: AuthLevel.ANONYMOUS,
        mcp_pb2.API_KEY: AuthLevel.API_KEY,
        mcp_pb2.BADGE: AuthLevel.BADGE,
    }
    auth_level = auth_level_map.get(response.auth_level, AuthLevel.ANONYMOUS)
    
    return GuardResult(
        decision=decision,
        deny_reason=deny_reason,
        deny_detail=response.deny_detail or None,
        agent_did=response.agent_did or None,
        badge_jti=response.badge_jti or None,
        auth_level=auth_level,
        trust_level=response.trust_level,
        evidence_id=response.evidence_id,
        evidence_json=response.evidence_json,
    )


# Decorator overloads for type hints
@overload
def guard(
    func: Callable[P, Coroutine[Any, Any, R]],
) -> Callable[P, Coroutine[Any, Any, R]]:
    ...


@overload
def guard(
    *,
    config: Optional[GuardConfig] = None,
    min_trust_level: Optional[int] = None,
    tool_name: Optional[str] = None,
    require_badge: bool = False,
) -> Callable[[Callable[P, Coroutine[Any, Any, R]]], Callable[P, Coroutine[Any, Any, R]]]:
    ...


def guard(
    func: Optional[Callable[P, Coroutine[Any, Any, R]]] = None,
    *,
    config: Optional[GuardConfig] = None,
    min_trust_level: Optional[int] = None,
    tool_name: Optional[str] = None,
    require_badge: bool = False,
) -> Union[
    Callable[P, Coroutine[Any, Any, R]],
    Callable[[Callable[P, Coroutine[Any, Any, R]]], Callable[P, Coroutine[Any, Any, R]]],
]:
    """
    Async decorator to guard MCP tool execution.
    
    Single RPC call returns decision + evidence atomically.
    
    Args:
        func: Function to decorate (if called without parentheses)
        config: Full configuration object
        min_trust_level: Shorthand for config.min_trust_level
        tool_name: Override tool name (default: function name)
        require_badge: If True, deny anonymous/API key access
    
    Returns:
        Decorated function that enforces access control
        
    Example:
        # Simple usage
        @guard
        async def list_files() -> list[str]:
            ...
        
        # With trust level requirement
        @guard(min_trust_level=2)
        async def execute_query(sql: str) -> list[dict]:
            ...
        
        # With full configuration
        @guard(config=GuardConfig(
            min_trust_level=2,
            trusted_issuers=["did:web:registry.capisc.io"],
        ))
        async def sensitive_operation(data: dict) -> dict:
            ...
    """
    def make_decorator(
        f: Callable[P, Coroutine[Any, Any, R]]
    ) -> Callable[P, Coroutine[Any, Any, R]]:
        # Build effective config
        effective_config = config or GuardConfig()
        if min_trust_level is not None:
            effective_config.min_trust_level = min_trust_level
        if require_badge:
            effective_config.require_badge = True
        
        effective_tool_name = tool_name or f.__name__
        
        @wraps(f)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            # Build params dict from kwargs for hashing
            # Note: args are not included in hash (position-dependent)
            params = dict(kwargs)
            
            # Evaluate access
            result = await evaluate_tool_access(
                tool_name=effective_tool_name,
                params=params,
                config=effective_config,
            )
            
            # Check decision
            if result.decision == Decision.DENY:
                raise GuardError(
                    reason=result.deny_reason or DenyReason.INTERNAL_ERROR,
                    detail=result.deny_detail or "Access denied",
                    evidence_id=result.evidence_id,
                    agent_did=result.agent_did,
                    trust_level=result.trust_level,
                )
            
            # Log successful access
            logger.debug(
                f"Access allowed for {effective_tool_name}: "
                f"agent={result.agent_did}, trust_level={result.trust_level}"
            )
            
            # Execute tool
            return await f(*args, **kwargs)
        
        return wrapper
    
    # Handle both @guard and @guard() syntax
    if func is not None:
        return make_decorator(func)
    return make_decorator


def guard_sync(
    func: Optional[Callable[P, R]] = None,
    *,
    config: Optional[GuardConfig] = None,
    min_trust_level: Optional[int] = None,
    tool_name: Optional[str] = None,
    require_badge: bool = False,
) -> Union[Callable[P, R], Callable[[Callable[P, R]], Callable[P, R]]]:
    """
    Sync decorator to guard MCP tool execution.
    
    Same as @guard but for synchronous functions.
    Internally runs the async guard in an event loop.
    
    Args:
        func: Function to decorate (if called without parentheses)
        config: Full configuration object
        min_trust_level: Shorthand for config.min_trust_level
        tool_name: Override tool name (default: function name)
        require_badge: If True, deny anonymous/API key access
    
    Example:
        @guard_sync(min_trust_level=2)
        def read_file(path: str) -> str:
            ...
    """
    def make_decorator(f: Callable[P, R]) -> Callable[P, R]:
        # Build effective config
        effective_config = config or GuardConfig()
        if min_trust_level is not None:
            effective_config.min_trust_level = min_trust_level
        if require_badge:
            effective_config.require_badge = True
        
        effective_tool_name = tool_name or f.__name__
        
        @wraps(f)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            # Build params dict from kwargs for hashing
            params = dict(kwargs)
            
            # Run async evaluation in event loop
            async def run_eval():
                return await evaluate_tool_access(
                    tool_name=effective_tool_name,
                    params=params,
                    config=effective_config,
                )
            
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None
            
            if loop is not None:
                # We're in an async context, use run_coroutine_threadsafe
                import concurrent.futures
                future = asyncio.run_coroutine_threadsafe(run_eval(), loop)
                result = future.result(timeout=30.0)
            else:
                # No event loop, create one
                result = asyncio.run(run_eval())
            
            # Check decision
            if result.decision == Decision.DENY:
                raise GuardError(
                    reason=result.deny_reason or DenyReason.INTERNAL_ERROR,
                    detail=result.deny_detail or "Access denied",
                    evidence_id=result.evidence_id,
                    agent_did=result.agent_did,
                    trust_level=result.trust_level,
                )
            
            # Execute tool
            return f(*args, **kwargs)
        
        return wrapper
    
    # Handle both @guard_sync and @guard_sync() syntax
    if func is not None:
        return make_decorator(func)
    return make_decorator
