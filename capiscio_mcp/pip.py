"""
RFC-005: Policy Integration Point (PIP) — Python thin client.

Delegates all PDP decision logic (query, cache, break-glass, enforcement mode)
to the Go core's EvaluatePolicyDecision gRPC RPC. The SDK handles:
- Building the request from badge claims and config
- Obligation execution (context-dependent: rate limiting, logging, etc.)
- Response propagation to the calling application

Architecture: Option B — centralised PDP logic in Go core.
See capiscio-core/internal/rpc/policy_decision.go for the authoritative
decision engine.

Usage:
    from capiscio_mcp.pip import PolicyClient, PIPConfig, PolicyResult

    config = PIPConfig(
        pdp_endpoint="https://pdp.example.com/v1/evaluate",
        enforcement_mode="EM-GUARD",
    )
    client = PolicyClient(config)
    result = await client.evaluate(
        subject_did="did:web:example.com:agents:bot",
        badge_jti="badge-123",
        trust_level="2",
        badge_exp=1750000000,
        operation="tools/call",
        resource="database://prod/users",
    )
    if result.decision == "ALLOW":
        await result.execute_obligations()
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class PIPConfig:
    """Configuration for the Policy Integration Point.

    Attributes:
        pdp_endpoint: PDP URL. Empty = badge-only mode (no PDP query).
        pdp_timeout_ms: PDP query timeout in milliseconds. 0 = 500ms default.
        enforcement_mode: EM-OBSERVE, EM-GUARD, EM-DELEGATE, EM-STRICT.
            Empty = EM-OBSERVE.
        pep_id: PEP identifier for audit logs.
        workspace: Workspace identifier for PDP requests.
        breakglass_public_key_path: Path to Ed25519 public key for break-glass.
    """

    pdp_endpoint: str = ""
    pdp_timeout_ms: int = 0
    enforcement_mode: str = ""
    pep_id: str = ""
    workspace: str = ""
    breakglass_public_key_path: str = ""


@dataclass
class Obligation:
    """A single obligation returned by the PDP.

    Attributes:
        id: Unique obligation identifier.
        type: Obligation type (e.g., "rate_limit", "audit_log").
        params: Parsed parameters dictionary (from params_json).
    """

    id: str
    type: str
    params: Dict[str, Any] = field(default_factory=dict)


# Type alias for obligation handler functions
ObligationHandler = Callable[[Obligation], Coroutine[Any, Any, None]]


@dataclass
class PolicyResult:
    """Result from a policy decision evaluation.

    Attributes:
        decision: "ALLOW", "DENY", or "ALLOW_OBSERVE".
        decision_id: Unique ID for this decision (from PDP or synthetic).
        reason: Human-readable reason (on DENY or PDP-provided).
        ttl: Cache TTL in seconds from PDP.
        obligations: List of obligations the SDK should execute.
        enforcement_mode: The enforcement mode applied.
        cache_hit: Whether the decision came from cache.
        breakglass_override: Whether break-glass was applied.
        breakglass_jti: Break-glass token JTI (for audit).
        error_code: Non-empty when PDP was not consulted
            ("pdp_unavailable", "pdp_timeout", "pdp_invalid_response").
        pdp_latency_ms: PDP query time in milliseconds.
        txn_id: Transaction ID (UUID v7) for correlation.
    """

    decision: str = ""
    decision_id: str = ""
    reason: str = ""
    ttl: int = 0
    obligations: List[Obligation] = field(default_factory=list)
    enforcement_mode: str = ""
    cache_hit: bool = False
    breakglass_override: bool = False
    breakglass_jti: str = ""
    error_code: str = ""
    pdp_latency_ms: int = 0
    txn_id: str = ""

    @property
    def allowed(self) -> bool:
        """Whether the decision permits execution (ALLOW or ALLOW_OBSERVE)."""
        return self.decision in ("ALLOW", "ALLOW_OBSERVE")

    @property
    def denied(self) -> bool:
        """Whether the decision denies execution."""
        return self.decision == "DENY"

    @property
    def pdp_error(self) -> bool:
        """Whether the PDP could not be consulted."""
        return bool(self.error_code)

    async def execute_obligations(
        self,
        handlers: Optional[Dict[str, ObligationHandler]] = None,
    ) -> None:
        """Execute obligations returned by the policy decision.

        Obligation execution is context-dependent and stays in the SDK.
        For example, rate limiting needs the SDK's HTTP layer, logging
        needs the SDK's logger.

        Args:
            handlers: Map of obligation type to async handler function.
                Unknown obligation types are logged and skipped.
        """
        if not self.obligations:
            return

        effective_handlers = handlers or {}

        for obligation in self.obligations:
            handler = effective_handlers.get(obligation.type)
            if handler is None:
                logger.warning(
                    "No handler for obligation type %r (id=%s), skipping",
                    obligation.type,
                    obligation.id,
                )
                continue

            try:
                await handler(obligation)
            except Exception:
                logger.exception(
                    "Obligation handler failed for %r (id=%s)",
                    obligation.type,
                    obligation.id,
                )


class PolicyClient:
    """Thin client for policy evaluation via capiscio-core gRPC.

    All decision logic (PDP query, caching, break-glass, enforcement mode)
    lives in the Go core. This client builds the request, sends it via gRPC,
    and returns a ``PolicyResult`` that the SDK can act on.

    Attributes:
        config: PIP configuration.
    """

    def __init__(self, config: Optional[PIPConfig] = None) -> None:
        self.config = config or PIPConfig()

    async def evaluate(
        self,
        *,
        subject_did: str = "",
        badge_jti: str = "",
        ial: str = "",
        trust_level: str = "",
        badge_exp: int = 0,
        operation: str = "",
        capability_class: str = "",
        resource: str = "",
        breakglass_token: str = "",
    ) -> PolicyResult:
        """Evaluate a policy decision via the Go core.

        Args:
            subject_did: Agent DID from verified badge.
            badge_jti: Badge JTI.
            ial: Badge IAL.
            trust_level: Badge trust level ("1", "2", etc.).
            badge_exp: Badge expiration (Unix seconds).
            operation: Tool name, HTTP method+route, etc.
            capability_class: Empty in badge-only mode (RFC-008).
            resource: Target resource URI.
            breakglass_token: Optional break-glass JWS token.

        Returns:
            PolicyResult with decision, obligations, and metadata.
        """
        from capiscio_mcp._core.client import CoreClient
        from capiscio_mcp._proto.capiscio.v1 import mcp_pb2

        client = await CoreClient.get_instance()

        request = mcp_pb2.PolicyDecisionRequest(
            subject=mcp_pb2.PolicySubject(
                did=subject_did,
                badge_jti=badge_jti,
                ial=ial,
                trust_level=trust_level,
                badge_exp=badge_exp,
            ),
            action=mcp_pb2.PolicyAction(
                operation=operation,
                capability_class=capability_class,
            ),
            resource=mcp_pb2.PolicyResource(
                identifier=resource,
            ),
            config=mcp_pb2.PolicyConfig(
                pdp_endpoint=self.config.pdp_endpoint,
                pdp_timeout_ms=self.config.pdp_timeout_ms,
                enforcement_mode=self.config.enforcement_mode,
                pep_id=self.config.pep_id,
                workspace=self.config.workspace,
                breakglass_public_key_path=self.config.breakglass_public_key_path,
            ),
            breakglass_token=breakglass_token,
        )

        response = await client.stub.EvaluatePolicyDecision(request)

        # Parse obligations
        obligations: List[Obligation] = []
        for obl in response.obligations:
            params: Dict[str, Any] = {}
            if obl.params_json:
                try:
                    params = json.loads(obl.params_json)
                except (json.JSONDecodeError, TypeError):
                    logger.warning(
                        "Failed to parse obligation params_json for %s", obl.id
                    )
            obligations.append(
                Obligation(id=obl.id, type=obl.type, params=params)
            )

        return PolicyResult(
            decision=response.decision,
            decision_id=response.decision_id,
            reason=response.reason,
            ttl=response.ttl,
            obligations=obligations,
            enforcement_mode=response.enforcement_mode,
            cache_hit=response.cache_hit,
            breakglass_override=response.breakglass_override,
            breakglass_jti=response.breakglass_jti,
            error_code=response.error_code,
            pdp_latency_ms=response.pdp_latency_ms,
            txn_id=response.txn_id,
        )
