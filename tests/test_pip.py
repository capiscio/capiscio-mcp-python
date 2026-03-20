"""Tests for capiscio_mcp.pip module (RFC-005 Policy Integration Point)."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from capiscio_mcp.pip import (
    Obligation,
    ObligationHandler,
    PIPConfig,
    PolicyClient,
    PolicyResult,
)


# ---------------------------------------------------------------------------
# PolicyResult unit tests
# ---------------------------------------------------------------------------


class TestPolicyResult:
    """Tests for PolicyResult dataclass."""

    def test_allowed_allow(self):
        r = PolicyResult(decision="ALLOW")
        assert r.allowed is True
        assert r.denied is False

    def test_allowed_observe(self):
        r = PolicyResult(decision="ALLOW_OBSERVE")
        assert r.allowed is True
        assert r.denied is False

    def test_denied(self):
        r = PolicyResult(decision="DENY")
        assert r.allowed is False
        assert r.denied is True

    def test_pdp_error(self):
        r = PolicyResult(decision="ALLOW_OBSERVE", error_code="pdp_unavailable")
        assert r.pdp_error is True
        assert r.allowed is True

    def test_no_pdp_error(self):
        r = PolicyResult(decision="ALLOW")
        assert r.pdp_error is False


class TestObligation:
    """Tests for Obligation dataclass."""

    def test_basic(self):
        o = Obligation(id="obl-1", type="rate_limit", params={"max_rps": 10})
        assert o.id == "obl-1"
        assert o.type == "rate_limit"
        assert o.params["max_rps"] == 10

    def test_empty_params(self):
        o = Obligation(id="obl-2", type="audit_log")
        assert o.params == {}


class TestPIPConfig:
    """Tests for PIPConfig dataclass."""

    def test_defaults(self):
        c = PIPConfig()
        assert c.pdp_endpoint == ""
        assert c.pdp_timeout_ms == 0
        assert c.enforcement_mode == ""
        assert c.pep_id == ""

    def test_custom(self):
        c = PIPConfig(
            pdp_endpoint="https://pdp.example.com/eval",
            enforcement_mode="EM-GUARD",
            pdp_timeout_ms=1000,
            pep_id="pep-42",
            workspace="ws-1",
            breakglass_public_key_path="/keys/bg.pub",
        )
        assert c.pdp_endpoint == "https://pdp.example.com/eval"
        assert c.enforcement_mode == "EM-GUARD"
        assert c.pdp_timeout_ms == 1000


# ---------------------------------------------------------------------------
# PolicyResult.execute_obligations tests
# ---------------------------------------------------------------------------


class TestExecuteObligations:
    """Tests for obligation execution on PolicyResult."""

    @pytest.mark.asyncio
    async def test_no_obligations(self):
        r = PolicyResult(decision="ALLOW")
        await r.execute_obligations()  # Should not raise

    @pytest.mark.asyncio
    async def test_handler_called(self):
        handler = AsyncMock()
        obl = Obligation(id="o1", type="rate_limit", params={"max_rps": 5})
        r = PolicyResult(decision="ALLOW", obligations=[obl])

        await r.execute_obligations(handlers={"rate_limit": handler})

        handler.assert_awaited_once_with(obl)

    @pytest.mark.asyncio
    async def test_unknown_type_skipped(self):
        obl = Obligation(id="o1", type="unknown_type")
        r = PolicyResult(decision="ALLOW", obligations=[obl])

        # Should not raise — just logs a warning
        await r.execute_obligations(handlers={})

    @pytest.mark.asyncio
    async def test_handler_exception_logged(self):
        handler = AsyncMock(side_effect=RuntimeError("boom"))
        obl = Obligation(id="o1", type="rate_limit")
        r = PolicyResult(decision="ALLOW", obligations=[obl])

        # Should not raise — logs the exception
        await r.execute_obligations(handlers={"rate_limit": handler})

    @pytest.mark.asyncio
    async def test_multiple_obligations(self):
        rate_handler = AsyncMock()
        audit_handler = AsyncMock()

        obligations = [
            Obligation(id="o1", type="rate_limit", params={"max_rps": 10}),
            Obligation(id="o2", type="audit_log", params={"detail": "high"}),
        ]
        r = PolicyResult(decision="ALLOW", obligations=obligations)

        await r.execute_obligations(
            handlers={"rate_limit": rate_handler, "audit_log": audit_handler}
        )

        rate_handler.assert_awaited_once()
        audit_handler.assert_awaited_once()


# ---------------------------------------------------------------------------
# PolicyClient.evaluate tests (mock gRPC)
# ---------------------------------------------------------------------------


def _mock_response(**overrides):
    """Build a mock PolicyDecisionResponse."""
    defaults = dict(
        decision="ALLOW",
        decision_id="dec-001",
        reason="",
        ttl=0,
        obligations=[],
        enforcement_mode="EM-GUARD",
        cache_hit=False,
        breakglass_override=False,
        breakglass_jti="",
        error_code="",
        pdp_latency_ms=12,
        txn_id="txn-abc",
    )
    defaults.update(overrides)
    resp = MagicMock()
    for k, v in defaults.items():
        setattr(resp, k, v)
    return resp


class TestPolicyClient:
    """Tests for PolicyClient.evaluate via mock gRPC."""

    @pytest.mark.asyncio
    async def test_allow(self, mock_core_client):
        mock_core_client.stub.EvaluatePolicyDecision = AsyncMock(
            return_value=_mock_response()
        )

        with patch(
            "capiscio_mcp._core.client.CoreClient.get_instance",
            return_value=mock_core_client,
        ):
            client = PolicyClient(PIPConfig(pdp_endpoint="http://pdp:8080"))
            result = await client.evaluate(
                subject_did="did:web:example.com:agents:bot",
                badge_jti="badge-1",
                trust_level="2",
                badge_exp=9999999999,
                operation="tools/call",
                resource="db://prod/users",
            )

        assert result.decision == "ALLOW"
        assert result.decision_id == "dec-001"
        assert result.txn_id == "txn-abc"
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_deny(self, mock_core_client):
        mock_core_client.stub.EvaluatePolicyDecision = AsyncMock(
            return_value=_mock_response(
                decision="DENY",
                decision_id="dec-002",
                reason="insufficient trust",
            )
        )

        with patch(
            "capiscio_mcp._core.client.CoreClient.get_instance",
            return_value=mock_core_client,
        ):
            client = PolicyClient(PIPConfig(pdp_endpoint="http://pdp:8080"))
            result = await client.evaluate(
                subject_did="did:web:example.com:agents:bot",
                operation="tools/call",
            )

        assert result.denied is True
        assert result.reason == "insufficient trust"

    @pytest.mark.asyncio
    async def test_allow_observe_pdp_unavailable(self, mock_core_client):
        mock_core_client.stub.EvaluatePolicyDecision = AsyncMock(
            return_value=_mock_response(
                decision="ALLOW_OBSERVE",
                decision_id="pdp-unavailable",
                error_code="pdp_unavailable",
                enforcement_mode="EM-OBSERVE",
            )
        )

        with patch(
            "capiscio_mcp._core.client.CoreClient.get_instance",
            return_value=mock_core_client,
        ):
            client = PolicyClient(
                PIPConfig(
                    pdp_endpoint="http://pdp:8080",
                    enforcement_mode="EM-OBSERVE",
                )
            )
            result = await client.evaluate(operation="tools/call")

        assert result.allowed is True
        assert result.pdp_error is True
        assert result.error_code == "pdp_unavailable"
        assert result.enforcement_mode == "EM-OBSERVE"

    @pytest.mark.asyncio
    async def test_obligations_parsed(self, mock_core_client):
        obl = MagicMock()
        obl.id = "obl-1"
        obl.type = "rate_limit"
        obl.params_json = json.dumps({"max_rps": 10})

        mock_core_client.stub.EvaluatePolicyDecision = AsyncMock(
            return_value=_mock_response(obligations=[obl])
        )

        with patch(
            "capiscio_mcp._core.client.CoreClient.get_instance",
            return_value=mock_core_client,
        ):
            client = PolicyClient(PIPConfig(pdp_endpoint="http://pdp:8080"))
            result = await client.evaluate(operation="tools/call")

        assert len(result.obligations) == 1
        assert result.obligations[0].type == "rate_limit"
        assert result.obligations[0].params == {"max_rps": 10}

    @pytest.mark.asyncio
    async def test_obligation_bad_json(self, mock_core_client):
        obl = MagicMock()
        obl.id = "obl-bad"
        obl.type = "audit_log"
        obl.params_json = "not-json"

        mock_core_client.stub.EvaluatePolicyDecision = AsyncMock(
            return_value=_mock_response(obligations=[obl])
        )

        with patch(
            "capiscio_mcp._core.client.CoreClient.get_instance",
            return_value=mock_core_client,
        ):
            client = PolicyClient(PIPConfig(pdp_endpoint="http://pdp:8080"))
            result = await client.evaluate(operation="tools/call")

        assert len(result.obligations) == 1
        assert result.obligations[0].params == {}

    @pytest.mark.asyncio
    async def test_cache_hit(self, mock_core_client):
        mock_core_client.stub.EvaluatePolicyDecision = AsyncMock(
            return_value=_mock_response(
                cache_hit=True, decision_id="cache-hit"
            )
        )

        with patch(
            "capiscio_mcp._core.client.CoreClient.get_instance",
            return_value=mock_core_client,
        ):
            client = PolicyClient(PIPConfig(pdp_endpoint="http://pdp:8080"))
            result = await client.evaluate(operation="tools/call")

        assert result.cache_hit is True

    @pytest.mark.asyncio
    async def test_breakglass_override(self, mock_core_client):
        mock_core_client.stub.EvaluatePolicyDecision = AsyncMock(
            return_value=_mock_response(
                decision="ALLOW",
                breakglass_override=True,
                breakglass_jti="bg-token-1",
                decision_id="breakglass-override",
            )
        )

        with patch(
            "capiscio_mcp._core.client.CoreClient.get_instance",
            return_value=mock_core_client,
        ):
            client = PolicyClient(PIPConfig(pdp_endpoint="http://pdp:8080"))
            result = await client.evaluate(
                operation="tools/call",
                breakglass_token="eyJ...",
            )

        assert result.breakglass_override is True
        assert result.breakglass_jti == "bg-token-1"

    @pytest.mark.asyncio
    async def test_no_pdp_endpoint(self, mock_core_client):
        """Badge-only mode: no PDP endpoint configured."""
        mock_core_client.stub.EvaluatePolicyDecision = AsyncMock(
            return_value=_mock_response(
                decision="ALLOW",
                decision_id="no-pdp",
                enforcement_mode="EM-GUARD",
            )
        )

        with patch(
            "capiscio_mcp._core.client.CoreClient.get_instance",
            return_value=mock_core_client,
        ):
            client = PolicyClient()  # No config = badge-only
            result = await client.evaluate(
                subject_did="did:web:example.com:agents:bot",
                operation="tools/call",
            )

        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_request_fields_sent(self, mock_core_client):
        """Verify the gRPC request includes all configured fields."""
        captured = {}

        async def capture_request(req):
            captured["subject_did"] = req.subject.did
            captured["badge_jti"] = req.subject.badge_jti
            captured["trust_level"] = req.subject.trust_level
            captured["badge_exp"] = req.subject.badge_exp
            captured["operation"] = req.action.operation
            captured["resource"] = req.resource.identifier
            captured["pdp_endpoint"] = req.config.pdp_endpoint
            captured["enforcement_mode"] = req.config.enforcement_mode
            captured["pep_id"] = req.config.pep_id
            captured["breakglass_token"] = req.breakglass_token
            return _mock_response()

        mock_core_client.stub.EvaluatePolicyDecision = AsyncMock(
            side_effect=capture_request
        )

        with patch(
            "capiscio_mcp._core.client.CoreClient.get_instance",
            return_value=mock_core_client,
        ):
            client = PolicyClient(
                PIPConfig(
                    pdp_endpoint="http://pdp:8080/eval",
                    enforcement_mode="EM-GUARD",
                    pep_id="pep-99",
                )
            )
            await client.evaluate(
                subject_did="did:web:ex.com:agents:a1",
                badge_jti="b-42",
                trust_level="3",
                badge_exp=1750000000,
                operation="tools/call",
                resource="db://prod/users",
                breakglass_token="bg-tok",
            )

        assert captured["subject_did"] == "did:web:ex.com:agents:a1"
        assert captured["badge_jti"] == "b-42"
        assert captured["trust_level"] == "3"
        assert captured["badge_exp"] == 1750000000
        assert captured["operation"] == "tools/call"
        assert captured["resource"] == "db://prod/users"
        assert captured["pdp_endpoint"] == "http://pdp:8080/eval"
        assert captured["enforcement_mode"] == "EM-GUARD"
        assert captured["pep_id"] == "pep-99"
        assert captured["breakglass_token"] == "bg-tok"
