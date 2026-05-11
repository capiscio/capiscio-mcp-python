"""Tests for capiscio_mcp.events module (guard event emission)."""

from unittest.mock import MagicMock, patch

import pytest
import requests

from capiscio_mcp.events import (
    GuardEventEmitter,
    get_event_emitter,
    set_event_emitter,
)


# ---------------------------------------------------------------------------
# Singleton management
# ---------------------------------------------------------------------------


class TestSingleton:
    """Tests for module-level emitter singleton."""

    def setup_method(self):
        set_event_emitter(None)

    def teardown_method(self):
        set_event_emitter(None)

    def test_get_returns_none_when_unset(self):
        assert get_event_emitter() is None

    def test_set_and_get(self):
        emitter = GuardEventEmitter(
            server_url="https://example.com",
            api_key="key-1",
        )
        set_event_emitter(emitter)
        assert get_event_emitter() is emitter

    def test_clear_singleton(self):
        emitter = GuardEventEmitter(
            server_url="https://example.com",
            api_key="key-1",
        )
        set_event_emitter(emitter)
        set_event_emitter(None)
        assert get_event_emitter() is None


# ---------------------------------------------------------------------------
# Constructor
# ---------------------------------------------------------------------------


class TestGuardEventEmitterInit:
    """Tests for GuardEventEmitter construction."""

    def test_defaults(self):
        e = GuardEventEmitter(
            server_url="https://registry.capisc.io/",
            api_key="test-key",
        )
        assert e.server_url == "https://registry.capisc.io"  # trailing slash stripped
        assert e.api_key == "test-key"
        assert e.agent_id is None
        assert e.server_id is None
        assert e.enabled is True
        assert e.timeout == 5.0

    def test_custom_params(self):
        e = GuardEventEmitter(
            server_url="https://example.com",
            api_key="k",
            agent_id="agent-uuid",
            server_id="server-uuid",
            enabled=False,
            timeout=2.0,
        )
        assert e.agent_id == "agent-uuid"
        assert e.server_id == "server-uuid"
        assert e.enabled is False
        assert e.timeout == 2.0


# ---------------------------------------------------------------------------
# emit_policy_enforced
# ---------------------------------------------------------------------------


class TestEmitPolicyEnforced:
    """Tests for emit_policy_enforced method."""

    def test_disabled_emitter_does_not_send(self):
        e = GuardEventEmitter(
            server_url="https://example.com",
            api_key="k",
            enabled=False,
        )
        with patch.object(e, "_send") as mock_send:
            e.emit_policy_enforced(decision="DENY", tool_name="read_file")
            mock_send.assert_not_called()

    def test_deny_event_builds_correct_payload(self):
        """Verify the flat event structure matches the server's db.Event."""
        captured = {}

        def capture_send(event):
            captured.update(event)

        e = GuardEventEmitter(
            server_url="https://example.com",
            api_key="k",
            agent_id="aaaaaaaa-1111-2222-3333-444444444444",
        )
        e._agents_loaded = True  # skip HTTP call
        with patch.object(e, "_send", side_effect=capture_send):
            e.emit_policy_enforced(
                decision="DENY",
                tool_name="delete_file",
                deny_reason="TRUST_INSUFFICIENT",
                deny_detail="Level 1 required",
                agent_did="did:web:example.com",
                trust_level=0,
                evidence_id="ev-123",
                error_code="E001",
                requested_capability="write",
                presented_capability="read",
                capability_class="filesystem",
                severity="CRITICAL",
            )
            e.flush(timeout=5.0)

        # Top-level fields (db.Event JSON tags)
        assert captured["eventType"] == "capiscio.policy_enforced"
        assert captured["agentId"] == "aaaaaaaa-1111-2222-3333-444444444444"
        assert captured["decision"] == "DENY"
        assert captured["severity"] == "CRITICAL"
        assert "traceId" in captured
        assert "timestamp" in captured
        assert "id" in captured

        # Nested payload
        p = captured["payload"]
        assert p["tool_name"] == "delete_file"
        assert p["deny_reason"] == "TRUST_INSUFFICIENT"
        assert p["deny_detail"] == "Level 1 required"
        assert p["agent_did"] == "did:web:example.com"
        assert p["trust_level"] == 0
        assert p["evidence_id"] == "ev-123"
        assert p["error_code"] == "E001"
        assert p["requested_capability"] == "write"
        assert p["presented_capability"] == "read"
        assert p["capability_class"] == "filesystem"

    def test_allow_event_severity_defaults_to_info(self):
        captured = {}

        def capture_send(event):
            captured.update(event)

        e = GuardEventEmitter(
            server_url="https://example.com",
            api_key="k",
            agent_id="aaaaaaaa-1111-2222-3333-444444444444",
        )
        e._agents_loaded = True
        with patch.object(e, "_send", side_effect=capture_send):
            e.emit_policy_enforced(decision="ALLOW", tool_name="read_file")
            e.flush(timeout=5.0)

        assert captured["severity"] == "INFO"
        assert captured["decision"] == "ALLOW"

    def test_deny_event_severity_defaults_to_high(self):
        captured = {}

        def capture_send(event):
            captured.update(event)

        e = GuardEventEmitter(
            server_url="https://example.com",
            api_key="k",
            agent_id="aaaaaaaa-1111-2222-3333-444444444444",
        )
        e._agents_loaded = True
        with patch.object(e, "_send", side_effect=capture_send):
            e.emit_policy_enforced(decision="DENY", tool_name="read_file")
            e.flush(timeout=5.0)

        assert captured["severity"] == "HIGH"

    def test_server_id_included_as_mcp_server_id(self):
        captured = {}

        def capture_send(event):
            captured.update(event)

        e = GuardEventEmitter(
            server_url="https://example.com",
            api_key="k",
            agent_id="agent-uuid",
            server_id="server-uuid",
        )
        e._agents_loaded = True
        with patch.object(e, "_send", side_effect=capture_send):
            e.emit_policy_enforced(decision="ALLOW", tool_name="t")
            e.flush(timeout=5.0)

        assert captured["mcpServerId"] == "server-uuid"

    def test_no_server_id_omits_mcp_server_id(self):
        captured = {}

        def capture_send(event):
            captured.update(event)

        e = GuardEventEmitter(
            server_url="https://example.com",
            api_key="k",
            agent_id="agent-uuid",
        )
        e._agents_loaded = True
        with patch.object(e, "_send", side_effect=capture_send):
            e.emit_policy_enforced(decision="ALLOW", tool_name="t")
            e.flush(timeout=5.0)

        assert "mcpServerId" not in captured

    def test_optional_payload_fields_omitted_when_none(self):
        captured = {}

        def capture_send(event):
            captured.update(event)

        e = GuardEventEmitter(
            server_url="https://example.com",
            api_key="k",
            agent_id="agent-uuid",
        )
        e._agents_loaded = True
        with patch.object(e, "_send", side_effect=capture_send):
            e.emit_policy_enforced(decision="ALLOW", tool_name="t")
            e.flush(timeout=5.0)

        p = captured["payload"]
        assert p == {"tool_name": "t"}
        # No deny_reason, deny_detail, etc.
        assert "deny_reason" not in p
        assert "deny_detail" not in p
        assert "error_code" not in p


# ---------------------------------------------------------------------------
# flush
# ---------------------------------------------------------------------------


class TestFlush:
    """Tests for the flush mechanism."""

    def test_flush_waits_for_pending_threads(self):
        e = GuardEventEmitter(
            server_url="https://example.com",
            api_key="k",
            agent_id="agent-uuid",
        )
        e._agents_loaded = True
        with patch.object(e, "_send"):
            e.emit_policy_enforced(decision="ALLOW", tool_name="t")
            # Threads should be tracked
            e.flush(timeout=5.0)
            # After flush, pending list should be empty
            assert len(e._pending_threads) == 0

    def test_flush_on_empty_is_noop(self):
        e = GuardEventEmitter(
            server_url="https://example.com",
            api_key="k",
        )
        e.flush(timeout=1.0)  # should not raise
        assert len(e._pending_threads) == 0


# ---------------------------------------------------------------------------
# _send
# ---------------------------------------------------------------------------


class TestSend:
    """Tests for the _send HTTP POST method."""

    def test_sends_flat_event_json(self):
        e = GuardEventEmitter(
            server_url="https://registry.capisc.io",
            api_key="test-api-key",
        )
        event = {"id": "abc", "agentId": "def", "eventType": "test"}

        with patch("capiscio_mcp.events.requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=202)
            e._send(event)

            mock_post.assert_called_once()
            call_kwargs = mock_post.call_args
            # Flat JSON, not wrapped in {"events": [...]}
            assert call_kwargs.kwargs["json"] == event
            assert call_kwargs.kwargs["headers"]["X-Capiscio-Registry-Key"] == "test-api-key"
            assert call_kwargs.kwargs["headers"]["Content-Type"] == "application/json"
            assert call_kwargs.args[0] == "https://registry.capisc.io/v1/events"

    def test_send_logs_warning_on_4xx(self, caplog):
        e = GuardEventEmitter(
            server_url="https://example.com",
            api_key="k",
        )
        with patch("capiscio_mcp.events.requests.post") as mock_post:
            mock_post.return_value = MagicMock(
                status_code=400,
                text="Bad Request: agentId is required",
            )
            import logging
            with caplog.at_level(logging.WARNING, logger="capiscio_mcp.events"):
                e._send({"id": "x"})
            assert "400" in caplog.text

    def test_send_swallows_network_errors(self):
        e = GuardEventEmitter(
            server_url="https://example.com",
            api_key="k",
        )
        with patch("capiscio_mcp.events.requests.post", side_effect=requests.ConnectionError):
            # Should not raise
            e._send({"id": "x"})


# ---------------------------------------------------------------------------
# DID resolution
# ---------------------------------------------------------------------------


class TestResolveAgentId:
    """Tests for DID → agent UUID resolution."""

    def test_returns_agent_id_when_no_did(self):
        e = GuardEventEmitter(
            server_url="https://example.com",
            api_key="k",
            agent_id="fallback-uuid",
        )
        e._agents_loaded = True
        assert e._resolve_agent_id(None) == "fallback-uuid"

    def test_returns_cached_value(self):
        e = GuardEventEmitter(
            server_url="https://example.com",
            api_key="k",
        )
        e._agents_loaded = True
        e._did_to_agent_id["did:web:cached.com"] = "cached-uuid"
        assert e._resolve_agent_id("did:web:cached.com") == "cached-uuid"

    def test_resolves_via_api_on_cache_miss(self):
        e = GuardEventEmitter(
            server_url="https://example.com",
            api_key="k",
        )
        e._agents_loaded = True

        with patch("capiscio_mcp.events.requests.get") as mock_get:
            mock_get.return_value = MagicMock(
                status_code=200,
                json=lambda: {"data": [{"id": "resolved-uuid", "did": "did:web:new.com"}]},
            )
            result = e._resolve_agent_id("did:web:new.com")
            assert result == "resolved-uuid"
            # Should be cached now
            assert e._did_to_agent_id["did:web:new.com"] == "resolved-uuid"

    def test_falls_back_to_agent_id_on_api_failure(self):
        e = GuardEventEmitter(
            server_url="https://example.com",
            api_key="k",
            agent_id="fallback",
        )
        e._agents_loaded = True

        with patch("capiscio_mcp.events.requests.get", side_effect=requests.ConnectionError):
            assert e._resolve_agent_id("did:web:unreachable.com") == "fallback"

    def test_falls_back_on_empty_api_response(self):
        e = GuardEventEmitter(
            server_url="https://example.com",
            api_key="k",
            agent_id="fallback",
        )
        e._agents_loaded = True

        with patch("capiscio_mcp.events.requests.get") as mock_get:
            mock_get.return_value = MagicMock(
                status_code=200,
                json=lambda: {"data": []},
            )
            assert e._resolve_agent_id("did:web:unknown.com") == "fallback"


# ---------------------------------------------------------------------------
# _load_all_agents
# ---------------------------------------------------------------------------


class TestLoadAllAgents:
    """Tests for the eager agent cache loading."""

    def test_populates_cache_from_api(self):
        e = GuardEventEmitter(
            server_url="https://example.com",
            api_key="k",
        )

        with patch("capiscio_mcp.events.requests.get") as mock_get:
            mock_get.return_value = MagicMock(
                status_code=200,
                json=lambda: {
                    "data": [
                        {"id": "uuid-1", "did": "did:web:agent1.com"},
                        {"id": "uuid-2", "did": "did:web:agent2.com"},
                        {"id": "uuid-3"},  # missing DID — should be skipped
                    ]
                },
            )
            e._load_all_agents()

        assert e._agents_loaded is True
        assert e._did_to_agent_id["did:web:agent1.com"] == "uuid-1"
        assert e._did_to_agent_id["did:web:agent2.com"] == "uuid-2"
        assert len(e._did_to_agent_id) == 2

    def test_sets_fallback_agent_id_from_first_agent(self):
        e = GuardEventEmitter(
            server_url="https://example.com",
            api_key="k",
        )
        assert e.agent_id is None

        with patch("capiscio_mcp.events.requests.get") as mock_get:
            mock_get.return_value = MagicMock(
                status_code=200,
                json=lambda: {"data": [{"id": "first-uuid", "did": "did:web:a.com"}]},
            )
            e._load_all_agents()

        assert e.agent_id == "first-uuid"

    def test_preserves_explicit_agent_id(self):
        e = GuardEventEmitter(
            server_url="https://example.com",
            api_key="k",
            agent_id="explicit-uuid",
        )

        with patch("capiscio_mcp.events.requests.get") as mock_get:
            mock_get.return_value = MagicMock(
                status_code=200,
                json=lambda: {"data": [{"id": "api-uuid", "did": "did:web:a.com"}]},
            )
            e._load_all_agents()

        assert e.agent_id == "explicit-uuid"  # not overwritten

    def test_handles_api_failure_gracefully(self):
        e = GuardEventEmitter(
            server_url="https://example.com",
            api_key="k",
        )

        with patch("capiscio_mcp.events.requests.get", side_effect=requests.ConnectionError):
            e._load_all_agents()  # should not raise

        assert e._agents_loaded is True
        assert len(e._did_to_agent_id) == 0

    def test_skips_reload_on_subsequent_calls(self):
        e = GuardEventEmitter(
            server_url="https://example.com",
            api_key="k",
        )
        e._agents_loaded = True

        with patch("capiscio_mcp.events.requests.get") as mock_get:
            # Calling _resolve_agent_id should not trigger _load_all_agents
            e._resolve_agent_id(None)
            mock_get.assert_not_called()
