"""Tests for capiscio_mcp.keeper.ServerBadgeKeeper."""

import base64
import json
import time
from unittest.mock import MagicMock, patch

import pytest

from capiscio_mcp.keeper import (
    ServerBadgeKeeper,
    _decode_jwt_exp,
)


# ---------------------------------------------------------------------------
# _decode_jwt_exp helpers
# ---------------------------------------------------------------------------


def _make_jwt(payload: dict) -> str:
    """Build a minimal JWT compact serialization with the given payload."""
    header = base64.urlsafe_b64encode(b'{"alg":"EdDSA"}').rstrip(b"=").decode()
    payload_bytes = json.dumps(payload).encode()
    payload_b64 = base64.urlsafe_b64encode(payload_bytes).rstrip(b"=").decode()
    return f"{header}.{payload_b64}.fakesig"


class TestDecodeJwtExp:
    def test_valid_exp(self):
        token = _make_jwt({"exp": 9999999999, "sub": "did:key:z6Mk"})
        assert _decode_jwt_exp(token) == 9999999999

    def test_no_exp_returns_none(self):
        token = _make_jwt({"sub": "did:key:z6Mk"})
        assert _decode_jwt_exp(token) is None

    def test_malformed_token_returns_none(self):
        assert _decode_jwt_exp("not.a.valid.jwt") is None

    def test_empty_string_returns_none(self):
        assert _decode_jwt_exp("") is None

    def test_single_part_returns_none(self):
        assert _decode_jwt_exp("onlyone") is None

    def test_exp_is_int(self):
        token = _make_jwt({"exp": 1700000000})
        result = _decode_jwt_exp(token)
        assert isinstance(result, int)
        assert result == 1700000000


# ---------------------------------------------------------------------------
# ServerBadgeKeeper unit tests
# ---------------------------------------------------------------------------


class TestServerBadgeKeeper:
    SERVER_ID = "550e8400-e29b-41d4-a716-446655440000"
    API_KEY = "sk_test_abc123"
    INITIAL_BADGE = _make_jwt({"exp": 9999999999, "sub": "test"})

    def _make_keeper(self, **kwargs) -> ServerBadgeKeeper:
        defaults = dict(
            server_id=self.SERVER_ID,
            api_key=self.API_KEY,
            initial_badge=self.INITIAL_BADGE,
            check_interval=100,  # very large so it never fires in tests
        )
        defaults.update(kwargs)
        return ServerBadgeKeeper(**defaults)

    def test_init_stores_initial_badge(self):
        keeper = self._make_keeper()
        assert keeper.get_current_badge() == self.INITIAL_BADGE

    def test_init_not_running(self):
        keeper = self._make_keeper()
        assert keeper.is_running() is False

    def test_start_sets_running(self):
        keeper = self._make_keeper()
        keeper.start()
        try:
            assert keeper.is_running() is True
        finally:
            keeper.stop()

    def test_stop_clears_running(self):
        keeper = self._make_keeper()
        keeper.start()
        keeper.stop()
        assert keeper.is_running() is False

    def test_start_twice_raises(self):
        keeper = self._make_keeper()
        keeper.start()
        try:
            with pytest.raises(RuntimeError, match="already running"):
                keeper.start()
        finally:
            keeper.stop()

    def test_context_manager(self):
        keeper = self._make_keeper()
        with keeper:
            assert keeper.is_running() is True
        assert keeper.is_running() is False

    def test_get_current_badge_returns_initial(self):
        keeper = self._make_keeper()
        assert keeper.get_current_badge() == self.INITIAL_BADGE

    def test_stop_without_start_is_noop(self):
        keeper = self._make_keeper()
        keeper.stop()  # Should not raise
        assert keeper.is_running() is False

    def test_renewal_updates_badge(self):
        """When _renew() is called and HTTP returns a new badge, badge is updated."""
        new_badge = _make_jwt({"exp": 9999999999 + 300, "sub": "renewed"})
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {"badge": new_badge}}

        keeper = self._make_keeper()
        with patch("capiscio_mcp.keeper.requests.post", return_value=mock_response):
            keeper._renew()

        assert keeper.get_current_badge() == new_badge

    def test_renewal_calls_on_renew_callback(self):
        """_renew() should call on_renew when provided."""
        new_badge = _make_jwt({"exp": 9999999999 + 300, "sub": "renewed"})
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"badge": new_badge}

        received = []
        keeper = self._make_keeper(on_renew=lambda b: received.append(b))
        with patch("capiscio_mcp.keeper.requests.post", return_value=mock_response):
            keeper._renew()

        assert received == [new_badge]

    def test_renewal_handles_http_error(self):
        """_renew() should not raise on HTTP error — just log."""
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"

        keeper = self._make_keeper()
        original_badge = keeper.get_current_badge()
        with patch("capiscio_mcp.keeper.requests.post", return_value=mock_response):
            keeper._renew()  # Should not raise

        # Badge should be unchanged after failure
        assert keeper.get_current_badge() == original_badge

    def test_renewal_handles_network_error(self):
        """_renew() should not raise on network error."""
        import requests as req

        keeper = self._make_keeper()
        with patch(
            "capiscio_mcp.keeper.requests.post",
            side_effect=req.RequestException("timeout"),
        ):
            keeper._renew()  # Should not raise

    def test_maybe_renew_skips_when_not_near_expiry(self):
        """_maybe_renew() should not call _renew when badge is not close to expiry."""
        far_future = _make_jwt({"exp": int(time.time()) + 9999})
        keeper = self._make_keeper(initial_badge=far_future, renewal_threshold=30)

        with patch.object(keeper, "_renew") as mock_renew:
            keeper._maybe_renew()
            mock_renew.assert_not_called()

    def test_maybe_renew_triggers_when_close_to_expiry(self):
        """_maybe_renew() should call _renew when exp - now <= threshold."""
        expiring_soon = _make_jwt({"exp": int(time.time()) + 5})
        keeper = self._make_keeper(initial_badge=expiring_soon, renewal_threshold=30)

        with patch.object(keeper, "_renew") as mock_renew:
            keeper._maybe_renew()
            mock_renew.assert_called_once()

    def test_maybe_renew_skips_undecodable_badge(self):
        """_maybe_renew() should not crash when badge has no exp."""
        keeper = self._make_keeper(initial_badge="not.a.jwt")
        # Should not raise and should not call _renew
        with patch.object(keeper, "_renew") as mock_renew:
            keeper._maybe_renew()
            mock_renew.assert_not_called()

    def test_renewal_response_alternative_shapes(self):
        """Keeper handles 'badge' at root level and 'token' key."""
        for response_body in [
            {"badge": "renewed-badge-1"},
            {"token": "renewed-badge-2"},
        ]:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = response_body

            keeper = self._make_keeper()
            with patch("capiscio_mcp.keeper.requests.post", return_value=mock_response):
                keeper._renew()

            expected = list(response_body.values())[0]
            assert keeper.get_current_badge() == expected

    def test_ca_url_trailing_slash_stripped(self):
        """ca_url trailing slash should be stripped so URL is clean."""
        keeper = ServerBadgeKeeper(
            server_id=self.SERVER_ID,
            api_key=self.API_KEY,
            initial_badge=self.INITIAL_BADGE,
            ca_url="https://registry.capisc.io/",
        )
        assert keeper.ca_url == "https://registry.capisc.io"
