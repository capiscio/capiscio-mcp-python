"""Tests for capiscio_mcp.connect.MCPServerIdentity."""

import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from capiscio_mcp.connect import (
    MCPServerIdentity,
    _issue_badge_sync,
    _load_private_key_pem,
    _log_key_capture_hint,
    DEFAULT_REGISTRY,
    DEFAULT_MCP_KEYS_DIR,
    ENV_SERVER_PRIVATE_KEY,
)
from capiscio_mcp.keeper import ServerBadgeKeeper


SERVER_ID = "550e8400-e29b-41d4-a716-446655440000"
API_KEY = "sk_test_abc123"
FAKE_DID = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
FAKE_BADGE = "eyJhbGciOiJFZERTQSJ9.eyJleHAiOjk5OTk5OTk5OTl9.fakesig"
FAKE_PRIV_KEY_PEM = "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n"
FAKE_PUB_KEY_PEM = "-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----\n"


def _make_real_ed25519_pem() -> tuple[str, str, str]:
    """Generate a real Ed25519 keypair for tests that need valid crypto."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding, NoEncryption, PrivateFormat, PublicFormat,
    )

    key = Ed25519PrivateKey.generate()
    priv_pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
    pub_pem = key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
    _, _, _, did = _load_private_key_pem(priv_pem)
    return priv_pem, pub_pem, did


# ---------------------------------------------------------------------------
# _issue_badge_sync
# ---------------------------------------------------------------------------


class TestIssueBadgeSync:
    def test_returns_badge_from_data_key(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": {"badge": FAKE_BADGE}}
        with patch("capiscio_mcp.connect.requests.post", return_value=mock_resp):
            result = _issue_badge_sync(SERVER_ID, API_KEY, DEFAULT_REGISTRY)
        assert result == FAKE_BADGE

    def test_returns_badge_from_root_key(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"badge": FAKE_BADGE}
        with patch("capiscio_mcp.connect.requests.post", return_value=mock_resp):
            result = _issue_badge_sync(SERVER_ID, API_KEY, DEFAULT_REGISTRY)
        assert result == FAKE_BADGE

    def test_returns_badge_from_token_key(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"token": FAKE_BADGE}
        with patch("capiscio_mcp.connect.requests.post", return_value=mock_resp):
            result = _issue_badge_sync(SERVER_ID, API_KEY, DEFAULT_REGISTRY)
        assert result == FAKE_BADGE

    def test_returns_none_on_http_error(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = "Server Error"
        with patch("capiscio_mcp.connect.requests.post", return_value=mock_resp):
            result = _issue_badge_sync(SERVER_ID, API_KEY, DEFAULT_REGISTRY)
        assert result is None

    def test_returns_none_on_network_error(self):
        import requests as req
        with patch(
            "capiscio_mcp.connect.requests.post",
            side_effect=req.RequestException("timeout"),
        ):
            result = _issue_badge_sync(SERVER_ID, API_KEY, DEFAULT_REGISTRY)
        assert result is None

    def test_returns_none_when_no_badge_field(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"status": "ok"}
        with patch("capiscio_mcp.connect.requests.post", return_value=mock_resp):
            result = _issue_badge_sync(SERVER_ID, API_KEY, DEFAULT_REGISTRY)
        assert result is None


# ---------------------------------------------------------------------------
# MCPServerIdentity dataclass
# ---------------------------------------------------------------------------


class TestMCPServerIdentityDataclass:
    def _make_identity(self, **kwargs) -> MCPServerIdentity:
        defaults = dict(
            server_id=SERVER_ID,
            did=FAKE_DID,
            api_key=API_KEY,
            server_url=DEFAULT_REGISTRY,
            keys_dir=Path("/tmp/test-keys"),
            badge=FAKE_BADGE,
            private_key_pem=FAKE_PRIV_KEY_PEM,
        )
        defaults.update(kwargs)
        return MCPServerIdentity(**defaults)

    def test_get_badge_returns_badge_without_keeper(self):
        identity = self._make_identity()
        assert identity.get_badge() == FAKE_BADGE

    def test_get_badge_prefers_keeper(self):
        keeper = MagicMock(spec=ServerBadgeKeeper)
        keeper.get_current_badge.return_value = "keeper-badge"
        identity = self._make_identity(_keeper=keeper)
        assert identity.get_badge() == "keeper-badge"

    def test_get_badge_falls_back_to_badge_when_keeper_empty(self):
        keeper = MagicMock(spec=ServerBadgeKeeper)
        keeper.get_current_badge.return_value = None
        identity = self._make_identity(_keeper=keeper)
        assert identity.get_badge() == FAKE_BADGE

    def test_close_stops_keeper(self):
        keeper = MagicMock(spec=ServerBadgeKeeper)
        identity = self._make_identity(_keeper=keeper)
        identity.close()
        keeper.stop.assert_called_once()
        assert identity._keeper is None

    def test_close_without_keeper_is_noop(self):
        identity = self._make_identity(_keeper=None)
        identity.close()  # Should not raise

    def test_context_manager(self):
        keeper = MagicMock(spec=ServerBadgeKeeper)
        identity = self._make_identity(_keeper=keeper)
        with identity:
            pass
        keeper.stop.assert_called_once()

    def test_context_manager_returns_self(self):
        identity = self._make_identity()
        with identity as ctx:
            assert ctx is identity


# ---------------------------------------------------------------------------
# MCPServerIdentity.connect() — new keys path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestMCPServerIdentityConnect:
    @pytest.fixture
    def tmp_keys_dir(self, tmp_path):
        return tmp_path / "mcp-server-keys"

    async def test_connect_generates_keys_when_none_exist(self, tmp_keys_dir):
        """connect() should generate keys when the keys_dir is empty."""
        fake_keys = {
            "did_key": FAKE_DID,
            "public_key_pem": FAKE_PUB_KEY_PEM,
            "private_key_pem": FAKE_PRIV_KEY_PEM,
            "key_id": "key-1",
        }

        with (
            patch("capiscio_mcp.connect.generate_server_keypair", new_callable=AsyncMock, return_value=fake_keys),
            patch("capiscio_mcp.connect.register_server_identity", new_callable=AsyncMock, return_value={"success": True}),
            patch("capiscio_mcp.connect._issue_badge", new_callable=AsyncMock, return_value=FAKE_BADGE),
            patch("capiscio_mcp.connect.ServerBadgeKeeper") as MockKeeper,
        ):
            mock_keeper = MagicMock(spec=ServerBadgeKeeper)
            mock_keeper.get_current_badge.return_value = FAKE_BADGE
            MockKeeper.return_value = mock_keeper

            identity = await MCPServerIdentity.connect(
                server_id=SERVER_ID,
                api_key=API_KEY,
                server_url="http://localhost:8080",
                keys_dir=tmp_keys_dir,
            )

        assert identity.did == FAKE_DID
        assert identity.server_id == SERVER_ID
        assert identity.api_key == API_KEY
        assert identity.badge == FAKE_BADGE
        mock_keeper.start.assert_called_once()

    async def test_connect_recovers_existing_keys(self, tmp_keys_dir):
        """connect() should not regenerate keys when they already exist."""
        # Write keys to disk
        tmp_keys_dir.mkdir(parents=True, exist_ok=True)
        (tmp_keys_dir / "private_key.pem").write_text(FAKE_PRIV_KEY_PEM)
        (tmp_keys_dir / "did.txt").write_text(FAKE_DID)
        (tmp_keys_dir / "public_key.pem").write_text(FAKE_PUB_KEY_PEM)

        with (
            patch("capiscio_mcp.connect.generate_server_keypair", new_callable=AsyncMock) as mock_gen,
            patch("capiscio_mcp.connect._load_private_key_pem", return_value=(
                None, FAKE_PRIV_KEY_PEM, FAKE_PUB_KEY_PEM, FAKE_DID,
            )),
            patch("capiscio_mcp.connect.register_server_identity", new_callable=AsyncMock),
            patch("capiscio_mcp.connect._issue_badge", new_callable=AsyncMock, return_value=FAKE_BADGE),
            patch("capiscio_mcp.connect.ServerBadgeKeeper") as MockKeeper,
        ):
            mock_keeper = MagicMock(spec=ServerBadgeKeeper)
            mock_keeper.get_current_badge.return_value = FAKE_BADGE
            MockKeeper.return_value = mock_keeper

            identity = await MCPServerIdentity.connect(
                server_id=SERVER_ID,
                api_key=API_KEY,
                server_url="http://localhost:8080",
                keys_dir=tmp_keys_dir,
            )

        # Should NOT have regenerated keys
        mock_gen.assert_not_called()
        assert identity.did == FAKE_DID

    async def test_connect_no_badge_when_auto_badge_false(self, tmp_keys_dir):
        """connect(auto_badge=False) should skip badge issuance."""
        fake_keys = {
            "did_key": FAKE_DID,
            "public_key_pem": FAKE_PUB_KEY_PEM,
            "private_key_pem": FAKE_PRIV_KEY_PEM,
            "key_id": "key-1",
        }

        with (
            patch("capiscio_mcp.connect.generate_server_keypair", new_callable=AsyncMock, return_value=fake_keys),
            patch("capiscio_mcp.connect.register_server_identity", new_callable=AsyncMock),
            patch("capiscio_mcp.connect._issue_badge", new_callable=AsyncMock) as mock_issue,
        ):
            identity = await MCPServerIdentity.connect(
                server_id=SERVER_ID,
                api_key=API_KEY,
                keys_dir=tmp_keys_dir,
                auto_badge=False,
            )

        mock_issue.assert_not_called()
        assert identity.badge is None
        assert identity._keeper is None

    async def test_connect_handles_badge_failure_gracefully(self, tmp_keys_dir):
        """connect() should complete even if badge issuance fails."""
        fake_keys = {
            "did_key": FAKE_DID,
            "public_key_pem": FAKE_PUB_KEY_PEM,
            "private_key_pem": FAKE_PRIV_KEY_PEM,
            "key_id": "key-1",
        }

        with (
            patch("capiscio_mcp.connect.generate_server_keypair", new_callable=AsyncMock, return_value=fake_keys),
            patch("capiscio_mcp.connect.register_server_identity", new_callable=AsyncMock),
            patch("capiscio_mcp.connect._issue_badge", new_callable=AsyncMock, return_value=None),
        ):
            identity = await MCPServerIdentity.connect(
                server_id=SERVER_ID,
                api_key=API_KEY,
                keys_dir=tmp_keys_dir,
            )

        assert identity.badge is None
        assert identity._keeper is None
        assert identity.did == FAKE_DID

    async def test_connect_uses_env_var_private_key(self, tmp_keys_dir):
        """connect() should load identity from CAPISCIO_SERVER_PRIVATE_KEY_PEM."""
        real_priv, real_pub, real_did = _make_real_ed25519_pem()

        with (
            patch.dict(os.environ, {ENV_SERVER_PRIVATE_KEY: real_priv}),
            patch("capiscio_mcp.connect.generate_server_keypair", new_callable=AsyncMock) as mock_gen,
            patch("capiscio_mcp.connect.register_server_identity", new_callable=AsyncMock),
            patch("capiscio_mcp.connect._issue_badge", new_callable=AsyncMock, return_value=None),
        ):
            identity = await MCPServerIdentity.connect(
                server_id=SERVER_ID,
                api_key=API_KEY,
                keys_dir=tmp_keys_dir,
            )

        # Should NOT have generated a new keypair
        mock_gen.assert_not_called()
        assert identity.did == real_did
        # Should have persisted key to disk
        assert (tmp_keys_dir / "private_key.pem").exists()
        assert (tmp_keys_dir / "public_key.pem").exists()
        assert (tmp_keys_dir / "did.txt").read_text() == real_did

    async def test_connect_env_var_takes_precedence_over_local_file(self, tmp_keys_dir):
        """Env var key should override a different key on disk."""
        real_priv, real_pub, real_did = _make_real_ed25519_pem()

        # Write a different (fake) key to disk
        tmp_keys_dir.mkdir(parents=True, exist_ok=True)
        (tmp_keys_dir / "private_key.pem").write_text(FAKE_PRIV_KEY_PEM)
        (tmp_keys_dir / "did.txt").write_text(FAKE_DID)

        with (
            patch.dict(os.environ, {ENV_SERVER_PRIVATE_KEY: real_priv}),
            patch("capiscio_mcp.connect.generate_server_keypair", new_callable=AsyncMock) as mock_gen,
            patch("capiscio_mcp.connect.register_server_identity", new_callable=AsyncMock),
            patch("capiscio_mcp.connect._issue_badge", new_callable=AsyncMock, return_value=None),
        ):
            identity = await MCPServerIdentity.connect(
                server_id=SERVER_ID,
                api_key=API_KEY,
                keys_dir=tmp_keys_dir,
            )

        mock_gen.assert_not_called()
        assert identity.did == real_did  # env var DID, not FAKE_DID

    async def test_connect_logs_capture_hint_on_new_generation(self, tmp_keys_dir):
        """connect() should log a capture hint when generating a new identity."""
        fake_keys = {
            "did_key": FAKE_DID,
            "public_key_pem": FAKE_PUB_KEY_PEM,
            "private_key_pem": FAKE_PRIV_KEY_PEM,
            "key_id": "key-1",
        }

        with (
            patch("capiscio_mcp.connect.generate_server_keypair", new_callable=AsyncMock, return_value=fake_keys),
            patch("capiscio_mcp.connect.register_server_identity", new_callable=AsyncMock, return_value={"success": True}),
            patch("capiscio_mcp.connect._issue_badge", new_callable=AsyncMock, return_value=None),
            patch("capiscio_mcp.connect._log_key_capture_hint") as mock_hint,
        ):
            await MCPServerIdentity.connect(
                server_id=SERVER_ID,
                api_key=API_KEY,
                keys_dir=tmp_keys_dir,
            )

        mock_hint.assert_called_once_with(SERVER_ID, FAKE_PRIV_KEY_PEM)

    async def test_connect_no_capture_hint_on_recovery(self, tmp_keys_dir):
        """connect() should NOT log a capture hint when recovering from local keys."""
        tmp_keys_dir.mkdir(parents=True, exist_ok=True)
        (tmp_keys_dir / "private_key.pem").write_text(FAKE_PRIV_KEY_PEM)

        with (
            patch("capiscio_mcp.connect._load_private_key_pem", return_value=(
                None, FAKE_PRIV_KEY_PEM, FAKE_PUB_KEY_PEM, FAKE_DID,
            )),
            patch("capiscio_mcp.connect.register_server_identity", new_callable=AsyncMock),
            patch("capiscio_mcp.connect._issue_badge", new_callable=AsyncMock, return_value=None),
            patch("capiscio_mcp.connect._log_key_capture_hint") as mock_hint,
        ):
            await MCPServerIdentity.connect(
                server_id=SERVER_ID,
                api_key=API_KEY,
                keys_dir=tmp_keys_dir,
            )

        mock_hint.assert_not_called()


# ---------------------------------------------------------------------------
# MCPServerIdentity.from_env()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestMCPServerIdentityFromEnv:
    async def test_raises_without_server_id(self):
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(ValueError, match="CAPISCIO_SERVER_ID"):
                await MCPServerIdentity.from_env()

    async def test_raises_without_api_key(self):
        env = {"CAPISCIO_SERVER_ID": SERVER_ID}
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(ValueError, match="CAPISCIO_API_KEY"):
                await MCPServerIdentity.from_env()

    async def test_calls_connect_with_env_values(self):
        env = {
            "CAPISCIO_SERVER_ID": SERVER_ID,
            "CAPISCIO_API_KEY": API_KEY,
            "CAPISCIO_SERVER_URL": "http://localhost:8080",
        }

        fake_identity = MCPServerIdentity(
            server_id=SERVER_ID,
            did=FAKE_DID,
            api_key=API_KEY,
            server_url="http://localhost:8080",
            keys_dir=Path("/tmp"),
        )

        with patch.dict(os.environ, env, clear=True):
            with patch.object(
                MCPServerIdentity,
                "connect",
                new_callable=AsyncMock,
                return_value=fake_identity,
            ) as mock_connect:
                result = await MCPServerIdentity.from_env()

        mock_connect.assert_called_once_with(
            server_id=SERVER_ID,
            api_key=API_KEY,
            server_url="http://localhost:8080",
            domain=None,
        )
        assert result is fake_identity
