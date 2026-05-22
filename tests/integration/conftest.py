"""Pytest fixtures for live integration tests.

These tests require:
- capiscio-core gRPC server (via CAPISCIO_CORE_ADDR or embedded binary)
- capiscio-server REST API (via CAPISCIO_SERVER_URL or default localhost:8080)

Skip automatically when infrastructure is unavailable.
"""

import os
import time

import pytest

CAPISCIO_SERVER_URL = os.getenv("CAPISCIO_SERVER_URL", "http://localhost:8080")
CAPISCIO_API_KEY = os.getenv("CAPISCIO_API_KEY", "test-integration-key")


@pytest.fixture(scope="session")
def server_url():
    """Base URL for capiscio-server."""
    return CAPISCIO_SERVER_URL


@pytest.fixture(scope="session")
def api_key():
    """API key for capiscio-server SDK endpoints."""
    return CAPISCIO_API_KEY


@pytest.fixture(scope="session")
def wait_for_server():
    """Wait for capiscio-server to be healthy (up to 30s)."""
    import requests

    for i in range(30):
        try:
            resp = requests.get(f"{CAPISCIO_SERVER_URL}/health", timeout=2)
            if resp.status_code == 200:
                return True
        except requests.exceptions.RequestException:
            pass
        time.sleep(1)
    pytest.skip(f"Server not available at {CAPISCIO_SERVER_URL} after 30s")


@pytest.fixture(autouse=True)
async def _reset_core_client():
    """Reset CoreClient singleton between tests to avoid stale connections."""
    yield
    from capiscio_mcp._core.client import CoreClient
    await CoreClient.reset()
