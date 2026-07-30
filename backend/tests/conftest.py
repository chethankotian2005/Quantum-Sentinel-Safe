"""Shared pytest fixtures/helpers."""
import pytest

BASE_URL = "http://127.0.0.1:8000"


def _server_is_up(timeout: float = 1.5) -> bool:
    try:
        import httpx
        httpx.get(f"{BASE_URL}/docs", timeout=timeout)
        return True
    except Exception:
        return False


# Tests that need the API server running should use this marker. Without it,
# an un-started server turned into a collection error that aborted the whole
# suite instead of skipping the handful of tests that actually need it.
requires_live_server = pytest.mark.skipif(
    not _server_is_up(),
    reason=f"API server not running at {BASE_URL} (start it with: uvicorn main:app)",
)
