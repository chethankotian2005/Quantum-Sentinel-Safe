"""
Live Scanner Verification — real TLS handshakes against public hostnames.

Proves each target returns genuinely different certificate data, and that the
NFR-3 fallback and hostname-validation paths return the right status codes.

Requires the API server to be running; skipped automatically if it isn't.
"""
import httpx
import pytest

from tests.conftest import BASE_URL, requires_live_server

TARGETS = ["google.com", "github.com", "cloudflare.com"]


@requires_live_server
@pytest.mark.parametrize("host", TARGETS)
def test_live_scan_returns_real_certificate_data(host):
    r = httpx.post(f"{BASE_URL}/api/scan/live", json={"hostname": host}, timeout=20.0)
    assert r.status_code == 200, f"Expected 200 for {host}, got {r.status_code}: {r.text}"

    scan = r.json()
    assert scan["findings"], f"No findings returned for {host}"

    finding = scan["findings"][-1]
    assert finding["hostname"] == host, "response must correspond to the requested host"
    assert finding["algorithm"] in ("RSA", "ECC", "DSA"), finding["algorithm"]
    assert finding["source_type"] == "live_scan"
    assert scan["risk_score"]["score"] <= 100
    assert scan["recommendations"], "a live finding should carry a PQC recommendation"


@requires_live_server
def test_live_scan_hosts_are_probed_individually():
    """Distinct hosts must produce distinct scans, not one cached result."""
    seen = {}
    for host in TARGETS:
        r = httpx.post(f"{BASE_URL}/api/scan/live", json={"hostname": host}, timeout=20.0)
        assert r.status_code == 200
        scan = r.json()
        seen[host] = scan["scan_id"]
        assert scan["target_id"] == host

    assert len(set(seen.values())) == len(TARGETS), f"scan_ids collided: {seen}"


@requires_live_server
def test_unreachable_host_returns_503():
    """NFR-3: genuine network failure gets a distinct 503 the frontend can act on."""
    r = httpx.post(
        f"{BASE_URL}/api/scan/live",
        json={"hostname": "nonexistent-host-xyz123.invalid"},
        timeout=20.0,
    )
    assert r.status_code == 503, f"expected 503, got {r.status_code}: {r.text}"
    assert "detail" in r.json()


@requires_live_server
@pytest.mark.parametrize("bad_host", [
    "127.0.0.1",                 # raw IP
    "8.8.8.8",
    "localhost",                 # no TLD
    "google.com; rm -rf /",      # shell metacharacters
    "<script>alert(1)</script>", # markup
])
def test_malformed_hostname_returns_400_not_500(bad_host):
    """
    Regression guard: these previously returned an unhandled 500 because the
    cached-fallback path re-validated the hostname and raised a second time
    inside the exception handler.
    """
    r = httpx.post(f"{BASE_URL}/api/scan/live", json={"hostname": bad_host}, timeout=20.0)
    assert r.status_code == 400, f"expected 400 for {bad_host!r}, got {r.status_code}: {r.text}"
    assert "not a valid hostname" in r.json()["detail"].lower()


@requires_live_server
def test_empty_hostname_returns_400():
    r = httpx.post(f"{BASE_URL}/api/scan/live", json={"hostname": ""}, timeout=10.0)
    assert r.status_code == 400
