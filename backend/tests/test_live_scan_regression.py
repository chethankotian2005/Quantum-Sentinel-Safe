"""
Score regression guard for the live-scan pipeline.

Pins the end-to-end risk score for three known hosts so an unintended change
to the classifier weights or scoring formula shows up immediately.

Requires the API server to be running; skipped automatically if it isn't.
"""
import httpx

from tests.conftest import BASE_URL, requires_live_server

# Derived from classification/risk_classifier.py weights (see test_impact.py
# for a worked example). Update deliberately when the scoring model changes.
#   cloudflare.com / ecc256.badssl.com: single ECC-256 production cert
#     -> 40 + 20.62 + 20 + 15 = 88.12; 100 - 88.12/100*15 = 86
#   rsa8192.badssl.com: TLS_VERIFY_ERROR (81.5) + RSA-8192 signing (66.0)
#     -> 100 - (147.5/100*15) = 77
EXPECTED_SCORES = {
    "cloudflare.com": 86,
    "ecc256.badssl.com": 86,
    "rsa8192.badssl.com": 77,
}


@requires_live_server
def test_live_scan_regression():
    for host, expected in EXPECTED_SCORES.items():
        res = httpx.post(f"{BASE_URL}/api/scan/live", json={"hostname": host}, timeout=25.0)
        assert res.status_code == 200, f"Expected 200 OK for {host}, got {res.status_code}"

        scan = res.json()
        actual = scan["risk_score"]["score"]
        assert actual == expected, (
            f"Score for {host} changed! Expected {expected}, got {actual}. "
            f"Findings: {[(f['algorithm'], f['risk_score'], f.get('vulnerability_score')) for f in scan['findings']]}"
        )
