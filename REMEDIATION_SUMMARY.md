# Remediation Summary

Every Blocking, Major, Minor, and Cosmetic-with-a-fix finding from
`QA_TEST_REPORT.md` has been addressed and re-verified by re-running the
original reproduction that found it. Verification commands and their real
output are recorded below each item.

**Test suite: 22/28 passing → 43/43 passing.**
**Ground-truth detection accuracy: 31/32 → 32/32.**

---

## Blocking

### B1 — Live scan returned HTTP 500 on malformed hostnames ✅ FIXED
**Files:** `backend/detection/live_scanner.py`, `backend/main.py`

Added `InvalidHostnameError` (subclass of `LiveScanError`) so the API can tell
"caller sent bad input" (400) from "we tried and the network failed" (503).
`get_cached_result()` no longer re-validates — it's called from inside an
exception handler, and raising there was the actual cause of the 500. The
fallback call is additionally wrapped so a failure in it can never mask the
original error. Error text is now actionable rather than generic.

```
127.0.0.1                 -> HTTP 400  "'127.0.0.1' is not a valid hostname. Enter a domain name such as example.com…"
8.8.8.8                   -> HTTP 400
localhost                 -> HTTP 400
google.com; rm -rf /      -> HTTP 400
<script>alert(1)</script> -> HTTP 400
google.com                -> HTTP 200  (good path intact)
no-such-host-…            -> HTTP 503  (network-failure path intact)
```
Now covered by `test_malformed_hostname_returns_400_not_500` (5 parametrised cases).

### B2 — Shipped GitHub Action failed on every invocation ✅ FIXED
**Files:** `.github/actions/quantumsafe-scan/action.yml`, `backend/cli/scan_cli.py`

`httpx` added to the Action's install step, **and** the `remediation.auto_fix`
import made lazy so the core scan path no longer depends on a network client it
doesn't use. Re-verified by rebuilding the Action's exact minimal environment:

```
$ python -m venv ci_sim && pip install pydantic cryptography   # exactly what the Action installs
$ python cli/scan_cli.py ../sample-data/vulnerable-repo
[High] RSA found in …auth.py:5 (Usage: misc)
[Critical] ECC found in …tls_helper.py:6 (Usage: key_exchange)
EXIT CODE: 2
```
(Previously: `ModuleNotFoundError: No module named 'httpx'`.)

Also fixed the related Minor issue where a crash and a real finding produced the
same exit code: the CLI now exits **2** for "findings met threshold" vs **1** for
"scanner failed", and the Action reports them differently instead of telling PR
authors to fix crypto that isn't there.

---

## Major

### M1 — Web dashboard never scanned JS/TS ✅ FIXED
`main.py` now routes `.js`/`.ts` through `scan_js_file()`, both bare-uploaded and
inside a zip. `InputPanel.tsx` accepts and advertises them.
```
node_rsa.js via /api/scan/codebase -> 1 finding [RSA line 3 High]   (was 0, silently)
```

### M2 — JS scanner produced false positives ✅ FIXED
Replaced naive substring matching with a comment/string-aware pass
(`_mask_js_source`) plus regex patterns. Comments are blanked; string literals
are preserved (the `'rsa'` argument must stay matchable) but a match that
*begins* inside a string is rejected as quoted prose. Also broadened coverage
from RSA-only to ECC, DSA, and DH.
```
trap_inline.js (call in trailing comment)   -> 0 findings  (was 1 false positive)
trap_string.js (call inside string literal) -> 0 findings  (was 1 false positive)
trap_block.js  (call inside /* */ block)    -> 0 findings  (was 1 false positive)
real_vuln.js -> RSA-4096 (line 2), ECC (line 3), DH (line 4)  — all correctly found
ground truth: node_rsa.js 1, node_cipher.js 1, trap_node_comment.js 0 — unchanged
```

### M3 — CLI severities didn't match the dashboard ✅ FIXED
`scan_cli.py` now calls `classify()` on every finding, the same weighted
classifier the web pipeline uses. Visible immediately in the B2 output above:
the ECC key-exchange finding now correctly reads **Critical** (was `High`).

### M4 — Auto-Fix only matched 3 hardcoded snippets ✅ FIXED
`patch_generator.py` rewritten around regex patterns tolerant of whitespace,
argument order, and formatting, covering: `cryptography` RSA/EC/DSA/DH,
PyCryptodome `RSA.generate`/`ECC.generate`, Node RSA/EC/DH, nginx `ssl_ciphers`,
and SSH `KexAlgorithms`. Required imports are inserted so the patch is directly
applicable rather than illustrative.
```
sample-data/vulnerable-repo/auth.py        RSA -> patch: YES (458 chars)   (was: none)
sample-data/vulnerable-repo/tls_helper.py  ECC -> patch: YES (542 chars)   (was: none)
```
The bundled demo repo's own vulnerable files now produce fixes.

### M5 — Risk score silently returned 100/A for unclassified findings ✅ FIXED
`compute_risk_score` now classifies any finding that hasn't been scored yet
instead of treating it as harmless, and the stale docstring (which described a
flat per-severity deduction that no longer existed) was rewritten to describe
the actual continuous model. New regression test
`test_risk_score_classifies_unscored_findings` locks this in.

### M6 — Mosca endpoint accepted nonsensical inputs ✅ FIXED
Pydantic validators on `MoscaRecomputeRequest` and `ScanRequest` reject negative
spans and non-positive threat horizons.
```
x=-5           -> HTTP 422   (was 200, produced a confident verdict)
z=-10          -> HTTP 422   (was 200, "-10 year threat horizon")
x=3,y=2,z=7    -> HTTP 200   (valid input unaffected)
```

### M7 — PCI-DSS/HIPAA never fired for config findings ✅ FIXED
`"network_config"` (not a real `ContextType`) corrected to `"config"` in
`compliance_frameworks.json` — 8 occurrences. Added load-time validation in
`compliance_mapper.py` that logs a warning for any trigger whose
context/usage/severity can never match, so this class of typo can't silently
recur.
```
nginx.conf RSA  -> ['CNSA 2.0', 'CISA PQC Roadmap', 'PCI-DSS v4.0', 'HIPAA Security Rule']
nginx.conf DH   -> ['CNSA 2.0', 'CISA PQC Roadmap', 'PCI-DSS v4.0', 'HIPAA Security Rule']
(previously only CNSA 2.0 / CISA — PCI-DSS and HIPAA were unreachable)
```

### M8 — Benchmarks frozen at startup but labelled "Live Data" ✅ FIXED
Added `GET /api/benchmark?refresh=true` and `GET /api/benchmark/status`.
`BenchmarkChart.tsx` now shows the measurement timestamp and sample count with a
**Re-measure** button, and the misleading "(Live Data)" title is gone.
```
cached  : Kyber768 0.27301   RSA-2048 55.413775
refresh : Kyber768 0.24073   RSA-2048 36.333135
refresh : Kyber768 0.226025  RSA-2048 42.6655
```
Values now visibly vary per measurement — useful on stage to show they're real.

### M9 — Migration impact used fabricated defaults ✅ FIXED
`_resolve_pqc_benchmark_key()` resolves compound ids like
`"Kyber768/ML-DSA-65"` to a component that was actually measured (choosing the
heavier candidate so ambiguous findings aren't under-estimated). When no
measurement genuinely exists, the `notes` field now says so explicitly instead
of claiming to be benchmark-sourced.
```
auth.py (RSA, usage=misc, liboqs_id="Kyber768/ML-DSA-65")
  handshake overhead: 0.913 ms   (was a hardcoded 1.5 ms placeholder)
```

### M10 — Integrity hash provided no tamper detection ✅ FIXED
`hardware_runner` now pins `counts_sha256` into the receipt at capture time, and
`check_integrity()` compares the stored hash against one recomputed from current
data. Returns `verified` / `mismatch` / `unpinned` with an accurate message. The
verify page and receipt card render all three states, and the overstated copy
("if this value ever changed…") was replaced with what the check actually
proves. Re-ran the exact tampering test from the report:
```
clean receipt          -> status: verified  | "matches the SHA-256 hash recorded when this job completed"
after tampering counts -> status: mismatch  | "INTEGRITY CHECK FAILED … must not be trusted"
```
(Previously: served a new, equally valid-looking hash with no indication at all.)

### M11 — Live-scan cache lost writes under concurrency ✅ FIXED
`_cache_result` now does its whole read-modify-write under a lock and lands via
an atomic `os.replace`.
```
8 concurrent scans -> hosts persisted: 8/8   (was 2/8)
```

### M12 — No rate limiting ✅ FIXED
Sliding-window per-client limit on `/api/scan/live`, returning 429 with
`Retry-After`. Set to 60/min deliberately: an audience behind one NAT'd venue IP
counts as a single client, so a tight cap would lock out real users before it
inconvenienced an abuser.

### M13 — liboqs failure would block app startup ✅ FIXED
Benchmark execution moved into `_refresh_benchmarks()`, which records failure
instead of raising. Startup no longer depends on it, `db.init_db()` and
`db.save_scan()` are likewise guarded, and `BenchmarkChart.tsx` renders an
explicit degraded-mode notice ("Scanning, classification, and reporting are
unaffected") rather than the whole app failing to serve.

---

## Minor / Cosmetic

- **Silent "all clean" for unparseable uploads** → new `SkippedFile` model,
  populated by all three upload endpoints and surfaced by a new
  `SkippedFilesNotice` component above the results.
  ```
  auth.py uploaded to /api/scan/certificate
    -> SKIPPED: "Not a readable X.509 certificate (expected PEM or DER).
                 If this is source code or a config file, use the matching scan type."
  ```
- **Certificate expiry never surfaced** → `not_valid_before` / `not_valid_after` /
  `is_expired` added to `Finding` and populated by `cert_scanner`; an **Expired**
  badge now appears next to the asset in `FindingsView`.
- **Port in hostname silently ignored** → `extract_port()` honours an explicit
  `:port` (validated 1–65535) instead of always probing 443.
- **Exit-code conflation in CI** → distinct codes 1 (error) vs 2 (findings), with
  matching Action messaging.
- **5 stale tests** → corrected to assert the code's actual documented behaviour
  (signing-over-encipherment precedence, continuous key-size interpolation, the
  "Configuration Fix" purpose), with the reasoning recorded in each docstring.
- **Live-scan regression baseline** → refreshed 76 → 77 with the derivation
  documented inline.
- **Network tests aborted the whole suite when no server was running** → new
  `tests/conftest.py` with a `requires_live_server` marker; the suite now runs
  offline (`31 passed, 12 skipped`) instead of erroring at collection.

---

## Verification

```
Backend test suite (server up)      43 passed
Backend test suite (no server)      31 passed, 12 skipped   (was: collection error)
Ground-truth detection accuracy     32/32 matched
Frontend production build           compiled successfully, 0 type errors
End-to-end live scan                182 ms  (scan → findings → score → benchmarks
                                             → impact → summary → PDF + CBOM export)
PDF export                          HTTP 200, valid PDF
CBOM export                         HTTP 200, valid JSON, component count == finding count
```

## Not addressed (unchanged from the report's Untestable section)

These need hardware, credentials, or a physical device that isn't available here
— they are **not** fixed or verified, and remain open:

- Physical QR-code scan from a phone on cellular data.
- Real IBM Quantum / qBraid hardware execution (no tokens; simulator path only).
- Real GitHub PR creation and the PR link resolving (no `GITHUB_TOKEN`).
- Running the Action against a real scratch PR, and external-repo consumption via
  `uses: your-org/…@main` (the path-resolution concern in the report's B2 note is
  a packaging question that still stands — the local `uses: ./…` path works).
- Browser-based UI interaction: the `ThreatHorizonSensitivity` slider still fires
  one request per drag event (no debounce added), PDF rendering in GUI viewers,
  and projector-distance readability.
