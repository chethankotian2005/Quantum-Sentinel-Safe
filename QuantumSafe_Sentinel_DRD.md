# Design Requirements Document (DRD)
## QuantumSafe Sentinel — PQC Migration Toolkit
**Team ACE | Quant-A-thon 2026 Grand Finale**
**Version 1.0 — companion to the PRD**

---

## 1. Document Purpose
This DRD translates every PRD requirement into a concrete technical design: architecture, module interfaces, data schemas, API contracts, folder structure, and error handling. It's written to be handed directly to an agentic build tool (Antigravity) as an implementation spec — each section maps to something buildable in one sitting.

---

## 2. Architecture Overview

```
                        ┌───────────────────────────┐
                        │        INPUT LAYER         │
                        │  • Codebase (repo/zip)     │
                        │  • Certificates (.pem/.crt)│
                        │  • Configs (nginx/ssh/etc) │
                        │  • Live website (on demand)│
                        └─────────────┬─────────────┘
                                      │
                        ┌─────────────▼─────────────┐
                        │   1. DETECTION ENGINE      │  → FR-1..4
                        └─────────────┬─────────────┘
                                      │  raw findings
                        ┌─────────────▼─────────────┐
                        │   2. RISK CLASSIFIER       │  → FR-5
                        └─────────────┬─────────────┘
                                      │  scored findings
                        ┌─────────────▼─────────────┐
                        │   3. PQC RECOMMENDER       │  → FR-6
                        └─────────────┬─────────────┘
                                      │  recommendations
                        ┌─────────────▼─────────────┐
                        │   4. BENCHMARK ENGINE      │  → FR-7, FR-8
                        └─────────────┬─────────────┘
                                      │  benchmark data
                        ┌─────────────▼─────────────┐
                        │  5. IMPACT & SCORING LAYER │  → FR-9, FR-10, FR-11
                        └─────────────┬─────────────┘
                                      │
                        ┌─────────────▼─────────────┐
                        │   6. API LAYER (FastAPI)   │
                        └─────────────┬─────────────┘
                                      │
                        ┌─────────────▼─────────────┐
                        │   7. DASHBOARD (Next.js)   │  → FR-13
                        └────────────────────────────┘
```

---

## 3. Tech Stack

| Layer | Choice | Notes |
|---|---|---|
| Backend | Python 3.11+, FastAPI | Async support needed for live TLS scan latency |
| PQC engine | `liboqs` + `liboqs-python` | Install/verify Day 1 — highest-risk dependency |
| Classical crypto | `cryptography` (Python) | Also used for X.509 parsing |
| Live TLS fetch | `ssl` + `socket` (stdlib) | No extra dependency needed |
| Code scanning | `ast` (stdlib) for Python; regex for Java/JS/config | Keep regex patterns in a single config file, not scattered in code |
| Frontend | Next.js + Tailwind | Reuse visual language from myatsscore.app where sensible |
| Charts | Recharts | Matches team's existing stack familiarity |
| PDF export | `weasyprint` (HTML→PDF) | Simplest path: render report as HTML template, convert |
| CBOM export | Native JSON, CycloneDX-CBOM-inspired schema | See Section 6.5 |
| Repo/file handling | Temp directory per scan job, cleaned up after | No persistent storage needed for hackathon scope |
| Hosting (if deployed) | Google Cloud Run | Matches existing myatsscore.app deployment pattern |

---

## 4. Repository Structure

```
quantumsafe-sentinel/
├── backend/
│   ├── main.py                  # FastAPI app entrypoint
│   ├── detection/
│   │   ├── code_scanner.py      # AST + regex scanning for repos
│   │   ├── cert_scanner.py      # x509 parsing (uploaded + live)
│   │   ├── config_scanner.py    # nginx/ssh/apache regex rules
│   │   └── live_scan.py         # live TLS handshake fetch
│   ├── classifier/
│   │   └── risk_classifier.py   # scoring logic (Section 5.2 of full doc)
│   ├── recommender/
│   │   └── pqc_recommender.py   # mapping table + hybrid flag
│   ├── benchmark/
│   │   └── benchmark_engine.py  # liboqs-python calls, timing
│   ├── impact/
│   │   ├── migration_estimator.py
│   │   └── risk_score.py
│   ├── export/
│   │   ├── cbom_export.py
│   │   └── pdf_report.py
│   ├── samples/                 # curated demo repos/certs with known vulnerable crypto
│   └── tests/
├── frontend/
│   ├── pages/ (or app/)
│   │   ├── index.tsx            # upload/scan trigger + history
│   │   ├── findings.tsx
│   │   ├── recommendations.tsx
│   │   ├── benchmarks.tsx
│   │   ├── impact-score.tsx
│   │   └── live-scan.tsx
│   └── components/
├── docs/
│   ├── QuantumSafe_Sentinel_PRD.md
│   ├── QuantumSafe_Sentinel_DRD.md
│   └── QuantumSafe_Sentinel_Complete_Documentation.md
└── README.md
```

---

## 5. Data Schemas

### 5.1 Finding (Detection Engine Output)
```json
{
  "finding_id": "f_0001",
  "source_type": "code | certificate | config | live_scan",
  "file": "auth/keys.py",
  "line": 42,
  "hostname": null,
  "algorithm": "RSA",
  "key_size": 2048,
  "context": "code | production_cert | test_file | config",
  "usage_type": "key_exchange | signing | misc",
  "risk_score": "Critical | High | Medium | Low"
}
```

### 5.2 Recommendation (PQC Recommender Output)
```json
{
  "finding_id": "f_0001",
  "classical_algorithm": "RSA",
  "purpose": "Key Encapsulation",
  "pqc_replacement": "ML-KEM (Kyber)",
  "liboqs_id": "Kyber768",
  "hybrid_recommended": true,
  "hybrid_scheme": "X25519+Kyber768"
}
```

### 5.3 Benchmark Result
```json
{
  "algorithm": "Kyber768",
  "compared_against": "RSA-2048",
  "keygen_ms": 0.05,
  "operation_ms": 0.08,
  "public_key_bytes": 1184,
  "ciphertext_or_signature_bytes": 1088,
  "run_count": 100
}
```

### 5.4 Migration Impact Estimate
```json
{
  "scan_id": "scan_0001",
  "total_assets": 42,
  "estimated_additional_storage_mb": 12.4,
  "estimated_additional_bandwidth_pct": 18,
  "estimated_handshake_overhead_ms": 0.9,
  "notes": "Estimate assumes full inventory migration to hybrid X25519+Kyber768 / Dilithium3"
}
```

### 5.5 Quantum Risk Score
```json
{
  "scan_id": "scan_0001",
  "score": 62,
  "grade": "C",
  "critical_count": 3,
  "high_count": 8,
  "medium_count": 5,
  "low_count": 2
}
```

### 5.6 CBOM Export (simplified, CycloneDX-CBOM-inspired)
```json
{
  "bomFormat": "CBOM",
  "specVersion": "1.0",
  "scan_id": "scan_0001",
  "generated_at": "2026-07-30T10:00:00Z",
  "components": [
    {
      "type": "cryptographic-asset",
      "name": "RSA-2048 (auth/keys.py:42)",
      "algorithm": "RSA",
      "keySize": 2048,
      "usage": "signing",
      "quantumVulnerable": true,
      "recommendedReplacement": "Dilithium3"
    }
  ]
}
```

---

## 6. API Design (FastAPI Endpoints)

| Method | Path | Request | Response |
|---|---|---|---|
| POST | `/scan/upload` | multipart file(s): repo zip / certs / configs | `{ "scan_id": "..." }` — triggers full pipeline async |
| POST | `/scan/live` | `{ "hostname": "example.com" }` | Full pipeline result for that single host, synchronous, target < 10s |
| GET | `/scan/{scan_id}/findings` | — | List of Finding objects (5.1) |
| GET | `/scan/{scan_id}/recommendations` | — | List of Recommendation objects (5.2) |
| GET | `/scan/{scan_id}/benchmarks` | — | List of Benchmark Result objects (5.3) |
| GET | `/scan/{scan_id}/impact` | — | Migration Impact Estimate (5.4) |
| GET | `/scan/{scan_id}/risk-score` | — | Quantum Risk Score (5.5) |
| GET | `/scan/{scan_id}/report.pdf` | — | Rendered PDF file |
| GET | `/scan/{scan_id}/cbom.json` | — | CBOM export (5.6) |

**Error handling requirement (ties to NFR-3):** `/scan/live` must catch network failures (DNS failure, connection timeout, TLS handshake failure) and return a distinct error code the frontend can use to trigger the offline fallback cache — not a generic 500.

---

## 7. Module Design Detail

### 7.1 Detection Engine
- **Code scanner:** walk directory tree; for `.py` files, parse with `ast`, walk `Import`/`ImportFrom`/`Call` nodes, match against a config-driven list of vulnerable import paths and function calls (RSA, EC, DH, DSA generation). For `.java`/`.js`, use regex patterns for the known-vulnerable call signatures listed in the PRD/full doc Section 6.
- **Cert scanner:** load with `cryptography.x509.load_pem_x509_certificate` (or DER equivalent); extract `public_key()`, determine algorithm type via `isinstance` checks (RSAPublicKey, EllipticCurvePublicKey, DSAPublicKey), extract key size, signature algorithm OID, and expiry (`not_valid_after`).
- **Config scanner:** regex over config files for known directives (`ssl_ciphers`, `KexAlgorithms`, `Ciphers`) capturing any RSA/DH/ECDH references.
- **Live scan:** open a TCP socket to the target host:443, wrap with `ssl.SSLContext` (`PROTOCOL_TLS_CLIENT`), perform the handshake, call `getpeercert(binary_form=True)`, then feed the DER bytes into the same cert-scanner code path used for uploaded certs. **No duplicate parsing logic — this is the point of designing it as an alternate input source, not a separate feature.**

### 7.2 Risk Classifier
Implement as a pure function `classify(finding) -> risk_score` using the weighted rule table in the PRD/full doc (algorithm type 40%, key size 25%, context 20%, usage type 15%). Keep the weights as named constants, not magic numbers, so they're easy to defend if a judge asks about the methodology.

### 7.3 PQC Recommender
Implement as a lookup table (dict) keyed by `(classical_algorithm, usage_type)` → recommendation, matching the mapping table in Section 5.3/7 of the full documentation. Flag `hybrid_recommended = True` whenever `usage_type == "key_exchange"` or the finding's context is `production_cert`.

### 7.4 Benchmark Engine
Wrap `liboqs-python`'s `KeyEncapsulation("Kyber768")` and `Signature("Dilithium3")` classes. For each, time `generate_keypair()`, `encap_secret()`/`decap_secret()` (or `sign()`/`verify()`) over N=100 runs, and record `statistics.mean`. Compare against classical equivalents run the same way using the `cryptography` library (RSA-2048 keygen/sign, ECDSA P-256 keygen/sign).

### 7.5 Migration Impact Estimator
Pure function over the full finding set for a scan: sum key/cert size deltas (classical vs. recommended PQC size, from benchmark data) across all findings, multiply by an assumed deployment scale factor (configurable, e.g., "per 1,000 endpoints") to produce the aggregate estimate. Document the scale-factor assumption visibly in the report — this is what makes the number defensible under judge questioning.

### 7.6 Quantum Risk Score
Pure function: weighted count of findings by severity (e.g., Critical=4, High=3, Medium=2, Low=1 points each, inverted and normalized to 0–100), mapped to a letter grade band (A: 90–100 ... F: <50). Keep the exact formula in one place and documented, for the same "explainability" reason as 7.2.

### 7.7 CBOM Export
Transform the finding list directly into the schema in 5.6 — this should be nearly a 1:1 mapping from existing data, not new computation.

### 7.8 PDF Report
Render an HTML template (Jinja2) with findings, recommendations, benchmarks, impact estimate, and risk score, then convert to PDF via `weasyprint`. Template should visually match the dashboard styling.

---

## 8. Frontend Design Requirements

| Page | Must Show |
|---|---|
| Home/Upload | Upload widget (repo/certs/configs), live-scan input box, recent scan history |
| Findings | Table + heatmap grid, filterable by severity/source type |
| Recommendations | Per-finding card: classical algo → PQC replacement, hybrid flag, rationale |
| Benchmarks | Bar chart(s): classical vs. PQC vs. hybrid, per metric (time, key size) |
| Impact & Score | Migration impact numbers + Quantum Risk Score as a large, single-glance visual (gauge or letter grade badge) |
| Live Scan | Hostname input, real-time loading state, result rendered inline using the same components as Findings/Recommendations/Benchmarks |
| Report Export | One-click PDF download + CBOM JSON download |

**Visual direction:** dark-mode-friendly, data-forward, consistent with the team's existing chethan.tech / myatsscore.app design language. Legible on a projector at demo distance — avoid small fonts or low-contrast severity colors.

---

## 9. Security & Error Handling Considerations
- Uploaded files (repo zips, cert files) must be handled in an isolated temp directory per scan, deleted after processing — no persistence of a stranger's uploaded code beyond the session (relevant if judges upload their own sample).
- Live-scan hostname input must be validated/sanitized before being used in a socket connection (basic hostname format check; no shell execution anywhere in the live-scan path).
- Any network failure on `/scan/live` must degrade gracefully per Section 6's error-handling requirement — this is a hard requirement, not a nice-to-have, given NFR-3.

---

## 10. Testing Strategy
- Unit tests for the risk classifier and PQC recommender against a fixed set of known inputs/expected outputs (deterministic, fast to demo-check).
- Integration test: run the full pipeline against the team's curated sample repo/cert set and confirm expected findings appear.
- Manual test matrix for the live-scan feature: the ~15 pre-tested real sites, plus at least 2 adversarial/unexpected inputs (e.g., a site with an expired cert, a site that times out) to confirm graceful fallback behavior.

---

## 11. Deployment Design (If Deployed Beyond the Laptop Demo)
- Backend: containerize with Docker, deploy to Google Cloud Run (matches myatsscore.app's existing pattern), since liboqs's C dependencies are easiest to manage in a controlled container image rather than relying on the demo laptop's local environment for anything beyond rehearsal.
- Frontend: Vercel or same Cloud Run project, depending on team preference at build time.
- For the actual on-stage/in-room demo, prefer running everything **locally on the demo laptop** to avoid depending on live internet for anything except the live-scan target's TLS connection itself — minimizes points of failure.

---

## 12. Non-Functional Design Targets (Numeric)

| Target | Value |
|---|---|
| Live-scan end-to-end response time (normal network) | < 10 seconds |
| Benchmark run count per algorithm | ≥ 100 iterations for stable averages |
| Dashboard load time (local demo) | < 2 seconds |
| PDF report generation time | < 5 seconds |

---

## 13. Traceability Note
Every module and schema in this document maps back to a PRD functional requirement (FR-1 through FR-13) or non-functional requirement (NFR-1 through NFR-7). When building in Antigravity, reference both documents together so implementation choices stay anchored to the *why*, not just the *how*.
