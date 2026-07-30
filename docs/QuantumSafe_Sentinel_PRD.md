# Product Requirements Document (PRD)
## QuantumSafe Sentinel — PQC Migration Toolkit
**Team ACE | Quant-A-thon 2026 Grand Finale | Problem Statement QT-3.6**
**Version 1.0**

---

## 1. Document Purpose
This PRD defines *what* QuantumSafe Sentinel must do and *why*, independent of implementation detail. It is the grounding spec for build sessions in Antigravity — every feature built should trace back to a requirement in this document. Implementation-level detail (architecture, schemas, APIs) lives in the companion Design Requirements Document (DRD).

---

## 2. Product Vision
Most organizations don't know where quantum-vulnerable cryptography (RSA, ECC, DH, DSA) lives across their codebases, certificates, and configs. QuantumSafe Sentinel is a discovery-first toolkit that finds every instance, scores its risk, recommends the correct NIST-standardized post-quantum replacement, and proves — with real benchmarks, not estimates — that migrating is practical today.

**One-line pitch:** "A scanner that tells you exactly where you're quantum-vulnerable, what to replace it with, and proves the replacement actually works — in seconds, on any target you name."

---

## 3. Problem Statement (Source: Official Track QT-3.6)
Organizations lack visibility into quantum-vulnerable cryptography across their systems, and lack tooling to plan a practical migration to post-quantum standards. "Harvest Now, Decrypt Later" makes this an active risk today, not a future one — encrypted data with long-term sensitivity is already being harvested for future decryption once quantum computers scale.

---

## 4. Goals

### 4.1 Hackathon Goals (Primary)
- Win the Quant-A-thon 2026 Grand Finale by fully satisfying all five official evaluation criteria (accuracy, benchmarking quality, practicality, automation, documentation).
- Deliver at least one "how did you do that" moment that differentiates from ~100 competing teams and resonates specifically with industry judges (IBM, National Quantum Mission, qBraid, and other listed partners).
- Ship a complete, demoable, non-faked product in the ~10 days before the finale.

### 4.2 Product Goals (Beyond the Hackathon)
- Prove the concept is real enough to plausibly become a SaaS product (in the spirit of the team's existing myatsscore.app), not just a demo shell.

---

## 5. Target Users / Personas

| Persona | Need |
|---|---|
| **Security engineer at a mid-size company** | Wants a fast inventory of where RSA/ECC is used before planning a PQC migration budget/timeline |
| **CTO/compliance lead** | Wants a single risk number and a report to justify migration spend to leadership |
| **Hackathon judge (in this context, also a "user")** | Wants to see real detection, real benchmarks, and a live, unscripted proof point within a few minutes |

---

## 6. Scope

### 6.1 In Scope (Must Build for the Finale)
1. Codebase scanning (Python, with config for extending to Java/JS patterns)
2. Certificate file scanning (.pem/.crt/.der)
3. Config file scanning (nginx/Apache/SSH-style configs)
4. **Live website scanning** (on-demand, judge/audience-chosen hostname)
5. Risk classification engine (rule-based scoring)
6. PQC recommendation engine (mapping table + hybrid-scheme flag)
7. Real benchmarking via liboqs (not simulated numbers)
8. Hybrid handshake demo (classical vs. X25519+Kyber768)
9. **Migration impact estimator** (org-scale bandwidth/storage/perf overhead)
10. **Quantum Risk Score** (single 0–100 or letter-grade aggregate)
11. **CBOM export** (structured cryptographic inventory, standards-aligned)
12. Dashboard (findings, recommendations, benchmarks, impact/score, live-scan panel)
13. Exportable PDF migration report

### 6.2 Out of Scope (Explicitly Not Built for the Finale)
- CI/CD GitHub Action (real PR-scanning integration) — roadmap-only, pitched not built
- Real quantum-hardware demo (e.g., Shor's algorithm on IBM Quantum hardware) — ruled out as infeasible in the timeframe
- Automatic in-place code remediation/patching — out of scope; this is a discovery and recommendation tool, not an auto-fixer
- Multi-language full AST support beyond Python (regex-level detection acceptable for Java/JS in v1)
- User authentication / multi-tenant accounts — single-session tool for the hackathon; not a production SaaS yet

---

## 7. Functional Requirements

Each requirement is written as: **ID — Requirement — Acceptance Criteria**

| ID | Requirement | Acceptance Criteria |
|---|---|---|
| FR-1 | Scan an uploaded codebase for quantum-vulnerable crypto usage | Given a sample repo with known RSA/ECC usage, the tool flags every instance with file, line, algorithm, and key size |
| FR-2 | Scan uploaded certificate files | Given a .pem/.crt file, the tool extracts public key algorithm, key size, signature algorithm, and expiry |
| FR-3 | Scan uploaded config files | Given an nginx/SSH config referencing RSA/DH/ECDH cipher suites, the tool flags the relevant lines |
| FR-4 | Scan a live website on demand | Given a hostname, the tool performs a live TLS handshake, retrieves the cert, and runs it through the same detection pipeline as an uploaded cert, returning a result in under ~10 seconds under normal network conditions |
| FR-5 | Classify risk per finding | Every finding receives a Critical/High/Medium/Low label derived from algorithm type, key size, context, and usage type, per the documented weighting |
| FR-6 | Recommend a PQC replacement per finding | Every finding maps to a NIST-standardized replacement (ML-KEM/Kyber or ML-DSA/Dilithium) with a stated liboqs identifier, and flags whether a hybrid scheme is advisable |
| FR-7 | Benchmark recommended algorithms | For each recommended algorithm, the tool runs real liboqs operations and reports keygen time, encaps/decaps or sign/verify time, and key/ciphertext/signature size, compared against the classical algorithm it replaces |
| FR-8 | Demonstrate a hybrid handshake | The tool can simulate and display a classical vs. hybrid (X25519+Kyber768) handshake side by side, with real timing |
| FR-9 | Estimate migration impact at scale | Given a scanned inventory, the tool estimates aggregate bandwidth, storage, and performance overhead of migrating that inventory to PQC |
| FR-10 | Compute a Quantum Risk Score | The tool aggregates all findings for a scanned target into a single 0–100 (or letter-grade) score |
| FR-11 | Export a CBOM | The tool can export a scanned target's findings as a structured Cryptographic Bill of Materials file |
| FR-12 | Generate a PDF migration report | The tool can export a prioritized, human-readable migration report as a PDF |
| FR-13 | Present all of the above in a dashboard | A user can trigger a scan, view findings/heatmap, view recommendations, view benchmarks, view impact/score, use the live-scan panel, and export the report/CBOM — all from one interface |

---

## 8. Non-Functional Requirements

| ID | Requirement |
|---|---|
| NFR-1 | **No faked data.** Every benchmark number shown in the demo or report must come from an actual liboqs run on the demo machine — never hardcoded placeholder numbers presented as real. |
| NFR-2 | **Live-scan responsiveness.** The live scan should return a result within ~5–10 seconds under normal conditions; if it exceeds this, the UI should show a clear loading state rather than appearing frozen. |
| NFR-3 | **Live-scan resilience.** If network access fails during a live demo, the tool must be able to fall back to a pre-cached result set without visibly breaking the demo flow. |
| NFR-4 | **Explainability.** Every risk score and recommendation must be traceable to a stated rule (not a black box), since judges may ask "why did it flag this as Critical." |
| NFR-5 | **Correctness over coverage.** It's acceptable to support a narrower set of languages/config formats if it means the supported set is reliably accurate — false positives/negatives on the core RSA/ECC/DH/DSA detection are worse than limited scope. |
| NFR-6 | **Usable UI.** The dashboard must be clean and legible enough to present live on a projector or a laptop screen in a small room. |
| NFR-7 | **Reproducibility.** Given the same input, the tool should produce the same finding/risk/recommendation output (benchmark timings will naturally vary run to run). |

---

## 9. Success Metrics

| Metric | Target |
|---|---|
| Official evaluation score across all 5 weighted criteria | Maximize, with explicit build effort mapped to each weight |
| Live-scan demo success rate in rehearsal | 100% across at least 2 full dry runs, including at least one adversarial/random site |
| Benchmark numbers presented | 100% real (zero placeholder/fabricated numbers in the final report or pitch) |
| Differentiator features shipped | All 4 finalized differentiators (CBOM, live scan, migration impact estimator, Quantum Risk Score) working end-to-end |

---

## 10. Assumptions & Constraints
- Team size: 4 people, ~10 days of build time before the finale (30–31 July 2026).
- Demo format (stage vs. private judge room) is unknown until the event — the product and script must work in either.
- Venue network conditions for the live-scan demo are not guaranteed — an offline fallback is mandatory, not optional.
- liboqs-python is assumed installable on the team's dev and demo machines; this should be validated on Day 1.

---

## 11. Dependencies
- `liboqs` / `liboqs-python` for real PQC benchmarking
- `cryptography` (Python) for classical crypto and X.509 parsing
- Python `ssl`/`socket` for live TLS handshakes
- A small set of curated sample repos/certs with known vulnerable crypto, prepared by the team (real crypto usage, deliberately planted for demo purposes — not fabricated results)

---

## 12. Milestones (High-Level — see DRD for engineering detail)

| Phase | Deliverable |
|---|---|
| Days 1–2 | Core detection engine + liboqs benchmark validated end-to-end |
| Days 3–4 | Risk classifier + recommender + live-scan input source wired in |
| Days 5–6 | Dashboard wired to backend; migration impact estimator, Quantum Risk Score, CBOM export built |
| Day 7 | Live-scan demo de-risked (pre-tested site list, offline fallback, venue network check) |
| Days 8–9 | Demo video, PPT, sample repos finalized; rehearsal under adversarial live-scan conditions |
| Day 10 | Final rehearsal (stage + room versions), buffer day, submission-ready |

---

## 13. Risks (Product-Level)
- A partially-working "extra" feature can score worse than a feature not attempted at all — prioritize finishing fewer things completely (this shaped the decision to leave the CI/CD Action as roadmap-only).
- Demo format uncertainty (stage vs. room) — mitigated by scripting both versions of the live-scan moment.
- Network dependency for the live-scan feature — mitigated by NFR-3's offline fallback requirement.

---

## 14. Open Questions
- None outstanding as of this version — all major feature-scope decisions have been finalized by the team. Any new ideas raised during the build should be evaluated against Section 6 (Scope) before being added.
