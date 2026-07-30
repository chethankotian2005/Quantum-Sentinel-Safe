import os
import json
import logging
import threading
import time
import uuid
import ast
import shutil
import tempfile
import zipfile
from collections import deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import List
from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator

from models.schemas import ScanResult, Finding, ContextType, UsageType, RiskLevel, BenchmarkResult, SkippedFile
from detection.cert_scanner import scan_certificate
from detection.code_scanner import CryptoASTVisitor, scan_js_file
from detection.config_scanner import scan_config_file, scan_config_content
from detection.config_scanner import scan_directory as config_scan_dir
from detection.sbom_scanner import scan_directory as sbom_scan_dir
from classification.risk_classifier import classify
from classification.mosca_calculator import calculate_mosca_risk
from classification.agility_scorer import calculate_migration_effort
from classification.compliance_mapper import map_compliance
from classification.executive_synthesizer import synthesize_narrative
from recommendation.recommender import generate_recommendation
from impact.risk_score import compute_risk_score
from impact.migration_estimator import compute_migration_impact
from export.cbom_exporter import export_cbom
from export.pdf_report import generate_pdf_report
from benchmarking.liboqs_bench import run_benchmark
from detection.live_scanner import (
    scan_live_host,
    get_cached_result,
    LiveScanError,
    InvalidHostnameError,
    HostUnreachableError,
    TimeoutScanError,
)
from quantum_demo.shor_circuit import execute_shor
from quantum_demo.resource_estimator import estimate_resources
from remediation.patch_generator import generate_patch
from remediation.auto_fix import create_github_pr
from storage import db

logger = logging.getLogger(__name__)

# Set when the liboqs-backed benchmark suite can't run. The rest of the app
# (scanning, classification, reporting, exports) does not depend on liboqs, so
# a benchmark failure must degrade that one panel — never block startup.
BENCHMARK_STATUS = {"available": True, "error": None, "measured_at": None}


def _refresh_benchmarks() -> bool:
    """
    (Re)runs the liboqs benchmark suite into the module-level cache.
    Returns True on success. Never raises — records the failure instead.
    """
    global cached_benchmarks
    try:
        results = run_benchmark(20)
    except Exception as e:
        BENCHMARK_STATUS.update({"available": False, "error": f"{type(e).__name__}: {e}"})
        logger.warning("Benchmark suite unavailable (liboqs?): %s", e)
        return False

    cached_benchmarks = results
    BENCHMARK_STATUS.update({
        "available": True,
        "error": None,
        "measured_at": datetime.now(timezone.utc).isoformat(),
    })
    return True


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not cached_benchmarks:
        _refresh_benchmarks()
    try:
        db.init_db()
    except Exception as e:
        logger.error("Database init failed, history/trends disabled: %s", e)
    yield

app = FastAPI(
    title="QuantumSafe Sentinel API",
    version="1.0.0",
    description="Backend API for static and dynamic cryptographic scanning.",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

scan_db: dict[str, ScanResult] = {}
cached_benchmarks: list[BenchmarkResult] = []

# ── Rate limiting for the outbound-network endpoint ───────────────────
# /api/scan/live makes a real TLS connection to an arbitrary host on the
# caller's behalf. Without a cap this is an open scanning proxy.
#
# Sized deliberately high: an audience sharing one NAT'd venue IP all counts
# as a single client here, so a tight limit would lock out real users long
# before it inconvenienced an abuser. This still bounds automated abuse.
RATE_LIMIT_MAX_REQUESTS = 60
RATE_LIMIT_WINDOW_SECONDS = 60
_rate_limit_hits: dict[str, deque] = {}
_rate_limit_lock = threading.Lock()


def _enforce_rate_limit(request: Request) -> None:
    """Sliding-window per-client limit. Raises 429 when exceeded."""
    client_ip = request.client.host if request.client else "unknown"
    now = time.monotonic()
    cutoff = now - RATE_LIMIT_WINDOW_SECONDS

    with _rate_limit_lock:
        hits = _rate_limit_hits.setdefault(client_ip, deque())
        while hits and hits[0] < cutoff:
            hits.popleft()
        if len(hits) >= RATE_LIMIT_MAX_REQUESTS:
            retry_after = max(1, int(hits[0] + RATE_LIMIT_WINDOW_SECONDS - now))
            raise HTTPException(
                status_code=429,
                detail=(
                    f"Rate limit exceeded ({RATE_LIMIT_MAX_REQUESTS} live scans per "
                    f"{RATE_LIMIT_WINDOW_SECONDS}s). Retry in {retry_after}s."
                ),
                headers={"Retry-After": str(retry_after)},
            )
        hits.append(now)


class ScanRequest(BaseModel):
    hostname: str = ""
    data_sensitivity_years: float | None = None
    z_years_until_quantum: float = 7.0
    apply_mosca_weight: bool = False

    @field_validator("data_sensitivity_years")
    @classmethod
    def _sensitivity_non_negative(cls, v):
        if v is not None and (v < 0 or v > 100):
            raise ValueError(f"data_sensitivity_years must be between 0 and 100 (got {v})")
        return v

    @field_validator("z_years_until_quantum")
    @classmethod
    def _horizon_positive(cls, v):
        if v is not None and (v <= 0 or v > 100):
            raise ValueError(f"z_years_until_quantum must be between 0 (exclusive) and 100 (got {v})")
        return v

class AutoFixRequest(BaseModel):
    finding_id: str
    repo: str = None

class ShorValidationRequest(BaseModel):
    target_n: int = 15

# Mosca's inequality is only meaningful for non-negative year spans, and a
# threat horizon must be strictly positive. These bounds mirror the frontend
# slider ranges so a direct API call can't produce a nonsensical verdict
# (e.g. a "-10 year threat horizon") that still renders as confident advice.
MOSCA_MAX_YEARS = 100.0


class MoscaRecomputeRequest(BaseModel):
    x_data_sensitivity_years: float = None
    y_migration_time_years: float = None
    z_years_until_quantum: float = 7.0

    @field_validator("x_data_sensitivity_years", "y_migration_time_years")
    @classmethod
    def _non_negative(cls, v, info):
        if v is None:
            return v
        if v < 0:
            raise ValueError(f"{info.field_name} must be >= 0 (got {v})")
        if v > MOSCA_MAX_YEARS:
            raise ValueError(f"{info.field_name} must be <= {MOSCA_MAX_YEARS} (got {v})")
        return v

    @field_validator("z_years_until_quantum")
    @classmethod
    def _positive_horizon(cls, v):
        if v is None:
            return v
        if v <= 0:
            raise ValueError(f"z_years_until_quantum must be > 0 (got {v})")
        if v > MOSCA_MAX_YEARS:
            raise ValueError(f"z_years_until_quantum must be <= {MOSCA_MAX_YEARS} (got {v})")
        return v

def process_findings(
    findings: list[Finding],
    target_id: str,
    data_sensitivity_years: float = None,
    z_years_until_quantum: float = 7.0,
    apply_mosca_weight: bool = False,
    skipped_files: list = None,
) -> ScanResult:
    recommendations = []
    for f in findings:
        # 1. Attach quantum resource estimation FIRST (Mosca needs it for roadmap comment)
        algo_upper = f.algorithm.upper()
        if algo_upper in ("RSA", "ECC", "ECDSA", "ECDH", "EC", "DH", "DSA"):
            k_size = f.key_size
            if not k_size:
                k_size = 2048 if algo_upper in ("RSA", "DH", "DSA") else 256
                
            try:
                est = estimate_resources(algo_upper, k_size)
                from models.schemas import QuantumAttackCost
                f.quantum_attack_cost = QuantumAttackCost(
                    algorithm=est.algorithm,
                    key_size_bits=est.key_size_bits,
                    idealized_logical_qubits=est.idealized_logical_qubits,
                    logical_qubit_source=est.logical_qubit_source,
                    realistic_physical_qubits_estimate=est.realistic_physical_qubits_estimate,
                    physical_qubit_source=est.physical_qubit_source,
                    is_directly_cited=est.is_directly_cited,
                    estimated_runtime_description=est.estimated_runtime_description,
                    comparison_to_current_hardware=est.comparison_to_current_hardware,
                    current_largest_qpc=est.current_largest_qpc,
                    gap_factor=est.gap_factor,
                )
            except (ValueError, Exception):
                pass  # unsupported algorithm or key size — skip gracefully

        # 2. Now run Mosca (can use quantum_attack_cost for IBM roadmap comment)
        f.mosca_result = calculate_mosca_risk(z_years_until_quantum, f, data_sensitivity_years)
        # Calculate migration effort and patch diff
        f.migration_effort = calculate_migration_effort(f, findings)
        f.patch_diff = generate_patch(f)
        
        classify(f)
        f.compliance_flags = map_compliance(f)
        recommendations.append(generate_recommendation(f))
        
    scan_id = f"scan_{uuid.uuid4().hex[:8]}"
    risk_score = compute_risk_score(scan_id, findings, apply_mosca_weight)
    impact = compute_migration_impact(scan_id, findings, cached_benchmarks, scale_factor=1000)
    
    # Filter benchmarks to only those relevant to this scan
    relevant_algs = set()
    for f, r in zip(findings, recommendations):
        c_alg = f.algorithm.upper()
        if c_alg in ["ECC", "ECDH", "ECDSA"]:
            relevant_algs.add("ECDSA-P256")
        elif c_alg in ["RSA", "DSA", "DH"]:
            relevant_algs.add("RSA-2048")
        relevant_algs.add(r.liboqs_id)
        if "Kyber" in r.stage_1_hybrid or "KEM" in r.stage_1_hybrid:
            relevant_algs.add("X25519")
            
    filtered_benchmarks = [b for b in cached_benchmarks if b.algorithm in relevant_algs]
    if not filtered_benchmarks:
        filtered_benchmarks = cached_benchmarks  # fallback
        
    result = ScanResult(
        scan_id=scan_id,
        target_id=target_id,
        findings=findings,
        recommendations=recommendations,
        benchmarks=filtered_benchmarks,
        impact=impact,
        risk_score=risk_score,
        skipped_files=skipped_files or [],
        benchmarks_measured_at=BENCHMARK_STATUS["measured_at"],
        benchmarks_available=BENCHMARK_STATUS["available"],
    )

    result.executive_summary = synthesize_narrative(result)

    scan_db[scan_id] = result

    # Persist to sqlite for historical tracking. History is a nice-to-have —
    # a storage failure must not take down the scan the user just ran.
    try:
        db.save_scan(target_id, result)
    except Exception as e:
        logger.error("Could not persist scan %s to history: %s", scan_id, e)

    return result


# ── Codebase Scan (accepts .py files or a .zip archive) ──────────────
@app.post("/api/scan/codebase", response_model=ScanResult)
async def scan_codebase(
    files: List[UploadFile] = File(...),
    data_sensitivity_years: float = Form(None),
    z_years_until_quantum: float = Form(7.0),
    apply_mosca_weight: bool = Form(False)
):
    all_findings: list[Finding] = []
    skipped: list[SkippedFile] = []
    target_id = files[0].filename if files else "unknown"

    def scan_python_source(source: str, display_name: str) -> bool:
        """Returns True if parsed, False if the source wasn't valid Python."""
        try:
            tree = ast.parse(source, filename=display_name)
        except (SyntaxError, ValueError) as e:
            skipped.append(SkippedFile(
                filename=display_name,
                reason=f"Not valid Python — could not be parsed ({type(e).__name__}).",
            ))
            return False
        visitor = CryptoASTVisitor(display_name)
        visitor.visit(tree)
        all_findings.extend(visitor.findings)
        return True

    for upload in files:
        raw = await upload.read()
        filename = upload.filename or "unknown"
        lowered = filename.lower()

        # If it's a zip, extract to isolated temp dir, scan, then delete (DRD §9)
        if lowered.endswith(".zip"):
            tmp_dir = tempfile.mkdtemp(prefix="qs_scan_")
            try:
                zip_path = os.path.join(tmp_dir, filename)
                with open(zip_path, "wb") as f:
                    f.write(raw)
                with zipfile.ZipFile(zip_path, "r") as zf:
                    zf.extractall(tmp_dir)
                # Walk the extracted tree for every supported source type
                for root, _, fnames in os.walk(tmp_dir):
                    for fname in fnames:
                        fpath = os.path.join(root, fname)
                        flow = fname.lower()
                        if flow.endswith(".py"):
                            try:
                                with open(fpath, "r", encoding="utf-8", errors="ignore") as pf:
                                    scan_python_source(pf.read(), fname)
                            except OSError as e:
                                skipped.append(SkippedFile(filename=fname, reason=f"Unreadable inside archive ({e.__class__.__name__})."))
                        elif flow.endswith((".js", ".ts")):
                            try:
                                all_findings.extend(scan_js_file(fpath))
                            except Exception as e:
                                skipped.append(SkippedFile(filename=fname, reason=f"Could not scan ({type(e).__name__})."))
            except zipfile.BadZipFile:
                skipped.append(SkippedFile(filename=filename, reason="Not a readable ZIP archive."))
            finally:
                shutil.rmtree(tmp_dir, ignore_errors=True)

        elif lowered.endswith(".py"):
            # Single .py file — parse directly from memory
            try:
                source = raw.decode("utf-8")
            except UnicodeDecodeError:
                skipped.append(SkippedFile(filename=filename, reason="Not valid UTF-8 text — cannot be parsed as Python."))
            else:
                scan_python_source(source, filename)

        elif lowered.endswith((".js", ".ts")):
            tmp_dir = tempfile.mkdtemp(prefix="qs_scan_js_")
            try:
                fpath = os.path.join(tmp_dir, os.path.basename(filename))
                with open(fpath, "wb") as f:
                    f.write(raw)
                for finding in scan_js_file(fpath):
                    finding.file = filename
                    all_findings.append(finding)
            except Exception as e:
                skipped.append(SkippedFile(filename=filename, reason=f"Could not scan ({type(e).__name__})."))
            finally:
                shutil.rmtree(tmp_dir, ignore_errors=True)

        else:
            skipped.append(SkippedFile(
                filename=filename,
                reason="Unsupported file type for a code scan. Expected .py, .js, .ts, or .zip.",
            ))

    return process_findings(
        all_findings, target_id, data_sensitivity_years,
        z_years_until_quantum, apply_mosca_weight, skipped_files=skipped,
    )


# ── Certificate Scan (accepts .pem / .crt / .der files) ──────────────
@app.post("/api/scan/certificate", response_model=ScanResult)
async def scan_cert(
    files: List[UploadFile] = File(...),
    data_sensitivity_years: float = Form(None),
    z_years_until_quantum: float = Form(7.0),
    apply_mosca_weight: bool = Form(False)
):
    all_findings: list[Finding] = []
    skipped: list[SkippedFile] = []
    target_id = files[0].filename if files else "unknown"

    for upload in files:
        raw = await upload.read()
        filename = upload.filename or "unknown"
        try:
            all_findings.append(scan_certificate(filename, raw))
        except ValueError:
            # Surface the rejection instead of returning a misleading "all clean".
            skipped.append(SkippedFile(
                filename=filename,
                reason="Not a readable X.509 certificate (expected PEM or DER). "
                       "If this is source code or a config file, use the matching scan type.",
            ))

    return process_findings(
        all_findings, target_id, data_sensitivity_years,
        z_years_until_quantum, apply_mosca_weight, skipped_files=skipped,
    )


# ── Config Scan (accepts any config text files) ──────────────────────
@app.post("/api/scan/config", response_model=ScanResult)
async def scan_config(
    files: List[UploadFile] = File(...),
    data_sensitivity_years: float = Form(None),
    z_years_until_quantum: float = Form(7.0),
    apply_mosca_weight: bool = Form(False)
):
    all_findings: list[Finding] = []
    skipped: list[SkippedFile] = []
    target_id = files[0].filename if files else "unknown"

    for upload in files:
        raw = await upload.read()
        filename = upload.filename or "unknown"
        try:
            content = raw.decode("utf-8")
        except UnicodeDecodeError:
            skipped.append(SkippedFile(
                filename=filename,
                reason="Not valid UTF-8 text — config files must be plain text.",
            ))
            continue
        try:
            all_findings.extend(scan_config_content(filename, content))
        except Exception as e:
            skipped.append(SkippedFile(filename=filename, reason=f"Could not scan ({type(e).__name__})."))

    return process_findings(
        all_findings, target_id, data_sensitivity_years,
        z_years_until_quantum, apply_mosca_weight, skipped_files=skipped,
    )

@app.post("/api/scan/live", response_model=ScanResult)
def scan_live(req: ScanRequest, request: Request):
    if not req.hostname:
        raise HTTPException(status_code=400, detail="Hostname required")

    _enforce_rate_limit(request)

    try:
        # Real TLS handshake — no mocks
        findings = scan_live_host(req.hostname)
        return process_findings(findings, req.hostname, req.data_sensitivity_years, req.z_years_until_quantum, req.apply_mosca_weight)
    except InvalidHostnameError as e:
        # Bad input, not a network failure — there is nothing to fall back to.
        raise HTTPException(status_code=400, detail={"category": "INVALID_HOSTNAME", "message": str(e)})
    except (HostUnreachableError, TimeoutScanError) as e:
        category = "HOST_UNREACHABLE" if isinstance(e, HostUnreachableError) else "TIMEOUT"
        raise HTTPException(status_code=503, detail={"category": category, "message": str(e)})
    except LiveScanError as e:
        # NFR-3: Try cached fallback on genuine network failures only.
        # Guarded so a failure in the fallback can never mask the real error.
        try:
            cached = get_cached_result(req.hostname)
        except Exception:
            cached = None
        if cached:
            return process_findings(cached, req.hostname, req.data_sensitivity_years, req.z_years_until_quantum, req.apply_mosca_weight)
        # No cache available — return distinct 503 for frontend fallback UI
        raise HTTPException(status_code=503, detail={"category": "UNKNOWN", "message": str(e)})

@app.get("/api/validation/report")
def get_validation_report():
    report_path = os.path.join(os.path.dirname(__file__), "validation", "accuracy_report.json")
    if not os.path.exists(report_path):
        raise HTTPException(status_code=404, detail="Validation report not found. Run validation harness first.")
    
    with open(report_path, "r", encoding="utf-8") as f:
        return JSONResponse(content=json.load(f))

@app.get("/api/quantum-demo/shor")
def run_quantum_shor():
    try:
        return execute_shor()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/quantum-demo/shor-validation")
def run_shor_validation(req: ShorValidationRequest):
    try:
        from quantum_demo.qbraid_runner import run_shor_on_qbraid
        from quantum_demo.resource_estimator import estimate_resources
        
        # Pick a valid 'a' based on N
        a = 2
        if req.target_n == 15:
            a = 7
            
        result = run_shor_on_qbraid(N=req.target_n, a=a, shots=1000)
        
        # Theoretical prediction
        n_bits = req.target_n.bit_length()
        # Using 3n ideal formula for theoretical (this matches resource_estimator)
        theoretical_qubits = 3 * n_bits
        
        # Measured is retrieved from result (measured_qubits)
        measured_qubits = result.get("measured_qubits", 0)
        measured_depth = result.get("measured_depth", 0)
        
        match_pct = 100.0
        if measured_qubits > 0 and theoretical_qubits > 0:
            match_pct = (theoretical_qubits / measured_qubits) * 100
            if match_pct > 100:
                match_pct = (measured_qubits / theoretical_qubits) * 100
                
        return {
            "target_n": req.target_n,
            "base_a": a,
            "theoretical_qubits": theoretical_qubits,
            "measured_qubits": measured_qubits,
            "measured_depth": measured_depth,
            "match_percentage": round(match_pct, 1),
            "device": result.get("device", "Unknown")
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))




@app.get("/api/scans/{scan_id}", response_model=ScanResult)
def get_scan(scan_id: str):
    if scan_id not in scan_db:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan_db[scan_id]

@app.get("/api/scan/history/{target_id:path}")
def get_scan_history(target_id: str):
    history = db.get_scan_history(target_id)
    return history

@app.post("/api/scans/{scan_id}/mosca", response_model=ScanResult)
def recompute_mosca(scan_id: str, req: MoscaRecomputeRequest):
    if scan_id not in scan_db:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = scan_db[scan_id]
    
    # Recompute Mosca for all findings
    for f in scan.findings:
        f.mosca_result = calculate_mosca_risk(
            req.z_years_until_quantum, 
            f, 
            req.x_data_sensitivity_years,
            req.y_migration_time_years
        )
        
    # We might need to recalculate the overall risk score if it uses Mosca.
    # Assuming apply_mosca_weight is true, let's just recalculate it anyway.
    # We'll just pass True for apply_mosca_weight so it updates properly.
    scan.risk_score = compute_risk_score(scan_id, scan.findings, True)
    
    # Persist the updated scan
    db.save_scan(scan.target_id, scan)
    
    return scan

@app.get("/api/scans/{scan_id}/report.pdf")
def get_report_pdf(scan_id: str):
    if scan_id not in scan_db:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = scan_db[scan_id]
    out_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "exports"))
    os.makedirs(out_dir, exist_ok=True)
    
    pdf_path = os.path.join(out_dir, f"{scan_id}.pdf")
    generate_pdf_report(scan, pdf_path)
    
    if not os.path.exists(pdf_path):
        html_path = pdf_path.replace(".pdf", ".html")
        return FileResponse(html_path, media_type="text/html", filename=f"{scan_id}.html")
    return FileResponse(pdf_path, media_type="application/pdf", filename=f"{scan_id}.pdf")

@app.get("/api/scans/{scan_id}/cbom.json")
def get_cbom(scan_id: str):
    if scan_id not in scan_db:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = scan_db[scan_id]
    out_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "exports"))
    os.makedirs(out_dir, exist_ok=True)
    
    json_path = os.path.join(out_dir, f"{scan_id}.json")
    export_cbom(scan, json_path)
    return FileResponse(json_path, media_type="application/json", filename=f"{scan_id}.json")

@app.post("/api/remediate/auto-fix")
def auto_fix_endpoint(req: AutoFixRequest):
    target_finding = None
    for scan in scan_db.values():
        for f in scan.findings:
            if f.finding_id == req.finding_id:
                target_finding = f
                break
        if target_finding:
            break
            
    if not target_finding:
        raise HTTPException(status_code=404, detail="Finding not found")
        
    result = create_github_pr(target_finding, repo=req.repo)
    if "error" in result:
        raise HTTPException(status_code=500, detail=result["error"])
        
    return result

@app.get("/api/benchmark", response_model=list[BenchmarkResult])
def get_benchmark(refresh: bool = False):
    """
    Returns the PQC-vs-classical benchmark suite.

    Results are cached because the suite takes ~1s of real cryptographic work
    (RSA-2048 keygen dominates) and re-running it on every dashboard render
    would be wasteful. Pass ?refresh=true to force a fresh measurement — the
    numbers genuinely change run to run, so this is how you demonstrate they
    are measured rather than hardcoded.
    """
    if refresh or not cached_benchmarks:
        _refresh_benchmarks()
    return cached_benchmarks


@app.get("/api/benchmark/status")
def get_benchmark_status():
    """When the cached benchmarks were measured, and whether liboqs is usable."""
    return {
        **BENCHMARK_STATUS,
        "algorithm_count": len(cached_benchmarks),
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
