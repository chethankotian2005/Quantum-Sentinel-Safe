import os
import json
import uuid
import ast
from models.schemas import ScanResult
from detection.cert_scanner import scan_certificate
from detection.code_scanner import CryptoASTVisitor
from detection.config_scanner import scan_config_file
from classification.risk_classifier import classify
from benchmarking.liboqs_bench import run_benchmark
from recommendation.recommender import generate_recommendation
from impact.risk_score import compute_risk_score
from impact.migration_estimator import compute_migration_impact
from export.cbom_exporter import export_cbom
from export.pdf_report import generate_pdf_report

def generate_full_test_scan_result():
    # Gather findings from the sample repos
    all_findings = []
    
    # Certs
    cert_dir = os.path.join(os.path.dirname(__file__), "..", "..", "sample-data", "certs")
    if os.path.exists(cert_dir):
        for filename in os.listdir(cert_dir):
            if filename.endswith(".pem"):
                path = os.path.join(cert_dir, filename)
                with open(path, "rb") as f:
                    try:
                        all_findings.append(scan_certificate(path, f.read()))
                    except ValueError:
                        pass
    
    # Code
    code_dir = os.path.join(os.path.dirname(__file__), "..", "..", "sample-data", "vulnerable-repo")
    if os.path.exists(code_dir):
        for filename in os.listdir(code_dir):
            if filename.endswith(".py"):
                path = os.path.join(code_dir, filename)
                with open(path, "r", encoding="utf-8") as f:
                    tree = ast.parse(f.read(), filename=path)
                    visitor = CryptoASTVisitor(path)
                    visitor.visit(tree)
                    all_findings.extend(visitor.findings)
                    
    # Config
    config_dir = os.path.join(os.path.dirname(__file__), "..", "..", "sample-data", "configs")
    if os.path.exists(config_dir):
        for filename in os.listdir(config_dir):
            path = os.path.join(config_dir, filename)
            if os.path.isfile(path):
                all_findings.extend(scan_config_file(path))
                
    # Classify & Recommend
    recommendations = []
    for f in all_findings:
        classify(f)
        recommendations.append(generate_recommendation(f))
        
    # Get Benchmarks
    benchmarks = run_benchmark(20)
    
    scan_id = f"scan_{uuid.uuid4().hex[:8]}"
    
    # Impact & Risk
    risk_score = compute_risk_score(scan_id, all_findings)
    impact = compute_migration_impact(scan_id, all_findings, benchmarks, scale_factor=1000)
    
    return ScanResult(
        scan_id=scan_id,
        findings=all_findings,
        recommendations=recommendations,
        benchmarks=benchmarks,
        impact=impact,
        risk_score=risk_score
    )

def test_export_pipeline():
    """
    Generate CBOM and PDF using the real output of the entire pipeline.
    """
    scan_result = generate_full_test_scan_result()
    
    out_dir = os.path.join(os.path.dirname(__file__), "output")
    os.makedirs(out_dir, exist_ok=True)
    
    cbom_path = os.path.join(out_dir, "test_cbom.json")
    export_cbom(scan_result, cbom_path)
    assert os.path.exists(cbom_path)
    
    # Test JSON structure
    with open(cbom_path, "r") as f:
        data = json.load(f)
        assert data["bomFormat"] == "CBOM"
        assert len(data["components"]) == len(scan_result.findings)
        
    pdf_path = os.path.join(out_dir, "test_report.pdf")
    html_path = os.path.join(out_dir, "test_report.html")
    generate_pdf_report(scan_result, pdf_path)
    
    # Due to missing GTK3 on bare Windows, weasyprint may fallback to HTML
    assert os.path.exists(pdf_path) or os.path.exists(html_path)
    
    if os.path.exists(pdf_path):
        assert os.path.getsize(pdf_path) > 1024
        print(f"Generated PDF Report at: {os.path.abspath(pdf_path)}")
    else:
        assert os.path.getsize(html_path) > 1024
        print(f"Generated HTML Fallback Report at: {os.path.abspath(html_path)}")
