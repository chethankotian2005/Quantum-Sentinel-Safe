import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from models.schemas import ScanResult, Finding, RiskLevel, UsageType, ContextType, QuantumRiskScore, MigrationImpactEstimate
from export.cbom_exporter import export_cbom
from export.pdf_report import generate_pdf_report

def test_exports():
    finding = Finding(
        finding_id="1", source_type="code", file="f1", line=1,
        algorithm="RSA", key_size=2048, context=ContextType.production_cert,
        usage_type=UsageType.key_exchange, risk_score=RiskLevel.High
    )
    scan = ScanResult(
        scan_id="test_scan_export",
        target_id="test",
        findings=[finding],
        recommendations=[],
        benchmarks=[],
        impact=MigrationImpactEstimate(
            scan_id="test_scan_export",
            total_assets=1,
            estimated_additional_storage_mb=1.0,
            estimated_additional_bandwidth_pct=1.0,
            estimated_handshake_overhead_ms=1.0,
            notes="test"
        ),
        risk_score=QuantumRiskScore(
            scan_id="test_scan_export", score=50, grade="D",
            critical_count=0, high_count=1, medium_count=0, low_count=0
        )
    )
    
    out_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "exports"))
    os.makedirs(out_dir, exist_ok=True)
    json_path = os.path.join(out_dir, "test.json")
    pdf_path = os.path.join(out_dir, "test.pdf")
    
    export_cbom(scan, json_path)
    generate_pdf_report(scan, pdf_path)
    
    print("CBOM exported:", os.path.exists(json_path))
    print("PDF exported:", os.path.exists(pdf_path))

if __name__ == "__main__":
    test_exports()
