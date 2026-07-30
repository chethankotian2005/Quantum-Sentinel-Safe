import pytest
from pydantic import ValidationError
from models.schemas import Finding, Recommendation, BenchmarkResult, ScanResult

def test_finding_valid_data():
    finding = Finding(
        finding_id="f_0001",
        source_type="code",
        file="auth/keys.py",
        line=42,
        hostname=None,
        algorithm="RSA",
        key_size=2048,
        context="code",
        usage_type="signing",
        risk_score="Critical"
    )
    assert finding.finding_id == "f_0001"
    assert finding.risk_score.value == "Critical"

def test_finding_invalid_risk_level():
    with pytest.raises(ValidationError) as exc_info:
        Finding(
            finding_id="f_0002",
            source_type="code",
            file="auth/keys.py",
            line=42,
            hostname=None,
            algorithm="RSA",
            key_size=2048,
            context="code",
            usage_type="signing",
            risk_score="InvalidLevel"
        )
    assert "Input should be 'Critical', 'High', 'Medium' or 'Low'" in str(exc_info.value)

def test_scan_result_composition():
    finding = Finding(
        finding_id="f_0001",
        source_type="code",
        file="auth/keys.py",
        line=42,
        hostname=None,
        algorithm="RSA",
        key_size=2048,
        context="code",
        usage_type="signing",
        risk_score="Critical"
    )
    rec = Recommendation(
        finding_id="f_0001",
        classical_algorithm="RSA",
        purpose="Key Encapsulation",
        stage_1_hybrid="X25519+Kyber768",
        stage_1_rationale="NIST guidance",
        stage_2_pqc="ML-KEM (Kyber)",
        liboqs_id="Kyber768"
    )
    benchmark = BenchmarkResult(
        algorithm="Kyber768",
        compared_against="RSA-2048",
        keygen_ms=0.05,
        operation_ms=0.08,
        public_key_bytes=1184,
        ciphertext_or_signature_bytes=1088,
        run_count=100
    )
    scan = ScanResult(
        scan_id="scan_123",
        findings=[finding],
        recommendations=[rec],
        benchmarks=[benchmark]
    )
    assert len(scan.findings) == 1
    assert scan.findings[0].risk_score == "Critical"
    assert len(scan.recommendations) == 1
    assert len(scan.benchmarks) == 1
