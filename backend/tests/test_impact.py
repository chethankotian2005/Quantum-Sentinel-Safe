import pytest
import os
from models.schemas import Finding, SourceType, ContextType, UsageType, RiskLevel, BenchmarkResult
from impact.risk_score import compute_risk_score
from impact.migration_estimator import compute_migration_impact
from detection.cert_scanner import scan_certificate
from detection.code_scanner import CryptoASTVisitor
from detection.config_scanner import scan_config_file
from classification.risk_classifier import classify
from benchmarking.liboqs_bench import run_benchmark
import ast

def get_dummy_benchmarks():
    return [
        BenchmarkResult(algorithm="Kyber768", compared_against="RSA", keygen_ms=0.6, operation_ms=0.4, public_key_bytes=1184, ciphertext_or_signature_bytes=1088, run_count=20),
        BenchmarkResult(algorithm="RSA-2048", compared_against="N/A", keygen_ms=100.0, operation_ms=2.0, public_key_bytes=256, ciphertext_or_signature_bytes=256, run_count=20),
    ]

def test_risk_score_and_migration_estimator():
    """
    Scoring is continuous: each finding deducts up to 15 points in proportion
    to its vulnerability_score (0-100) from the weighted classifier, rather
    than a flat amount per severity bucket.

    Derivation for these four findings (see classification/risk_classifier.py
    for the weights):
      f1 RSA-2048 / production_cert / key_exchange -> 36 + 17.5 + 20 + 15  = 88.5
      f2 RSA-2048 / code            / signing      -> 36 + 17.5 + 12 + 7.5 = 73.0
      f3 RSA-4096 / test_file       / signing      -> 36 +  2.5 +  0 + 7.5 = 46.0
      f4 RSA-8192 / test_file       / misc         -> 36 +  2.5 +  0 + 1.5 = 40.0
      penalty = (88.5 + 73 + 46 + 40) / 100 * 15   = 37.125
      score   = 100 - 37.125 = 62.875 -> 62 (grade D)
    """
    findings = [
        Finding(finding_id="f1", source_type=SourceType.code, algorithm="RSA", key_size=2048, context=ContextType.production_cert, usage_type=UsageType.key_exchange, risk_score=RiskLevel.Critical),
        Finding(finding_id="f2", source_type=SourceType.code, algorithm="RSA", key_size=2048, context=ContextType.code, usage_type=UsageType.signing, risk_score=RiskLevel.High),
        Finding(finding_id="f3", source_type=SourceType.code, algorithm="RSA", key_size=4096, context=ContextType.test_file, usage_type=UsageType.signing, risk_score=RiskLevel.Medium),
        Finding(finding_id="f4", source_type=SourceType.code, algorithm="RSA", key_size=8192, context=ContextType.test_file, usage_type=UsageType.misc, risk_score=RiskLevel.Low),
    ]

    score = compute_risk_score("test_scan", findings)

    assert score.score == 62
    assert score.grade == "D"


def test_risk_score_classifies_unscored_findings():
    """
    Regression guard: compute_risk_score must never treat an unclassified
    finding as harmless. Before this was fixed, findings that hadn't been
    through classify() contributed a zero penalty, so a set of Critical
    findings silently scored a perfect 100/A.
    """
    findings = [
        Finding(finding_id="c1", source_type=SourceType.code, algorithm="ECC", key_size=256,
                context=ContextType.production_cert, usage_type=UsageType.key_exchange,
                risk_score=RiskLevel.Critical),
        Finding(finding_id="c2", source_type=SourceType.code, algorithm="RSA", key_size=2048,
                context=ContextType.production_cert, usage_type=UsageType.key_exchange,
                risk_score=RiskLevel.Critical),
    ]
    # Deliberately NOT calling classify() first.
    assert all(f.vulnerability_score == 0.0 for f in findings)

    score = compute_risk_score("scan_unscored", findings)

    assert score.score < 100, "unclassified Critical findings must still deduct points"
    assert score.grade != "A"
    assert all(f.vulnerability_score > 0.0 for f in findings), "findings should be classified in place"


def test_risk_score_combinations():
    """
    2 Critical + 1 High, all in source code.
      f1 RSA-2048 / code / key_exchange -> 36 + 17.50 + 12 + 15  = 80.50
      f2 ECC-256  / code / key_exchange -> 40 + 20.62 + 12 + 15  = 87.62
      f3 DSA-2048 / code / signing      -> 36 + 17.50 + 12 + 7.5 = 73.00
      penalty = 241.12 / 100 * 15 = 36.17 -> score 63 (grade D)
    """
    findings_2c_1h = [
        Finding(finding_id="f1", source_type=SourceType.code, algorithm="RSA", key_size=2048, context=ContextType.code, usage_type=UsageType.key_exchange, risk_score=RiskLevel.Critical),
        Finding(finding_id="f2", source_type=SourceType.code, algorithm="ECC", key_size=256, context=ContextType.code, usage_type=UsageType.key_exchange, risk_score=RiskLevel.Critical),
        Finding(finding_id="f3", source_type=SourceType.code, algorithm="DSA", key_size=2048, context=ContextType.code, usage_type=UsageType.signing, risk_score=RiskLevel.High),
    ]
    score_2c_1h = compute_risk_score("scan_2c_1h", findings_2c_1h)
    assert score_2c_1h.score == 63
    assert score_2c_1h.critical_count == 2
    assert score_2c_1h.high_count == 1

    # More findings must never produce a better score than a subset of them.
    subset = compute_risk_score("scan_subset", findings_2c_1h[:1])
    assert subset.score > score_2c_1h.score
    
def test_real_sample_scans_and_print_scores():
    """
    Run against actual sample data from our repo to see what grades they get,
    and print them for the artifact.
    """
    # Scan Certs
    cert_dir = os.path.join(os.path.dirname(__file__), "..", "..", "sample-data", "certs")
    all_findings = []
    
    for filename in os.listdir(cert_dir):
        if filename.endswith(".pem"):
            path = os.path.join(cert_dir, filename)
            with open(path, "rb") as f:
                try:
                    all_findings.append(scan_certificate(path, f.read()))
                except ValueError:
                    pass
    
    # Scan Code
    code_dir = os.path.join(os.path.dirname(__file__), "..", "..", "sample-data", "vulnerable-repo")
    for filename in os.listdir(code_dir):
        if filename.endswith(".py"):
            path = os.path.join(code_dir, filename)
            with open(path, "r", encoding="utf-8") as f:
                tree = ast.parse(f.read(), filename=path)
                visitor = CryptoASTVisitor(path)
                visitor.visit(tree)
                all_findings.extend(visitor.findings)
    
    # Scan Config
    config_dir = os.path.join(os.path.dirname(__file__), "..", "..", "sample-data", "configs")
    for filename in os.listdir(config_dir):
        path = os.path.join(config_dir, filename)
        if os.path.isfile(path):
            all_findings.extend(scan_config_file(path))
    
    
    for f in all_findings:
        classify(f)
        
    score = compute_risk_score("demo_full_scan", all_findings)
    
    print("\n--- Real Demo Repository Scan Results ---")
    print(f"Total Findings: {len(all_findings)}")
    print(f"Critical: {score.critical_count} | High: {score.high_count} | Medium: {score.medium_count} | Low: {score.low_count}")
    print(f"Final Score: {score.score}/100")
    print(f"Grade: {score.grade}")
    
    # Note on calibration:
    if score.grade == "F":
        print("\nNote: The grade is an 'F'. This makes sense because the sample repos are specifically planted with dozens of vulnerabilities. However, if a real repo gets 3 Criticals, it instantly fails. That is intended behavior for a 'Quantum Safe' scanner (zero tolerance for production Key Exchanges).")
    
    assert score.score >= 0
    assert score.score <= 100
