import os
import sys
import json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from models.schemas import Finding, RiskLevel, UsageType, ContextType, BenchmarkResult
from recommendation.recommender import generate_recommendation
from impact.risk_score import compute_risk_score
from impact.migration_estimator import compute_migration_impact
from detection.live_scanner import scan_live_host, get_cached_result, LiveScanError

def test_risk_score():
    findings = [
        Finding(
            finding_id="1", source_type="code", file="f1", line=1,
            algorithm="RSA", key_size=2048, context=ContextType.production_cert,
            usage_type=UsageType.key_exchange, risk_score=RiskLevel.Low
        ),
        Finding(
            finding_id="2", source_type="code", file="f2", line=1,
            algorithm="RSA", key_size=2048, context=ContextType.production_cert,
            usage_type=UsageType.key_exchange, risk_score=RiskLevel.Low
        ),
        Finding(
            finding_id="3", source_type="code", file="f3", line=1,
            algorithm="RSA", key_size=2048, context=ContextType.config,
            usage_type=UsageType.key_exchange, risk_score=RiskLevel.Low
        ),
    ]
    findings[0].risk_score = RiskLevel.Critical
    findings[1].risk_score = RiskLevel.Critical
    findings[2].risk_score = RiskLevel.High
    
    score_obj = compute_risk_score("test_scan", findings)
    print("Risk Score test: score =", score_obj.score, " expected: 100 - (15*2 + 8*1) = 62")
    return score_obj.score == 62

def test_recommender():
    finding_misc_rsa = Finding(
        finding_id="4", source_type="code", file="f4", line=1,
        algorithm="RSA", key_size=2048, context=ContextType.code,
        usage_type=UsageType.misc, risk_score=RiskLevel.Low
    )
    rec = generate_recommendation(finding_misc_rsa)
    print("Misc RSA recommendation:", rec.pqc_replacement)
    
    finding_signing_rsa = Finding(
        finding_id="5", source_type="code", file="f5", line=1,
        algorithm="RSA", key_size=2048, context=ContextType.code,
        usage_type=UsageType.signing, risk_score=RiskLevel.Low
    )
    rec_sig = generate_recommendation(finding_signing_rsa)
    print("Signing RSA recommendation:", rec_sig.pqc_replacement)

def test_migration_estimator():
    benchmarks = [
        BenchmarkResult(algorithm="RSA-2048", public_key_bytes=256, ciphertext_or_signature_bytes=256, operation_ms=1.0, compared_against="N/A", keygen_ms=1.0, run_count=20),
        BenchmarkResult(algorithm="ECDSA-P256", public_key_bytes=64, ciphertext_or_signature_bytes=64, operation_ms=0.5, compared_against="N/A", keygen_ms=0.5, run_count=20),
        BenchmarkResult(algorithm="Kyber768", public_key_bytes=1184, ciphertext_or_signature_bytes=1088, operation_ms=1.5, compared_against="N/A", keygen_ms=1.5, run_count=20),
        BenchmarkResult(algorithm="ML-DSA-65", public_key_bytes=1952, ciphertext_or_signature_bytes=3309, operation_ms=2.0, compared_against="N/A", keygen_ms=2.0, run_count=20)
    ]
    findings1 = [
        Finding(
            finding_id="f1", source_type="code", file="f", line=1,
            algorithm="RSA", key_size=2048, context=ContextType.production_cert,
            usage_type=UsageType.key_exchange, risk_score=RiskLevel.High
        )
    ]
    impact1 = compute_migration_impact("s1", findings1, benchmarks, scale_factor=1000)
    print(f"Impact scan 1: bandwidth {impact1.estimated_additional_bandwidth_pct}%")
    
    findings2 = [
        Finding(
            finding_id="f2", source_type="code", file="f", line=1,
            algorithm="ECC", key_size=256, context=ContextType.production_cert,
            usage_type=UsageType.key_exchange, risk_score=RiskLevel.High
        )
    ]
    impact2 = compute_migration_impact("s2", findings2, benchmarks, scale_factor=1000)
    print(f"Impact scan 2: bandwidth {impact2.estimated_additional_bandwidth_pct}%")
    
    findings3 = findings1 + findings2
    impact3 = compute_migration_impact("s3", findings3, benchmarks, scale_factor=1000)
    print(f"Impact scan 3: bandwidth {impact3.estimated_additional_bandwidth_pct}%")

def test_live_scanner_cache():
    # Test fallback path for BLOCKED PORT
    try:
        scan_live_host("test-blocked.local")
    except LiveScanError as e:
        print("LiveScanError caught for blocked port:", str(e))
        res = get_cached_result("test-blocked.local")
        print("Cached fallback for blocked port:", "Found" if res else "Not found")

if __name__ == "__main__":
    test_risk_score()
    test_recommender()
    test_migration_estimator()
    test_live_scanner_cache()
