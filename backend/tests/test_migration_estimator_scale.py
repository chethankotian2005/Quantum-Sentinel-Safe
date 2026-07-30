import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.schemas import Finding, SourceType, ContextType, UsageType, RiskLevel, BenchmarkResult
from impact.migration_estimator import compute_migration_impact

def test_migration_estimator_scale():
    # Empty benchmark list for test, it should fallback to defaults gracefully
    benchmarks = [
        BenchmarkResult(algorithm="RSA-2048", security_level=1, public_key_bytes=294, ciphertext_or_signature_bytes=256, operation_ms=1.0, compared_against="None", keygen_ms=1.0, run_count=10),
        BenchmarkResult(algorithm="Kyber768", security_level=3, public_key_bytes=1184, ciphertext_or_signature_bytes=1088, operation_ms=1.5, compared_against="None", keygen_ms=1.0, run_count=10),
    ]
    
    # 1. RSA-2048 finding
    f_2048 = Finding(
        finding_id="1",
        source_type=SourceType.code,
        context=ContextType.code,
        algorithm="RSA",
        key_size=2048,
        usage_type=UsageType.key_exchange,
        risk_score=RiskLevel.High
    )
    
    # 2. RSA-8192 finding
    f_8192 = Finding(
        finding_id="2",
        source_type=SourceType.code,
        context=ContextType.code,
        algorithm="RSA",
        key_size=8192,
        usage_type=UsageType.key_exchange,
        risk_score=RiskLevel.High
    )
    
    impact_2048 = compute_migration_impact("test1", [f_2048], benchmarks, scale_factor=1)
    impact_8192 = compute_migration_impact("test2", [f_8192], benchmarks, scale_factor=1)
    
    # The absolute bytes added by PQC should be the same in a hybrid scheme (since we ADD the PQC bytes)
    # BUT the bandwidth percentage increase should be drastically smaller for RSA-8192 since its baseline classical size is huge!
    
    # Let's inspect the exact storage differences just to be sure
    print(f"RSA-2048: Storage overhead = {impact_2048.estimated_additional_storage_mb} MB, Bandwidth overhead = {impact_2048.estimated_additional_bandwidth_pct}%")
    print(f"RSA-8192: Storage overhead = {impact_8192.estimated_additional_storage_mb} MB, Bandwidth overhead = {impact_8192.estimated_additional_bandwidth_pct}%")
    
    assert impact_8192.estimated_additional_bandwidth_pct < impact_2048.estimated_additional_bandwidth_pct, "Bandwidth % should be smaller for larger classical baseline"
    assert impact_8192.estimated_additional_bandwidth_pct > 0, "Bandwidth % should be positive"
    
    print("test_migration_estimator_scale passed!")

if __name__ == "__main__":
    test_migration_estimator_scale()
