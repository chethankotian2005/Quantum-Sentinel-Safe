import pytest
from models.schemas import Finding, SourceType, ContextType, UsageType, RiskLevel
from classification.risk_classifier import classify

def test_classify_critical():
    # ECC P-256 for Key Exchange in Production Cert
    # Alg (ECC): 100 * 0.40 = 40
    # Key (256 - Medium): 80 * 0.25 = 20
    # Ctx (Prod Cert): 100 * 0.20 = 20
    # Usage (KEX): 100 * 0.15 = 15
    # Total = 95 -> Critical (>= 80)
    finding = Finding(
        finding_id="f_1", source_type=SourceType.certificate, algorithm="ECC", key_size=256,
        context=ContextType.production_cert, usage_type=UsageType.key_exchange, risk_score=RiskLevel.Low
    )
    assert classify(finding) == RiskLevel.Critical
    assert finding.risk_score == RiskLevel.Critical

def test_classify_high():
    # RSA 2048 for Signing in Code.
    # Key-size scoring is a continuous interpolation (1024 -> 100, 4096 -> 10),
    # not discrete buckets, so 2048 scores 70 rather than a flat "medium".
    # Alg (RSA):      90 * 0.40 = 36
    # Key (2048->70): 70 * 0.25 = 17.5
    # Ctx (Code):     60 * 0.20 = 12
    # Usage (Signing):50 * 0.15 = 7.5
    # Total = 73 -> High (>= 60)
    finding = Finding(
        finding_id="f_2", source_type=SourceType.code, algorithm="RSA", key_size=2048,
        context=ContextType.code, usage_type=UsageType.signing, risk_score=RiskLevel.Low
    )
    assert classify(finding) == RiskLevel.High


def test_key_size_scoring_is_monotonic():
    """A larger key must never score as more vulnerable than a smaller one."""
    def score_for(key_size):
        f = Finding(
            finding_id=f"f_{key_size}", source_type=SourceType.code, algorithm="RSA",
            key_size=key_size, context=ContextType.code, usage_type=UsageType.signing,
            risk_score=RiskLevel.Low,
        )
        classify(f)
        return f.vulnerability_score

    scores = [score_for(n) for n in (1024, 2048, 3072, 4096)]
    assert scores == sorted(scores, reverse=True), f"expected descending risk, got {scores}"

def test_classify_medium():
    # RSA 2048 for Signing in Test File
    # Alg (RSA): 90 * 0.40 = 36
    # Key (2048 - Medium): 80 * 0.25 = 20
    # Ctx (Test File): 10 * 0.20 = 2
    # Usage (Signing): 50 * 0.15 = 7.5
    # Total = 65.5 -> High. Wait, let's make it Medium by using a Large key size and Test File.
    # Total = 36 + 5 + 0 + 7.5 = 48.5 (Medium)
    finding = Finding(
        finding_id="f_3", source_type=SourceType.code, algorithm="RSA", key_size=4096,
        context=ContextType.test_file, usage_type=UsageType.signing, risk_score=RiskLevel.Low
    )
    assert classify(finding) == RiskLevel.Medium

def test_classify_low():
    # Unknown algorithm, Large key, Test file, Misc usage
    # Alg (Unknown: 50): 50 * 0.40 = 20
    # Key (Large: 20): 20 * 0.25 = 5
    # Ctx (Test: 0): 0 * 0.20 = 0
    # Usage (Misc: 10): 10 * 0.15 = 1.5
    # Total = 26.5 -> Low (< 40)
    finding = Finding(
        finding_id="f_4", source_type=SourceType.code, algorithm="UNKNOWN", key_size=8192,
        context=ContextType.test_file, usage_type=UsageType.misc, risk_score=RiskLevel.High
    )
    assert classify(finding) == RiskLevel.Low
