import pytest
from models.schemas import Finding, SourceType, ContextType, UsageType, RiskLevel
from recommendation.pqc_mapping import PQC_MAPPING
from recommendation.recommender import generate_recommendation

def test_every_mapping_entry():
    """
    Ensure every algorithm/usage combination in PQC_MAPPING generates a valid Recommendation
    with the correct replacements and purpose.
    """
    for (algorithm, usage), (expected_pqc, expected_id, expected_hybrid) in PQC_MAPPING.items():
        finding = Finding(
            finding_id=f"f_map_{algorithm}_{usage.value}",
            source_type=SourceType.code,
            algorithm=algorithm,
            key_size=2048,
            context=ContextType.code,
            usage_type=usage,
            risk_score=RiskLevel.Medium
        )
        rec = generate_recommendation(finding)
        
        assert rec.finding_id == finding.finding_id
        assert rec.classical_algorithm == algorithm
        assert rec.stage_2_pqc == expected_pqc
        assert rec.stage_1_hybrid == expected_hybrid
        assert rec.liboqs_id == expected_id
        assert "NIST SP 800-208" in rec.stage_1_rationale
            
        # Check purpose string. Mirrors the precedence in recommender.py:
        # ambiguous usage first, then non-crypto configuration fixes (e.g. the
        # TLS_VERIFY_ERROR mapping), then KEM vs. signature.
        if "Unclear" in expected_pqc:
            assert rec.purpose == "Unknown (Manual Verification Required)"
        elif "Fix" in expected_pqc:
            assert rec.purpose == "Configuration Fix"
        elif "KEM" in expected_pqc or "Kyber" in expected_pqc:
            assert rec.purpose == "Key Encapsulation"
        else:
            assert rec.purpose == "Digital Signature"

def test_fallback_mapping():
    """
    Unknown algorithm should use the fallback mapping (KEM).
    """
    finding = Finding(
        finding_id="f_unknown",
        source_type=SourceType.config,
        algorithm="UNKNOWN_ALG",
        key_size=None,
        context=ContextType.config,
        usage_type=UsageType.misc,
        risk_score=RiskLevel.Low
    )
    rec = generate_recommendation(finding)
    assert rec.stage_2_pqc == "ML-KEM or ML-DSA (Usage Unclear - Verify)"
    assert rec.stage_1_hybrid == "X25519+Kyber768 or RSA3072+ML-DSA-65"
