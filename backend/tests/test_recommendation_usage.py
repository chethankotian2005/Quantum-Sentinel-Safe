import sys
import os

# Add the backend dir to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.schemas import Finding, SourceType, ContextType, UsageType, RiskLevel
from recommendation.recommender import generate_recommendation

def test_recommendation_usage():
    # 1. RSA Signing finding -> Signature-based recommendation
    rsa_sign = Finding(
        finding_id="1",
        source_type=SourceType.code,
        context=ContextType.code,
        algorithm="RSA",
        usage_type=UsageType.signing,
        risk_score=RiskLevel.High
    )
    rec1 = generate_recommendation(rsa_sign)
    assert "ML-DSA" in rec1.stage_2_pqc, f"Expected ML-DSA for RSA signing, got {rec1.stage_2_pqc}"
    assert "ML-DSA" in rec1.stage_1_hybrid, f"Expected signature hybrid, got {rec1.stage_1_hybrid}"

    # 2. RSA Key Exchange finding -> KEM-based recommendation
    rsa_kex = Finding(
        finding_id="2",
        source_type=SourceType.code,
        context=ContextType.code,
        algorithm="RSA",
        usage_type=UsageType.key_exchange,
        risk_score=RiskLevel.High
    )
    rec2 = generate_recommendation(rsa_kex)
    assert "ML-KEM" in rec2.stage_2_pqc, f"Expected ML-KEM for RSA key exchange, got {rec2.stage_2_pqc}"
    assert "Kyber" in rec2.stage_1_hybrid, f"Expected KEM hybrid, got {rec2.stage_1_hybrid}"

    # 3. ECC Signing finding -> Signature-based recommendation
    ecc_sign = Finding(
        finding_id="3",
        source_type=SourceType.code,
        context=ContextType.code,
        algorithm="ECC",
        usage_type=UsageType.signing,
        risk_score=RiskLevel.High
    )
    rec3 = generate_recommendation(ecc_sign)
    assert "ML-DSA" in rec3.stage_2_pqc, f"Expected ML-DSA for ECC signing, got {rec3.stage_2_pqc}"
    assert "ML-DSA" in rec3.stage_1_hybrid, f"Expected signature hybrid, got {rec3.stage_1_hybrid}"
    
    # 4. ECC Key Exchange finding -> KEM-based recommendation
    ecc_kex = Finding(
        finding_id="4",
        source_type=SourceType.code,
        context=ContextType.code,
        algorithm="ECC",
        usage_type=UsageType.key_exchange,
        risk_score=RiskLevel.High
    )
    rec4 = generate_recommendation(ecc_kex)
    assert "ML-KEM" in rec4.stage_2_pqc, f"Expected ML-KEM for ECC key exchange, got {rec4.stage_2_pqc}"
    assert "Kyber" in rec4.stage_1_hybrid, f"Expected KEM hybrid, got {rec4.stage_1_hybrid}"
    
    print("test_recommendation_usage passed!")

if __name__ == "__main__":
    test_recommendation_usage()
