from models.schemas import Finding, Recommendation, UsageType, ContextType
from recommendation.pqc_mapping import PQC_MAPPING, DEFAULT_MAPPING

def generate_recommendation(finding: Finding) -> Recommendation:
    """
    Generates a two-stage PQC Recommendation for a given finding based on DRD 7.3 mappings.
    Stage 1 provides a hybrid classical+PQC scheme per NIST SP 800-208.
    Stage 2 provides the pure PQC end-state algorithm.
    """
    key = (finding.algorithm.upper(), finding.usage_type)
    if key in PQC_MAPPING:
        pqc_name, liboqs_id, hybrid_scheme = PQC_MAPPING[key]
    else:
        # Fallback if specific algorithm not in table
        if finding.usage_type == UsageType.signing or "DSA" in finding.algorithm.upper():
            pqc_name, liboqs_id, hybrid_scheme = ("ML-DSA (Dilithium)", "ML-DSA-65", "RSA3072+ML-DSA-65")
        else:
            pqc_name, liboqs_id, hybrid_scheme = DEFAULT_MAPPING
        
    if "Unclear" in pqc_name:
        purpose = "Unknown (Manual Verification Required)"
    elif "Fix" in pqc_name:
        purpose = "Configuration Fix"
    else:
        purpose = "Key Encapsulation" if "KEM" in pqc_name or "Kyber" in pqc_name else "Digital Signature"
    
    stage_1_rationale = "NIST SP 800-208 / hybrid-mode guidance recommends pairing classical and PQC algorithms during the transition period to maintain FIPS compliance while providing quantum resistance."
    
    return Recommendation(
        finding_id=finding.finding_id,
        classical_algorithm=finding.algorithm,
        purpose=purpose,
        stage_1_hybrid=hybrid_scheme,
        stage_1_rationale=stage_1_rationale,
        stage_2_pqc=pqc_name,
        liboqs_id=liboqs_id
    )
