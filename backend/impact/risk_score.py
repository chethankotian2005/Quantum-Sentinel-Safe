from models.schemas import Finding, RiskLevel, QuantumRiskScore
from classification.risk_classifier import classify

def compute_risk_score(scan_id: str, findings: list[Finding], apply_mosca_weight: bool = False) -> QuantumRiskScore:
    """
    Computes a Quantum Risk Score (0-100) from the severity of findings.

    Each finding deducts up to 15 points in proportion to its continuous
    `vulnerability_score` (0-100), which is produced by
    classification.risk_classifier.classify(). Findings that have not been
    classified yet are classified here rather than silently contributing a
    zero penalty — previously an unclassified finding set scored a perfect
    100/A no matter how many Critical items it contained.

    An additional flat penalty (max 20) applies when apply_mosca_weight is set
    and any finding has an urgent Mosca verdict.

    Floor at 0. Grades: A(>=90), B(>=80), C(>=70), D(>=50), F(<50)
    """
    if not findings:
        return QuantumRiskScore(scan_id=scan_id, score=100, grade="A",
                                critical_count=0, high_count=0, medium_count=0, low_count=0)

    counts = {
        RiskLevel.Critical: 0,
        RiskLevel.High: 0,
        RiskLevel.Medium: 0,
        RiskLevel.Low: 0
    }

    mosca_penalty = 0

    penalty = 0.0
    for f in findings:
        if not getattr(f, "is_actionable", True):
            continue
            
        # Self-heal rather than silently scoring an unclassified finding as
        # harmless. classify() is idempotent, so re-running it is safe.
        if not getattr(f, "vulnerability_score", 0.0):
            classify(f)

        counts[f.risk_score] += 1

        # Continuous deduction: max 15 points per finding based on its vulnerability score
        penalty += (getattr(f, "vulnerability_score", 0.0) / 100.0) * 15.0

        if apply_mosca_weight and f.mosca_result:
            if f.mosca_result.verdict == "CRITICAL_ACT_NOW":
                mosca_penalty = max(mosca_penalty, 20)
            elif f.mosca_result.verdict == "AT_RISK":
                mosca_penalty = max(mosca_penalty, 10)
        
    score = 100.0 - penalty - mosca_penalty
    score = max(0, score)
    
    if score >= 90: grade = "A"
    elif score >= 80: grade = "B"
    elif score >= 70: grade = "C"
    elif score >= 50: grade = "D"
    else: grade = "F"
        
    return QuantumRiskScore(
        scan_id=scan_id,
        score=int(score),
        grade=grade,
        critical_count=counts[RiskLevel.Critical],
        high_count=counts[RiskLevel.High],
        medium_count=counts[RiskLevel.Medium],
        low_count=counts[RiskLevel.Low]
    )
