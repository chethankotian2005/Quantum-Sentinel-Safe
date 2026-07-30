from typing import List
from models.schemas import ScanResult, ExecutiveSynthesis, Finding

def synthesize_narrative(scan: ScanResult) -> ExecutiveSynthesis:
    """Synthesizes raw scan findings into a high-level business narrative."""
    
    if not scan.findings:
        return ExecutiveSynthesis(
            headline_risk_statement="No immediate quantum risk detected. The target is well-positioned for future cryptographic agility.",
            top_3_priority_actions=[],
            compliance_summary_line="No compliance violations related to quantum cryptography detected."
        )

    critical_count = scan.risk_score.critical_count if scan.risk_score else 0
    high_count = scan.risk_score.high_count if scan.risk_score else 0
    
    # Calculate worst Mosca margin
    worst_mosca = None
    for f in scan.findings:
        if not getattr(f, "is_actionable", True):
            continue
        if f.mosca_result:
            if worst_mosca is None or f.mosca_result.margin_years < worst_mosca.margin_years:
                worst_mosca = f.mosca_result

    # Construct Headline Risk Statement
    if worst_mosca and worst_mosca.margin_years < 0:
        headline = f"CRITICAL: {critical_count + high_count} assets have an active Harvest-Now-Decrypt-Later exposure window."
    elif worst_mosca and worst_mosca.margin_years < 3:
        headline = f"URGENT: {critical_count + high_count} assets face a closing Harvest-Now-Decrypt-Later exposure window within {worst_mosca.margin_years:.1f} years."
    elif critical_count > 0:
        headline = f"High Risk: {critical_count} critical cryptographic implementations require post-quantum remediation."
    else:
        actionable_count = sum(1 for f in scan.findings if getattr(f, "is_actionable", True))
        headline = f"Moderate Risk: {actionable_count} quantum-vulnerable cryptographic implementations detected, but no immediate exposure window."

    # Construct Top 3 Priority Actions
    # Sort findings by risk score, then mosca margin
    def finding_sort_key(f: Finding):
        risk_weight = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}.get(f.risk_score.value, 0)
        mosca_weight = -f.mosca_result.margin_years if f.mosca_result else 0
        return (risk_weight, mosca_weight)

    sorted_findings = sorted(scan.findings, key=finding_sort_key, reverse=True)
    
    top_3_actions = []
    seen_contexts = set()
    
    for f in sorted_findings:
        if not getattr(f, "is_actionable", True):
            continue
            
        if len(top_3_actions) >= 3:
            break
            
        # Try to deduplicate similar advice
        context_key = f"{f.algorithm}-{f.context.value}"
        if context_key in seen_contexts:
            continue
        seen_contexts.add(context_key)
        
        # Match with recommendation
        rec = next((r for r in scan.recommendations if r.finding_id == f.finding_id), None)
        
        target = f.file or f.hostname or "the target"
        if rec:
            action = f"Migrate {f.algorithm} usage in {target} to {rec.stage_1_hybrid}."
            if f.mosca_result and f.mosca_result.margin_years < 0:
                action += " (Immediate action required due to negative Mosca margin)."
            top_3_actions.append(action)
        else:
            top_3_actions.append(f"Remediate {f.algorithm} usage in {target}.")

    # If we couldn't find 3 distinct ones, just pad with generic advice if there are more findings
    if len(top_3_actions) < 3 and len(scan.findings) > len(top_3_actions):
        top_3_actions.append(f"Review and remediate the remaining {len(scan.findings) - len(top_3_actions)} vulnerable implementations.")

    # Construct Compliance Summary Line
    compliance_frameworks = set()
    for f in scan.findings:
        if f.compliance_flags:
            for flag in f.compliance_flags:
                compliance_frameworks.add(flag.framework_name)
    
    if compliance_frameworks:
        compliance_str = ", ".join(sorted(compliance_frameworks))
        compliance_summary = f"Non-compliant with {compliance_str} requirements across {len(scan.findings)} instances."
    else:
        compliance_summary = "No immediate compliance violations detected."

    return ExecutiveSynthesis(
        headline_risk_statement=headline,
        top_3_priority_actions=top_3_actions,
        compliance_summary_line=compliance_summary
    )
