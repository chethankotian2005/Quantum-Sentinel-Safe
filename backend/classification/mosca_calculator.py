"""
Mosca's Theorem Calculator
==========================
Implements Michele Mosca's risk inequality: if X + Y > Z, act now.

  X = years data must remain confidential
  Y = years to migrate cryptographic infrastructure
  Z = years until a Cryptographically Relevant Quantum Computer (CRQC)

When a finding has an attached quantum_attack_cost (from resource_estimator),
we can refine Z using IBM's published quantum hardware roadmap milestones,
comparing the qubit requirement against projected hardware availability:

  IBM Roadmap (public, ibm.com/quantum/roadmap):
    - Starling (2029): 200 error-corrected logical qubits
    - Blue Jay (2033): 2,000 error-corrected logical qubits

  This comparison produces a more specific, sourced timeline comment rather
  than relying solely on the generic default Z.

  IMPORTANT: These milestones describe *logical* qubit counts, which are
  orders of magnitude below the millions of *physical* qubits needed to
  break RSA-2048. The roadmap comparison is used to annotate Z with a
  sourced comment, NOT to replace the default Z — the gap is so large
  that the default 7-year horizon remains reasonable for near-term planning,
  while the roadmap data adds a "but realistically, here's the scale of
  the gap" qualifier.
"""

from models.schemas import Finding, MoscaResult, ContextType, UsageType


# ──────────────────────────────────────────────────────────────────────
# IBM Quantum Roadmap Milestones (public)
# Source: https://www.ibm.com/quantum/roadmap (accessed July 2025)
# ──────────────────────────────────────────────────────────────────────
IBM_ROADMAP = [
    {
        "name": "Starling",
        "year": 2029,
        "logical_qubits": 200,
        "source": "IBM Quantum Roadmap (ibm.com/quantum/roadmap), announced 2024",
    },
    {
        "name": "Blue Jay",
        "year": 2033,
        "logical_qubits": 2_000,
        "source": "IBM Quantum Roadmap (ibm.com/quantum/roadmap), announced 2024",
    },
]

# Current year for relative calculations
_CURRENT_YEAR = 2025


def get_default_migration_time(finding: Finding) -> float:
    # Y: years to migrate
    if finding.context == ContextType.production_cert:
        return 1.0  # Rotating certs is relatively fast
    elif finding.context == ContextType.code:
        return 3.0  # Refactoring embedded crypto takes longer
    elif finding.context == ContextType.config:
        return 1.5  # Updating server configs
    else:
        return 2.0


def get_default_data_sensitivity(finding: Finding) -> float:
    # X: years data must remain secure
    # INTENTIONAL DIFFERENCE: Key exchange (even if flagged as Critical risk due to 
    # Harvest-Now-Decrypt-Later threats) defaults to a shorter shelf life (2 years) 
    # under the assumption of ephemeral session keys/PFS and near-term data relevance.
    # Signing defaults to a longer shelf life (5 years) because it often protects 
    # long-term identities, code signatures, or documents that must remain trusted 
    # further into the future. This causes signing to often receive a more urgent 
    # Mosca verdict (AT RISK) than key exchange (SAFE) for the same migration timeframe.
    if finding.usage_type == UsageType.key_exchange:
        return 2.0  # Ephemeral session keys, assuming PFS
    elif finding.usage_type == UsageType.signing:
        return 5.0  # Long-term trust, identities, documents
    else:
        return 3.0


def _build_roadmap_comment(finding: Finding) -> str | None:
    """
    If the finding has a quantum_attack_cost attached, compare its logical
    qubit requirement against IBM's roadmap milestones.

    Returns a sourced plain-language comment, or None if comparison isn't
    applicable (no quantum_attack_cost, or algorithm not RSA/ECC).
    """
    qac = getattr(finding, "quantum_attack_cost", None)
    if qac is None:
        return None

    required_logical = qac.idealized_logical_qubits
    required_physical = qac.realistic_physical_qubits_estimate
    algo_label = f"{qac.algorithm}-{qac.key_size_bits}"

    # Find the first roadmap milestone that exceeds the requirement
    # (spoiler: none of them will for RSA-2048's 6,144 logical / 20M physical)
    sufficient_milestone = None
    for milestone in IBM_ROADMAP:
        if milestone["logical_qubits"] >= required_logical:
            sufficient_milestone = milestone
            break

    if sufficient_milestone:
        # The roadmap reaches the logical qubit count — but this ignores
        # error correction overhead. Add a strong caveat.
        years_away = sufficient_milestone["year"] - _CURRENT_YEAR
        return (
            f"IBM's {sufficient_milestone['name']} processor ({sufficient_milestone['year']}) "
            f"targets {sufficient_milestone['logical_qubits']:,} logical qubits, "
            f"which meets the {required_logical:,} logical qubit requirement for {algo_label}. "
            f"However, breaking {algo_label} also requires ~{required_physical:,} physical qubits "
            f"with current error correction — far beyond this milestone's physical capacity. "
            f"Earliest plausible threat: well beyond {sufficient_milestone['year']}. "
            f"(Source: {sufficient_milestone['source']})"
        )
    else:
        # The requirement exceeds all roadmap milestones
        last_milestone = IBM_ROADMAP[-1]
        gap_factor = required_logical / last_milestone["logical_qubits"]
        return (
            f"Breaking {algo_label} requires ~{required_logical:,} logical qubits. "
            f"IBM's most ambitious announced milestone ({last_milestone['name']}, "
            f"{last_milestone['year']}) targets only {last_milestone['logical_qubits']:,} "
            f"logical qubits — {gap_factor:.1f}× short of the requirement, "
            f"before accounting for error correction overhead "
            f"(~{required_physical:,} physical qubits needed). "
            f"No announced hardware roadmap reaches this threshold. "
            f"(Source: {last_milestone['source']})"
        )


def calculate_mosca_risk(
    z_years: float,
    finding: Finding,
    global_data_sensitivity_override: float = None,
    global_migration_override: float = None,
) -> MoscaResult:

    if global_migration_override is not None:
        y = float(global_migration_override)
    else:
        y = get_default_migration_time(finding)

    if global_data_sensitivity_override is not None:
        x = float(global_data_sensitivity_override)
    elif finding.data_sensitivity_years is not None:
        x = finding.data_sensitivity_years
    else:
        x = get_default_data_sensitivity(finding)

    z = float(z_years)
    sum_xy = x + y
    margin_years = z - sum_xy

    if margin_years <= 0:
        verdict = "CRITICAL_ACT_NOW"
    elif margin_years <= 2:
        verdict = "AT_RISK"
    else:
        verdict = "SAFE"

    explanation = (
        f"X ({x} yrs) + Y ({y} yrs) = {sum_xy} yrs. "
        f"Z (Threat Horizon) = {z} yrs. Margin: {margin_years} yrs."
    )

    # Attempt to enrich Z with IBM roadmap context
    roadmap_comment = _build_roadmap_comment(finding)

    return MoscaResult(
        x=x,
        y=y,
        z=z,
        sum_xy=sum_xy,
        margin_years=margin_years,
        verdict=verdict,
        explanation=explanation,
        z_threat_horizon_comment=roadmap_comment,
    )
