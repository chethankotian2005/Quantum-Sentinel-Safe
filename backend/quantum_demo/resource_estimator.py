"""
Quantum Resource Estimator
==========================
Given a classical cryptographic algorithm (RSA or ECC) and key size,
estimates the quantum computing resources required to break it using
Shor's algorithm (RSA) or Shor-adapted elliptic curve discrete log
algorithms (ECC).

This module complements shor_circuit.py (which demonstrates the *mechanism*
on N=15) by projecting what real-world key sizes would actually require
in terms of qubits and runtime — making the theoretical threat concrete.

All numbers are sourced from published research. Each figure is annotated
with its citation. Rough extrapolations are explicitly labeled as such
in both code comments and returned data.

Primary References:
  [1] Gidney, C. & Ekerå, M. (2019). "How to factor 2048 bit RSA integers
      in 8 hours using 20 million noisy qubits." arXiv:1905.09749.
  [2] Gidney, C. (2025). "Factoring 2048-bit RSA integers in 177 days with
      13,436 qubits and 8 million Toffoli gates." (Refined estimate, under
      1 million physical qubits with improved error correction.)
  [3] Roetteler, M. et al. (2017). "Quantum resource estimates for computing
      elliptic curve discrete logarithms." arXiv:1706.06752.
  [4] IBM Condor: 1,121 superconducting qubits (released Dec 2023).
  [5] Google Willow: 105 qubits (released Dec 2024).
  [6] Atom Computing: 1,180 neutral-atom qubits (announced Oct 2023).
"""

from dataclasses import dataclass
from typing import Optional
import os
import concurrent.futures


@dataclass
class ResourceEstimate:
    """Structured output for quantum resource estimation."""
    algorithm: str
    key_size_bits: int
    idealized_logical_qubits: int
    logical_qubit_source: str
    realistic_physical_qubits_estimate: int
    physical_qubit_source: str
    is_directly_cited: bool  # True = from a specific paper; False = rough extrapolation
    estimated_runtime_description: str
    comparison_to_current_hardware: str
    current_largest_qpc: int  # largest real quantum processor count for ratio
    gap_factor: float  # how many × current hardware is needed


# ──────────────────────────────────────────────────────────────────────
# Directly-cited research figures for RSA-2048
# These are NOT computed — they are read directly from the papers.
# ──────────────────────────────────────────────────────────────────────

# [1] Gidney & Ekerå 2019: 20 million physical qubits, 8 hours runtime
_RSA_2048_PHYSICAL_GIDNEY_2019 = 20_000_000
_RSA_2048_RUNTIME_GIDNEY_2019 = "8 hours"

# [2] Gidney 2025 refinement: under 1 million physical qubits, 177 days
# Uses improved error correction and fewer Toffoli gates
_RSA_2048_PHYSICAL_GIDNEY_2025 = 1_000_000  # "under 1 million"
_RSA_2048_RUNTIME_GIDNEY_2025 = "177 days (with 13,436 logical qubits)"

# Current hardware ceiling (as of mid-2025)
# Sources: IBM Condor (1,121 qubits, Dec 2023), Atom Computing (1,180
# qubits, Oct 2023). Google Willow is 105 qubits but demonstrated
# superior error correction.
_CURRENT_MAX_PHYSICAL_QUBITS = 1_200  # approximate ceiling across vendors

_LIVE_QPU_CACHE = None

def get_current_max_physical_qubits() -> tuple[int, str]:
    """
    Returns (max_qubits, source_label).
    Attempts a live qBraid query to find the largest available QPU.
    Falls back to static cited figures if the network call fails or times out.
    """
    global _LIVE_QPU_CACHE
    if _LIVE_QPU_CACHE is not None:
        return _LIVE_QPU_CACHE
        
    fallback_qubits = _CURRENT_MAX_PHYSICAL_QUBITS
    fallback_source = "IBM Condor: 1,121; Atom Computing: 1,180 (Static citation)"
    
    if not os.environ.get("QBRAID_API_KEY"):
        _LIVE_QPU_CACHE = (fallback_qubits, fallback_source)
        return _LIVE_QPU_CACHE
        
    def _fetch():
        try:
            from qbraid.runtime import QbraidProvider
            provider = QbraidProvider()
            devices = provider.get_devices()
            max_q = 0
            best_name = ""
            for d in devices:
                did = getattr(d, 'id', str(d)).lower()
                if 'sim' in did or 'emu' in did:
                    continue  # Skip simulators for physical qubit comparison
                
                q = getattr(d, 'num_qubits', 0)
                if isinstance(q, int) and q > max_q:
                    max_q = q
                    best_name = getattr(d, 'id', str(d))
            if max_q > 0:
                return max_q, best_name
        except Exception:
            pass
        return None

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_fetch)
            result = future.result(timeout=5.0)
            if result:
                max_q, best_name = result
                _LIVE_QPU_CACHE = (max_q, f"Live qBraid query: {best_name}")
                return _LIVE_QPU_CACHE
    except Exception:
        pass
        
    _LIVE_QPU_CACHE = (fallback_qubits, fallback_source)
    return _LIVE_QPU_CACHE


def estimate_rsa(key_size: int, algorithm: str = "RSA") -> ResourceEstimate:
    """
    Estimate quantum resources to factor an RSA key via Shor's algorithm.

    Logical qubit formula:
      ~3n logical qubits for an n-bit RSA modulus.
      Source: Gidney & Ekerå 2019, Section 2 — abstract circuit model
      uses 3n + 0.002n log₂(n) qubits, simplified here to 3n for the
      idealized count since the log term is <1% for practical key sizes.

    Physical qubit estimates:
      For 2048-bit keys, we cite the two published figures directly.
      For other key sizes, we apply rough sub-quadratic scaling from the
      2048-bit anchor point. This extrapolation is explicitly marked.
    """

    # ── Idealized logical qubits: 3 * key_size ──
    # Cite: Gidney & Ekerå 2019, abstract circuit model, Section 2.
    idealized_logical = 3 * key_size
    current_qpc, current_qpc_source = get_current_max_physical_qubits()

    if key_size == 2048:
        # ── Directly-cited figures — NOT extrapolated ──
        return ResourceEstimate(
            algorithm=algorithm,
            key_size_bits=key_size,
            idealized_logical_qubits=idealized_logical,
            logical_qubit_source=(
                "3n logical qubits per Gidney & Ekerå 2019 (arXiv:1905.09749), "
                "Section 2 abstract circuit model."
            ),
            realistic_physical_qubits_estimate=_RSA_2048_PHYSICAL_GIDNEY_2019,
            physical_qubit_source=(
                "Directly cited: 20 million physical qubits per Gidney & Ekerå 2019 "
                "(arXiv:1905.09749). A 2025 refinement by Gidney reduces this to under "
                "1 million physical qubits but requires 177 days of runtime."
            ),
            is_directly_cited=True,
            estimated_runtime_description=(
                f"Cited: {_RSA_2048_RUNTIME_GIDNEY_2019} with 20M qubits "
                f"(Gidney & Ekerå 2019); or {_RSA_2048_RUNTIME_GIDNEY_2025} "
                f"with <1M qubits (Gidney 2025 refinement)."
            ),
            comparison_to_current_hardware=(
                f"Today's largest quantum processors have ~{current_qpc:,} "
                f"physical qubits ({current_qpc_source}). "
                f"Breaking RSA-2048 requires ~20,000,000 qubits — roughly "
                f"{_RSA_2048_PHYSICAL_GIDNEY_2019 // current_qpc:,}× "
                f"current hardware. Even with the 2025 refinement (<1M qubits), the gap "
                f"is still ~{_RSA_2048_PHYSICAL_GIDNEY_2025 // current_qpc:,}×."
            ),
            current_largest_qpc=current_qpc,
            gap_factor=round(_RSA_2048_PHYSICAL_GIDNEY_2019 / current_qpc, 1),
        )

    # ── Other RSA key sizes: rough scaling extrapolation ──
    # Shor's algorithm scales roughly as O(n^2 log n) in gate count and
    # O(n^2) in qubit count for error-corrected implementations.
    # We anchor to the 2048-bit published figure and scale quadratically.
    # THIS IS A ROUGH ESTIMATE, not a separately published figure.
    scale_factor = (key_size / 2048) ** 2
    extrapolated_physical = int(_RSA_2048_PHYSICAL_GIDNEY_2019 * scale_factor)

    return ResourceEstimate(
        algorithm=algorithm,
        key_size_bits=key_size,
        idealized_logical_qubits=idealized_logical,
        logical_qubit_source=(
            "3n logical qubits per Gidney & Ekerå 2019 (arXiv:1905.09749), "
            "Section 2 abstract circuit model."
        ),
        realistic_physical_qubits_estimate=extrapolated_physical,
        physical_qubit_source=(
            f"ROUGH ESTIMATE — extrapolated from the 2048-bit figure "
            f"(20M qubits, Gidney & Ekerå 2019) using quadratic scaling "
            f"O(n²). This is NOT a separately published research figure "
            f"for {key_size}-bit keys."
        ),
        is_directly_cited=False,
        estimated_runtime_description=(
            f"Rough extrapolation from RSA-2048 baseline. No independently "
            f"published runtime estimate exists for RSA-{key_size} specifically."
        ),
        comparison_to_current_hardware=(
            f"Today's largest quantum processors have ~{current_qpc:,} "
            f"physical qubits ({current_qpc_source}). "
            f"Breaking RSA-{key_size} would require ~{extrapolated_physical:,} qubits "
            f"(rough estimate) — roughly "
            f"{extrapolated_physical // current_qpc:,}× current hardware."
        ),
        current_largest_qpc=current_qpc,
        gap_factor=round(extrapolated_physical / current_qpc, 1),
    )


def estimate_ecc(key_size: int, algorithm: str = "ECC") -> ResourceEstimate:
    """
    Estimate quantum resources for breaking ECC via Shor-adapted ECDLP.

    Logical qubit formula:
      Published estimates exist in Roetteler et al. 2017 (arXiv:1706.06752)
      for specific curves (e.g., P-256 requires ~2,330 logical qubits,
      Table 1). However, mapping from "key_size in bits" to a specific
      curve's resource count requires curve-specific parameters.

      # TODO: VERIFY EXACT ECC FORMULA BEFORE FINAL CITATION
      # The Roetteler et al. 2017 paper gives curve-specific estimates
      # (e.g., 2,330 logical qubits for P-256, 2n+1 ancilla qubits for
      # generic n-bit curves). The exact formula depends on the field
      # arithmetic implementation. Do NOT present 9*key_size as a
      # published figure — it is a rough approximation for display
      # purposes only. The team must verify against the actual paper
      # (Table 1) before putting this on a slide.

    For display, we use a rough heuristic of ~9n logical qubits for an
    n-bit curve, acknowledging this is an approximation.
    """

    # Rough heuristic — NOT a direct citation. See TODO above.
    idealized_logical = 9 * key_size
    current_qpc, current_qpc_source = get_current_max_physical_qubits()

    # No directly-published physical qubit figure for arbitrary ECC key sizes.
    # Scale very roughly from the RSA-2048 anchor, noting ECC requires
    # fewer qubits than equivalent-security RSA but still millions.
    # A 256-bit ECC key ≈ 3072-bit RSA security.
    # This is an ORDER-OF-MAGNITUDE estimate only.
    if key_size <= 256:
        rough_physical = 5_000_000  # order-of-magnitude rough estimate
    elif key_size <= 384:
        rough_physical = 10_000_000
    else:
        rough_physical = 15_000_000

    return ResourceEstimate(
        algorithm=algorithm,
        key_size_bits=key_size,
        idealized_logical_qubits=idealized_logical,
        logical_qubit_source=(
            "ROUGH APPROXIMATION (~9n logical qubits for n-bit curve). "
            "Published curve-specific estimates exist in Roetteler et al. 2017 "
            "(arXiv:1706.06752, Table 1) — e.g., 2,330 logical qubits for P-256. "
            "Verify exact formula against the paper before citing in presentations."
        ),
        realistic_physical_qubits_estimate=rough_physical,
        physical_qubit_source=(
            "ROUGH ORDER-OF-MAGNITUDE ESTIMATE — no directly published physical "
            "qubit count for generic ECC key sizes. Derived by analogy to RSA "
            "resource estimates (Gidney & Ekerå 2019). Do NOT cite as a precise figure."
        ),
        is_directly_cited=False,
        estimated_runtime_description=(
            "No independently published runtime estimate for this ECC key size. "
            "Expect similar order of magnitude to RSA-equivalent security levels."
        ),
        comparison_to_current_hardware=(
            f"Today's largest quantum processors have ~{current_qpc:,} "
            f"physical qubits ({current_qpc_source}). "
            f"Breaking ECC-{key_size} would require ~{rough_physical:,} qubits "
            f"(rough estimate) — roughly "
            f"{rough_physical // current_qpc:,}× current hardware."
        ),
        current_largest_qpc=current_qpc,
        gap_factor=round(rough_physical / current_qpc, 1),
    )


def estimate_resources(algorithm: str, key_size: int) -> ResourceEstimate:
    """
    Main entry point. Given an algorithm name and key size, return a
    ResourceEstimate with fully-sourced qubit counts and hardware comparison.

    Args:
        algorithm: "RSA" or "ECC" (case-insensitive)
        key_size: key size in bits (e.g., 2048 for RSA, 256 for ECC)

    Returns:
        ResourceEstimate dataclass with all fields populated and sourced.
    """
    algo = algorithm.strip().upper()
    if algo in ("RSA", "DH", "DSA"):
        return estimate_rsa(key_size, algorithm=algorithm)
    elif algo in ("ECC", "ECDSA", "ECDH", "EC"):
        return estimate_ecc(key_size, algorithm=algorithm)
    else:
        raise ValueError(
            f"Unsupported algorithm '{algorithm}'. Supported: RSA, DH, DSA, ECC, ECDH, ECDSA, EC."
        )
