"""
qBraid Runner — Run the existing Shor's circuit via qBraid's cloud simulator.

This is an ADDITIVE module.  It does NOT touch shor_circuit.py or the local
Aer execution path.  It imports `build_shor_circuit` and submits the same
circuit to qBraid's QIR state-vector simulator.

Prerequisites
─────────────
  pip install qbraid

  # Set your API key (get one at https://account.qbraid.com):
  #   Linux / macOS:  export QBRAID_API_KEY="your_key"
  #   Windows CMD:    set QBRAID_API_KEY=your_key
  #   PowerShell:     $env:QBRAID_API_KEY="your_key"
"""

from __future__ import annotations

import os
import sys
import json
import time
from typing import Optional

# ---------------------------------------------------------------------------
# Import the circuit builder from the existing, untouched shor_circuit.py
# ---------------------------------------------------------------------------
from quantum_demo.shor_circuit import build_shor_circuit, build_generic_shor_circuit
try:
    from qiskit import transpile
    from qiskit_aer import AerSimulator
except ImportError:
    pass


def _get_provider():
    """Return a QbraidProvider, authenticating via QBRAID_API_KEY env var."""
    try:
        from qbraid.runtime import QbraidProvider
    except ImportError as exc:
        raise ImportError(
            "qbraid is not installed.  Run:  pip install qbraid"
        ) from exc

    api_key: Optional[str] = os.environ.get("QBRAID_API_KEY")
    if api_key:
        return QbraidProvider(api_key=api_key)
    # Fall back to ~/.qbraid/qbraidrc saved credentials
    return QbraidProvider()


def _get_device(provider, device_id: Optional[str] = None):
    """
    Resolve the qBraid QIR simulator device.

    Tries the v2 QRN first, then the legacy short-name.
    """
    candidates = (
        [device_id] if device_id
        else ["qbraid_qir_simulator", "qbraid:qbraid:sim:qir-sv"]
    )
    last_exc = None
    for did in candidates:
        try:
            return provider.get_device(did)
        except Exception as exc:          # noqa: BLE001
            last_exc = exc
    raise RuntimeError(
        f"Could not resolve any qBraid device from {candidates}"
    ) from last_exc


def run_shor_on_qbraid(
    N: int = 15,
    a: int = 7,
    shots: int = 1000,
    device_id: Optional[str] = None,
) -> dict:
    """
    Build the Shor circuit used by the local Aer demo
    and execute it on qBraid's cloud QIR simulator.
    """
    # 1.  Build circuit
    if N == 15:
        qc = build_shor_circuit(a)
    else:
        qc = build_generic_shor_circuit(N, a)

    print(f"[qBraid] Circuit built: {qc.num_qubits} qubits")
    
    # Measure compiled resources
    sim = AerSimulator()
    transpiled = transpile(qc, sim)
    measured_qubits = transpiled.num_qubits
    measured_depth = transpiled.depth()

    # 2.  Connect to qBraid
    provider = None
    device = None
    try:
        provider = _get_provider()
        device = _get_device(provider, device_id)
        print(f"[qBraid] Using device: {device}")
    except Exception as e:
        print(f"[qBraid] Could not connect to qBraid ({e}). Falling back to local simulator.")

    # 3.  Submit the job
    counts = {}
    if device:
        print(f"[qBraid] Submitting job ({shots} shots)...")
        try:
            job = device.run(qc, shots=shots)
            print("[qBraid] Waiting for results...")
            result = job.result()
            
            try:
                counts = result.data.get_counts()
            except AttributeError:
                try:
                    counts = result.get_counts()
                except AttributeError:
                    counts = result.raw_counts if hasattr(result, "raw_counts") else {}
        except Exception as e:
            print(f"[qBraid] Execution failed: {e}. Falling back to local Aer simulator.")
            device = None
            
    if not device:
        print("[qBraid] Running locally on AerSimulator...")
        result = sim.run(transpiled, shots=shots).result()
        counts = result.get_counts()

    # 6.  Build human-readable phase labels
    # If N is not 15, we might need a more generic phase map, but for the demo, 
    # we just format it as bitstrings.
    formatted: dict[str, int] = {}
    n_count = qc.num_clbits
    for bitstring, count in counts.items():
        phase_int = int(bitstring, 2) if isinstance(bitstring, str) else bitstring
        if N == 15 and n_count == 8:
            phase_map = {0: "0/4", 64: "1/4", 128: "2/4", 192: "3/4"}
            label = phase_map.get(phase_int)
            if label:
                formatted[f"phase {label}"] = formatted.get(f"phase {label}", 0) + count
        else:
            formatted[f"phase {phase_int}"] = count

    return {
        "raw_counts": counts,
        "formatted_phases": formatted,
        "shots": shots,
        "device": str(device) if device else "Local AerSimulator",
        "measured_qubits": measured_qubits,
        "measured_depth": measured_depth
    }


# ---------------------------------------------------------------------------
# CLI entry-point — allows:  python -m quantum_demo.qbraid_runner
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    try:
        result = run_shor_on_qbraid()
    except Exception as exc:
        print(f"\n✘  qBraid run failed: {exc}", file=sys.stderr)
        sys.exit(1)

    print("\n" + "=" * 60)
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    print("  qBraid QIR Simulator -- Shor N=15 (a=7) results")
    print("=" * 60)
    print(f"\nDevice : {result['device']}")
    print(f"Shots  : {result['shots']}")
    print(f"\nRaw counts ({len(result['raw_counts'])} unique bitstrings):")
    for bs, cnt in sorted(
        result["raw_counts"].items(),
        key=lambda x: x[1],
        reverse=True,
    ):
        print(f"  {bs}  ->  {cnt}")
    print(f"\nFormatted phase peaks:")
    for label, cnt in sorted(result["formatted_phases"].items()):
        print(f"  {label}  ->  {cnt}")
    print()
