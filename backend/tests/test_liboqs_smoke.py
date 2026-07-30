#!/usr/bin/env python3
"""
liboqs Smoke Test — Kyber768 + Dilithium3
==========================================
QuantumSafe Sentinel — Highest-Risk Dependency Validation (PRD Day 1 gate)

This script validates that liboqs-python is properly installed and functional
by running REAL Kyber768 (KEM) and Dilithium3 (Signature) operations, each
at least 5 times, and printing actual measured timings.

Per PRD NFR-1: "No faked data." Every benchmark number must come from an
actual liboqs run — never hardcoded placeholder numbers.

Usage:
    python backend/tests/test_liboqs_smoke.py
"""

import time
import sys
import statistics


def run_kyber768_smoke(iterations: int = 5) -> list[dict]:
    """Run Kyber768 keygen + encapsulation/decapsulation and time each iteration."""
    import oqs

    results = []
    for i in range(iterations):
        # --- Keygen ---
        t0 = time.perf_counter_ns()
        kem = oqs.KeyEncapsulation("Kyber768")
        public_key = kem.generate_keypair()
        t_keygen_ns = time.perf_counter_ns() - t0

        # --- Encapsulation ---
        t0 = time.perf_counter_ns()
        ciphertext, shared_secret_enc = kem.encap_secret(public_key)
        t_encaps_ns = time.perf_counter_ns() - t0

        # --- Decapsulation ---
        t0 = time.perf_counter_ns()
        shared_secret_dec = kem.decap_secret(ciphertext)
        t_decaps_ns = time.perf_counter_ns() - t0

        # Verify correctness
        assert shared_secret_enc == shared_secret_dec, (
            f"Kyber768 iteration {i+1}: shared secrets do not match!"
        )

        result = {
            "iteration": i + 1,
            "keygen_us": t_keygen_ns / 1000.0,
            "encaps_us": t_encaps_ns / 1000.0,
            "decaps_us": t_decaps_ns / 1000.0,
            "public_key_bytes": len(public_key),
            "ciphertext_bytes": len(ciphertext),
            "shared_secret_bytes": len(shared_secret_enc),
        }
        results.append(result)

    return results


def run_dilithium3_smoke(iterations: int = 5) -> list[dict]:
    """Run Dilithium3 keygen + sign/verify and time each iteration."""
    import oqs

    test_message = b"QuantumSafe Sentinel smoke test - Team ACE - Quant-A-thon 2026"

    results = []
    for i in range(iterations):
        # --- Keygen ---
        t0 = time.perf_counter_ns()
        sig = oqs.Signature("ML-DSA-65")
        public_key = sig.generate_keypair()
        t_keygen_ns = time.perf_counter_ns() - t0

        # --- Sign ---
        t0 = time.perf_counter_ns()
        signature = sig.sign(test_message)
        t_sign_ns = time.perf_counter_ns() - t0

        # --- Verify ---
        t0 = time.perf_counter_ns()
        is_valid = sig.verify(test_message, signature, public_key)
        t_verify_ns = time.perf_counter_ns() - t0

        assert is_valid, f"Dilithium3 iteration {i+1}: signature verification failed!"

        result = {
            "iteration": i + 1,
            "keygen_us": t_keygen_ns / 1000.0,
            "sign_us": t_sign_ns / 1000.0,
            "verify_us": t_verify_ns / 1000.0,
            "public_key_bytes": len(public_key),
            "signature_bytes": len(signature),
        }
        results.append(result)

    return results


def print_kem_results(results: list[dict]) -> None:
    """Pretty-print Kyber768 results."""
    print("=" * 72)
    print("  KYBER768 (ML-KEM) — Key Encapsulation Mechanism")
    print("=" * 72)
    print(
        f"  {'Iter':>4}  {'Keygen (µs)':>12}  {'Encaps (µs)':>12}  "
        f"{'Decaps (µs)':>12}  {'PK (B)':>7}  {'CT (B)':>7}  {'SS (B)':>7}"
    )
    print("-" * 72)

    for r in results:
        print(
            f"  {r['iteration']:>4}  {r['keygen_us']:>12.2f}  "
            f"{r['encaps_us']:>12.2f}  {r['decaps_us']:>12.2f}  "
            f"{r['public_key_bytes']:>7}  {r['ciphertext_bytes']:>7}  "
            f"{r['shared_secret_bytes']:>7}"
        )

    keygen_times = [r["keygen_us"] for r in results]
    encaps_times = [r["encaps_us"] for r in results]
    decaps_times = [r["decaps_us"] for r in results]

    print("-" * 72)
    print(
        f"  {'AVG':>4}  {statistics.mean(keygen_times):>12.2f}  "
        f"{statistics.mean(encaps_times):>12.2f}  "
        f"{statistics.mean(decaps_times):>12.2f}"
    )
    print(
        f"  {'STDEV':>4}  "
        f"{statistics.stdev(keygen_times) if len(keygen_times) > 1 else 0:>12.2f}  "
        f"{statistics.stdev(encaps_times) if len(encaps_times) > 1 else 0:>12.2f}  "
        f"{statistics.stdev(decaps_times) if len(decaps_times) > 1 else 0:>12.2f}"
    )
    print()


def print_sig_results(results: list[dict]) -> None:
    """Pretty-print Dilithium3 results."""
    print("=" * 72)
    print("  DILITHIUM3 (ML-DSA) — Digital Signature Algorithm")
    print("=" * 72)
    print(
        f"  {'Iter':>4}  {'Keygen (µs)':>12}  {'Sign (µs)':>12}  "
        f"{'Verify (µs)':>12}  {'PK (B)':>7}  {'Sig (B)':>7}"
    )
    print("-" * 72)

    for r in results:
        print(
            f"  {r['iteration']:>4}  {r['keygen_us']:>12.2f}  "
            f"{r['sign_us']:>12.2f}  {r['verify_us']:>12.2f}  "
            f"{r['public_key_bytes']:>7}  {r['signature_bytes']:>7}"
        )

    keygen_times = [r["keygen_us"] for r in results]
    sign_times = [r["sign_us"] for r in results]
    verify_times = [r["verify_us"] for r in results]

    print("-" * 72)
    print(
        f"  {'AVG':>4}  {statistics.mean(keygen_times):>12.2f}  "
        f"{statistics.mean(sign_times):>12.2f}  "
        f"{statistics.mean(verify_times):>12.2f}"
    )
    print(
        f"  {'STDEV':>4}  "
        f"{statistics.stdev(keygen_times) if len(keygen_times) > 1 else 0:>12.2f}  "
        f"{statistics.stdev(sign_times) if len(sign_times) > 1 else 0:>12.2f}  "
        f"{statistics.stdev(verify_times) if len(verify_times) > 1 else 0:>12.2f}"
    )
    print()


def validate_non_zero(results: list[dict], algo_name: str) -> None:
    """Assert that all timing values are non-zero (real, not placeholder)."""
    for r in results:
        for key, val in r.items():
            if key.endswith("_us"):
                assert val > 0, (
                    f"{algo_name} iteration {r['iteration']}: "
                    f"{key} = {val} — must be non-zero!"
                )


def main() -> int:
    print()
    print("========================================================================")
    print("|  QuantumSafe Sentinel — liboqs PQC Smoke Test                        |")
    print("|  Validates real Kyber768 + Dilithium3 operations                     |")
    print("|  PRD NFR-1: No faked data — all timings from actual liboqs runs      |")
    print("========================================================================")
    print()

    iterations = 5

    # ---- Check liboqs is loadable ----
    try:
        import oqs
        print(f"  ✓ liboqs-python loaded successfully")
        print(f"  ✓ Enabled KEMs: {len(oqs.get_enabled_kem_mechanisms())} algorithms")
        print(f"  ✓ Enabled Sigs: {len(oqs.get_enabled_sig_mechanisms())} algorithms")

        # Verify our target algorithms are available
        assert "Kyber768" in oqs.get_enabled_kem_mechanisms(), \
            "Kyber768 not available in this liboqs build!"
        assert "ML-DSA-65" in oqs.get_enabled_sig_mechanisms(), \
            "ML-DSA-65 not available in this liboqs build!"
        print(f"  ✓ Kyber768 available")
        print(f"  ✓ ML-DSA-65 available")
        print()
    except Exception as e:
        print(f"  ✗ FATAL: Failed to load liboqs-python: {e}")
        print(f"    This is the highest-risk dependency — resolve before proceeding.")
        return 1

    # ---- Run Kyber768 ----
    print(f"  Running Kyber768 KEM × {iterations} iterations...")
    kyber_results = run_kyber768_smoke(iterations)
    validate_non_zero(kyber_results, "Kyber768")
    print(f"  ✓ All {iterations} Kyber768 iterations passed (secrets match, non-zero timings)")
    print()
    print_kem_results(kyber_results)

    # ---- Run Dilithium3 ----
    print(f"  Running Dilithium3 Signature × {iterations} iterations...")
    dilithium_results = run_dilithium3_smoke(iterations)
    validate_non_zero(dilithium_results, "Dilithium3")
    print(f"  ✓ All {iterations} Dilithium3 iterations passed (sigs verify, non-zero timings)")
    print()
    print_sig_results(dilithium_results)

    # ---- Summary ----
    print("=" * 72)
    print("  SMOKE TEST PASSED ✓")
    print("  All operations produced real, non-zero, non-placeholder timings.")
    print("  liboqs dependency is validated — safe to proceed with build.")
    print("=" * 72)
    print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
