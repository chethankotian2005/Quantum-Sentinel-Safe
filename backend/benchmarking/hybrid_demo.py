import os
import sys

if os.name == 'nt':
    oqs_bin_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "liboqs", "build", "bin"))
    if os.path.exists(oqs_bin_path):
        os.environ["OQS_LIB_DIR"] = oqs_bin_path
        try:
            os.add_dll_directory(oqs_bin_path)
        except AttributeError:
            pass

from benchmarking.liboqs_bench import run_benchmark

def simulate_hybrid_handshake(iterations: int = 20):
    """
    Simulate the timing of a Hybrid X25519+Kyber768 handshake compared to classical-only.
    Reuses the core benchmarking engine to acquire real cryptographic timings.
    """
    # Fetch base timings
    results = run_benchmark(iterations)
    
    x25519_res = next((r for r in results if r.algorithm == "X25519"), None)
    kyber_res = next((r for r in results if r.algorithm == "Kyber768"), None)
    rsa_res = next((r for r in results if r.algorithm == "RSA-2048"), None)
    
    if not (x25519_res and kyber_res and rsa_res):
        raise ValueError("Missing algorithms in benchmark results")

    # Classical X25519 Handshake 
    # Time to generate key + exchange
    classical_time = x25519_res.keygen_ms + x25519_res.operation_ms
    
    # Hybrid X25519 + Kyber768 Handshake
    # Both algorithms run independently (often in parallel in real implementations, 
    # but we simulate serial overhead to be conservative)
    hybrid_time = (x25519_res.keygen_ms + x25519_res.operation_ms) + (kyber_res.keygen_ms + kyber_res.operation_ms)
    
    # Legacy RSA KEX Handshake
    rsa_time = rsa_res.keygen_ms + rsa_res.operation_ms
    
    return {
        "classical_x25519_ms": classical_time,
        "hybrid_x25519_kyber768_ms": hybrid_time,
        "legacy_rsa_ms": rsa_time,
        "overhead_ms": hybrid_time - classical_time,
        "x25519_pk_bytes": x25519_res.public_key_bytes,
        "kyber_pk_bytes": kyber_res.public_key_bytes,
        "hybrid_pk_bytes": x25519_res.public_key_bytes + kyber_res.public_key_bytes
    }

if __name__ == "__main__":
    print("Running Hybrid Handshake Simulation (N=20)...")
    sim = simulate_hybrid_handshake(20)
    
    print("\n--- Handshake Timing Comparison ---")
    print(f"Classical (X25519):         {sim['classical_x25519_ms']:.3f} ms")
    print(f"Hybrid (X25519+Kyber768):   {sim['hybrid_x25519_kyber768_ms']:.3f} ms")
    print(f"Legacy (RSA-2048):          {sim['legacy_rsa_ms']:.3f} ms")
    print("-" * 35)
    print(f"PQC Overhead penalty:       +{sim['overhead_ms']:.3f} ms")
    print("\n--- Handshake Payload Size Comparison ---")
    print(f"Classical (X25519) PK:      {sim['x25519_pk_bytes']} bytes")
    print(f"Hybrid (X25519+Kyber768) PK: {sim['hybrid_pk_bytes']} bytes")
    print("-" * 35)
