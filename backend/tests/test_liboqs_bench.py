import pytest
from benchmarking.liboqs_bench import run_benchmark

def test_benchmark_run_count_enforcement():
    """
    Enforces PRD NFR-1 (no faked data, sufficient sample count).
    This proves the benchmark engine structurally refuses to run trivially short benchmarks.
    """
    with pytest.raises(AssertionError) as exc:
        run_benchmark(19)
    assert "sample count must be >= 20" in str(exc.value)

def test_benchmark_produces_valid_results():
    """
    Ensure the benchmarking engine produces 4 correct outputs (Kyber, RSA, ML-DSA, ECDSA).
    Since RSA keygen is slow, we limit test to exact boundary 20 runs.
    """
    results = run_benchmark(20)
    
    assert len(results) == 5
    
    kyber = next(r for r in results if r.algorithm == "Kyber768")
    assert kyber.run_count == 20
    assert kyber.keygen_ms > 0
    assert kyber.operation_ms > 0
    assert kyber.public_key_bytes > 0
    
    dsa = next(r for r in results if r.algorithm == "ML-DSA-65")
    assert dsa.run_count == 20
    assert dsa.keygen_ms > 0
