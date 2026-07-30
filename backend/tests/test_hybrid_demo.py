from benchmarking.hybrid_demo import simulate_hybrid_handshake

def test_hybrid_demo_computes_overhead():
    """
    Ensure the hybrid demo function correctly computes overheads using 
    real timings fetched from the benchmark engine.
    """
    result = simulate_hybrid_handshake(20)
    
    # Hybrid time must be greater than classical alone (due to addition of Kyber)
    assert result["hybrid_x25519_kyber768_ms"] > result["classical_x25519_ms"]
    
    # Overhead must be strictly positive
    assert result["overhead_ms"] > 0
    
    # Payload sizes must be correct
    assert result["hybrid_pk_bytes"] == result["x25519_pk_bytes"] + result["kyber_pk_bytes"]
