from models.schemas import Finding, MigrationImpactEstimate
from recommendation.recommender import generate_recommendation
from models.schemas import BenchmarkResult


def _resolve_pqc_benchmark_key(liboqs_id: str, algo_stats: dict) -> str:
    """
    Maps a recommendation's liboqs_id onto a key that exists in the benchmark
    results.

    Ambiguous-usage findings (e.g. a bare RSA keygen with no inferrable usage)
    carry a compound id like "Kyber768/ML-DSA-65". Looking that up directly
    never matched, so the estimate silently fell back to hardcoded placeholder
    sizes and latencies while still claiming to be "sourced directly from local
    hardware benchmarks". Split on "/" and use the first component we actually
    measured; the conservative choice is the larger of the candidates.
    """
    if not liboqs_id:
        return ""
    if liboqs_id in algo_stats:
        return liboqs_id

    candidates = [part.strip() for part in liboqs_id.split("/") if part.strip() in algo_stats]
    if not candidates:
        return liboqs_id  # genuinely unmeasured; caller falls back to defaults

    # Prefer the heavier option so an ambiguous finding isn't under-estimated.
    return max(candidates, key=lambda k: algo_stats[k]["pk"] + algo_stats[k]["ct_sig"])


def compute_migration_impact(scan_id: str, findings: list[Finding], benchmarks: list[BenchmarkResult], scale_factor: int = 1000) -> MigrationImpactEstimate:
    """
    Computes an estimate of the migration impact across all findings.
    scale_factor: e.g. 1000 means "assuming 1000 connections/handshakes per day per finding".
    """
    # Create lookup map for raw benchmark data
    algo_stats = {}
    for b in benchmarks:
        algo_stats[b.algorithm] = {
            "pk": b.public_key_bytes,
            "ct_sig": b.ciphertext_or_signature_bytes,
            "op_ms": b.operation_ms
        }
    
    total_bytes_delta = 0
    total_handshake_ms_delta = 0.0

    total_classical_bytes = 0
    total_pqc_bytes = 0
    estimated_count = 0  # findings priced from reference values, not measurements
    
    for f in findings:
        rec = generate_recommendation(f)
        
        # Normalize classical algorithm names to match benchmarking outputs if possible
        c_alg = f.algorithm.upper()
        if c_alg == "ECC" or c_alg == "ECDH" or c_alg == "ECDSA": 
            c_alg = "ECDSA-P256"
        if c_alg == "RSA" or c_alg == "DSA" or c_alg == "DH": 
            c_alg = "RSA-2048"
            
        p_alg = _resolve_pqc_benchmark_key(rec.liboqs_id, algo_stats)

        c_pk = algo_stats.get(c_alg, {}).get("pk", 256)
        c_ct = algo_stats.get(c_alg, {}).get("ct_sig", 256)
        c_ms = algo_stats.get(c_alg, {}).get("op_ms", 1.0)
        
        # Override with exact mathematical sizes if the finding has a key_size
        if f.key_size:
            if f.algorithm.upper() in ["RSA", "DSA", "DH"]:
                c_pk = (f.key_size / 8) + 38  # Includes DER overhead approx
                c_ct = f.key_size / 8
            elif f.algorithm.upper() in ["ECC", "ECDSA", "ECDH", "EC"]:
                c_pk = (f.key_size / 8) * 2 + 1  # Uncompressed point
                c_ct = (f.key_size / 8) * 2
        
        p_stats = algo_stats.get(p_alg)
        if p_stats is None:
            # No measurement for this algorithm — fall back to published
            # reference sizes, and record that we did so.
            estimated_count += 1
            p_pk, p_ct, p_ms = 1184, 1088, 1.5
        else:
            p_pk = p_stats["pk"]
            p_ct = p_stats["ct_sig"]
            p_ms = p_stats["op_ms"]
        
        c_total = c_pk + c_ct
        total_classical_bytes += c_total
        
        # Assume migration impact is calculated for Stage 1 (Hybrid)
        # We keep classical and add PQC overhead
        p_total = c_total + p_pk + p_ct
        delta_ms = p_ms
            
        total_pqc_bytes += p_total
        
        total_bytes_delta += max(0, p_total - c_total)
        total_handshake_ms_delta += max(0.0, delta_ms)

    additional_bytes_per_handshake = total_bytes_delta
    total_bytes_scaled = additional_bytes_per_handshake * scale_factor
    
    storage_mb = total_bytes_scaled / (1024 * 1024)
    
    # Calculate true bandwidth percentage increase based on actual bytes
    if total_classical_bytes > 0:
        bandwidth_pct = (total_bytes_delta / total_classical_bytes) * 100
    else:
        bandwidth_pct = 0.0
    
    notes = f"Assumes {scale_factor} ops/day. Sourced from local hardware benchmarks."
    if estimated_count:
        notes += (
            f" {estimated_count} of {len(findings)} findings had no matching benchmark "
            f"(ambiguous algorithm usage) and use published reference sizes instead."
        )

    return MigrationImpactEstimate(
        scan_id=scan_id,
        total_assets=len(findings),
        estimated_additional_storage_mb=round(storage_mb, 4),
        estimated_additional_bandwidth_pct=round(bandwidth_pct, 1),
        estimated_handshake_overhead_ms=round(total_handshake_ms_delta, 3),
        notes=notes,
    )
