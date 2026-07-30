import os

# Ensure liboqs DLL can be found on Windows
if os.name == 'nt':
    oqs_bin_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "liboqs", "build", "bin"))
    if os.path.exists(oqs_bin_path):
        os.environ["OQS_LIB_DIR"] = oqs_bin_path
        # Adding to dll directory to ensure Windows can load it for ctypes
        try:
            os.add_dll_directory(oqs_bin_path)
        except AttributeError:
            pass

import time
import statistics
import oqs
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding, x25519
from cryptography.hazmat.primitives import hashes, serialization

from models.schemas import BenchmarkResult

def run_benchmark(iterations: int = 20) -> list[BenchmarkResult]:
    # NFR-1: No faked data. We require at least 20 real operations.
    assert iterations >= 20, "NFR-1 violation: Benchmark sample count must be >= 20."
    
    results = []
    
    # ---------------------------------------------------------
    # 1. PQC: Kyber768 (vs RSA-2048)
    # ---------------------------------------------------------
    keygen_times = []
    op_times = []
    pk_size = 0
    ct_size = 0
    
    kem = oqs.KeyEncapsulation("Kyber768")
    for _ in range(iterations):
        t0 = time.perf_counter_ns()
        public_key = kem.generate_keypair()
        keygen_times.append(time.perf_counter_ns() - t0)
        pk_size = len(public_key)
        
        t0 = time.perf_counter_ns()
        ciphertext, shared_secret = kem.encap_secret(public_key)
        kem.decap_secret(ciphertext)
        op_times.append(time.perf_counter_ns() - t0)
        ct_size = len(ciphertext)
        
    results.append(BenchmarkResult(
        algorithm="Kyber768",
        compared_against="RSA-2048",
        keygen_ms=statistics.mean(keygen_times) / 1_000_000.0,
        operation_ms=statistics.mean(op_times) / 1_000_000.0,
        public_key_bytes=pk_size,
        ciphertext_or_signature_bytes=ct_size,
        run_count=iterations
    ))
    
    # ---------------------------------------------------------
    # 2. Classical: RSA-2048
    # ---------------------------------------------------------
    rsa_keygen_times = []
    rsa_op_times = []
    rsa_pk_size = 0
    rsa_ct_size = 0
    dummy_secret = b"12345678901234567890123456789012"
    
    for _ in range(iterations):
        t0 = time.perf_counter_ns()
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rsa_keygen_times.append(time.perf_counter_ns() - t0)
        
        rsa_pub = rsa_key.public_key()
        pk_bytes = rsa_pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        rsa_pk_size = len(pk_bytes)
        
        t0 = time.perf_counter_ns()
        ct = rsa_pub.encrypt(
            dummy_secret,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        rsa_key.decrypt(
            ct,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        rsa_op_times.append(time.perf_counter_ns() - t0)
        rsa_ct_size = len(ct)
        
    results.append(BenchmarkResult(
        algorithm="RSA-2048",
        compared_against="N/A",
        keygen_ms=statistics.mean(rsa_keygen_times) / 1_000_000.0,
        operation_ms=statistics.mean(rsa_op_times) / 1_000_000.0,
        public_key_bytes=rsa_pk_size,
        ciphertext_or_signature_bytes=rsa_ct_size,
        run_count=iterations
    ))

    # ---------------------------------------------------------
    # 3. PQC: ML-DSA-65 (vs ECDSA-P256)
    # ---------------------------------------------------------
    sign_keygen_times = []
    sign_op_times = []
    sign_pk_size = 0
    sign_sig_size = 0
    
    sig = oqs.Signature("ML-DSA-65")
    test_msg = b"benchmarking signature speed"
    for _ in range(iterations):
        t0 = time.perf_counter_ns()
        public_key = sig.generate_keypair()
        sign_keygen_times.append(time.perf_counter_ns() - t0)
        sign_pk_size = len(public_key)
        
        t0 = time.perf_counter_ns()
        signature = sig.sign(test_msg)
        sig.verify(test_msg, signature, public_key)
        sign_op_times.append(time.perf_counter_ns() - t0)
        sign_sig_size = len(signature)
        
    results.append(BenchmarkResult(
        algorithm="ML-DSA-65",
        compared_against="ECDSA-P256",
        keygen_ms=statistics.mean(sign_keygen_times) / 1_000_000.0,
        operation_ms=statistics.mean(sign_op_times) / 1_000_000.0,
        public_key_bytes=sign_pk_size,
        ciphertext_or_signature_bytes=sign_sig_size,
        run_count=iterations
    ))
    
    # ---------------------------------------------------------
    # 4. Classical: ECDSA-P256
    # ---------------------------------------------------------
    ec_keygen_times = []
    ec_op_times = []
    ec_pk_size = 0
    ec_sig_size = 0
    
    for _ in range(iterations):
        t0 = time.perf_counter_ns()
        ec_key = ec.generate_private_key(ec.SECP256R1())
        ec_keygen_times.append(time.perf_counter_ns() - t0)
        
        ec_pub = ec_key.public_key()
        pk_bytes = ec_pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        ec_pk_size = len(pk_bytes)
        
        t0 = time.perf_counter_ns()
        signature = ec_key.sign(test_msg, ec.ECDSA(hashes.SHA256()))
        ec_pub.verify(signature, test_msg, ec.ECDSA(hashes.SHA256()))
        ec_op_times.append(time.perf_counter_ns() - t0)
        ec_sig_size = len(signature)
        
    results.append(BenchmarkResult(
        algorithm="ECDSA-P256",
        compared_against="N/A",
        keygen_ms=statistics.mean(ec_keygen_times) / 1_000_000.0,
        operation_ms=statistics.mean(ec_op_times) / 1_000_000.0,
        public_key_bytes=ec_pk_size,
        ciphertext_or_signature_bytes=ec_sig_size,
        run_count=iterations
    ))

    # ---------------------------------------------------------
    # 5. Classical: X25519 (ECDH) for Hybrid Demo
    # ---------------------------------------------------------
    x2_keygen_times = []
    x2_op_times = []
    x2_pk_size = 0
    x2_ct_size = 0
    
    for _ in range(iterations):
        t0 = time.perf_counter_ns()
        x2_server_key = x25519.X25519PrivateKey.generate()
        x2_keygen_times.append(time.perf_counter_ns() - t0)
        
        x2_pub = x2_server_key.public_key()
        pk_bytes = x2_pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        x2_pk_size = len(pk_bytes)
        
        # Simulating client creating key and deriving secret
        x2_client_key = x25519.X25519PrivateKey.generate()
        
        t0 = time.perf_counter_ns()
        server_secret = x2_server_key.exchange(x2_client_key.public_key())
        client_secret = x2_client_key.exchange(x2_pub)
        x2_op_times.append(time.perf_counter_ns() - t0)
        x2_ct_size = len(x2_client_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        
    results.append(BenchmarkResult(
        algorithm="X25519",
        compared_against="N/A",
        keygen_ms=statistics.mean(x2_keygen_times) / 1_000_000.0,
        operation_ms=statistics.mean(x2_op_times) / 1_000_000.0,
        public_key_bytes=x2_pk_size,
        ciphertext_or_signature_bytes=x2_ct_size,
        run_count=iterations
    ))
    
    return results

if __name__ == "__main__":
    print("Running PQC vs Classical benchmarks (N=20)... Please wait as RSA keygen is slow.")
    results = run_benchmark(20)
    for r in results:
        print(f"Algorithm: {r.algorithm}")
        print(f"  Keygen:    {r.keygen_ms:.3f} ms")
        print(f"  Operation: {r.operation_ms:.3f} ms")
        print(f"  PK Size:   {r.public_key_bytes} bytes")
        print(f"  CT/Sig Sz: {r.ciphertext_or_signature_bytes} bytes")
        print("-" * 40)
