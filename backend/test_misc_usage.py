import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from detection.code_scanner import scan_directory
from recommendation.recommender import generate_recommendation
from models.schemas import UsageType

def main():
    target_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../sample-data/certbot"))
    if not os.path.exists(target_dir):
        print(f"Directory not found: {target_dir}")
        return

    findings = scan_directory(target_dir)
    print(f"Found {len(findings)} findings in certbot")

    for f in findings:
        rec = generate_recommendation(f)
        print(f"File: {f.file.split('sample-data/certbot/')[-1]}:{f.line}")
        print(f"  Algorithm: {f.algorithm}, Usage: {f.usage_type.value}")
        print(f"  Recommended PQC: {rec.pqc_replacement} ({rec.purpose})")
        print(f"  Hybrid: {rec.hybrid_scheme if rec.hybrid_recommended else 'N/A'}")
        print()
        
    print("--- Test unambiguous vs ambiguous ---")
    
    # Let's create a temporary file to test our precise usage inference
    test_code = """
import rsa
def do_signing():
    my_sign_key = rsa.generate_private_key(key_size=2048)
    my_sign_key.sign(b"data")
    
def do_exchange():
    my_ex_key = rsa.generate_private_key(key_size=2048)
    my_ex_key.exchange(b"data")
    
def do_ambiguous():
    amb_key = rsa.generate_private_key(key_size=2048)
    return amb_key
"""
    test_file = os.path.join(os.path.dirname(__file__), "temp_misc_test.py")
    with open(test_file, "w") as f:
        f.write(test_code)
        
    from detection.code_scanner import scan_python_file
    test_findings = scan_python_file(test_file)
    for f in test_findings:
        rec = generate_recommendation(f)
        print(f"Line {f.line} ({f.algorithm}):")
        print(f"  Inferred Usage: {f.usage_type.value}")
        print(f"  Recommended PQC: {rec.pqc_replacement} ({rec.purpose})")
        print()
        
    os.remove(test_file)

if __name__ == "__main__":
    main()
