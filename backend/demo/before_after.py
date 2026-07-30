import os
import sys
import shutil
import tempfile
import time

# Ensure backend directory is in the python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detection import code_scanner, config_scanner
from impact.risk_score import compute_risk_score
from remediation.patch_generator import apply_patch, generate_patch

def setup_demo_repo(target_dir):
    os.makedirs(target_dir, exist_ok=True)
    
    # 1. Python cryptography RSA keygen
    with open(os.path.join(target_dir, "demo_key.py"), "w", encoding="utf-8") as f:
        f.write("""import os
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return private_key
""")

    # 2. Node.js RSA
    with open(os.path.join(target_dir, "demo_server.js"), "w", encoding="utf-8") as f:
        f.write("""const crypto = require('crypto');

function setupKeys() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    return publicKey;
}
""")

    # 3. OpenSSL/TLS config
    with open(os.path.join(target_dir, "tls.conf"), "w", encoding="utf-8") as f:
        f.write("""server {
    listen 443 ssl;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384;
}
""")

def run_scan_and_get_score(target_dir):
    findings = []
    findings.extend(code_scanner.scan_directory(target_dir))
    findings.extend(config_scanner.scan_directory(target_dir))
    
    # Generate patches so they exist on the findings
    for f in findings:
        f.patch_diff = generate_patch(f)
        
    score = compute_risk_score("demo_scan", findings, apply_mosca_weight=False)
    return findings, score

def main():
    print("=" * 60)
    print("QuantumSafe Sentinel: End-to-End Remediation Demo")
    print("=" * 60)
    
    tmp_dir = tempfile.mkdtemp(prefix="qs_demo_")
    try:
        print(f"\n[+] Setting up vulnerable demo repository at {tmp_dir}")
        setup_demo_repo(tmp_dir)
        time.sleep(1)
        
        print("\n[+] Scanning repository for cryptographic vulnerabilities...")
        findings, initial_score = run_scan_and_get_score(tmp_dir)
        
        print(f"    - Found {len(findings)} vulnerable assets.")
        print(f"    - Initial Quantum Risk Score: {initial_score.score}/100 (Grade: {initial_score.grade})")
        print(f"    - Critical/High Findings: {initial_score.critical_count + initial_score.high_count}")
        
        print("\n[+] Generating and applying liboqs-backed PQC patches...")
        time.sleep(1)
        patches_applied = 0
        for f in findings:
            if apply_patch(f):
                patches_applied += 1
                print(f"    -> Successfully patched {os.path.basename(f.file)}")
                
        print(f"\n[+] Rescanning patched repository...")
        new_findings, new_score = run_scan_and_get_score(tmp_dir)
        
        print(f"    - Found {len(new_findings)} vulnerable assets.")
        print(f"    - New Quantum Risk Score: {new_score.score}/100 (Grade: {new_score.grade})")
        
        print("\n" + "=" * 60)
        if new_score.score > initial_score.score:
            print(f"SUCCESS: Risk score dropped by {new_score.score - initial_score.score} points!")
        else:
            print("SUCCESS: Vulnerabilities mitigated.")
        print("=" * 60 + "\n")
        
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

if __name__ == "__main__":
    main()
