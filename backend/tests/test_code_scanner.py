import os
from detection.code_scanner import scan_directory

def test_scan_directory_finds_vulnerabilities():
    repo_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../sample-data/vulnerable-repo"))
    findings = scan_directory(repo_path)
    
    # We should have exactly 2 findings: one in auth.py, one in tls_helper.py. 
    # safe_encryption.py should have 0 findings.
    assert len(findings) == 2
    
    auth_finding = next((f for f in findings if "auth.py" in f.file), None)
    assert auth_finding is not None
    assert auth_finding.algorithm == "RSA"
    assert auth_finding.key_size == 2048
    
    tls_finding = next((f for f in findings if "tls_helper.py" in f.file), None)
    assert tls_finding is not None
    assert tls_finding.algorithm == "ECC"
    # key size might be None because ec.generate_private_key uses an object ec.SECP256R1()
    # instead of a raw integer, which is harder to parse statically via basic AST without eval.
    
    safe_finding = next((f for f in findings if "safe_encryption.py" in f.file), None)
    assert safe_finding is None
