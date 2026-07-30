import os
from detection.config_scanner import scan_directory

def test_config_scanner_finds_vulnerabilities():
    repo_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../sample-data/configs"))
    findings = scan_directory(repo_path)
    
    # Check nginx findings
    nginx_findings = [f for f in findings if "nginx.conf" in f.file]
    assert len(nginx_findings) > 0
    algorithms_found = {f.algorithm for f in nginx_findings}
    assert "RSA" in algorithms_found
    assert "DH" in algorithms_found
    assert "ECDH" in algorithms_found

    # Check SSH findings
    ssh_findings = [f for f in findings if "sshd_config" in f.file]
    assert len(ssh_findings) > 0
    ssh_algorithms_found = {f.algorithm for f in ssh_findings}
    assert "DH" in ssh_algorithms_found
    assert "ECDH" in ssh_algorithms_found
