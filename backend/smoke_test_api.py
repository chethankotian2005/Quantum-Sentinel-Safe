import httpx
import os
import time

BASE_URL = "http://127.0.0.1:8000"

def test_endpoints():
    print("Testing QuantumSafe Sentinel API Endpoints...\n")
    
    sample_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "sample-data"))
    code_dir = os.path.join(sample_dir, "vulnerable-repo")
    cert_dir = os.path.join(sample_dir, "certs")
    config_dir = os.path.join(sample_dir, "configs")
    
    print("1. /api/scan/codebase")
    res = httpx.post(f"{BASE_URL}/api/scan/codebase", json={"path": code_dir}, timeout=30.0)
    print(f"Status: {res.status_code}")
    scan_code = res.json()
    print(f"Findings: {len(scan_code['findings'])}")
    
    print("\n2. /api/scan/certificate")
    res = httpx.post(f"{BASE_URL}/api/scan/certificate", json={"path": cert_dir}, timeout=30.0)
    print(f"Status: {res.status_code}")
    scan_cert = res.json()
    print(f"Findings: {len(scan_cert['findings'])}")
    
    print("\n3. /api/scan/config")
    res = httpx.post(f"{BASE_URL}/api/scan/config", json={"path": config_dir}, timeout=30.0)
    print(f"Status: {res.status_code}")
    scan_config = res.json()
    print(f"Findings: {len(scan_config['findings'])}")
    
    print("\n4. /api/scan/live")
    res = httpx.post(f"{BASE_URL}/api/scan/live", json={"hostname": "example.com"}, timeout=30.0)
    print(f"Status: {res.status_code}")
    scan_live = res.json()
    print(f"Findings: {len(scan_live['findings'])}")
    
    scan_id = scan_code['scan_id']
    
    print(f"\n5. /api/scans/{scan_id} (GET)")
    res = httpx.get(f"{BASE_URL}/api/scans/{scan_id}", timeout=30.0)
    print(f"Status: {res.status_code}")
    assert res.json()['scan_id'] == scan_id
    
    print(f"\n6. /api/scans/{scan_id}/cbom.json")
    res = httpx.get(f"{BASE_URL}/api/scans/{scan_id}/cbom.json", timeout=30.0)
    print(f"Status: {res.status_code}")
    print(f"Content Type: {res.headers.get('content-type')}")
    
    print(f"\n7. /api/scans/{scan_id}/report.pdf")
    res = httpx.get(f"{BASE_URL}/api/scans/{scan_id}/report.pdf", timeout=30.0)
    print(f"Status: {res.status_code}")
    print(f"Content Type: {res.headers.get('content-type')}")
    
    print("\n8. /api/benchmark")
    res = httpx.get(f"{BASE_URL}/api/benchmark", timeout=30.0)
    print(f"Status: {res.status_code}")
    print(f"Benchmark results: {len(res.json())}")

    print("\nAll endpoints tested successfully!")

if __name__ == "__main__":
    test_endpoints()
