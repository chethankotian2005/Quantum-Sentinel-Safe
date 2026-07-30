import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from main import scan_codebase
from export.pdf_report import generate_pdf_report
from fastapi import UploadFile
import tempfile
import zipfile

def run_actual_scan_and_export():
    backend_dir = os.path.dirname(__file__)
    
    # We can scan a zip file of the sample data
    sample_zip = os.path.join(backend_dir, "../sample-data/certbot.zip")
    
    if not os.path.exists(sample_zip):
        print("Sample zip not found")
        return
        
    print(f"Scanning {sample_zip}...")
    
    with open(sample_zip, "rb") as f:
        file_content = f.read()
        
    # We need to mock a fastapi UploadFile
    class MockUploadFile:
        def __init__(self, filename, content):
            self.filename = filename
            self.content = content
        async def read(self):
            return self.content
            
    upload_file = MockUploadFile("certbot.zip", file_content)
    
    # Need to run async function
    import asyncio
    scan_result = asyncio.run(scan_codebase(
        files=[upload_file],
        data_sensitivity_years=10,
        z_years_until_quantum=7.0,
        apply_mosca_weight=True
    ))
    
    print(f"Scan complete. Found {len(scan_result.findings)} findings.")
    
    pdf_path = os.path.join(backend_dir, "report_real_scan.pdf")
    generate_pdf_report(scan_result, pdf_path)
    
    if os.path.exists(pdf_path):
        print(f"Generated PDF at {pdf_path}")
    else:
        print("Failed to generate PDF")

if __name__ == "__main__":
    run_actual_scan_and_export()
