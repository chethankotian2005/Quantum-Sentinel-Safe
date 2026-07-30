import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from models.schemas import Finding, SourceType, ContextType, UsageType, RiskLevel
from classification.compliance_mapper import map_compliance
from classification.executive_synthesizer import synthesize_narrative
from models.schemas import ScanResult

def main():
    finding1 = Finding(
        finding_id="f_test",
        source_type=SourceType.certificate,
        file="cert.pem",
        line=1,
        algorithm="RSA",
        key_size=2048,
        context=ContextType.production_cert,
        usage_type=UsageType.signing,
        risk_score=RiskLevel.High
    )
    
    # Reload mapper to pick up updated json
    import classification.compliance_mapper
    classification.compliance_mapper._mapper._load_frameworks()
    
    flags = classification.compliance_mapper.map_compliance(finding1)
    
    print("Mapped Compliance Frameworks for finding1 (RSA, production_cert):")
    for flag in flags:
        print(f" - {flag.framework_name}: {flag.summary} (Deadline: {flag.deadline})")
        
    print("\nCheck executive synthesis text:")
    # Inject it into a scan
    scan = ScanResult(
        scan_id="test",
        target_id="test_cert",
        findings=[finding1],
        recommendations=[],
        benchmarks=[],
        impact=None,
        risk_score=None
    )
    # Generate findings flags
    for f in scan.findings:
        f.compliance_flags = classification.compliance_mapper.map_compliance(f)
        
    summary = synthesize_narrative(scan)
    print("Compliance Summary Line:", summary.compliance_summary_line)

if __name__ == "__main__":
    main()
