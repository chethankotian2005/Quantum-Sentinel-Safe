import sys
import os
import argparse
import json
from typing import List, Dict, Any

# Ensure backend directory is in the python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.schemas import RiskLevel, Finding
from detection import code_scanner, config_scanner, sbom_scanner
from classification.risk_classifier import classify
from remediation.patch_generator import generate_patch
# NOTE: remediation.auto_fix is imported lazily inside the --auto-fix branch.
# It pulls in httpx (a network client the core scan does not need), and a
# top-level import made the CLI unusable in minimal CI environments.

# Exit-code contract (see main() for usage)
EXIT_OK = 0
EXIT_ERROR = 1                      # scanner failed to run
EXIT_FINDINGS_OVER_THRESHOLD = 2    # scan succeeded, findings met --fail-on


def serialize_finding(finding: Finding) -> Dict[str, Any]:
    return {
        "finding_id": finding.finding_id,
        "source_type": finding.source_type.value,
        "file": finding.file,
        "line": finding.line,
        "algorithm": finding.algorithm,
        "key_size": finding.key_size,
        "context": finding.context.value,
        "usage_type": finding.usage_type.value,
        "risk_score": finding.risk_score.value,
        "patch_diff": finding.patch_diff
    }

def main():
    parser = argparse.ArgumentParser(description="QuantumSafe Sentinel Static Scanner CLI")
    parser.add_argument("target_dir", help="Directory to scan for cryptographic vulnerabilities")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    parser.add_argument("--fail-on", choices=["Critical", "High", "Medium", "Low"], default="High", help="Minimum risk level to cause a non-zero exit code")
    parser.add_argument("--auto-fix", action="store_true", help="Automatically generate hybrid PQC replacements and open GitHub PRs")
    
    args = parser.parse_args()

    target_dir = os.path.abspath(args.target_dir)
    if not os.path.isdir(target_dir):
        print(f"Error: Directory '{target_dir}' does not exist.", file=sys.stderr)
        sys.exit(EXIT_ERROR)

    findings: List[Finding] = []
    
    # Run Scanners
    findings.extend(code_scanner.scan_directory(target_dir))
    findings.extend(config_scanner.scan_directory(target_dir))
    findings.extend(sbom_scanner.scan_directory(target_dir))

    for f in findings:
        # Run the same weighted classifier the dashboard uses. Without this the
        # CLI reported each scanner's raw placeholder severity, so a CI gate
        # could pass/fail differently than the dashboard showed for the same code.
        classify(f)
        f.patch_diff = generate_patch(f)

    # Determine exit code based on risk level
    risk_level_values = {
        "Critical": 4,
        "High": 3,
        "Medium": 2,
        "Low": 1
    }
    
    threshold_value = risk_level_values[args.fail_on]
    max_found_value = 0
    
    for finding in findings:
        val = risk_level_values.get(finding.risk_score.value, 0)
        if val > max_found_value:
            max_found_value = val

    if args.format == "json":
        output = {
            "target": target_dir,
            "total_findings": len(findings),
            "findings": [serialize_finding(f) for f in findings]
        }
        print(json.dumps(output, indent=2))
    else:
        # Text summary
        print(f"QuantumSafe Sentinel Scan Results for: {target_dir}")
        print(f"Total findings: {len(findings)}\n")
        
        if not findings:
            print("No quantum-vulnerable cryptography detected.")
        else:
            for f in findings:
                print(f"[{f.risk_score.value}] {f.algorithm} found in {f.file}:{f.line} (Usage: {f.usage_type.value})")
                if args.auto_fix and f.patch_diff:
                    print(f"  -> Triggering Auto-Fix for {f.finding_id}...")
                    try:
                        from remediation.auto_fix import create_github_pr
                    except ImportError as e:
                        print(f"  -> Auto-Fix unavailable ({e}). Install 'httpx' to enable PR creation.", file=sys.stderr)
                        continue
                    result = create_github_pr(f, dry_run=False) # dry_run falls back automatically if no token
                    if result.get("dry_run"):
                        print(f"  -> [DRY RUN] Would create PR. Title: {result.get('pr_title')}")
                        print(f"  -> Diff:\n{result.get('diff')}")
                    elif result.get("url"):
                        print(f"  -> Successfully opened PR: {result.get('url')}")
                    else:
                        print(f"  -> Failed to open PR: {result.get('error')}")

    # Exit codes are distinct so callers can tell "we found vulnerabilities"
    # (2) apart from "the scanner itself failed to run" (1). Both are non-zero,
    # so any CI that simply gates on success still behaves the same.
    if max_found_value >= threshold_value:
        sys.exit(EXIT_FINDINGS_OVER_THRESHOLD)
    else:
        sys.exit(EXIT_OK)

if __name__ == "__main__":
    main()
