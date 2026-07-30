import os
import re
import uuid
from typing import List

from models.schemas import Finding, SourceType, ContextType, UsageType, RiskLevel

# We match the directive, then capture the rest of the line to inspect the cipher list
CONFIG_DIRECTIVES_REGEX = re.compile(
    r'^\s*(ssl_ciphers|KexAlgorithms|Ciphers|SSLCipherSuite|tls-cipher|ssl-default-bind-ciphers)\s+([^;#]+)',
    re.IGNORECASE
)

# Known vulnerable cryptographic keywords in cipher lists
VULNERABLE_KEYWORDS = {
    'RSA': {"algorithm": "RSA", "usage": UsageType.signing}, # In TLS it's usually auth/signing, but sometimes KEX
    'DHE': {"algorithm": "DH", "usage": UsageType.key_exchange},
    'DH': {"algorithm": "DH", "usage": UsageType.key_exchange},
    'ECDHE': {"algorithm": "ECDH", "usage": UsageType.key_exchange},
    'ECDH': {"algorithm": "ECDH", "usage": UsageType.key_exchange},
    'DIFFIE': {"algorithm": "DH", "usage": UsageType.key_exchange},
}

def scan_config_file(file_path: str) -> List[Finding]:
    findings = []
    
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line_no, line in enumerate(f, start=1):
            match = CONFIG_DIRECTIVES_REGEX.search(line)
            if match:
                directive = match.group(1).strip()
                ciphers = match.group(2).strip()
                
                # Check for any vulnerable keywords using regex word boundary or splitting
                # To avoid 'DH' matching inside 'ECDHE', we split by common delimiters
                tokens = set(re.split(r'[:\-_\s,]+', ciphers.upper()))
                
                for keyword, meta in VULNERABLE_KEYWORDS.items():
                    if keyword.upper() in tokens:
                        findings.append(Finding(
                            finding_id=f"f_{uuid.uuid4().hex[:8]}",
                            source_type=SourceType.config,
                            file=file_path,
                            line=line_no,
                            algorithm=meta["algorithm"],
                            key_size=None,
                            context=ContextType.config,
                            usage_type=meta["usage"],
                            risk_score=RiskLevel.High
                        ))
                        # We only need to flag each vulnerable line once per algorithm/usage, but multiple algorithms can exist.

    # Deduplicate findings if multiple keywords map to the same algorithm on the same line
    unique_findings = []
    seen = set()
    for f in findings:
        key = (f.file, f.line, f.algorithm)
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)
            
    return unique_findings

def scan_config_content(filename: str, content: str) -> List[Finding]:
    """Scan config content from an uploaded file (no disk I/O)."""
    findings = []
    for line_no, line in enumerate(content.splitlines(), start=1):
        match = CONFIG_DIRECTIVES_REGEX.search(line)
        if match:
            directive = match.group(1).strip()
            ciphers = match.group(2).strip()
            tokens = set(re.split(r'[:\-_\s,]+', ciphers.upper()))
            for keyword, meta in VULNERABLE_KEYWORDS.items():
                if keyword.upper() in tokens:
                    findings.append(Finding(
                        finding_id=f"f_{uuid.uuid4().hex[:8]}",
                        source_type=SourceType.config,
                        file=filename,
                        line=line_no,
                        algorithm=meta["algorithm"],
                        key_size=None,
                        context=ContextType.config,
                        usage_type=meta["usage"],
                        risk_score=RiskLevel.High
                    ))
    unique_findings = []
    seen = set()
    for f in findings:
        key = (f.file, f.line, f.algorithm)
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)
    return unique_findings

def scan_directory(directory_path: str) -> List[Finding]:
    findings = []
    for root, _, files in os.walk(directory_path):
        for file in files:
            full_path = os.path.join(root, file)
            findings.extend(scan_config_file(full_path))
    return findings
