import os
import uuid
import json
import re
import xml.etree.ElementTree as ET
from typing import List

from models.schemas import Finding, SourceType, ContextType, UsageType, RiskLevel

CRYPTO_LIBS = {
    # Python
    "pyopenssl": {"algorithm": "RSA/ECC", "risk": RiskLevel.High, "usage": UsageType.misc},
    "cryptography": {"algorithm": "RSA/ECC", "risk": RiskLevel.High, "usage": UsageType.misc},
    "paramiko": {"algorithm": "RSA/ECC", "risk": RiskLevel.High, "usage": UsageType.misc},
    # Node.js
    "crypto": {"algorithm": "RSA/ECC", "risk": RiskLevel.High, "usage": UsageType.misc},
    "node-forge": {"algorithm": "RSA/ECC", "risk": RiskLevel.High, "usage": UsageType.misc},
    # Java
    "bouncycastle": {"algorithm": "RSA/ECC", "risk": RiskLevel.High, "usage": UsageType.misc},
    "bcprov-jdk15on": {"algorithm": "RSA/ECC", "risk": RiskLevel.High, "usage": UsageType.misc},
    "org.bouncycastle": {"algorithm": "RSA/ECC", "risk": RiskLevel.High, "usage": UsageType.misc},
}

def create_finding(file_path: str, line: int, package_name: str, version: str) -> Finding:
    meta = CRYPTO_LIBS[package_name.lower()]
    return Finding(
        finding_id=f"f_{uuid.uuid4().hex[:8]}",
        source_type=SourceType.dependency,
        file=file_path,
        line=line,
        algorithm=meta["algorithm"],
        context=ContextType.dependency,
        usage_type=meta["usage"],
        risk_score=meta["risk"]
    )

def scan_requirements(file_path: str) -> List[Finding]:
    findings = []
    with open(file_path, 'r', encoding='utf-8') as f:
        for idx, line in enumerate(f, start=1):
            line_content = line.strip()
            if not line_content or line_content.startswith('#'):
                continue
            
            # Simple parsing of package==version
            parts = re.split(r'==|>=|<=|~=|>|<', line_content)
            if parts:
                package_name = parts[0].strip().lower()
                if package_name in CRYPTO_LIBS:
                    findings.append(create_finding(file_path, idx, package_name, line_content))
    return findings

def scan_package_json(file_path: str) -> List[Finding]:
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            data = json.loads(content)
            
            # In package.json we cannot easily map to line numbers for each dep without a custom JSON parser,
            # so we'll just report line 1 or search string
            for dep_type in ['dependencies', 'devDependencies']:
                if dep_type in data:
                    for pkg, ver in data[dep_type].items():
                        if pkg.lower() in CRYPTO_LIBS:
                            # Try to find line number
                            line_num = 1
                            lines = content.split('\n')
                            for idx, line in enumerate(lines, start=1):
                                if f'"{pkg}"' in line:
                                    line_num = idx
                                    break
                            findings.append(create_finding(file_path, line_num, pkg, ver))
    except Exception:
        pass
    return findings

def scan_go_mod(file_path: str) -> List[Finding]:
    findings = []
    with open(file_path, 'r', encoding='utf-8') as f:
        in_require_block = False
        for idx, line in enumerate(f, start=1):
            line_content = line.strip()
            if line_content.startswith('require ('):
                in_require_block = True
                continue
            if in_require_block and line_content == ')':
                in_require_block = False
                continue
                
            if in_require_block or line_content.startswith('require '):
                # parse the dependency
                parts = line_content.split()
                if len(parts) >= 2:
                    pkg_name = parts[1] if parts[0] == 'require' else parts[0]
                    # check if the package name or its last part matches our libraries
                    pkg_base = pkg_name.split('/')[-1].lower()
                    if pkg_base in CRYPTO_LIBS:
                        findings.append(create_finding(file_path, idx, pkg_base, line_content))
    return findings

def scan_pom_xml(file_path: str) -> List[Finding]:
    findings = []
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        # Namespace handling for pom.xml
        ns = {'m': 'http://maven.apache.org/POM/4.0.0'}
        
        # Determine if default namespace is used
        if root.tag.startswith('{'):
            deps = root.findall('.//m:dependency', ns)
        else:
            deps = root.findall('.//dependency')
            
        for dep in deps:
            artifact_id_elem = dep.find('m:artifactId', ns) if root.tag.startswith('{') else dep.find('artifactId')
            group_id_elem = dep.find('m:groupId', ns) if root.tag.startswith('{') else dep.find('groupId')
            version_elem = dep.find('m:version', ns) if root.tag.startswith('{') else dep.find('version')
            
            if artifact_id_elem is not None and artifact_id_elem.text:
                pkg_name = artifact_id_elem.text.lower()
                group_name = group_id_elem.text.lower() if group_id_elem is not None and group_id_elem.text else ""
                
                matched = None
                if pkg_name in CRYPTO_LIBS:
                    matched = pkg_name
                elif group_name in CRYPTO_LIBS:
                    matched = group_name
                    
                if matched:
                    # Line numbers are hard in ElementTree, default to 1
                    findings.append(create_finding(file_path, 1, matched, version_elem.text if version_elem is not None else "unknown"))
    except Exception:
        pass
    return findings

def scan_directory(directory_path: str) -> List[Finding]:
    findings = []
    for root, _, files in os.walk(directory_path):
        for file in files:
            full_path = os.path.join(root, file)
            if file == 'requirements.txt':
                findings.extend(scan_requirements(full_path))
            elif file == 'package.json':
                findings.extend(scan_package_json(full_path))
            elif file == 'go.mod':
                findings.extend(scan_go_mod(full_path))
            elif file == 'pom.xml':
                findings.extend(scan_pom_xml(full_path))
    return findings
