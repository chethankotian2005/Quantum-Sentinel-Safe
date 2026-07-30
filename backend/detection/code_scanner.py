import ast
import bisect
import os
import re
import uuid
from typing import List

from models.schemas import Finding, SourceType, ContextType, UsageType, RiskLevel

# Configuration mapping specific method calls to algorithms and usages.
VULNERABLE_CALLS = {
    "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key": {"algorithm": "RSA", "usage_type": UsageType.misc},
    "Crypto.PublicKey.RSA.generate": {"algorithm": "RSA", "usage_type": UsageType.misc},
    "cryptography.hazmat.primitives.asymmetric.ec.generate_private_key": {"algorithm": "ECC", "usage_type": UsageType.key_exchange},
    "cryptography.hazmat.primitives.asymmetric.dsa.generate_private_key": {"algorithm": "DSA", "usage_type": UsageType.signing},
    "cryptography.hazmat.primitives.asymmetric.dh.generate_parameters": {"algorithm": "DH", "usage_type": UsageType.key_exchange}
}

ECC_CURVES = {
    "SECP256R1": 256,
    "prime256v1": 256,
    "SECP384R1": 384,
    "SECP521R1": 521,
    "SECP256K1": 256,
    "brainpoolP256R1": 256,
    "brainpoolP384R1": 384,
    "brainpoolP512R1": 512,
}

class CryptoASTVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.findings: List[Finding] = []
        self.findings_dict = {}
        self.tracked_keys = {}
        self.current_assignment_targets = []
        self.variable_values = {}
        self.import_aliases = {}

    def _resolve_int_value(self, node: ast.expr):
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return node.value
        elif isinstance(node, ast.Name) and node.id in self.variable_values:
            return self.variable_values[node.id]
        return None

    def _get_call_name(self, node: ast.Call) -> str:
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        elif isinstance(node.func, ast.Name):
            return node.func.id
        return ""

    def _get_full_call_name(self, node: ast.Call) -> str:
        # e.g., rsa.generate_private_key
        def get_name(n):
            if isinstance(n, ast.Attribute):
                return f"{get_name(n.value)}.{n.attr}"
            elif isinstance(n, ast.Name):
                return n.id
            return ""
        return get_name(node.func)

    def _resolve_canonical_path(self, full_name: str) -> str:
        if not full_name:
            return ""
        parts = full_name.split('.')
        base = parts[0]
        if base in self.import_aliases:
            parts[0] = self.import_aliases[base]
        return ".".join(parts)

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            name = alias.name
            asname = alias.asname if alias.asname else name
            self.import_aliases[asname] = name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        module = node.module if node.module else ""
        for alias in node.names:
            name = alias.name
            asname = alias.asname if alias.asname else name
            if module:
                self.import_aliases[asname] = f"{module}.{name}"
            else:
                self.import_aliases[asname] = name
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, int):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.variable_values[target.id] = node.value.value
                    
        old_targets = self.current_assignment_targets
        self.current_assignment_targets = []
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.current_assignment_targets.append(target.id)
        self.generic_visit(node)
        self.current_assignment_targets = old_targets

    def visit_Call(self, node: ast.Call):
        full_name = self._get_full_call_name(node)
        canonical_name = self._resolve_canonical_path(full_name)
        short_name = self._get_call_name(node)

        # Check if canonical_name matches any vulnerable pattern
        matched_pattern = None
        for pattern in VULNERABLE_CALLS:
            if canonical_name == pattern or pattern.endswith("." + canonical_name):
                matched_pattern = pattern
                break

        if matched_pattern:
            meta = VULNERABLE_CALLS[matched_pattern]
            key_size = None
            
            if meta["algorithm"] == "RSA":
                for kw in node.keywords:
                    if kw.arg == 'key_size':
                        key_size = self._resolve_int_value(kw.value)
                
                if key_size is None and node.args:
                    if len(node.args) == 1:
                        key_size = self._resolve_int_value(node.args[0])
                    elif len(node.args) >= 2:
                        if "rsa.generate_private_key" in canonical_name or "generate_private_key" in short_name:
                            key_size = self._resolve_int_value(node.args[1])
                        elif "RSA.generate" in canonical_name or "generate" in short_name:
                            key_size = self._resolve_int_value(node.args[0])
                        else:
                            key_size = self._resolve_int_value(node.args[0])

            elif meta["algorithm"] == "ECC":
                curve_node = None
                if node.args:
                    curve_node = node.args[0]
                else:
                    for kw in node.keywords:
                        if kw.arg == 'curve':
                            curve_node = kw.value
                            break
                
                if curve_node:
                    curve_name = ""
                    if isinstance(curve_node, ast.Call):
                        curve_name = self._get_call_name(curve_node)
                    elif isinstance(curve_node, ast.Attribute):
                        curve_name = curve_node.attr
                    elif isinstance(curve_node, ast.Name):
                        curve_name = curve_node.id
                        
                    if curve_name:
                        curve_name_lower = curve_name.lower()
                        for k, v in ECC_CURVES.items():
                            if k.lower() == curve_name_lower:
                                key_size = v
                                break

            risk_score = RiskLevel.High
            if meta["algorithm"] == "RSA" and key_size and key_size >= 4096:
                risk_score = RiskLevel.Medium
                
            finding = Finding(
                finding_id=f"f_{uuid.uuid4().hex[:8]}",
                source_type=SourceType.code,
                file=self.file_path,
                line=node.lineno,
                algorithm=meta["algorithm"],
                key_size=key_size,
                context=ContextType.code,
                usage_type=meta["usage_type"],
                risk_score=risk_score
            )
            self.findings.append(finding)
            self.findings_dict[finding.finding_id] = finding
            
            # Track variable assignment for later usage inference
            for target in self.current_assignment_targets:
                self.tracked_keys[target] = finding.finding_id
                
        else:
            # Not a key generation call, check if it's a method call on a tracked key variable
            if isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name):
                    var_name = node.func.value.id
                    if var_name in self.tracked_keys:
                        method_name = node.func.attr
                        finding_id = self.tracked_keys[var_name]
                        finding = self.findings_dict[finding_id]
                        
                        # Infer usage based on the method called
                        if method_name in ["sign", "sign_deterministic"]:
                            finding.usage_type = UsageType.signing
                        elif method_name in ["exchange", "decrypt"]:
                            finding.usage_type = UsageType.key_exchange

        self.generic_visit(node)

def scan_python_file(file_path: str) -> List[Finding]:
    with open(file_path, 'r', encoding='utf-8') as f:
        source = f.read()
    
    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError:
        return []
        
    visitor = CryptoASTVisitor(file_path)
    visitor.visit(tree)
    return visitor.findings

def _mask_js_source(source: str) -> tuple[str, list[bool]]:
    """
    Returns (comment_stripped_source, in_string_flags).

    Python gets a real AST; JS/TS has no parser available here, so detection is
    textual. Raw text matching produced false positives on crypto calls merely
    *mentioned* in a comment or quoted inside a string literal.

    Comments are blanked outright (nothing in them is ever code). String
    literals are kept verbatim — the algorithm name in
    generateKeyPairSync('rsa', ...) is itself a string and must stay matchable —
    but each character is flagged so a match that *begins* inside a string
    (i.e. the whole call is quoted prose) can be rejected. Line structure is
    preserved throughout so reported line numbers stay accurate.
    """
    out = []
    in_string = []
    i = 0
    n = len(source)
    state = None  # None | 'line_comment' | 'block_comment' | quote char

    def emit(char: str, is_string: bool):
        out.append(char)
        in_string.append(is_string)

    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ''

        if state is None:
            if ch == '/' and nxt == '/':
                state = 'line_comment'
                emit(' ', False)
                emit(' ', False)
                i += 2
                continue
            if ch == '/' and nxt == '*':
                state = 'block_comment'
                emit(' ', False)
                emit(' ', False)
                i += 2
                continue
            if ch in ('"', "'", '`'):
                state = ch
                emit(ch, False)  # the opening quote itself is still code
                i += 1
                continue
            emit(ch, False)
            i += 1
            continue

        if state == 'line_comment':
            if ch == '\n':
                state = None
                emit('\n', False)
            else:
                emit(' ', False)
            i += 1
            continue

        if state == 'block_comment':
            if ch == '*' and nxt == '/':
                state = None
                emit(' ', False)
                emit(' ', False)
                i += 2
            else:
                emit('\n' if ch == '\n' else ' ', False)
                i += 1
            continue

        # Inside a string literal: keep the text, but flag it.
        if ch == '\\':
            emit(' ', True)
            if i + 1 < n:
                emit(' ', True)
            i += 2
            continue
        if ch == state:
            state = None
            emit(ch, False)
            i += 1
            continue
        emit(ch, True)
        i += 1

    return ''.join(out), in_string


# (regex, algorithm, usage_type). Regexes tolerate whitespace/quote variation
# rather than requiring one exact literal spelling.
JS_PATTERNS = [
    (re.compile(r"generateKeyPairSync\s*\(\s*['\"]rsa['\"]"), "RSA", UsageType.misc),
    (re.compile(r"generateKeyPair\s*\(\s*['\"]rsa['\"]"), "RSA", UsageType.misc),
    (re.compile(r"generateKeyPairSync\s*\(\s*['\"]ec['\"]"), "ECC", UsageType.key_exchange),
    (re.compile(r"generateKeyPair\s*\(\s*['\"]ec['\"]"), "ECC", UsageType.key_exchange),
    (re.compile(r"generateKeyPairSync\s*\(\s*['\"]dsa['\"]"), "DSA", UsageType.signing),
    (re.compile(r"createDiffieHellman\s*\("), "DH", UsageType.key_exchange),
    (re.compile(r"crypto\.createCipheriv\s*\("), "RSA", UsageType.misc),
]

_JS_MODULUS_RE = re.compile(r"modulusLength\s*:\s*(\d+)")


def scan_js_file(file_path: str) -> List[Finding]:
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            source = f.read()
    except OSError:
        return []

    masked, in_string = _mask_js_source(source)
    raw_lines = source.split('\n')

    # Offset of each line's start within `masked`, to map matches back to lines.
    line_starts = [0]
    for idx, ch in enumerate(masked):
        if ch == '\n':
            line_starts.append(idx + 1)

    matched_lines = set()
    for pattern, algorithm, usage in JS_PATTERNS:
        for m in pattern.finditer(masked):
            start = m.start()
            # A call whose name begins inside a string literal is quoted prose,
            # not an actual invocation.
            if start < len(in_string) and in_string[start]:
                continue

            line_no = bisect.bisect_right(line_starts, start)
            if line_no in matched_lines:
                continue
            matched_lines.add(line_no)

            key_size = None
            if algorithm == "RSA":
                # modulusLength may sit on the same line or the next few
                window = ' '.join(raw_lines[line_no - 1:line_no + 3])
                mod = _JS_MODULUS_RE.search(window)
                key_size = int(mod.group(1)) if mod else 2048

            risk_score = RiskLevel.High
            if algorithm == "RSA" and key_size and key_size >= 4096:
                risk_score = RiskLevel.Medium

            findings.append(Finding(
                finding_id=f"f_{uuid.uuid4().hex[:8]}",
                source_type=SourceType.code,
                file=file_path,
                line=line_no,
                algorithm=algorithm,
                key_size=key_size,
                context=ContextType.code,
                usage_type=usage,
                risk_score=risk_score
            ))

    findings.sort(key=lambda f: f.line)
    return findings

def scan_directory(directory_path: str) -> List[Finding]:
    findings = []
    for root, _, files in os.walk(directory_path):
        for file in files:
            full_path = os.path.join(root, file)
            if file.endswith('.py'):
                findings.extend(scan_python_file(full_path))
            elif file.endswith('.js') or file.endswith('.ts'):
                findings.extend(scan_js_file(full_path))
    return findings
