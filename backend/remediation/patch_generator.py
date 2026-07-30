import os
import re
import difflib
from models.schemas import Finding

# ── Remediation patterns ──────────────────────────────────────────────
# Each entry matches a vulnerable call with a regex (tolerant of whitespace,
# argument order, and formatting) and rewrites it to a hybrid PQC equivalent.
#
# These were previously exact literal-string matches against three specific
# snippets, which meant realistic code — a different crypto library, different
# indentation, or any algorithm other than RSA — silently produced no fix at
# all. Regexes keep the same deterministic, reviewable output while actually
# matching code as written in the wild.

PY_HYBRID_KEM_IMPORT = "import oqs  # hybrid PQC key encapsulation"
PY_HYBRID_SIG_IMPORT = "import oqs  # hybrid PQC digital signatures"


def _indent_of(text: str) -> str:
    """Leading whitespace of the line containing the match start."""
    line_start = text.rfind("\n") + 1
    line = text[line_start:]
    return line[: len(line) - len(line.lstrip())]


PATTERNS = [
    # ── Python: `cryptography` library ────────────────────────────────
    {
        "name": "py_cryptography_rsa",
        "languages": (".py",),
        "algorithms": ("RSA",),
        "regex": re.compile(
            r"rsa\.generate_private_key\s*\((?:[^()]|\([^()]*\))*\)",
            re.MULTILINE,
        ),
        "replacement": (
            "oqs.KeyEncapsulation('Kyber768')  # hybrid PQC (was RSA); "
            "pair with X25519 during transition"
        ),
        "import_hint": PY_HYBRID_KEM_IMPORT,
    },
    {
        "name": "py_cryptography_ec",
        "languages": (".py",),
        "algorithms": ("ECC", "ECDH", "ECDSA"),
        "regex": re.compile(
            r"ec\.generate_private_key\s*\((?:[^()]|\([^()]*\))*\)",
            re.MULTILINE,
        ),
        "replacement": (
            "oqs.KeyEncapsulation('Kyber768')  # hybrid PQC (was ECC); "
            "pair with X25519 during transition"
        ),
        "import_hint": PY_HYBRID_KEM_IMPORT,
    },
    {
        "name": "py_cryptography_dsa",
        "languages": (".py",),
        "algorithms": ("DSA",),
        "regex": re.compile(
            r"dsa\.generate_private_key\s*\((?:[^()]|\([^()]*\))*\)",
            re.MULTILINE,
        ),
        "replacement": (
            "oqs.Signature('ML-DSA-65')  # hybrid PQC signature (was DSA)"
        ),
        "import_hint": PY_HYBRID_SIG_IMPORT,
    },
    {
        "name": "py_cryptography_dh",
        "languages": (".py",),
        "algorithms": ("DH",),
        "regex": re.compile(
            r"dh\.generate_parameters\s*\((?:[^()]|\([^()]*\))*\)",
            re.MULTILINE,
        ),
        "replacement": (
            "oqs.KeyEncapsulation('Kyber768')  # hybrid PQC KEM (was Diffie-Hellman)"
        ),
        "import_hint": PY_HYBRID_KEM_IMPORT,
    },
    # ── Python: PyCryptodome ──────────────────────────────────────────
    {
        "name": "py_pycryptodome_rsa",
        "languages": (".py",),
        "algorithms": ("RSA",),
        "regex": re.compile(r"RSA\.generate\s*\((?:[^()]|\([^()]*\))*\)", re.MULTILINE),
        "replacement": (
            "oqs.KeyEncapsulation('Kyber768')  # hybrid PQC (was RSA); "
            "pair with X25519 during transition"
        ),
        "import_hint": PY_HYBRID_KEM_IMPORT,
    },
    {
        "name": "py_pycryptodome_ecc",
        "languages": (".py",),
        "algorithms": ("ECC", "ECDH", "ECDSA"),
        "regex": re.compile(r"ECC\.generate\s*\((?:[^()]|\([^()]*\))*\)", re.MULTILINE),
        "replacement": (
            "oqs.KeyEncapsulation('Kyber768')  # hybrid PQC (was ECC); "
            "pair with X25519 during transition"
        ),
        "import_hint": PY_HYBRID_KEM_IMPORT,
    },
    # ── Node.js ───────────────────────────────────────────────────────
    {
        "name": "node_rsa",
        "languages": (".js", ".ts"),
        "algorithms": ("RSA",),
        "regex": re.compile(
            r"crypto\.generateKeyPair(?:Sync)?\s*\(\s*['\"]rsa['\"](?:[^()]|\([^()]*\)|\{[^{}]*\})*\)",
            re.MULTILINE,
        ),
        "replacement": (
            "new oqs.KeyEncapsulation('Kyber768') /* hybrid PQC (was RSA) */"
        ),
        "import_hint": "const oqs = require('liboqs-node'); // hybrid PQC",
    },
    {
        "name": "node_ec",
        "languages": (".js", ".ts"),
        "algorithms": ("ECC", "ECDH", "ECDSA"),
        "regex": re.compile(
            r"crypto\.generateKeyPair(?:Sync)?\s*\(\s*['\"]ec['\"](?:[^()]|\([^()]*\)|\{[^{}]*\})*\)",
            re.MULTILINE,
        ),
        "replacement": (
            "new oqs.KeyEncapsulation('Kyber768') /* hybrid PQC (was ECC) */"
        ),
        "import_hint": "const oqs = require('liboqs-node'); // hybrid PQC",
    },
    {
        "name": "node_dh",
        "languages": (".js", ".ts"),
        "algorithms": ("DH",),
        "regex": re.compile(
            r"crypto\.createDiffieHellman\s*\((?:[^()]|\([^()]*\))*\)", re.MULTILINE
        ),
        "replacement": (
            "new oqs.KeyEncapsulation('Kyber768') /* hybrid PQC KEM (was DH) */"
        ),
        "import_hint": "const oqs = require('liboqs-node'); // hybrid PQC",
    },
    # ── Server configuration ──────────────────────────────────────────
    {
        "name": "tls_ciphers",
        "languages": (".conf", ".cfg", ".config", ""),
        "algorithms": ("RSA", "ECC", "ECDH", "DH", "ECDSA"),
        "regex": re.compile(r"^(\s*ssl_ciphers\s+)(.+);", re.MULTILINE),
        "replacement": r"\1X25519_KYBER768:\2;",
        "import_hint": None,
    },
    {
        "name": "ssh_kex",
        "languages": (".conf", ".cfg", ".config", ""),
        "algorithms": ("DH", "ECDH", "ECC"),
        "regex": re.compile(r"^(\s*KexAlgorithms\s+)(.+)$", re.MULTILINE),
        "replacement": r"\1sntrup761x25519-sha512@openssh.com,\2",
        "import_hint": None,
    },
]


def _applicable_patterns(finding: Finding):
    """Patterns whose language and algorithm both match this finding."""
    if not finding.file:
        return []
    ext = os.path.splitext(finding.file)[1].lower()
    algo = (finding.algorithm or "").upper()

    matches = []
    for pattern in PATTERNS:
        if ext not in pattern["languages"]:
            continue
        if algo not in pattern["algorithms"]:
            continue
        matches.append(pattern)
    return matches


def generate_new_content(finding: Finding) -> tuple[str, str] | None:
    """
    Returns (original_content, new_content) if the finding matches a known
    pattern, else None.
    """
    if not finding.file or not os.path.exists(finding.file):
        return None

    try:
        with open(finding.file, "r", encoding="utf-8") as f:
            content = f.read()
    except OSError:
        return None

    new_content = content
    needed_imports = []

    for pattern in _applicable_patterns(finding):
        if not pattern["regex"].search(new_content):
            continue
        new_content = pattern["regex"].sub(pattern["replacement"], new_content)
        if pattern["import_hint"] and pattern["import_hint"] not in new_content:
            needed_imports.append(pattern["import_hint"])

    if new_content == content:
        return None

    # Prepend any required imports after the existing import block so the
    # patch is directly applicable rather than merely illustrative.
    for hint in dict.fromkeys(needed_imports):
        new_content = _insert_import(new_content, hint)

    return (content, new_content)


def _insert_import(content: str, import_line: str) -> str:
    """Inserts an import after the last existing top-level import."""
    lines = content.splitlines(keepends=True)
    last_import = -1
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith(("import ", "from ")) or stripped.startswith("const ") and "require(" in stripped:
            last_import = idx
    insert_at = last_import + 1 if last_import >= 0 else 0
    lines.insert(insert_at, import_line + "\n")
    return "".join(lines)


def generate_patch(finding: Finding) -> str | None:
    """
    Generates a unified diff patch string if the finding matches a known pattern.
    """
    result = generate_new_content(finding)
    if not result:
        return None

    content, new_content = result
    a = content.splitlines(keepends=True)
    b = new_content.splitlines(keepends=True)

    diff = difflib.unified_diff(
        a, b,
        fromfile=os.path.basename(finding.file),
        tofile=os.path.basename(finding.file),
        n=3
    )
    diff_str = "".join(diff)
    return diff_str or None


def apply_patch(finding: Finding) -> bool:
    """
    Applies the patch directly to the file on disk.
    Returns True if successful, False otherwise.
    """
    result = generate_new_content(finding)
    if not result:
        return False

    _, new_content = result
    try:
        with open(finding.file, "w", encoding="utf-8") as f:
            f.write(new_content)
        return True
    except OSError:
        return False
