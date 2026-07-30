import pytest
import os
import tempfile
from detection.code_scanner import scan_python_file

def test_ast_import_aliasing_resolution():
    code_content = """
from cryptography.hazmat.primitives.asymmetric import rsa as my_aliased_rsa

# The naive keyword scanner would miss this entirely because it looks for 'rsa.generate_private_key'
my_aliased_rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code_content)
        temp_file = f.name
        
    try:
        findings = scan_python_file(temp_file)
        assert len(findings) == 1
        assert findings[0].algorithm == "RSA"
        assert findings[0].key_size == 2048
    finally:
        os.remove(temp_file)

def test_ast_import_star_fallback():
    # Since we can't definitively track star imports, it should fallback to matching the suffix 'rsa.generate_private_key'
    code_content = """
from cryptography.hazmat.primitives.asymmetric import *

# Should fallback to suffix matching
rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096,
)
"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code_content)
        temp_file = f.name
        
    try:
        findings = scan_python_file(temp_file)
        assert len(findings) == 1
        assert findings[0].algorithm == "RSA"
        assert findings[0].key_size == 4096
    finally:
        os.remove(temp_file)

def test_ast_fully_qualified_call():
    code_content = """
import cryptography.hazmat.primitives.asymmetric.ec

cryptography.hazmat.primitives.asymmetric.ec.generate_private_key(
    cryptography.hazmat.primitives.asymmetric.ec.SECP384R1()
)
"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code_content)
        temp_file = f.name
        
    try:
        findings = scan_python_file(temp_file)
        assert len(findings) == 1
        assert findings[0].algorithm == "ECC"
        assert findings[0].key_size == 384
    finally:
        os.remove(temp_file)
