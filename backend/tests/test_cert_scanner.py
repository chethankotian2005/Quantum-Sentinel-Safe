import os
from detection.cert_scanner import scan_certificate
from models.schemas import Finding, SourceType, UsageType

def test_scan_rsa_2048_sign():
    cert_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../sample-data/certs/rsa_2048_sign.pem"))
    with open(cert_path, "rb") as f:
        cert_bytes = f.read()
    
    finding = scan_certificate(cert_path, cert_bytes)
    assert finding.source_type == SourceType.certificate
    assert finding.algorithm == "RSA"
    assert finding.key_size == 2048
    assert finding.usage_type == UsageType.signing

def test_scan_ecc_p256_kex():
    cert_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../sample-data/certs/ecc_p256_kex.pem"))
    with open(cert_path, "rb") as f:
        cert_bytes = f.read()
    
    finding = scan_certificate(cert_path, cert_bytes)
    assert finding.algorithm == "ECC"
    assert finding.key_size == 256
    assert finding.usage_type == UsageType.key_exchange

def test_scan_rsa_4096_misc():
    cert_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../sample-data/certs/rsa_4096_misc.pem"))
    with open(cert_path, "rb") as f:
        cert_bytes = f.read()

    finding = scan_certificate(cert_path, cert_bytes)
    assert finding.algorithm == "RSA"
    assert finding.key_size == 4096
    # This cert sets BOTH digital_signature and key_encipherment. cert_scanner
    # deliberately resolves that ambiguity in favour of signing, because
    # signature-based authentication is the primary role of an RSA cert in
    # modern TLS. (The test previously asserted the opposite precedence.)
    assert finding.usage_type == UsageType.signing


def test_certificate_expiry_metadata():
    """Validity dates are surfaced as their own metadata, not folded into risk."""
    cert_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../sample-data/certs/rsa_2048_sign.pem"))
    with open(cert_path, "rb") as f:
        cert_bytes = f.read()

    finding = scan_certificate(cert_path, cert_bytes)
    assert finding.not_valid_before is not None
    assert finding.not_valid_after is not None
    assert isinstance(finding.is_expired, bool)


def test_malformed_certificate_raises_value_error():
    """Unparseable input must raise, so the API can report it as skipped."""
    import pytest
    with pytest.raises(ValueError):
        scan_certificate("garbage.pem", b"this is definitely not a certificate")
