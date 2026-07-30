import uuid
from datetime import datetime, timezone
import cryptography.x509 as x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
from cryptography.x509.extensions import ExtensionNotFound
from cryptography.hazmat.backends import default_backend

from models.schemas import Finding, SourceType, ContextType, UsageType, RiskLevel

def scan_certificate(file_path: str, cert_bytes: bytes, context: ContextType = ContextType.production_cert) -> Finding:
    try:
        cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
    except ValueError:
        try:
            cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
        except ValueError:
            raise ValueError(f"Could not parse certificate {file_path}")

    public_key = cert.public_key()
    
    algorithm = "Unknown"
    key_size = getattr(public_key, "key_size", None)
    
    if isinstance(public_key, rsa.RSAPublicKey):
        algorithm = "RSA"
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        algorithm = "ECC"
    elif isinstance(public_key, dsa.DSAPublicKey):
        algorithm = "DSA"

    usage_type = UsageType.misc
    try:
        key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        # Prioritize signing usage over encipherment since RSA certs often have both,
        # but their primary usage in modern TLS is signature-based authentication.
        if getattr(key_usage, 'digital_signature', False) or getattr(key_usage, 'key_cert_sign', False) or getattr(key_usage, 'crl_sign', False):
            usage_type = UsageType.signing
        elif getattr(key_usage, 'key_agreement', False) or getattr(key_usage, 'key_encipherment', False):
            usage_type = UsageType.key_exchange
    except ExtensionNotFound:
        pass

    # A basic placeholder for risk. The classifier will replace this later based on weightings.
    risk_score = RiskLevel.High
    if algorithm == "RSA" and key_size and key_size >= 4096:
        risk_score = RiskLevel.Medium

    # Validity window — reported as separate metadata rather than folded into
    # the quantum risk. An expired cert is its own operational problem.
    not_valid_before = not_valid_after = None
    is_expired = None
    try:
        try:
            start = cert.not_valid_before_utc
            end = cert.not_valid_after_utc
        except AttributeError:  # cryptography < 42 fallback
            start = cert.not_valid_before.replace(tzinfo=timezone.utc)
            end = cert.not_valid_after.replace(tzinfo=timezone.utc)
        not_valid_before = start.isoformat()
        not_valid_after = end.isoformat()
        is_expired = datetime.now(timezone.utc) > end
    except Exception:
        pass
        
    try:
        cn_attr = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        subject_str = cn_attr[0].value if cn_attr else "Unknown"
    except Exception:
        subject_str = "Unknown"

    try:
        issuer_attr = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        issuer_str = issuer_attr[0].value if issuer_attr else "Unknown"
    except Exception:
        issuer_str = "Unknown"

    return Finding(
        finding_id=f"f_{uuid.uuid4().hex[:8]}",
        source_type=SourceType.certificate,
        file=file_path,
        subject=subject_str,
        issuer=issuer_str,
        algorithm=algorithm,
        key_size=key_size,
        context=context,
        usage_type=usage_type,
        risk_score=risk_score,
        not_valid_before=not_valid_before,
        not_valid_after=not_valid_after,
        is_expired=is_expired,
    )
