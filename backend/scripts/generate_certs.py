import datetime
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from cryptography import x509

def generate_cert(private_key, filename, common_name, key_usage):
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        # Valid for 10 days
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=10)
    ).add_extension(
        key_usage, critical=True
    ).sign(private_key, hashes.SHA256())
    
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"Generated {filename}")

if __name__ == "__main__":
    out_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../sample-data/certs"))
    
    # 1. RSA 2048 (Signing)
    rsa_key_2048 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    generate_cert(
        rsa_key_2048, 
        os.path.join(out_dir, "rsa_2048_sign.pem"), 
        "RSA 2048 Test",
        x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False)
    )

    # 2. ECDSA P-256 (Key Exchange / Agreement)
    ecc_key = ec.generate_private_key(ec.SECP256R1())
    generate_cert(
        ecc_key, 
        os.path.join(out_dir, "ecc_p256_kex.pem"), 
        "ECC P256 Test",
        x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=True, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False)
    )

    # 3. RSA 4096 (Misc / Both)
    rsa_key_4096 = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    generate_cert(
        rsa_key_4096, 
        os.path.join(out_dir, "rsa_4096_misc.pem"), 
        "RSA 4096 Test",
        x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=True, data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False)
    )
