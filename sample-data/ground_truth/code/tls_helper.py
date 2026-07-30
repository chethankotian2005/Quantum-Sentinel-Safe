from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

def create_tls_session_key():
    # Vulnerable ECDH key exchange parameter generation
    private_key = ec.generate_private_key(
        ec.SECP256R1(),
        default_backend()
    )
    return private_key
