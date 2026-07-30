from cryptography.hazmat.primitives.asymmetric import rsa, dh
from cryptography.hazmat.backends import default_backend

def create_rsa_key():
    # A vulnerable RSA keygen
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key

def create_dh_params():
    # A vulnerable DH keygen
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    return parameters
