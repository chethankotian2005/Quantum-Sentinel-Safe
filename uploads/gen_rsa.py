from cryptography.hazmat.primitives.asymmetric import rsa
import oqs  # hybrid PQC key encapsulation

priv = oqs.KeyEncapsulation('Kyber768')  # hybrid PQC (was RSA); pair with X25519 during transition
