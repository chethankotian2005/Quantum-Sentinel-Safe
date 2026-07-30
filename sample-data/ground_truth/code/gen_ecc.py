from cryptography.hazmat.primitives.asymmetric import ec

priv = ec.generate_private_key(
    ec.SECP384R1()
)
