from cryptography.hazmat.primitives.asymmetric import dsa

priv = dsa.generate_private_key(key_size=2048)
