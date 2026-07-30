from cryptography.hazmat.primitives.asymmetric import dh

params = dh.generate_parameters(generator=2, key_size=2048)
