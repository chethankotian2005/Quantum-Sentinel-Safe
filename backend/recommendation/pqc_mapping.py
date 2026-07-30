from models.schemas import UsageType

# Mapping tuple format: (PQC Replacement Name, liboqs_id, Default Hybrid Scheme)
# Keyed by (Classical Algorithm, UsageType)
PQC_MAPPING = {
    # Key Exchange / Encapsulation Mappings (Threat: Harvest Now, Decrypt Later)
    ("RSA", UsageType.key_exchange): ("ML-KEM (Kyber)", "Kyber768", "X25519+Kyber768"),
    ("ECC", UsageType.key_exchange): ("ML-KEM (Kyber)", "Kyber768", "X25519+Kyber768"),
    ("ECDH", UsageType.key_exchange): ("ML-KEM (Kyber)", "Kyber768", "X25519+Kyber768"),
    ("DH", UsageType.key_exchange): ("ML-KEM (Kyber)", "Kyber768", "X25519+Kyber768"),
    
    # Signature Mappings (Threat: Authenticity breaks upon Quantum arrival)
    ("RSA", UsageType.signing): ("ML-DSA (Dilithium)", "ML-DSA-65", "RSA3072+ML-DSA-65"),
    ("ECC", UsageType.signing): ("ML-DSA (Dilithium)", "ML-DSA-65", "ECDSA256+ML-DSA-65"),
    ("ECDSA", UsageType.signing): ("ML-DSA (Dilithium)", "ML-DSA-65", "ECDSA256+ML-DSA-65"),
    ("DSA", UsageType.signing): ("ML-DSA (Dilithium)", "ML-DSA-65", "ECDSA256+ML-DSA-65"),
    
    # Misc Usage Fallbacks (Ambiguous Cases)
    ("RSA", UsageType.misc): ("ML-KEM or ML-DSA (Usage Unclear - Verify)", "Kyber768/ML-DSA-65", "X25519+Kyber768 or RSA3072+ML-DSA-65"),
    ("ECC", UsageType.misc): ("ML-KEM or ML-DSA (Usage Unclear - Verify)", "Kyber768/ML-DSA-65", "X25519+Kyber768 or ECDSA256+ML-DSA-65"),
    ("DH", UsageType.misc): ("ML-KEM (Kyber)", "Kyber768", "X25519+Kyber768"), # DH is exclusively key exchange
    ("DSA", UsageType.misc): ("ML-DSA (Dilithium)", "ML-DSA-65", "ECDSA256+ML-DSA-65"), # DSA is exclusively signing
    ("ECDH", UsageType.misc): ("ML-KEM (Kyber)", "Kyber768", "X25519+Kyber768"), # ECDH is exclusively key exchange
    ("ECDSA", UsageType.misc): ("ML-DSA (Dilithium)", "ML-DSA-65", "ECDSA256+ML-DSA-65"), # ECDSA is exclusively signing
    
    # Live Scan TLS Verification Error
    ("TLS_VERIFY_ERROR", UsageType.misc): ("Fix TLS Configuration", "N/A", "Install valid/trusted certificate"),
}

DEFAULT_MAPPING = ("ML-KEM or ML-DSA (Usage Unclear - Verify)", "Kyber768/ML-DSA-65", "X25519+Kyber768 or RSA3072+ML-DSA-65")
