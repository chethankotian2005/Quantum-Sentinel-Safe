"""
PQC Recommender — mapping table + hybrid flag.
DRD Section 7.3 / FR-6

Lookup table keyed by (classical_algorithm, usage_type) → recommendation.
hybrid_recommended = True when usage_type == "key_exchange"
or context is production_cert.
"""
