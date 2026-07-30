from models.schemas import Finding, RiskLevel, ContextType, UsageType

# Weights as defined in DRD 7.2 (FR-5, NFR-4) for explainability to judges
WEIGHT_ALGORITHM = 0.40
WEIGHT_KEY_SIZE = 0.25
WEIGHT_CONTEXT = 0.20
WEIGHT_USAGE = 0.15

# Sub-scores for Algorithm Type (out of 100)
# ECC requires fewer logical qubits to break via Shor's Algorithm compared to RSA
SCORE_ALGORITHM_ECC = 100
SCORE_ALGORITHM_RSA = 90
SCORE_ALGORITHM_DH = 90
SCORE_ALGORITHM_DSA = 90
SCORE_ALGORITHM_DEFAULT = 50

# Sub-scores for Key Size (out of 100)
# Smaller keys are more vulnerable both classically and quantumly.
SCORE_KEY_SMALL = 100  # e.g., RSA < 2048, ECC < 256
SCORE_KEY_MEDIUM = 80  # e.g., RSA 2048-3072, ECC 256-384
SCORE_KEY_LARGE = 20   # e.g., RSA >= 4096, ECC >= 521
SCORE_KEY_UNKNOWN = 80 # Default if key size is not extractable (e.g., config files)

# Sub-scores for Context (out of 100)
# Production exposed assets are highest risk.
SCORE_CONTEXT_PROD_CERT = 100
SCORE_CONTEXT_CONFIG = 80
SCORE_CONTEXT_CODE = 60
SCORE_CONTEXT_TEST = 0

# Sub-scores for Usage Type (out of 100)
# KEX is highly vulnerable due to "Harvest Now, Decrypt Later"
# Digital signatures are less critical for past data, though still an issue when QC arrives.
SCORE_USAGE_KEX = 100
SCORE_USAGE_SIGNING = 50
SCORE_USAGE_MISC = 10

# Thresholds for final Risk Level
THRESHOLD_CRITICAL = 80
THRESHOLD_HIGH = 60
THRESHOLD_MEDIUM = 40

def _score_algorithm(alg: str) -> float:
    alg = alg.upper()
    if alg in ["ECC", "ECDH", "ECDSA"]:
        return SCORE_ALGORITHM_ECC
    if alg == "RSA":
        return SCORE_ALGORITHM_RSA
    if alg == "DH":
        return SCORE_ALGORITHM_DH
    if alg == "DSA":
        return SCORE_ALGORITHM_DSA
    if alg == "TLS_VERIFY_ERROR":
        return 100
    return SCORE_ALGORITHM_DEFAULT

def _score_key_size(alg: str, size: int | None) -> float:
    if size is None:
        return SCORE_KEY_UNKNOWN
    
    alg = alg.upper()
    if alg in ["ECC", "ECDH", "ECDSA"]:
        # Interpolate linearly from 192 (100) to 521 (10)
        score = 100 - ((size - 192) / (521 - 192)) * 90
        return max(10.0, min(100.0, score))
    else:
        # RSA/DH/DSA
        # Interpolate linearly from 1024 (100) to 4096 (10)
        score = 100 - ((size - 1024) / (4096 - 1024)) * 90
        return max(10.0, min(100.0, score))

def _score_context(ctx: ContextType) -> float:
    if ctx == ContextType.production_cert: return SCORE_CONTEXT_PROD_CERT
    if ctx == ContextType.config: return SCORE_CONTEXT_CONFIG
    if ctx == ContextType.code: return SCORE_CONTEXT_CODE
    if ctx == ContextType.test_file: return SCORE_CONTEXT_TEST
    return 0

def _score_usage(usage: UsageType) -> float:
    if usage == UsageType.key_exchange: return SCORE_USAGE_KEX
    if usage == UsageType.signing: return SCORE_USAGE_SIGNING
    return SCORE_USAGE_MISC

def classify(finding: Finding) -> RiskLevel:
    """
    Pure function that calculates a weighted risk score and assigns a RiskLevel.
    This modifies the finding object's risk_score in place and also returns it.
    """
    s_alg = _score_algorithm(finding.algorithm)
    s_key = _score_key_size(finding.algorithm, finding.key_size)
    s_ctx = _score_context(finding.context)
    s_use = _score_usage(finding.usage_type)

    total_score = (
        (s_alg * WEIGHT_ALGORITHM) +
        (s_key * WEIGHT_KEY_SIZE) +
        (s_ctx * WEIGHT_CONTEXT) +
        (s_use * WEIGHT_USAGE)
    )

    if total_score >= THRESHOLD_CRITICAL:
        level = RiskLevel.Critical
    elif total_score >= THRESHOLD_HIGH:
        level = RiskLevel.High
    elif total_score >= THRESHOLD_MEDIUM:
        level = RiskLevel.Medium
    else:
        level = RiskLevel.Low

    finding.risk_score = level
    finding.vulnerability_score = total_score
    return level
