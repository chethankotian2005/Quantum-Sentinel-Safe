from enum import Enum
from typing import List, Optional
from pydantic import BaseModel

class SourceType(str, Enum):
    code = "code"
    certificate = "certificate"
    config = "config"
    live_scan = "live_scan"
    dependency = "dependency"

class ContextType(str, Enum):
    code = "code"
    production_cert = "production_cert"
    test_file = "test_file"
    config = "config"
    dependency = "dependency"

class UsageType(str, Enum):
    key_exchange = "key_exchange"
    signing = "signing"
    misc = "misc"

class RiskLevel(str, Enum):
    Critical = "Critical"
    High = "High"
    Medium = "Medium"
    Low = "Low"

class MoscaResult(BaseModel):
    x: float
    y: float
    z: float
    sum_xy: float
    margin_years: float
    verdict: str
    explanation: str
    z_threat_horizon_comment: Optional[str] = None

class ComplianceFlag(BaseModel):
    framework_name: str
    summary: str
    deadline: str
    source_link: str

class QuantumAttackCost(BaseModel):
    algorithm: str
    key_size_bits: int
    idealized_logical_qubits: int
    logical_qubit_source: str
    realistic_physical_qubits_estimate: int
    physical_qubit_source: str
    is_directly_cited: bool
    estimated_runtime_description: str
    comparison_to_current_hardware: str
    current_largest_qpc: int
    gap_factor: float

class Finding(BaseModel):
    finding_id: str
    source_type: SourceType
    file: Optional[str] = None
    line: Optional[int] = None
    hostname: Optional[str] = None
    subject: Optional[str] = None
    description: Optional[str] = None
    issuer: Optional[str] = None
    chain_position: Optional[str] = None
    is_actionable: bool = True
    algorithm: str
    key_size: Optional[int] = None
    context: ContextType
    usage_type: UsageType
    risk_score: RiskLevel
    data_sensitivity_years: Optional[float] = None
    mosca_result: Optional[MoscaResult] = None
    compliance_flags: Optional[List[ComplianceFlag]] = None
    quantum_attack_cost: Optional[QuantumAttackCost] = None
    migration_effort: Optional[int] = None
    patch_diff: Optional[str] = None
    vulnerability_score: float = 0.0
    # Certificate validity metadata (populated for certificate/live_scan findings).
    # Reported alongside the quantum finding, not folded into it — an expired
    # cert is a separate operational problem worth surfacing on its own.
    not_valid_before: Optional[str] = None
    not_valid_after: Optional[str] = None
    is_expired: Optional[bool] = None


class SkippedFile(BaseModel):
    """
    A file the scanner could not process. Surfaced so an unparseable upload
    is never silently indistinguishable from a genuinely clean result.
    """
    filename: str
    reason: str

class Recommendation(BaseModel):
    finding_id: str
    classical_algorithm: str
    purpose: str
    stage_1_hybrid: str
    stage_1_rationale: str
    stage_2_pqc: str
    liboqs_id: str

class BenchmarkResult(BaseModel):
    algorithm: str
    compared_against: str
    keygen_ms: float
    operation_ms: float
    public_key_bytes: int
    ciphertext_or_signature_bytes: int
    run_count: int

class MigrationImpactEstimate(BaseModel):
    scan_id: str
    total_assets: int
    estimated_additional_storage_mb: float
    estimated_additional_bandwidth_pct: float
    estimated_handshake_overhead_ms: float
    notes: str

class QuantumRiskScore(BaseModel):
    scan_id: str
    score: int
    grade: str
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int

class Component(BaseModel):
    type: str
    name: str
    algorithm: str
    keySize: Optional[int] = None
    usage: str
    quantumVulnerable: bool
    recommendedReplacement: str
    notes: Optional[str] = None

class CBOMExport(BaseModel):
    bomFormat: str = "CBOM"
    specVersion: str = "1.0"
    scan_id: str
    generated_at: str
    components: List[Component]

class ExecutiveSynthesis(BaseModel):
    headline_risk_statement: str
    top_3_priority_actions: List[str]
    compliance_summary_line: Optional[str] = None

class ScanResult(BaseModel):
    scan_id: str
    target_id: Optional[str] = None
    timestamp: Optional[str] = None
    findings: List[Finding] = []
    recommendations: List[Recommendation] = []
    benchmarks: List[BenchmarkResult] = []
    impact: Optional[MigrationImpactEstimate] = None
    risk_score: Optional[QuantumRiskScore] = None
    executive_summary: Optional[ExecutiveSynthesis] = None
    skipped_files: List[SkippedFile] = []
    benchmarks_measured_at: Optional[str] = None
    benchmarks_available: bool = True
