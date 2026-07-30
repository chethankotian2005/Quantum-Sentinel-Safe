import os
import json
import logging
from typing import List
from models.schemas import Finding, ComplianceFlag, RiskLevel, ContextType, UsageType

logger = logging.getLogger(__name__)

SEVERITY_WEIGHT = {
    RiskLevel.Low: 1,
    RiskLevel.Medium: 2,
    RiskLevel.High: 3,
    RiskLevel.Critical: 4
}

_VALID_CONTEXTS = {c.value for c in ContextType}
_VALID_USAGE_TYPES = {u.value for u in UsageType}
_VALID_SEVERITIES = {r.value for r in RiskLevel}

class ComplianceMapper:
    def __init__(self):
        self.frameworks = []
        self._load_frameworks()

    def _load_frameworks(self):
        config_path = os.path.join(os.path.dirname(__file__), "compliance_frameworks.json")
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                self.frameworks = data.get("frameworks", [])
        except Exception as e:
            # Fallback to empty if not found
            logger.error("Could not load compliance frameworks from %s: %s", config_path, e)
            self.frameworks = []
        self._validate_frameworks()

    def _validate_frameworks(self):
        """
        Warn loudly about trigger values that can never match a real Finding.

        A context/usage/severity typo here doesn't raise — it just makes the
        framework silently never fire, which previously hid PCI-DSS and HIPAA
        from every config-file finding.
        """
        for fw in self.frameworks:
            name = fw.get("name", "<unnamed>")
            for trigger in fw.get("triggers", []):
                for ctx in trigger.get("contexts", []):
                    if ctx not in _VALID_CONTEXTS:
                        logger.warning(
                            "Compliance framework %r has unknown context %r "
                            "(valid: %s) — this trigger can never match.",
                            name, ctx, sorted(_VALID_CONTEXTS),
                        )
                for usage in trigger.get("usage_types", []):
                    if usage not in _VALID_USAGE_TYPES:
                        logger.warning(
                            "Compliance framework %r has unknown usage_type %r "
                            "(valid: %s) — this trigger can never match.",
                            name, usage, sorted(_VALID_USAGE_TYPES),
                        )
                min_sev = trigger.get("min_severity", "Low")
                if min_sev not in _VALID_SEVERITIES:
                    logger.warning(
                        "Compliance framework %r has unknown min_severity %r "
                        "(valid: %s) — defaulting to Low.",
                        name, min_sev, sorted(_VALID_SEVERITIES),
                    )

    def map_compliance(self, finding: Finding) -> List[ComplianceFlag]:
        flags = []
        f_weight = SEVERITY_WEIGHT.get(finding.risk_score, 1)
        
        for fw in self.frameworks:
            for trigger in fw.get("triggers", []):
                # 1. Match Algorithm
                if trigger.get("algorithm", "").upper() != finding.algorithm.upper():
                    continue
                
                # 2. Match Usage Type
                usage_types = trigger.get("usage_types", [])
                if usage_types and finding.usage_type.value not in usage_types:
                    continue
                    
                # 2.5 Match Context (if specified)
                contexts = trigger.get("contexts", [])
                if contexts and finding.context.value not in contexts:
                    continue
                
                # 3. Match Severity
                min_sev = trigger.get("min_severity", "Low")
                # Need to convert string back to RiskLevel enum for dict lookup
                try:
                    min_risk_enum = RiskLevel(min_sev)
                    min_weight = SEVERITY_WEIGHT.get(min_risk_enum, 1)
                except ValueError:
                    min_weight = 1
                
                if f_weight >= min_weight:
                    flags.append(ComplianceFlag(
                        framework_name=fw["name"],
                        summary=fw["summary"],
                        deadline=fw["deadline"],
                        source_link=fw["source_link"]
                    ))
                    break # We only need to flag the framework once per finding

        return flags

# Singleton instance
_mapper = ComplianceMapper()

def map_compliance(finding: Finding) -> List[ComplianceFlag]:
    return _mapper.map_compliance(finding)
