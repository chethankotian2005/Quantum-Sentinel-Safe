from typing import List
from models.schemas import Finding, ContextType, SourceType

def calculate_migration_effort(finding: Finding, all_findings: List[Finding]) -> int:
    """
    Computes a 1-5 'migration effort' score (5 = hardest).
    Base score is 3.
    """
    effort = 3
    
    # 1. Hardcoded vs Configured
    if finding.context in [ContextType.config, ContextType.production_cert]:
        effort -= 1  # easier to update config/cert
    elif finding.context == ContextType.code:
        effort += 1  # harder to refactor code
        
    # 2. Dependency vs 1st Party
    if finding.source_type == SourceType.dependency:
        effort += 1  # harder (needs upstream bump)
        
    # 3. Leaf vs Shared
    # Heuristic: count how many findings occur in the same file
    if finding.file:
        file_count = sum(1 for f in all_findings if f.file == finding.file)
        if file_count > 1:
            effort += 1  # more usages in this file implies it's more shared/complex
            
    # Clamp to 1-5
    if effort < 1:
        effort = 1
    elif effort > 5:
        effort = 5
        
    return effort
