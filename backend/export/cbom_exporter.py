import json
from datetime import datetime, timezone
from models.schemas import ScanResult, CBOMExport, Component
from recommendation.recommender import generate_recommendation

def export_cbom(scan_result: ScanResult, filepath: str) -> str:
    """
    Exports a ScanResult to a standard CBOM JSON file.
    Returns the JSON string as well.
    """
    components = []
    
    for f in scan_result.findings:
        rec = generate_recommendation(f)
        
        name_str = f"{f.source_type.value}: "
        if f.file:
            name_str += f"{f.file}"
            if f.line:
                name_str += f" L{f.line}"
        elif f.hostname:
            name_str += f"{f.hostname}"
        else:
            name_str += "Unknown source"
            
        comp = Component(
            type="crypto-asset",
            name=name_str,
            algorithm=f.algorithm,
            keySize=f.key_size,
            usage=f.usage_type.value,
            quantumVulnerable=(f.risk_score != "Low"), # Simple heuristic for CBOM
            recommendedReplacement=rec.stage_1_hybrid,
            notes="Informational: This CA-issued intermediate/root certificate is not directly controlled by the target." if not getattr(f, "is_actionable", True) else None
        )
        components.append(comp)
        
    cbom = CBOMExport(
        scan_id=scan_result.scan_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        components=components
    )
    
    json_data = cbom.model_dump_json(indent=2)
    
    with open(filepath, "w", encoding="utf-8") as out:
        out.write(json_data)
        
    return json_data
