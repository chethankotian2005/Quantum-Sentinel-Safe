import os
import json
from validation.accuracy_harness import AccuracyHarness

harness = AccuracyHarness(r"e:\QuantumSafe Sentinel\sample-data\ground_truth")
manifest = harness.load_manifest()

for file_entry in manifest.get("files", []):
    rel_path = file_entry["path"]
    expected = file_entry.get("findings", [])
    full_path = os.path.join(harness.ground_truth_dir, rel_path)
    
    actual = harness.scan_file(rel_path, full_path)
    
    matched_actual = set()
    matched_expected = set()
    
    for exp_idx, exp in enumerate(expected):
        found = False
        for act_idx, act in enumerate(actual):
            if act_idx in matched_actual:
                continue
            line_match = exp.get("line") is None or act.line == exp.get("line")
            algo_match = act.algorithm.upper() == exp.get("algorithm", "").upper()
            if line_match and algo_match:
                matched_actual.add(act_idx)
                matched_expected.add(exp_idx)
                found = True
                break
        if not found:
            print(f"FN in {rel_path}: Expected {exp} but not found.")
            
    for act_idx, act in enumerate(actual):
        if act_idx not in matched_actual:
            print(f"FP in {rel_path}: Found {act.algorithm} at line {act.line}, which was not expected.")

