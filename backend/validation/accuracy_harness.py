import os
import json
from dataclasses import dataclass, asdict
from typing import List, Dict, Any

from detection.code_scanner import scan_python_file, scan_js_file
from detection.config_scanner import scan_config_file
from detection.cert_scanner import scan_certificate
from detection.live_scanner import scan_live_host
from models.schemas import Finding

@dataclass
class CategoryMetrics:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    files_tested: int = 0
    
    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) > 0 else 1.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 1.0

    @property
    def f1(self) -> float:
        p = self.precision
        r = self.recall
        return 2 * (p * r) / (p + r) if (p + r) > 0 else 0.0

@dataclass
class ValidationReport:
    code: CategoryMetrics
    certs: CategoryMetrics
    configs: CategoryMetrics
    live: CategoryMetrics
    overall: CategoryMetrics

class AccuracyHarness:
    def __init__(self, ground_truth_dir: str):
        self.ground_truth_dir = ground_truth_dir
        self.manifest_path = os.path.join(ground_truth_dir, "manifest.json")
        self.metrics = {
            "code": CategoryMetrics(),
            "certs": CategoryMetrics(),
            "configs": CategoryMetrics(),
            "live": CategoryMetrics(),
            "overall": CategoryMetrics()
        }

    def load_manifest(self) -> Dict[str, Any]:
        with open(self.manifest_path, 'r', encoding='utf-8') as f:
            return json.load(f)

    def scan_file(self, rel_path: str, full_path: str) -> List[Finding]:
        if rel_path.startswith("code/"):
            if full_path.endswith(".js") or full_path.endswith(".ts"):
                return scan_js_file(full_path)
            return scan_python_file(full_path)
        elif rel_path.startswith("configs/"):
            return scan_config_file(full_path)
        elif rel_path.startswith("certs/"):
            try:
                with open(full_path, 'rb') as f:
                    # cert_scanner returns a single Finding if valid, so we wrap it
                    return [scan_certificate(full_path, f.read())]
            except Exception:
                return []
        elif rel_path.startswith("live/"):
            hostname = rel_path.split("live/")[1]
            try:
                return scan_live_host(hostname)
            except Exception:
                return []
        return []

    def evaluate(self):
        manifest = self.load_manifest()
        
        for file_entry in manifest.get("files", []):
            rel_path = file_entry["path"]
            expected_findings = file_entry.get("findings", [])
            full_path = os.path.join(self.ground_truth_dir, rel_path)
            
            category = rel_path.split("/")[0]
            if category not in self.metrics:
                continue
                
            self.metrics[category].files_tested += 1
            self.metrics["overall"].files_tested += 1

            actual_findings = self.scan_file(rel_path, full_path)
            
            # Match actual to expected
            matched_actual_ids = set()
            matched_expected_indices = set()
            
            for exp_idx, exp in enumerate(expected_findings):
                found = False
                for act_idx, act in enumerate(actual_findings):
                    if act_idx in matched_actual_ids:
                        continue
                        
                    # Basic matching logic
                    line_match = exp.get("line") is None or act.line == exp.get("line")
                    algo_match = act.algorithm.upper() == exp.get("algorithm", "").upper()
                    
                    if line_match and algo_match:
                        matched_actual_ids.add(act_idx)
                        matched_expected_indices.add(exp_idx)
                        found = True
                        break
                        
                if found:
                    self.metrics[category].tp += 1
                    self.metrics["overall"].tp += 1
                else:
                    self.metrics[category].fn += 1
                    self.metrics["overall"].fn += 1
                    
            # Any actual findings that weren't matched are false positives
            fp_count = len(actual_findings) - len(matched_actual_ids)
            self.metrics[category].fp += fp_count
            self.metrics["overall"].fp += fp_count

    def generate_report(self, output_dir: str):
        os.makedirs(output_dir, exist_ok=True)
        report = ValidationReport(
            code=self.metrics["code"],
            certs=self.metrics["certs"],
            configs=self.metrics["configs"],
            live=self.metrics["live"],
            overall=self.metrics["overall"]
        )
        
        # Build a dict with calculated properties
        def serialize_category(cat: CategoryMetrics):
            d = asdict(cat)
            d["precision"] = cat.precision
            d["recall"] = cat.recall
            d["f1"] = cat.f1
            return d

        report_dict = {
            "code": serialize_category(report.code),
            "certs": serialize_category(report.certs),
            "configs": serialize_category(report.configs),
            "live": serialize_category(report.live),
            "overall": serialize_category(report.overall),
        }
        
        json_path = os.path.join(output_dir, "accuracy_report.json")
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(report_dict, f, indent=4)
            
        md_path = os.path.join(output_dir, "accuracy_report.md")
        with open(md_path, 'w', encoding='utf-8') as f:
            f.write("# Accuracy Validation Report\n\n")
            f.write("| Category | Files | TP | FP | FN | Precision | Recall | F1 Score |\n")
            f.write("|----------|-------|----|----|----|-----------|--------|----------|\n")
            for cat_name, cat in report_dict.items():
                f.write(f"| {cat_name.capitalize()} | {cat['files_tested']} | {cat['tp']} | {cat['fp']} | {cat['fn']} | ")
                f.write(f"{cat['precision']:.2%} | {cat['recall']:.2%} | {cat['f1']:.2%} |\n")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Run accuracy validation harness")
    parser.add_argument("--gt", type=str, default="../sample-data/ground_truth", help="Path to ground truth directory")
    parser.add_argument("--out", type=str, default=".", help="Path to output directory")
    args = parser.parse_args()
    
    harness = AccuracyHarness(args.gt)
    harness.evaluate()
    harness.generate_report(args.out)
    print(f"Validation complete. Reports generated in {args.out}")
