import os
from validation.accuracy_harness import AccuracyHarness

def main():
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    gt_dir = os.path.join(base_dir, "sample-data", "ground_truth")
    out_dir = os.path.join(base_dir, "backend", "validation")
    
    print(f"Running accuracy harness against {gt_dir}")
    harness = AccuracyHarness(gt_dir)
    harness.evaluate()
    harness.generate_report(out_dir)
    print(f"Reports saved to {out_dir}")

if __name__ == "__main__":
    main()
