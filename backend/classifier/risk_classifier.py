"""
Risk Classifier — scoring logic per DRD Section 7.2 / FR-5.

Pure function classify(finding) -> risk_score using weighted rule table:
  algorithm type 40%, key size 25%, context 20%, usage type 15%.
Weights kept as named constants for explainability (NFR-4).
"""
