import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from models.schemas import ContextType

filepath = os.path.join(os.path.dirname(__file__), "classification", "compliance_frameworks.json")
with open(filepath, "r") as f:
    data = json.load(f)

pci_dss = {
    "name": "PCI-DSS v4.0",
    "summary": "Requires 'strong cryptography' for cardholder data in transit over public networks (Requirement 4.2.1 area). While not explicitly mandating PQC yet, any RSA/ECC usage protecting cardholder data is flagged as needing a migration plan.",
    "deadline": "Ongoing (Requirement 4.2.1)",
    "source_link": "https://www.pcisecuritystandards.org/document_library/",
    "triggers": [
        {
            "algorithm": "RSA",
            "contexts": ["production_cert", "network_config"],
            "min_severity": "Low"
        },
        {
            "algorithm": "ECC",
            "contexts": ["production_cert", "network_config"],
            "min_severity": "Low"
        },
        {
            "algorithm": "DH",
            "contexts": ["production_cert", "network_config"],
            "min_severity": "Low"
        },
        {
            "algorithm": "ECDH",
            "contexts": ["production_cert", "network_config"],
            "min_severity": "Low"
        }
    ]
}

hipaa = {
    "name": "HIPAA Security Rule",
    "summary": "Requires 'reasonable and appropriate' safeguards for ePHI. Encryption is an 'addressable' implementation specification (45 CFR 164.312). Any vulnerable cryptographic finding protecting health data is flagged as a HIPAA-relevant exposure.",
    "deadline": "Ongoing (45 CFR 164.312)",
    "source_link": "https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html",
    "triggers": [
        {
            "algorithm": "RSA",
            "contexts": ["production_cert", "network_config"],
            "min_severity": "Low"
        },
        {
            "algorithm": "ECC",
            "contexts": ["production_cert", "network_config"],
            "min_severity": "Low"
        },
        {
            "algorithm": "DH",
            "contexts": ["production_cert", "network_config"],
            "min_severity": "Low"
        },
        {
            "algorithm": "ECDH",
            "contexts": ["production_cert", "network_config"],
            "min_severity": "Low"
        }
    ]
}

data["frameworks"].append(pci_dss)
data["frameworks"].append(hipaa)

with open(filepath, "w") as f:
    json.dump(data, f, indent=4)
print("Updated compliance_frameworks.json")
