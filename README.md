# QuantumSafe Sentinel

QuantumSafe Sentinel is an advanced cryptographic risk assessment and automated remediation platform. It provides dynamic discovery of legacy cryptographic assets (RSA, ECC), evaluates their vulnerability against the impending Cryptographically Relevant Quantum Computer (CRQC) threat using Mosca's Theorem, and automatically generates deterministic hybrid Post-Quantum Cryptography (PQC) patches via GitHub Pull Requests.

## Features

- **Multi-Modal Scanning Pipeline:** Scans application source code (Python, JS, TS, ZIP), infrastructure configurations (nginx, Apache, SSH), and X.509 certificate chains.
- **Live Endpoint Analysis:** Performs real-time TLS handshakes to extract live certificate chains, automatically categorizing weak cryptography and network reachability.
- **Quantum Threat Modeling:** Implements Mosca's Theorem ($X + Y > Z$) to compute hard deadlines for asset migration based on data sensitivity, migration effort, and the quantum horizon.
- **"Shift-Left" CI/CD Integration:** Includes native GitHub Action workflows that scan PRs in real-time, blocking merges containing vulnerable legacy algorithms based on organizational thresholds.
- **Automated PR Remediation:** Generates hybrid PQC implementations (e.g., combining RSA with ML-KEM/Kyber via `liboqs`) and automatically opens live Pull Requests directly from the dashboard.
- **Export & Reporting:** One-click generation of Cryptographic Bills of Materials (CBOM) and boardroom-ready PDF risk summaries.

## Architecture

The project is structured with a FastAPI (Python) backend and a Next.js (React/TypeScript) frontend.

### Backend (`/backend`)
- **Detection Engine:** AST-based code parsers, regex config scanners, and X.509 ASN.1 certificate decoders.
- **Classification & Scoring:** Evaluates migration effort, maps to CISA/NIST compliance frameworks, and calculates the Mosca Risk Score.
- **Remediation:** Generates unified diffs and handles GitHub API interactions for auto-fixes.

### Frontend (`/frontend`)
- **SOC Dashboard:** A premium, Security Operations Center-themed interface tailored for high-contrast data visualization.
- **Mosca Timeline:** Interactive visualization of the $X+Y>Z$ risk model.

## Getting Started

### Prerequisites
- Python 3.10+
- Node.js 18+ (npm or yarn)
- *Optional:* A valid `GITHUB_TOKEN` for the auto-fix PR feature.

### 1. Start the Backend
```bash
cd backend
python -m venv .venv
source .venv/bin/activate  # Or `.\.venv\Scripts\activate` on Windows
pip install -r requirements.txt
python main.py
```
*The backend API will start on `http://127.0.0.1:8000`.*

### 2. Start the Frontend
```bash
cd frontend
npm install
npm run dev
```
*The web dashboard will start on `http://localhost:3000`.*

## Configuration

To enable automated Pull Request generation, export your GitHub token before starting the backend:
```bash
export GITHUB_TOKEN="your_personal_access_token_here"
```

## License
MIT License
