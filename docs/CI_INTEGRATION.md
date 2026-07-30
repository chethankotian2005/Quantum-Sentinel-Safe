# CI/CD Integration for QuantumSafe Sentinel

QuantumSafe Sentinel provides a lightweight, standalone static scanner designed to run directly in your CI/CD pipelines. This allows you to gate pull requests automatically based on the presence of quantum-vulnerable cryptography, without requiring the full backend server or dashboard to be deployed.

## 🚀 GitHub Actions Integration

The easiest way to use the static scanner is via the provided composite GitHub Action. The action will scan your codebase (Python files and TLS/SSH configuration files) and post a PR comment if vulnerabilities are detected.

### Setup

Create a new workflow file in your repository at `.github/workflows/quantumsafe-scan.yml`:

```yaml
name: QuantumSafe Sentinel Scan

on:
  pull_request:
    branches: [ "main" ]

jobs:
  pqc-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write # Required to post PR comments
    
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4

      - name: Run QuantumSafe Sentinel Scan
        # Replace `your-org` with the organization hosting the Sentinel repo
        uses: your-org/QuantumSafe-Sentinel/.github/actions/quantumsafe-scan@main
        with:
          target_dir: '.'         # The directory to scan (default: '.')
          fail_on: 'High'         # Fail the job if risk is >= High (default: 'High')
          github_token: ${{ secrets.GITHUB_TOKEN }}
```

### Action Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `target_dir` | The directory relative to the repository root to scan. | `.` |
| `fail_on` | The threshold risk level that causes the check to fail. Valid options: `Critical`, `High`, `Medium`, `Low`. | `High` |
| `github_token` | The GitHub token for the action to post PR comments. | N/A (Required) |

## 💻 Local CLI Usage

You can also run the scanner locally using the CLI wrapper.

### Prerequisites

Ensure you have the scanner dependencies installed:
```bash
pip install cryptography pydantic
```

*(Note: The CLI only requires `cryptography` and `pydantic`. It does not require `fastapi`, `liboqs`, or other heavy backend dependencies.)*

### Running the Scan

Navigate to the `backend/cli` directory and run `scan_cli.py`:

```bash
# Output human-readable text (default)
python scan_cli.py /path/to/your/codebase

# Output raw JSON for custom integration
python scan_cli.py /path/to/your/codebase --format json

# Change the failure threshold to Critical only
python scan_cli.py /path/to/your/codebase --fail-on Critical
```

The CLI will exit with code `1` if findings meet or exceed the `--fail-on` threshold, and code `0` otherwise.
