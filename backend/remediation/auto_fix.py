import os
import httpx
import base64
from typing import Dict, Any, Optional
from models.schemas import Finding
from remediation.patch_generator import generate_new_content, generate_patch

GITHUB_API_URL = "https://api.github.com"

def _get_headers(token: str) -> Dict[str, str]:
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28"
    }

def create_github_pr(finding: Finding, repo: str = None, dry_run: bool = False) -> Dict[str, Any]:
    """
    Generates a patch for the given finding and opens a GitHub PR.
    If dry_run is True or GITHUB_TOKEN is missing, returns the exact diff and PR body without making network calls.
    """
    if not repo:
        repo = os.environ.get("GITHUB_DEMO_REPO", "owner/demo-repo")
        
    token = os.environ.get("GITHUB_TOKEN")
    
    # 1. Generate the content and diff
    patch_result = generate_new_content(finding)
    if not patch_result:
        return {"error": "No patch pattern matched this finding."}
        
    original_content, new_content = patch_result
    diff_str = generate_patch(finding)
    
    # 2. Construct the PR Metadata
    pr_title = f"[QuantumSafe Sentinel] Remediation for {finding.algorithm} Vulnerability"
    pr_body = f"""### Quantum-Safe Remediation Proposed
This PR automatically replaces legacy cryptographic usage with a hybrid Post-Quantum Cryptography (PQC) implementation.

**Finding Reference**: `{finding.finding_id}`
**Algorithm**: `{finding.algorithm}` (Risk Score: `{finding.risk_score.value}`)

### CISA PQC Roadmap Compliance
According to the CISA PQC Roadmap and CNSA 2.0 guidelines, classical algorithms such as {finding.algorithm} are vulnerable to "Store Now, Decrypt Later" attacks by Cryptographically Relevant Quantum Computers (CRQCs). 

**Migration Rationale**:
This patch replaces the vulnerable pattern with a deterministic hybrid PQC template, combining classical mechanisms with ML-KEM/ML-DSA (via liboqs) to provide quantum resistance while maintaining classical security bounds during the transition period.
"""

    if dry_run or not token:
        return {
            "dry_run": True,
            "diff": diff_str,
            "pr_body": pr_body,
            "pr_title": pr_title,
            "url": None
        }
        
    # 3. Execute GitHub API Workflow
    headers = _get_headers(token)
    branch_name = f"auto-fix/{finding.finding_id}"
    
    try:
        with httpx.Client(base_url=GITHUB_API_URL, headers=headers) as client:
            # A. Get default branch SHA
            repo_resp = client.get(f"/repos/{repo}")
            repo_resp.raise_for_status()
            default_branch = repo_resp.json()["default_branch"]
            
            ref_resp = client.get(f"/repos/{repo}/git/refs/heads/{default_branch}")
            ref_resp.raise_for_status()
            base_sha = ref_resp.json()["object"]["sha"]
            
            # B. Create new branch
            create_ref_resp = client.post(
                f"/repos/{repo}/git/refs",
                json={"ref": f"refs/heads/{branch_name}", "sha": base_sha}
            )
            if create_ref_resp.status_code != 201:
                # If branch already exists, we could just use it, but for simplicity:
                pass
                
            # C. Get file blob SHA
            # We need the relative path of the file in the repo.
            # Assuming the scan was run from the root of the repo.
            rel_path = os.path.relpath(finding.file, start=os.getcwd())
            # Convert Windows paths to Unix paths for GitHub
            rel_path = rel_path.replace("\\", "/")
            
            file_resp = client.get(f"/repos/{repo}/contents/{rel_path}?ref={branch_name}")
            file_sha = None
            if file_resp.status_code == 200:
                file_sha = file_resp.json()["sha"]
                
            # D. Update file
            update_data = {
                "message": pr_title,
                "content": base64.b64encode(new_content.encode("utf-8")).decode("utf-8"),
                "branch": branch_name
            }
            if file_sha:
                update_data["sha"] = file_sha
                
            update_resp = client.put(f"/repos/{repo}/contents/{rel_path}", json=update_data)
            update_resp.raise_for_status()
            
            # E. Create PR
            pr_data = {
                "title": pr_title,
                "body": pr_body,
                "head": branch_name,
                "base": default_branch
            }
            pr_resp = client.post(f"/repos/{repo}/pulls", json=pr_data)
            pr_resp.raise_for_status()
            
            pr_json = pr_resp.json()
            pr_url = pr_json["html_url"]
            pr_number = pr_json["number"]
            
            # F. Fetch the actual diff from GitHub
            diff_headers = _get_headers(token)
            diff_headers["Accept"] = "application/vnd.github.v3.diff"
            diff_resp = client.get(f"/repos/{repo}/pulls/{pr_number}", headers=diff_headers)
            actual_diff = diff_resp.text if diff_resp.status_code == 200 else diff_str
            
            return {
                "dry_run": False,
                "url": pr_url,
                "pr_number": pr_number,
                "pr_title": pr_title,
                "diff": actual_diff,
                "files_changed": [rel_path]
            }
            
    except httpx.HTTPStatusError as e:
        return {"error": f"GitHub API error: {e.response.status_code} {e.response.text}"}
    except Exception as e:
        return {"error": str(e)}
