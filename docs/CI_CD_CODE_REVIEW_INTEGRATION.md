# RepoShield AI — DevSecOps Code Review & CI/CD Integration Guide

This guide details how **RepoShield AI** makes security findings and fix-verification results accessible during pull-request code reviews and CI/CD pipelines while enforcing strict DevSecOps security invariants.

---

## 1. Architecture Overview & Core Objectives

RepoShield AI integrates directly into pull request code reviews to shift security left and empower developers with evidence-based remediation feedback:

```
      +--------------------+
      | Pull Request Event | (Opened / Synchronize / Reopened)
      +---------+----------+
                |
                v
  +-------------+--------------+
  |  HMAC Webhook Validation   |  (X-Hub-Signature-256 + Replay Prevention)
  +-------------+--------------+
                |
                v
  +-------------+--------------+
  | Exact Repo & Commit Binder |  (Head SHA: 40-hex | Base SHA: 40-hex)
  +-------------+--------------+
                |
                v
  +-------------+--------------+
  | Diff-Aware Finding Scanner |  (Categorizes: NEW, RESOLVED, UNCHANGED, REGRESSED)
  +-------------+--------------+
                |
                v
  +-------------+--------------+
  | Fix Verification Engine    |  (Evaluates Patches in Ephemeral Workspace)
  +-------------+--------------+
                |
                +---------------------------------------+
                |                                       |
                v                                       v
  +-------------+--------------+         +--------------+---------------+
  | Concise PR Markdown Summary|         | Machine-Readable CI Results   |
  | (Evidence & Diff Previews) |         | (JSON / SARIF | Exit: 0/1/2) |
  +----------------------------+         +-------------------------------+
```

### Core DevSecOps Objectives
1. **Exact Commit & Repository Association**: Every scan is immutably linked to the 40-character `head_commit_sha` and `base_commit_sha`.
2. **Diff-Aware Classification**: Scans analyze modified files and categorize findings into `NEW`, `RESOLVED`, `UNCHANGED`, and `REGRESSED`.
3. **Evidence-Based Fix Verification**: Pull request comments display concrete verification evidence (SAST regression deltas, unit test passes, sandbox logs) alongside proposed candidate patches.
4. **Machine-Readable CI Automation**: CLI gate script and REST endpoint emit standardized JSON reports.
5. **Strict Policy Gating**: Non-success exit codes block merges when required checks fail or are skipped.
6. **Omission Auditing**: Distinguishes checks that *failed* from checks that were *unavailable* or *skipped* (avoiding silent false-clean passes).
7. **Local Reproducibility**: Developers can reproduce the exact gate decision locally before pushing code.

---

## 2. DevSecOps Security Invariants

RepoShield AI enforces the following security controls:

| Security Requirement | Implementation in RepoShield AI |
| :--- | :--- |
| **Least-Privilege GitHub Permissions** | The GitHub App requests only `contents: read`, `pull_requests: write`, and `checks: write`. Excessive scopes (`administration`, `secrets`, `write-all`) are rejected by `evaluate_permissions()`. |
| **Webhook Signature & Replay Defense** | All incoming webhooks validate constant-time `hmac.compare_digest` with HMAC-SHA256 (`X-Hub-Signature-256`). `X-GitHub-Delivery` GUIDs are stored and checked against replays. |
| **Anti-Prompt Injection / Zero Trust** | Untrusted PR titles, PR body texts, and commit messages are sanitized by `sanitize_pr_untrusted_text()`. Untrusted text is never parsed as system instructions or configuration directives. |
| **No Credential Exposure** | Tokens, private keys, and secrets are encrypted at rest with Fernet (`encrypt_credentials`). Webhook secrets use salted SHA-256. Credentials are never written to logs or comments. |
| **No Auto-Merge or Auto-Deploy** | Proposed patches and verification statuses are strictly advisory. Automated merge or deployment is forbidden; human review is required. |
| **Explicit Operator Authorization** | Comments are published *only* if the repository policy toggle `publish_pr_comments` is explicitly enabled by the repository owner. |
| **Truth-in-Evidence (No Silent Passes)** | When configured tools are unavailable or timed out, the scan status is marked `INCOMPLETE` with exit code `2`. Scans are never marked clean when checks were skipped. |
| **Private Source Confidentiality** | Code analysis and patch verifications run locally in ephemeral, disposable workspaces. No code is transmitted to third-party model providers. |

---

## 3. Finding Categorization Taxonomy

RepoShield AI classifies security findings across the PR diff:

| Classification | Definition | CI Impact | PR Icon |
| :--- | :--- | :--- | :---: |
| `NEW` | Finding introduced in a file modified by the pull request. | **Blocks CI** if severity $\ge$ threshold | 🚨 |
| `REGRESSED` | Finding newly appearing in an unmodified file, or a previously resolved vulnerability re-introduced. | **Blocks CI** | ⚠️ |
| `RESOLVED` | Pre-existing baseline finding in a modified file that is now absent in the patched code. | **Evidence of fix** | ✅ |
| `UNCHANGED` | Pre-existing baseline finding in unmodified files unaffected by the PR. | Informational (tech debt) | ℹ️ |

---

## 4. Fix Verification Evidence Display

When candidate patches are evaluated by RepoShield's Fix Verification Engine, the PR comment renders concrete verification proof:

```markdown
### 🔬 Proposed Fixes & Verification Evidence
Concrete verification evidence collected from candidate fix evaluation runs:

| Target Vulnerability | Verification Status | Verification Evidence | Report |
| :--- | :--- | :--- | :--- |
| **CWE-89: SQL Injection**<br>`backend/app/db/crud.py` | ✅ `VERIFIED_AGAINST_DEFINED_CHECKS` | • SAST Regression: Clean (0 findings)<br>• Security Test: Passed (test_sqli_patch.py)<br>• Workspace Hash: Verified clean | [View Report](/verifications/vr_20261011_01) |

<details><summary>🔎 View Proposed Fix Unified Diffs</summary>

#### Fix for CWE-89: SQL Injection
```diff
- query = f"SELECT * FROM users WHERE email = '{user_input}'"
+ query = "SELECT * FROM users WHERE email = :email"
+ result = session.execute(query, {"email": user_input})
```
</details>
```

> [!NOTE]
> *Disclaimer: RepoShield AI analysis reflects static scanner results and targeted verification checks on supported file formats. Passing checks do not provide cryptographic mathematical proof of universal security or exploit impossibility.*

---

## 5. Machine-Readable CI Pipeline Integration

### 5.1 CLI Tool: `scripts/ci_security_gate.py`

RepoShield provides a standalone CLI runner suitable for GitHub Actions, GitLab CI, Jenkins, and pre-commit hooks:

```bash
python -m scripts.ci_security_gate \
  --repo-path . \
  --head-sha "3a4b5c6d..." \
  --base-sha "1e2f3a4b..." \
  --fail-on HIGH \
  --strict-checks \
  --format json \
  --output-file reposhield_result.json
```

### 5.2 Exit Codes Specification

The script returns standard DevSecOps exit codes:

| Exit Code | Gate Status | Meaning | Action Required |
| :---: | :---: | :--- | :--- |
| `0` | `PASS` | No blocking findings detected. All configured scanners ran cleanly. | Pipeline proceeds / Merge permitted. |
| `1` | `FAIL` | Security policy violated (`NEW` or `REGRESSED` findings at or above threshold, or fix verification failed). | Pipeline fails. Developer must fix vulnerabilities. |
| `2` | `INCOMPLETE` | Configured scanners were unavailable, timed out, or omitted. | Pipeline fails. Check CI tool installation and runner environment. |

### 5.3 Machine-Readable JSON Schema

```json
{
  "schema_version": "1.0.0",
  "evaluated_at": "2026-10-11T20:50:00Z",
  "repository": "auth-service",
  "head_commit_sha": "a1b2c3d4e5f67890123456789012345678901234",
  "base_commit_sha": "f1e2d3c4b5a67890123456789012345678901234",
  "gate_status": "FAIL",
  "exit_code": 1,
  "gate_passed": false,
  "policy": {
    "fail_on_severity": "HIGH",
    "strict_checks": true
  },
  "metrics": {
    "new_findings": 1,
    "resolved_findings": 1,
    "regressed_findings": 0,
    "unchanged_findings": 2,
    "verified_fixes": 1,
    "failed_checks": 1,
    "unavailable_checks": 0
  },
  "failed_checks": [
    "NEW finding exceeds threshold: HIGH 'CWE-89' in backend/app/db/crud.py"
  ],
  "unavailable_checks": [],
  "categorized_findings": [
    {
      "classification": "NEW",
      "rule_id": "CWE-89",
      "severity": "HIGH",
      "file_path": "backend/app/db/crud.py",
      "line_number": 42,
      "message": "Potential SQL injection via raw string formatting",
      "commit_sha": "a1b2c3d4e5f67890123456789012345678901234",
      "detail_url": "/findings/f_8901"
    }
  ],
  "verification_evidence": [
    {
      "finding_id": "f_7901",
      "finding_title": "CWE-79: Cross-Site Scripting",
      "status": "VERIFIED_AGAINST_DEFINED_CHECKS",
      "evidence_items": [
        "SAST Regression: Clean (0 findings)",
        "Security Test: Passed (test_xss_patch.py)"
      ],
      "evidence_report_link": "/verifications/vr_101"
    }
  ],
  "reproduction": {
    "command": "python -m scripts.ci_security_gate --repo-path . --head-sha a1b2c3d4 --base-sha f1e2d3c4 --fail-on HIGH",
    "guide": "docs/CI_CD_CODE_REVIEW_INTEGRATION.md"
  }
}
```

### 5.4 REST API Endpoint: `POST /api/v1/integrations/ci/evaluate`

CI runners can query the RepoShield API directly:

```http
POST /api/v1/integrations/ci/evaluate
Authorization: Bearer <JWT_OR_SCOPED_TOKEN>
Content-Type: application/json

{
  "repository_id": "repo_auth_service",
  "head_commit_sha": "a1b2c3d4e5f67890123456789012345678901234",
  "base_commit_sha": "f1e2d3c4b5a67890123456789012345678901234",
  "pr_number": 142,
  "changed_files": ["backend/app/db/crud.py"],
  "fail_on_severity": "HIGH",
  "require_all_checks": true
}
```

Response returns HTTP 200 with `CIEvaluationResponse` containing `gate_status`, `exit_code`, and formatted `summary_markdown`.

---

## 6. Local Developer Reproduction Workflow

Developers do not need to push to GitHub to test security compliance. Follow these steps locally:

### Step 1: Install Local Scanners
```bash
python -m pip install semgrep bandit pip-audit
```

### Step 2: Run the Security Gate against Your Branch Diff
```bash
# Compare working branch against main
python -m scripts.ci_security_gate \
  --repo-path . \
  --head-sha $(git rev-parse HEAD) \
  --base-sha $(git merge-base origin/main HEAD) \
  --fail-on HIGH \
  --strict-checks
```

### Step 3: Inspect the Output
- If `gate_status` is `PASS` (exit 0): You are ready to push and open your PR!
- If `gate_status` is `FAIL` (exit 1): The command lists the exact files, line numbers, and CWE rules to resolve.
- If `gate_status` is `INCOMPLETE` (exit 2): The output specifies which scanner was missing.

### Step 4: Verify Proposed Fixes Locally
Execute targeted fix verification tests:
```bash
python -m scripts.evaluate_fix_verification
```

---

## 7. GitHub Actions Workflow Configuration

Add [`.github/workflows/reposhield_pr_gate.yml`](file:///.github/workflows/reposhield_pr_gate.yml) to your repository:

```yaml
name: "RepoShield AI — Code Review Security Gate"

on:
  pull_request:
    types: [opened, synchronize, reopened]
    branches: ["main", "master", "develop"]

permissions:
  contents: read        # Read repo code and diff
  pull-requests: write  # Post review summary comment
  checks: write         # Create commit check run

jobs:
  security-gate:
    name: "RepoShield Security Gate"
    runs-on: ubuntu-latest
    timeout-minutes: 15

    steps:
      - name: "Checkout repository"
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: "Set up Python Environment"
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: "Install Security Scanners"
        run: |
          python -m pip install --upgrade pip
          python -m pip install semgrep bandit pip-audit

      - name: "Execute RepoShield CI Security Gate"
        id: gate
        continue-on-error: true
        run: |
          mkdir -p .reposhield_artifacts
          python -m scripts.ci_security_gate \
            --repo-path . \
            --head-sha "${{ github.event.pull_request.head.sha }}" \
            --base-sha "${{ github.event.pull_request.base.sha }}" \
            --pr-number "${{ github.event.pull_request.number }}" \
            --fail-on HIGH \
            --strict-checks \
            --format json \
            --output-file .reposhield_artifacts/ci_gate_result.json
          
          echo "GATE_EXIT_CODE=$?" >> $GITHUB_ENV

      - name: "Upload Artifact"
        uses: actions/upload-artifact@v4
        with:
          name: reposhield-ci-result
          path: .reposhield_artifacts/ci_gate_result.json

      - name: "Publish Pull Request Summary"
        if: always()
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const data = JSON.parse(fs.readFileSync('.reposhield_artifacts/ci_gate_result.json', 'utf8'));
            await github.rest.issues.createComment({
              owner: context.repo.owner,
              repo: context.repo.repo,
              issue_number: context.issue.number,
              body: data.summary_markdown
            });

      - name: "Enforce Security Decision"
        run: |
          if [ "${GATE_EXIT_CODE}" -eq 0 ]; then
            echo "✅ Security Gate PASSED."
            exit 0
          elif [ "${GATE_EXIT_CODE}" -eq 1 ]; then
            echo "❌ Security Gate FAILED on policy violations."
            exit 1
          elif [ "${GATE_EXIT_CODE}" -eq 2 ]; then
            echo "⚠️ Security Gate INCOMPLETE on skipped checks."
            exit 2
          fi
```

---

## 8. GitHub App Setup & Webhook Configuration

### 8.1 Registering the GitHub App
1. Go to **Settings > Developer Settings > GitHub Apps > New GitHub App**.
2. Specify:
   - **App Name**: `RepoShield AI Security Gate`
   - **Webhook URL**: `https://<your-reposhield-host>/api/v1/integrations/github/webhook`
   - **Webhook Secret**: Generate a secure 32-byte secret (`openssl rand -hex 32`).
3. Set **Permissions**:
   - `Repository permissions > Contents`: **Read-only**
   - `Repository permissions > Pull requests`: **Read & write**
   - `Repository permissions > Checks`: **Read & write**
   - `Repository permissions > Metadata`: **Read-only**
4. Subscribe to Events:
   - Check `Pull request` (types: `opened`, `synchronize`, `reopened`).
   - Check `Check run` and `Check suite`.

### 8.2 Storing Credentials in RepoShield AI
Use the encrypted registration endpoint:
```bash
curl -X POST "http://localhost:8000/api/v1/integrations/github/installations" \
  -H "Authorization: Bearer <USER_JWT>" \
  -H "Content-Type: application/json" \
  -d '{
    "installation_id": "12345678",
    "account_login": "my-org",
    "account_type": "Organization",
    "auth_mode": "github_app",
    "access_token": "ghs_installation_scoped_token",
    "webhook_secret": "my_32_byte_secret",
    "permissions": {
      "contents": "read",
      "pull_requests": "write",
      "checks": "write",
      "metadata": "read"
    }
  }'
```

---

## 9. Troubleshooting & FAQ

### Q: Why did my clean PR fail with Exit Code 2?
**A:** Exit Code 2 signifies **Omission Auditing**. One or more configured scanners (such as `semgrep` or `bandit`) were not found in your runner's `PATH`. Under RepoShield's truth-in-evidence model, a scan with missing tools cannot be certified clean. Ensure scanners are installed via `pip install semgrep bandit pip-audit`.

### Q: Can RepoShield AI automatically merge verified fixes?
**A:** **No.** RepoShield AI strictly adheres to human-in-the-loop DevSecOps principles. We provide evidence, verification confidence, and candidate diffs, but write operations and merge decisions require explicit human authorization.

### Q: How does RepoShield protect against prompt injection in PRs?
**A:** PR titles and descriptions are sanitized by `sanitize_pr_untrusted_text()`, stripping prompt directives, shell metacharacters, and markdown injection vectors before logging or comment generation. Untrusted text is never parsed as instruction data.
