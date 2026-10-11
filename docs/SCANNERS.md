# RepoShield AI — Security Scanning Engine

This document details the architecture, integrations, execution security controls, normalized finding schema, and technical limitations of the security-scanning engine in RepoShield AI.

---

## 1. Architecture & Modular Adapter Interface

RepoShield AI decouples scanning engines through the `BaseScannerAdapter` interface defined in `app/scanner/base.py`. This modular design allows new static analysis, dynamic verification, or software composition tools to be introduced without modifying core orchestration logic.

```
                          ┌────────────────────────┐
                          │   POST /api/v1/scans   │
                          └───────────┬────────────┘
                                      │
                                      ▼
                          ┌────────────────────────┐
                          │   run_security_scan    │
                          │  (scanner/runner.py)   │
                          └───────────┬────────────┘
                                      │
           ┌──────────────────────────┼──────────────────────────┐
           │                          │                          │
           ▼                          ▼                          ▼
┌────────────────────┐     ┌────────────────────┐     ┌────────────────────┐
│   Bandit Adapter   │     │  pip-audit Adapter │     │  Semgrep Adapter   │
│   (Python SAST)    │     │  (Dependency SCA)  │     │   (Multi-lang)     │
└──────────┬─────────┘     └──────────┬─────────┘     └──────────┬─────────┘
           │                          │                          │
           └──────────────────────────┼──────────────────────────┘
                                      │
           ┌──────────────────────────┴──────────────────────────┐
           │                          │                          │
           ▼                          ▼                          ▼
┌────────────────────┐     ┌────────────────────┐     ┌────────────────────┐
│ Built-in Secrets   │     │  Gitleaks Adapter  │     │ Database & Health  │
│ (Redaction Engine) │     │ (External Binary)  │     │  Score Calculator  │
└────────────────────┘     └────────────────────┘     └────────────────────┘
```

### Adapter Responsibilities
Each adapter must:
1. **Tool Verification**: Implement `is_available()` and `get_version()` safely without throwing unhandled exceptions.
2. **Explicit Arguments**: Avoid shell interpretation (`shell=True` prohibited). Execute via explicit argument lists.
3. **Execution Timeouts**: Enforce bounded execution times (`timeout_seconds`, default 60s).
4. **Machine-Readable Parsing**: Consume standard structured outputs (JSON).
5. **Output Normalization**: Map scanner-specific alerts to `NormalizedFinding`.
6. **Secret Redaction**: Apply `redact_secrets()` to evidence strings and messages before persistence.
7. **Clean Exit Code Handling**: Differentiate legitimate issue exits (e.g., Bandit exit code 1, pip-audit exit code 1) from tool crashes.

---

## 2. Integrated Security Scanners

### A. Bandit (Python SAST)
* **Purpose**: AST-based static security analysis for Python code.
* **Verified Version**: `1.9.4`
* **License**: Apache 2.0
* **Execution**: `bandit -f json -r <workspace_path>`
* **CWE Mapping**:
  - `B608`: CWE-89 (SQL Injection)
  - `B602`, `B603`, `B605`, `B607`: CWE-78 (OS Command Injection)
  - `B303`, `B304`, `B305`: CWE-327 (Broken Cryptography)
  - `B105`, `B106`, `B107`: CWE-798 (Hard-coded Credentials)
  - `B301`, `B302`: CWE-502 (Deserialization of Untrusted Data)
  - `B201`: CWE-94 (Code Injection / Eval)
* **Limitations**:
  - Evaluates Python AST only; does not scan polyglot repos (JavaScript, Go, C#).
  - Intra-procedural AST inspection lacks inter-procedural dataflow taint analysis.

### B. pip-audit (Software Composition Analysis)
* **Purpose**: Scans Python package dependencies for published vulnerabilities using the Open Source Vulnerabilities (OSV) database.
* **Verified Version**: `2.10.1`
* **License**: Apache 2.0
* **Execution**: `pip-audit -f json -r <manifest_path>`
* **Advisory Source**: OSV.dev and PyPI Advisory Feed.
* **Manifests Inspected**: `requirements.txt`, `requirements-dev.txt`, `Pipfile.lock`, `pyproject.toml`.
* **CWE Mapping**: `CWE-1395: Dependency on Vulnerable Third-Party Component`.
* **Limitations**:
  - Requires declared dependency manifest files. Packages installed without a manifest cannot be detected.
  - Requires egress network connectivity to query live vulnerability databases (unless configured with local cache/mirror).

### C. Semgrep OSS (Multi-Language SAST)
* **Purpose**: Multi-language semantic code search and static analysis.
* **Verified Version**: `1.180.0`
* **License**: LGPL-2.1
* **Execution**: `semgrep scan --json --config <ruleset> --disable-version-check --metrics=off <workspace_path>`
* **Capabilities**: Pattern matching across Python, TypeScript, JavaScript, Go, Java, Dockerfile, etc.
* **Limitations**:
  - Deep taint tracking across multiple repositories or complex inter-module call graphs is exclusive to Semgrep Proprietary.
  - Offline scans require pre-bundled or local YAML rule configurations.

### D. Gitleaks (Secret Scanner)
* **Purpose**: Fast standalone detection of exposed secrets, tokens, and private keys.
* **License**: MIT
* **Execution**: `gitleaks dir <workspace_path> --report-format json --report-path <tmp_report> --no-banner`
* **Capabilities**: High-performance detection of cloud keys, tokens, and credentials.
* **Limitations**:
  - Requires installation of standalone compiled Go binary.
  - If binary is absent, the adapter returns `ScannerStatus.TOOL_NOT_INSTALLED` without disrupting other active scanners.

### E. RepoShield Secret Engine (Built-in Credential Engine)
* **Purpose**: Deterministic, zero-dependency credential and API token scanner with automated redaction.
* **Verified Version**: `1.0.0`
* **Patterns Supported**:
  - `SEC-AWS-KEY`: AWS Access Key IDs (`AKIA...`) [CRITICAL]
  - `SEC-GITHUB-TOKEN`: GitHub Personal Access Tokens (`ghp_...`, `github_pat_...`) [CRITICAL]
  - `SEC-GITLAB-TOKEN`: GitLab Personal Access Tokens (`glpat-...`) [CRITICAL]
  - `SEC-STRIPE-KEY`: Stripe Live Secret Keys (`sk_live_...`) [CRITICAL]
  - `SEC-SLACK-TOKEN`: Slack Bot & User Tokens (`xoxb-...`) [HIGH]
  - `SEC-PRIVATE-KEY`: Unencrypted PEM Private Keys [CRITICAL]
  - `SEC-GENERIC-SECRET`: Hardcoded password and API token assignments [HIGH]
* **Strict Redaction Guarantee**: Raw credentials are automatically masked into replacement tokens (e.g. `[REDACTED_AWS_KEY]`) before being stored or presented to users.

---

## 3. Execution Security Architecture

To protect the application host and multi-tenant assets against untrusted repositories:

1. **Zero Code Execution**:
   - The scanner engine exclusively conducts static analysis.
   - It **never** runs `setup.py`, `pip install`, `npm install`, shell build scripts, or test harnesses of the target repository on the application host.
2. **Filesystem Isolation**:
   - Scanners execute exclusively within the repository's isolated workspace directory (`Repository.workspace_path`).
   - Temporary report files are created in isolated system scratch paths and unlinked in `finally` blocks.
3. **Process Sandboxing & Safety**:
   - Every scanner process is invoked with explicit argument vectors.
   - Shell command construction (`shell=True`) is strictly prohibited.
   - Execution timeouts (default: 60 seconds per scanner) abort runaway or malicious loops.
4. **Credential Isolation**:
   - Host secrets, database connection strings, and application configuration keys are **never** injected into the scanner execution environment.
   - The scanner environment only exposes the search PATH necessary to locate scanner binaries.

---

## 4. Normalized Finding Schema

All scanner alerts are converted into `NormalizedFinding` instances before saving to the database:

| Field | Type | Description | Example |
| :--- | :--- | :--- | :--- |
| `finding_id` | `str` | Unique finding identifier | `fnd-a8b2c4e1f0d3` |
| `scan_id` | `str` | Reference to parent scan job | `scan-789a-4bc1` |
| `scanner_name` | `str` | Display name of the scanning tool | `Bandit Python SAST` |
| `scanner_rule_id` | `str` | Specific rule or CVE identifier | `B608` or `CVE-2020-28493` |
| `vulnerability_category` | `str` | Standardized category / CWE | `CWE-89: SQL Injection` |
| `severity` | `str` | Normalized severity level | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `confidence` | `str` | Tool confidence level | `HIGH`, `MEDIUM`, `LOW` |
| `file_path` | `str` | Relative path within repository | `src/api/auth.py` |
| `start_line` / `end_line` | `int` | Exact line range | `42` to `45` |
| `scanner_message` | `str` | Human-readable issue description | `Possible SQL injection vector via string formatting` |
| `evidence_reference` | `str` | Redacted code excerpt or manifest dependency | `query = "SELECT * FROM users WHERE id = '" + uid` |
| `metadata` | `dict` | Scanner-specific metadata (aliases, fix versions) | `{"fix_versions": ["2.11.3"]}` |

---

## 5. Repository Health Score Metric

The repository health score is dynamically computed after every scan job:

$$\text{Health Score} = \max\left(0, 100 - (25 \times N_{\text{crit}} + 15 \times N_{\text{high}} + 5 \times N_{\text{med}} + 1 \times N_{\text{low}})\right)$$

* Clean repositories with 0 findings receive a 100% health score.
* Each open critical finding deducts 25 points; high findings deduct 15 points.

---

## 6. Scanner Limitations Summary

| Scanner | Strengths | Limitations |
| :--- | :--- | :--- |
| **Bandit** | Extremely fast AST analysis; standard for Python security hygiene. | Python-only; intra-procedural; can flag false positives on intentional debug statements. |
| **pip-audit** | Direct CVE mapping from official advisory feeds; provides upgrade guidance. | Requires dependency manifest; requires internet connectivity for advisory queries. |
| **Semgrep** | Fast pattern matching; polyglot support; highly customizable YAML syntax. | Community edition lacks deep inter-file taint analysis; offline requires local rule packs. |
| **Gitleaks** | Fast Go regex secret scanning across directories and commit histories. | Requires external binary; entropy rules can flag random test strings. |
| **RepoShield Secret Engine** | Zero external dependencies; instant execution; 100% secret redaction guarantee. | Regex-based; highly obfuscated secrets or encrypted tokens require entropy analysis. |
