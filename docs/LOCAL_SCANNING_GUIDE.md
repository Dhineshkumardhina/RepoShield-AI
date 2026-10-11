# RepoShield AI — Local Security Scanning Guide for Developers

This guide provides instructions for developers to run RepoShield security checks locally before pushing commits or creating pull requests. Running checks locally accelerates the feedback loop and prevents introducing security regressions into CI/CD pipelines.

---

## 1. Prerequisites & Tool Installation

Ensure Python 3.10+ and Git are installed on your machine.

### Install Static Analysis Tools
Install the standard security tools used by RepoShield AI:

```bash
# Install Python scanners
pip install semgrep bandit pip-audit

# Optional: verify scanner installations
bandit --version
semgrep --version
pip-audit --version
```

### Install Gitleaks (Secret Detection)

* **macOS (Homebrew):**
  ```bash
  brew install gitleaks
  ```
* **Linux:**
  ```bash
  curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/v8.18.2/gitleaks_8.18.2_linux_x64.tar.gz" | tar -xz
  sudo mv gitleaks /usr/local/bin/
  ```
* **Windows (Chocolatey / Scoop):**
  ```powershell
  choco install gitleaks
  # or
  scoop install gitleaks
  ```

---

## 2. Running Local Scans

### Step 1: Python AST Security Analysis (Bandit)
Analyzes Python source files for insecure coding patterns (e.g. unsafe string formatting in SQL queries, hardcoded temp directories, insecure deserialization):

```bash
# Run bandit excluding test directories and virtual environments
bandit -r . --exclude "tests,venv,.venv,node_modules" -ll
```

### Step 2: Multi-Language Rule Matching (Semgrep)
Runs rules against your codebase using the default security ruleset:

```bash
# Run Semgrep with security-audit rules
semgrep scan --config=auto --exclude="tests,venv,.venv"
```

### Step 3: Dependency Vulnerability Audit (pip-audit)
Audits Python package dependencies against the Open Source Vulnerability (OSV) and PyPI advisory databases:

```bash
# Audit requirements
pip-audit -r requirements.txt
```

### Step 4: Secret Leakage Detection (Gitleaks)
Checks your local uncommitted staged changes or git history for exposed API keys, passwords, and tokens:

```bash
# Audit staged files prior to commit
gitleaks protect --staged --verbose

# Audit entire git repository history
gitleaks detect --redact --verbose
```

---

## 3. Pre-Commit Hook Integration (Automated Local Checks)

You can automatically run these checks prior to every git commit using `pre-commit`:

1. Install `pre-commit`:
   ```bash
   pip install pre-commit
   ```

2. Add a `.pre-commit-config.yaml` to your repository:
   ```yaml
   repos:
     - repo: https://github.com/gitleaks/gitleaks
       rev: v8.18.2
       hooks:
         - id: gitleaks

     - repo: https://github.com/PyCQA/bandit
       rev: 1.7.8
       hooks:
         - id: bandit
           args: ["-r", "-ll", "--exclude", "tests,venv"]

     - repo: https://github.com/returntocorp/semgrep
       rev: v1.65.0
       hooks:
         - id: semgrep
           args: ["--config=auto", "--error"]
   ```

3. Install the git hook:
   ```bash
   pre-commit install
   ```

---

## 4. Validating Proposed Fixes Locally

When you believe you have resolved a security finding:
1. Re-run the specific scanner that reported the finding to confirm the issue no longer appears:
   ```bash
   semgrep scan --config="p/security-audit" path/to/modified_file.py
   ```
2. Run your test suite to ensure functional behavior and regression tests pass:
   ```bash
   pytest tests/
   ```
3. Commit and push your changes to your branch. RepoShield AI will automatically compare against the base branch and classify the finding as **`RESOLVED`** in your PR security summary.
