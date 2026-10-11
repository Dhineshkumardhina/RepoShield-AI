# RepoShield AI — Secure GitHub & CI/CD Integration Architecture

This document provides a comprehensive technical overview of the GitHub App and CI/CD integration subsystem for RepoShield AI.

---

## 1. Executive Summary & Design Principles

RepoShield AI integrates with GitHub to allow authorized developers and security leads to evaluate code changes and review verified security findings prior to merging pull requests.

### Core Security Invariants
1. **Least-Privilege by Default:** RepoShield requests only the minimal permissions required for source analysis. No administrative, secret-management, or deployment privileges are requested.
2. **Read-Only Scanning Default:** Commenting on pull requests or modifying external status requires explicit operator consent (`publish_pr_comments = true`).
3. **Encrypted Credentials at Rest:** Access tokens and private keys are never stored in plaintext. They are encrypted using authenticated symmetric cryptography (`Fernet`).
4. **Anti-Prompt-Injection Safeguards:** Pull request titles, descriptions, and commit messages are untrusted inputs. They are strictly sanitized and never treated as instructions.
5. **Multi-Tenant Authorization Isolation:** Repositories and GitHub installations belong strictly to individual authenticated tenants. Cross-tenant linkage is prevented at the API boundary.
6. **Truth in Evidence:** PR summaries never declare a clean bill of health if required scanners timed out, failed, or were skipped. Incomplete scans are clearly identified.
7. **No Autonomous Merges or Deployments:** RepoShield AI is an evaluation and verification gate; it never automatically merges branches or triggers production deployments.

---

## 2. GitHub Permissions Matrix

### Supported Permissions (Least-Privilege)

| Permission Scope | Access Level | Rationale | Stage |
| :--- | :--- | :--- | :--- |
| `contents` | **Read-only** | Required to inspect repository commit trees and fetch changed files between base and head. | Stage 1 & 2 |
| `pull_requests` | **Read-only** *(Default)* | Required to read PR base/head commit SHAs, author metadata, and changed file paths. | Stage 2 |
| `pull_requests` | **Read/Write** *(Optional)* | Required **only** when repository owner explicitly opts in to inline PR security summary comments. | Stage 3 |
| `metadata` | **Read-only** | Base permission required by GitHub for all GitHub Apps to resolve repository IDs and public metadata. | Stage 1 |

### Prohibited / Excessive Permissions (Strictly Never Requested)

RepoShield explicitly detects and flags excessive permissions. The following permissions are rejected or warned against:
* `administration` (No repository settings modification)
* `actions` (No workflow or CI tampering)
* `secrets` (Zero access to organizational or repository secrets)
* `deployments` (No autonomous release or deployment capabilities)
* `single_file` write (No direct modifications to protected branches)

---

## 3. Repository Connection Model

```mermaid
graph TD
    User([Authorized Developer / Admin]) -->|1. Registers Installation| WebAPI[RepoShield API]
    WebAPI -->|2. Validates Least-Privilege| PermCheck[Permission Evaluator]
    WebAPI -->|3. Encrypts Credentials| FernetCrypto[Fernet Authenticated Cipher]
    FernetCrypto -->|4. Persists Record| DB[(PostgreSQL / SQLite)]
    User -->|5. Links Repo with Policy| RepoLink[Repository GitHub Link]
    GitHub[GitHub Webhook / Actions] -->|6. Event Signed with HMAC| WebhookHandler[HMAC & Replay Defense]
    WebhookHandler -->|7. Dispatches PR Scan| PRScanner[PR Diff & Scanner Engine]
    PRScanner -->|8. Four-Dimension Categorization| FindingDiff[NEW / RESOLVED / UNCHANGED / REGRESSED]
    FindingDiff -->|9. Gated Publication| Publisher[PR Summary Publisher]
    Publisher -->|10. Posts Markdown (If Authorized)| GitHubPR[GitHub PR Comment]
```

### Authentication Modes
1. **GitHub App (Recommended for Teams):** Uses GitHub App Installation tokens, short-lived tokens, and granular permission boundaries.
2. **Fine-Grained Personal Access Token (PAT):** Scoped strictly to target repositories with `contents: read` and `pull_requests: read/write`.

---

## 4. Credential Storage Security

- **Encryption Algorithm:** Symmetric authenticated encryption using `Fernet` (AES-128 in CBC mode with HMAC-SHA256 authenticated integrity), key-derived from `settings.SECRET_KEY`.
- **Database Fields:** Stored in `github_integrations.encrypted_credentials`. No plaintext token is ever logged or exposed in API serialization models (`GitHubInstallationResponse` masks secrets).
- **Webhook Secrets:** Hashed with random 16-byte cryptographic salt and SHA-256 for tamper-proof storage in `webhook_secret_hash`.

---

## 5. PR Analysis & Finding Categorization Workflow

When a PR scan is triggered (via webhook or CI/CD endpoint):
1. **Changed Files Detection:** RepoShield determines the list of modified files between `base_commit_sha` and `head_commit_sha`.
2. **Scanner Execution:** Active security scanners (Semgrep, Bandit, pip-audit, Gitleaks) run against the workspace.
3. **Commit Association:** Every finding is linked directly to the `head_commit_sha` and its source line reference.
4. **Four-Dimension Categorization:**
   - **`NEW`:** Finding was not present on the base branch and is reported on a changed file.
   - **`RESOLVED`:** Finding existed on the base branch within a modified file and is no longer detected on head.
   - **`UNCHANGED`:** Finding existed on base and remains detected on head.
   - **`REGRESSED`:** New finding detected on an unchanged file (e.g. indirect dependency or side-effect flaw).

---

## 6. Gated PR Summary Commenting & Truth in Evidence

Posting comments to GitHub requires passing two security gates:
1. **Operator Policy Consent:** `link.publish_pr_comments == True`.
2. **Verified Permission:** GitHub installation holds `pull_requests: write`.

### Omission & Incomplete Check Auditing
If any security tool encounters an execution timeout, missing binary, or syntax failure:
- The check is captured in `incomplete_checks`.
- The PR comment displays a prominent `> [!WARNING]` banner.
- The status is marked as `PARTIAL` or `INCONCLUSIVE`.
- **RepoShield will NEVER report a "clean" or "passed" status when checks failed or were omitted.**

---

## 7. Webhook Security Architecture

All incoming webhooks at `/api/v1/integrations/github/webhook` are protected with:
1. **Constant-Time HMAC-SHA256 Verification:** `hmac.compare_digest` verifies `X-Hub-Signature-256` against the shared secret, preventing timing attacks.
2. **Replay Attack Defense:** The `X-GitHub-Delivery` GUID is logged in the `webhook_deliveries` table. Any duplicate delivery ID is rejected with an audit log alert.
3. **Missing Header Rejection:** Webhook requests missing the signature header are immediately rejected with `401 Unauthorized`.

---

## 8. Graceful Handling of Revoked Credentials

When an API request to GitHub returns `401 Bad Credentials`:
1. The client raises `RevokedCredentialError`.
2. The `github_integrations` record is marked `is_active = False` with `revoked_at` timestamp.
3. An audit log event `GITHUB_INSTALLATION_REVOKED` is created.
4. RepoShield informs the user via the API and UI to re-authenticate or generate a new fine-grained token.
