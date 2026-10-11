# RepoShield AI — Contextual Risk Prioritization & Security Evidence Management

## Overview

RepoShield AI implements an evidence-based risk prioritization engine and an auditable security evidence management module.

> [!CAUTION]
> **Core Truth-in-Evidence Guardrails:**
> - **Do not invent runtime exposure, exploitability, or reachability.** If call graph or execution trace evidence is absent, reachability is recorded as `unproven`.
> - **Separation of Dimensions:** Original scanner severity, contextual priority, evidence completeness, and fix-verification status are strictly separated.
> - **No False Mathematical Claims:** Numerical priority scores are transparent triage ranking indices. They are **not** labeled or treated as validated probabilities of real-world exploitation.
> - **Hash Provenance Limits:** SHA-256 content hashes assist in detecting accidental alterations or record tampering, but a hash alone never proves the origin or authenticity of evidence.

---

## PART A — Contextual Risk Prioritization

### Four Separated Evaluation Dimensio| Dimension | Description | Possible Values |
| :--- | :--- | :--- |
| **1. Original Scanner Severity** | Raw, unmodified severity reported by the scanner tool | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL` |
| **2. RepoShield Contextual Priority** | Prioritized urgency derived strictly from verified evidence | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL` |
| **3. Evidence Completeness** | Granularity and depth of supporting context observed | `COMPLETE`, `PARTIAL`, `MINIMAL`, `INSUFFICIENT` |
| **4. Verification Status** | Fix verification lifecycle status | `NOT_TESTED`, `RUNNING`, `VERIFIED_AGAINST_DEFINED_CHECKS`, `FAILED_VERIFICATION`, `INCONCLUSIVE` |

---

### Documented Scoring Model Specification

The priority score $S \in [0.0, 100.0]$ is computed deterministically:

$$S = \text{clamp}\Big( \text{ApplyFloorProtection}\big( (\text{BaseSeverity} \times \text{ConfidenceMultiplier}) + \sum \text{Modifiers} \big), \; 0.0, \; 100.0 \Big)$$

*(See [VULNERABILITY_PRIORITIZATION_MODEL.md](file:///c:/PROJECTS/dhina%20projects/RepoShield%20AI/docs/VULNERABILITY_PRIORITIZATION_MODEL.md) for full architectural specification).*

#### 1. Base Severity Baseline
Derived from standard CVSS v3.1 qualitative intervals:
* `CRITICAL`: **80.0**
* `HIGH`: **60.0**
* `MEDIUM`: **40.0**
* `LOW`: **20.0**
* `INFORMATIONAL`: **5.0**

#### 2. Scanner Confidence Multiplier
Discounts heuristic rules with higher false-positive rates:
* `HIGH` (confidence $\ge 0.85$): **1.00**
* `MEDIUM` (confidence $0.50 - 0.84$): **0.85**
* `LOW` (confidence $< 0.50$): **0.70**
* `UNSPECIFIED` (confidence omitted): **1.00** (neutral baseline, no penalty)

#### 3. Evidence-Backed Contextual Modifiers
Modifiers are applied **only when supported by concrete evidence**:

| Factor | Evidence Condition | Impact | Rationale |
| :--- | :--- | :---: | :--- |
| **Core Security Boundary** | File or rule resides in `auth/`, `login/`, `crypto/`, `iam/`, `tokens/`, or session logic | **+10.0** | Critical architectural boundary; high exploit leverage. |
| **Public Ingress API** | File resides in API routers, controllers, HTTP endpoints, or public entrypoints | **+5.0** | Directly exposed to untrusted external requests. |
| **Internal Utility** | File resides in `utils/`, `helpers/`, `scripts/`, or internal CLI tooling | **-5.0** | Functions typically process sanitized inputs or non-serving jobs. |
| **Test Fixture Confinement** | File resides strictly in `tests/`, `test_*.py`, `mocks/`, `fixtures/`, or `samples/` | **-20.0** | Vulnerabilities strictly in test fixtures cannot be invoked in deployment. |
| **Validated by Evidence** | FindingValidation status is `SUPPORTED_BY_EVIDENCE` | **+10.0** | Affirmative code-level validation confirms flaw presence. |
| **Possible False Positive** | FindingValidation status is `POSSIBLE_FALSE_POSITIVE` | **-30.0** | Concrete refuting evidence de-prioritizes false alarms. |
| **Verified Remediation Ready** | Candidate patch proposal passed targeted verification checks | **+5.0** | Actionable fix ready to merge elevates triage scheduling. |
| **Sensitive Data Exposure** | Rule, title, or code excerpt matches credentials, private keys, API tokens, or PII | **+10.0** | Compromise of secrets or PII incurs severe operational and compliance impact. |
| **Ingress Reachability** | File resides in an API router, controller, HTTP view, or public ingress entrypoint | **+10.0** | Code directly exposed to external requests has higher exposure. |
| **Unproven Reachability** | No call graph or trace evidence available | **0.0** | Truth-in-evidence: reachability is never fabricated. |
| **Direct Production Dependency** | Package directly imported in production runtime manifest | **+5.0** | Invoked directly by application code. |
| **Transitive / Dev Dependency** | Package present only in build-time or dev requirements | **-10.0** | Excluded from deployed production artifacts. |
| **Unauthenticated Surface** | Endpoint confirmed unauthenticated and publicly accessible | **+10.0** | Any anonymous client can invoke the affected capability. |
| **Authenticated Admin / Internal** | Endpoint restricted by admin auth, mTLS, or internal service boundary | **-10.0** | Requires pre-existing privileged credentials or internal network access. |
| **Production Environment** | User-supplied environment tier: `production` | **+5.0** | Hosts live customer and business data. |
| **Non-Production Environment** | User-supplied environment tier: `development` or `staging` | **-10.0** | Does not process live customer traffic. |
| **Internet-Facing Asset** | User confirms asset is directly exposed to public Internet | **+5.0** | Subject to automated reconnaissance and untargeted bot scanning. |
| **Internal Network Perimeter** | User confirms asset is isolated from public Internet | **-5.0** | Requires internal perimeter breach to reach. |

#### 4. Severe Finding Protection Floor (Explicit Handling of Missing Context)
- In the absence of affirmative refuting evidence (test fixture, confirmed false positive, dev dependency):
  * Scanner `CRITICAL` findings cannot drop below `HIGH` (floor score: **60.0**).
  * Scanner `HIGH` findings cannot drop below `MEDIUM` (floor score: **40.0**).
- Severe findings are never silently downgraded because environmental or reachability evidence is missing.
- When evidence is insufficient, that limitation is flagged, and manual investigation is recommended.

#### 5. Priority Mapping Intervals
* **Score $\ge 80.0$** &rarr; `CRITICAL`
* **Score $60.0 - 79.9$** &rarr; `HIGH`
* **Score $40.0 - 59.9$** &rarr; `MEDIUM`
* **Score $20.0 - 39.9$** &rarr; `LOW`
* **Score $< 20.0$** &rarr; `INFORMATIONAL`

---

## PART B — Security Evidence Management

### Key Capabilities

1. **Association:** Every evidence record is linked via foreign keys to its `repository_id`, optional `scan_id`, `verification_run_id`, and `finding_id`.
2. **Timestamps:** ISO-8601 UTC timestamps recorded at ingestion (`recorded_at`, `created_at`).
3. **Multi-Tenant Authorization:** Enforces repository ownership checks. Cross-tenant access is rejected with `403 Forbidden`.
4. **Secret Scrubbing & Bounded Storage:**
   - Private keys, AWS keys, JWT tokens, API keys, and database passwords are redacted to `[REDACTED_...]`.
   - Code excerpts are bounded to 50 lines to prevent storing entire source trees.
5. **Content Hashing:** SHA-256 hash computed on sanitized payload to detect accidental tampering.
6. **Preservation of Failures:** Failed and inconclusive verification runs are preserved and included in reports.
7. **Omission Auditing:** Reports explicitly list security checks that were **not** performed (e.g. unconfigured DAST taint, missing IAST agents).
8. **Provenance Separation:** Clear visual distinction between verified scanner evidence and AI commentary.

---

### Exportable Auditable Reports

#### 1. Security Findings Report
* Endpoint: `GET /api/v1/evidence/reports/findings?repo_id={id}&format={markdown|json}`
* Contains:
  - Repository metadata and scanning timestamps
  - Prioritization summary table (Scanner Severity vs RepoShield Contextual Priority vs Verification Status)
  - Granular evidence breakdown with raw sanitized excerpts
  - Identified checks not performed
  - Governance and threat model limitations notice

#### 2. Fix Verification Report
* Endpoint: `GET /api/v1/evidence/reports/verification/{run_id}?format={markdown|json}`
* Contains:
  - Pre-patch baseline content hash (SHA-256) vs post-patch source hash
  - Evaluated unified diff with touched line numbers
  - Scanner re-run results (Resolved vs Persisting)
  - Regression check results and test summaries
  - Step-by-step traceable rationale and recorded missing evidence
  - Verification limitations notice
