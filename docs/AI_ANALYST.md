# AI Security Analyst Module

The **AI Security Analyst** module in RepoShield AI assists security engineers by translating raw scanner findings into plain-language explanations, identifying likely root causes, analyzing potential impacts, and suggesting remediation steps and targeted regression tests.

---

## 1. Core Architecture & Workflow

```
[ Real Scanner Finding ]
          │
          ▼
[ Bounded Context Retrieval ] ──▶ Traversal rejection, line boundary clamping (+/- 15 lines)
          │
          ▼
[ Secret Redaction Engine ]   ──▶ High-entropy tokens, JWTs, API keys, passwords stripped
          │
          ▼
[ Prompt Injection Guard ]    ──▶ Heuristic scan of comments & code, untrusted XML boundary
          │
          ▼
[ Constrained AI Request ]    ──▶ Google Gemini API via backend httpx client (zero browser exposure)
          │
      ┌───┴────────────────────────┐
      │ (Success)                  │ (Timeout / Failure / Offline)
      ▼                            ▼
[ Strict Pydantic Validation ] [ Deterministic AppSec Fallback Engine ]
      │                            │
      └───┬────────────────────────┘
          ▼
[ Exploitability Moderator ]  ──▶ Downgrades unproven exploitability without verified flow
          │
          ▼
[ FindingAnalysis Storage ]   ──▶ Stored separately in `finding_analyses` (finding is immutable)
          │
          ▼
[ Finding Detail Page ]       ──▶ Displayed alongside raw scanner evidence with review warnings
```

---

## 2. Key Security Principles & Guardrails

1. **Untrusted Input Treatment**: All repository source code, comments, commit messages, and README files are treated as hostile, untrusted inputs.
2. **Defend Against Prompt Injection**:
   - System prompts are declared immutable and separate from user content.
   - Code excerpts are wrapped inside unambiguous `<untrusted_source_code>` blocks.
   - Comments attempting instruction override (`"Ignore previous instructions"`, `"System prompt:"`) are detected and stripped before reaching the LLM.
3. **No Autonomous Patching**: The AI Security Analyst never applies code patches directly to repositories. All remediations are advisory and require human review followed by automated AST sandbox testing.
4. **Guardrail Against Unsupported Exploitability Claims**: The analyst refrains from asserting that a finding is definitely exploitable unless complete static data-flow evidence connecting untrusted sources directly to sinks is present. If context is truncated, exploitability is marked unproven.
5. **No Key Exposure**: The Gemini API key is configured strictly on the backend (`GEMINI_API_KEY` in environment or `.env`) and is never sent or exposed to frontend clients.
6. **Explicit User Authorization**: In compliance with zero-retention AppSec policies, repository content is only transmitted to external AI endpoints if the operator confirms the authorization toggle (`user_authorized_analysis = true`).
7. **Deterministic AppSec Fallback**: If the Gemini API is unreachable, times out, or receives rate-limiting responses, RepoShield AI falls back to a deterministic rules engine (covering SQLi, Command Injection, Hardcoded Secrets, Insecure Hash, Path Traversal, and Deserialization) to ensure high platform availability.
8. **Separation of Scanner Output & AI Output**: Scanner findings in `SecurityFinding` are strictly immutable; AI evaluations are persisted separately in `FindingAnalysis` rows linked via foreign keys.

---

## 3. API Contract

### `POST /api/v1/analyze-finding`

**Request Payload (`FindingAnalysisRequest`):**
```json
{
  "finding_id": "FIND-418",
  "repo_id": "repo-auth-gateway",
  "scanner_name": "Semgrep OSS",
  "vulnerability_category": "CWE-89: SQL Injection",
  "file_path": "auth-gateway/src/dao/user_query.py",
  "line_number": 42,
  "scanner_severity": "CRITICAL",
  "scanner_message": "Raw string interpolation formatted into cursor.execute() call",
  "code_excerpt": "cursor.execute(f\"SELECT * FROM users WHERE tenant_id = '{tenant_id}'\")",
  "data_flow_evidence": [
    "request.args.get('tenant_id')",
    "user_query.py:cursor.execute(f\"SELECT...\")"
  ],
  "user_authorized_analysis": true
}
```

**Response Payload (`FindingAnalysisResponse`):**
```json
{
  "id": "fa_981a2f4c",
  "finding_id": "FIND-418",
  "vulnerability_category": "CWE-89: SQL Injection",
  "plain_language_explanation": "Untrusted request data is interpolated directly into an SQL command string without parameterized binding.",
  "potential_impact": "Full database compromise, unauthorized record extraction, and potential authentication bypass.",
  "relevant_code_evidence": [
    "cursor.execute(f\"SELECT * FROM users WHERE tenant_id = '{tenant_id}'\")"
  ],
  "likely_root_cause": "Direct string interpolation formatted in DAO query construction.",
  "suggested_remediation": [
    "Use parameterized placeholders '%s' with query argument tuples.",
    "cursor.execute(\"SELECT * FROM users WHERE tenant_id = %s\", (tenant_id,))"
  ],
  "suggested_targeted_tests": [
    "test_sql_injection_payload_in_tenant_param_rejected()",
    "test_normal_tenant_retrieval_returns_user_record()"
  ],
  "missing_context": [
    "Router middleware authorization not captured in 30-line window"
  ],
  "limitations": [
    "Static code analysis cannot determine runtime database permissions."
  ],
  "ai_model": "gemini-1.5-flash",
  "analysis_timestamp": "2026-10-11T10:00:00Z",
  "confidence": "HIGH",
  "is_exploitable_claim_supported": true,
  "requires_human_review": true,
  "user_authorized": true
}
```

### `GET /api/v1/findings/{finding_id}/analyses`

Retrieves historical AI analyses run for a specific finding.

---

## 4. Test Suite Coverage

The module is verified through automated test suites in both backend and frontend:

- **Backend (`tests/test_analyst.py`)**:
  1. `test_valid_analysis_response`: Valid responses conforming to strict 10-field schema.
  2. `test_malformed_json_fallback_handling`: Fallback when LLM returns invalid JSON.
  3. `test_missing_fields_validation_and_safe_defaults`: Safe default handling for absent fields.
  4. `test_unsupported_vulnerability_claims_moderation`: Exploitability claims downgraded without evidence.
  5. `test_prompt_injection_in_source_files_defended`: Injection attacks in comments sanitized.
  6. `test_api_failure_and_timeout_fallback`: Deterministic fallback on API errors and timeouts.
  7. `test_incomplete_and_truncated_source_context`: Handling truncated or missing file excerpts.
  8. `test_user_authorization_toggle_enforced`: Rejection when user authorization is withheld.
  9. `test_bounded_context_prevents_path_traversal`: Protection against `../` path traversal.
  10. `test_secret_redaction_in_analyst_pipeline`: Verification that credentials never reach prompts.
  11. `test_analysis_stored_separately_from_scanner_finding`: Original scanner findings remain immutable.

- **Frontend (`frontend/src/__tests__/AiAnalyst.test.tsx` & `App.test.tsx`)**:
  - Verification of mandatory human review banners.
  - Exploitability status badges (proven vs unproven).
  - Explicit authorization consent controls.
  - Error and loading state presentation.
  - Full route integration on `/findings/:id` and `/analyzer`.
