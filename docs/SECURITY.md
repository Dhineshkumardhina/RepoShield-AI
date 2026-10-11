# RepoShield AI - Security Policy & Threat Model

RepoShield AI is an Application Security platform. As an AppSec tool, it adheres strictly to industry best practices and defensive engineering principles.

---

## 1. Secrets Management

- **Zero Hardcoded Secrets**: Secrets must never be committed to Git. `.gitignore` strictly rejects `.env`, `.pem`, `.key`, and `.db` files.
- **Frontend Isolation**: Frontend environment variables must never receive database credentials, private API keys, or server secrets. All external services are proxied through the FastAPI backend.
- **Automated Secret Redaction**: Source-code excerpts submitted for analysis are run through pre-flight regex redaction to strip AWS keys, JWT tokens, and API credentials before inspection.

---

## 2. Invariant Rules for AI Security Triaging

RepoShield AI enforces 8 core invariants:

1. **Strict Line & File Grounding**: Model cannot invent hypothetical files. Every reference must correspond to real line numbers.
2. **Evidence vs. Inference Separation**: Observed AST taint traces are clearly distinguished from speculative inferences.
3. **Context Completeness**: Truncated 1-line snippets lacking caller context are classified as *Insufficient Evidence*.
4. **Benign Parameterization**: Properly parameterized SQL bindings are recognized as secure, preventing false positives.
5. **Calibrated Confidence**: Confidence scores are treated as probabilistic metrics, not proof of correctness.
6. **Prompt Injection Defense**: Comments within source code are treated as untrusted text to neutralize jailbreak attempts.
7. **Secret Scrubbing**: Discovered secrets are redacted in output.
8. **Operator Consent**: Analysis requires explicit authorization.

---

## 3. Network Hardening & HTTP Headers

All HTTP responses from the backend include:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `X-Permitted-Cross-Domain-Policies: none`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains` (enforced in production)
