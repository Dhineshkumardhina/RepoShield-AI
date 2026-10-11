# RepoShield AI — Production Deployment & Operational Safety Guide

**Xerova Digital Solutions**  
*Document Version: 1.0 | Target Environment: Production & Staging*

---

## 1. Deployment Architecture

RepoShield AI is an enterprise Application Security and Fix Verification platform. Because RepoShield analyzes untrusted third-party source code, archives, and git repositories, its deployment architecture enforces strict **zero-trust boundary isolation**.

### Architecture Overview

```mermaid
graph TD
    User([Browser / Developer / CI Client]) -->|HTTPS:443| Ingress[Reverse Proxy / Cloudflare / Nginx]
    Ingress -->|Static Assets| FrontendSPA[Frontend Hosting / Nginx Container]
    Ingress -->|/api/v1/*| APICluster[FastAPI Application Cluster]
    APICluster -->|Pooled Queries (SSL)| PostgreSQL[(Managed PostgreSQL 16)]
    APICluster -->|Scan & Verify Jobs| SandboxedWorker[Sandboxed Security Worker Container]
    
    subgraph "Untrusted Code Sandbox (Worker)"
        SandboxedWorker -->|Non-root UID 10002| ToolAST[Bandit AST Analysis]
        SandboxedWorker -->|cap_drop: ALL| ToolSAST[Semgrep Rule Engine]
        SandboxedWorker -->|pids_limit: 100| ToolSecrets[Gitleaks Secret Detection]
        SandboxedWorker -->|No Egress Network| ToolDeps[pip-audit & Pytest Sandbox]
    end

    APICluster -->|Encrypted Credentials| SecretStorage[(PostgreSQL Fernet Encrypted)]
```

### Component Responsibilities & Isolation Invariants

1. **Frontend (React / TypeScript / Vite):**
   - Served as static compiled assets (`dist/`) via an unprivileged static web server (Nginx Alpine, Cloudflare Pages, AWS S3+CloudFront, or Vercel).
   - **Critical Constraint:** Untrusted repository code or scanner binaries **MUST NEVER** execute in the frontend hosting environment. The browser is purely a presentation layer for reviewed findings and reports.
2. **Backend API (FastAPI / Gunicorn / Uvicorn):**
   - Runs in a containerized environment (AWS ECS Fargate, GCP Cloud Run, or Kubernetes) running under an unprivileged user (`reposhield:10001`).
   - Exposes REST endpoints, validates schemas with Pydantic, enforces authentication and RBAC, orchestrates jobs, and encrypts integration credentials at rest.
   - **Critical Constraint:** The backend process never runs untrusted user scripts with root or host-level privileges.
3. **Database (PostgreSQL 16):**
   - Managed relational database (AWS RDS / Aurora / GCP Cloud SQL) configured with encrypted storage (EBS/KMS AES-256) and mandatory SSL connections (`sslmode=require`).
   - SQLite is strictly blocked in production by backend configuration validators.
4. **Sandboxed Security Workers (Isolated Execution):**
   - Dedicated Linux containers running with dropped privileges (`cap_drop: ALL`), `no-new-privileges: true`, non-root user `reposhield-sandbox:10002`, `pids_limit: 100`, read-only root filesystems, and strict memory/CPU limits.
   - Offline execution flags (`PIP_NO_INDEX=1`, `NO_PROXY="*"`) prevent untrusted repositories from executing SSRF attacks or calling out to command-and-control servers during analysis.

---

## 2. Environment-Variable Checklist

All production secrets **must be injected via cloud secrets management** (AWS Secrets Manager, GCP Secret Manager, HashiCorp Vault) rather than hardcoded `.env` files.

| Environment Variable | Description | Development | Staging | Production | Secret? |
| :--- | :--- | :--- | :--- | :--- | :---: |
| `APP_NAME` | Service display name | `RepoShield AI` | `RepoShield AI [Staging]` | `RepoShield AI` | No |
| `APP_ENV` | Application runtime environment | `development` | `staging` | `production` | No |
| `DEBUG` | FastAPI debugging mode | `true` | `false` | `false` | No |
| `HOST` | Server bind IP address | `127.0.0.1` | `0.0.0.0` | `0.0.0.0` | No |
| `PORT` | ASGI listening port | `8000` | `8000` | `8000` | No |
| `DOCS_ENABLED` | OpenAPI `/docs` and `/redoc` access | `true` | `true` | `false` | No |
| `DATABASE_URL` | PostgreSQL connection string | `sqlite:///./reposhield.db` | `postgresql+psycopg://...` | `postgresql+psycopg://...` | **YES** |
| `CORS_ORIGINS` | Trusted origin whitelist | `http://localhost:5173,...` | `https://staging.reposhield.xerova.com` | `https://reposhield.xerova.com` | No |
| `SECRET_KEY` | Cryptographic key (min 32 chars) | Dev insecure fallback | 64-character hex | 64-character hex | **YES** |
| `LOG_LEVEL` | Logging verbosity | `INFO` | `INFO` | `INFO` | No |
| `LOG_FORMAT_JSON`| Structured JSON logs for telemetry | `false` | `true` | `true` | No |
| `COOKIE_NAME` | Session cookie identifier | `access_token` | `reposhield_token_staging` | `__Host-reposhield-token` | No |
| `COOKIE_SAMESITE`| Cross-site cookie attribute | `lax` | `lax` | `lax` | No |
| `COOKIE_HTTPONLY`| HttpOnly cookie flag | `true` | `true` | `true` | No |
| `MAX_UPLOAD_SIZE_BYTES` | Max ZIP upload limit (50 MB) | `52428800` | `52428800` | `52428800` | No |
| `MAX_EXTRACTED_SIZE_BYTES` | Max expansion limit (200 MB) | `209715200` | `209715200` | `209715200` | No |
| `MAX_CONCURRENT_SCANS_PER_USER` | Concurrent scan quota | `3` | `5` | `3` | No |
| `MAX_DAILY_SCANS_PER_USER` | 24-hour scan quota | `100` | `200` | `100` | No |
| `MAX_REQUEST_BODY_SIZE_BYTES` | DoS request limit (60 MB) | `62914560` | `62914560` | `62914560` | No |
| `STALE_JOB_TIMEOUT_MINUTES` | Interrupted job cutoff | `15` | `15` | `15` | No |
| `GEMINI_API_KEY` | Optional AI Analyst Key | `""` | Optional | Optional | **YES** |

---

## 3. Production Configuration Examples

* Template configuration files are provided in the repository:
  - Production environment: [`.env.production.example`](file:///c:/PROJECTS/dhina%20projects/RepoShield%20AI/.env.production.example)
  - Staging environment: [`.env.staging.example`](file:///c:/PROJECTS/dhina%20projects/RepoShield%20AI/.env.staging.example)
  - Docker Compose production stack: [`docker-compose.prod.yml`](file:///c:/PROJECTS/dhina%20projects/RepoShield%20AI/docker-compose.prod.yml)
  - Nginx TLS reverse proxy: [`nginx/production.conf`](file:///c:/PROJECTS/dhina%20projects/RepoShield%20AI/nginx/production.conf)
  - Frontend static Nginx config: [`nginx/frontend.conf`](file:///c:/PROJECTS/dhina%20projects/RepoShield%20AI/nginx/frontend.conf)

---

## 4. Database Migration Instructions

RepoShield AI uses **Alembic** for schema migrations.

### Running Migrations in Production
Before traffic is routed to a new backend release, execute migrations against the production database:

```bash
# 1. Run migrations to the latest revision (head)
alembic upgrade head

# 2. Verify current revision matches expectation
alembic current
```

### Pre-Deployment Migration Strategy
In containerized platforms (e.g., Kubernetes / AWS ECS), run migrations as an **InitContainer** or **ECS One-Off Task** prior to the main container launch:

```bash
# Example Kubernetes Job / Entrypoint migration step
docker run --rm \
  -e DATABASE_URL="$PRODUCTION_DATABASE_URL" \
  reposhield-api:latest \
  alembic upgrade head
```

### Zero-Downtime Migration Guidelines
1. **Additive Schema Changes:** Add new columns as nullable or with defaults before updating application code.
2. **Do Not Drop Columns in Same Release:** Deprecate columns in release `N`, remove usage in release `N+1`, and drop the column in release `N+2`.
3. **Automated Backups Before Migrations:** Always create a point-in-time snapshot of the database prior to executing migrations.

---

## 5. Scanner-Worker Deployment Instructions

Security scanning of third-party repositories presents code execution risks. The worker container [`Dockerfile.worker`](file:///c:/PROJECTS/dhina%20projects/RepoShield%20AI/Dockerfile.worker) is hardened with the following sandboxing parameters:

### Docker Run / Kubernetes Security Context

```yaml
# Kubernetes SecurityContext for Scanner Worker Pod
securityContext:
  runAsNonRoot: true
  runAsUser: 10002
  runAsGroup: 10002
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop:
      - ALL
resources:
  limits:
    cpu: "2000m"
    memory: "2048Mi"
  requests:
    cpu: "500m"
    memory: "512Mi"
```

### Workspace Volume Isolation
* Workspace volumes are mounted as isolated disposable scratch directories.
* Workers cannot access the host filesystem, Docker socket, or metadata APIs (`169.254.169.254`).
* Environment variables containing application secrets (`SECRET_KEY`, `DATABASE_URL`, `GEMINI_API_KEY`) are stripped by [`get_sanitized_runner_env()`](file:///c:/PROJECTS/dhina%20projects/RepoShield%20AI/backend/app/verification/workspace.py#L64) before any subprocess scanner or pytest job is executed.

---

## 6. Health-Check Configuration

The backend provides three safe, unauthenticated health probes designed for load balancers and orchestrators:

| Probe | Endpoint | Expected Response | Usage |
| :--- | :--- | :--- | :--- |
| **Liveness** | `GET /live` | `200 OK {"status": "alive"}` | Kubernetes `livenessProbe` / Container restart check |
| **Readiness**| `GET /ready` | `200 OK {"status": "ready"}` or `503 Service Unavailable` | Kubernetes `readinessProbe` / ALB target health check |
| **Diagnostics**| `GET /api/v1/health` | `200 OK` with database dialect & version | Operational dashboard status probe |

### Kubernetes Probe Manifest Example

```yaml
livenessProbe:
  httpGet:
    path: /live
    port: 8000
  initialDelaySeconds: 10
  periodSeconds: 15
  timeoutSeconds: 3
  failureThreshold: 3

readinessProbe:
  httpGet:
    path: /ready
    port: 8000
  initialDelaySeconds: 5
  periodSeconds: 10
  timeoutSeconds: 3
  failureThreshold: 2
```

---

## 7. CI Test and Build Workflow

The continuous integration pipeline is defined in [`.github/workflows/ci.yml`](file:///c:/PROJECTS/dhina%20projects/RepoShield%20AI/.github/workflows/ci.yml) and runs on all pushes and pull requests to `main` and `staging`:

1. **Backend Test Suite:**
   - Runs `python -m pytest tests/` with SQLite isolation.
   - Enforces 100% test pass rate across auth, authorization, ingestion, scanners, verification, and evidence management.
2. **Frontend Test & Build:**
   - Executes Vitest unit tests (`npm test -- --run`).
   - Compiles production TypeScript bundle via `npm run build` (`dist/`).
3. **Container Build Validation:**
   - Validates multi-stage builds for `Dockerfile.api` and `Dockerfile.worker` without publishing untagged images.

---

## 8. Monitoring & Telemetry Recommendations

### Structured Logging
In production, `LOG_FORMAT_JSON=true` emits structured single-line JSON records containing:
* `timestamp` (UTC ISO-8601)
* `request_id` (Correlation UUID for end-to-end tracing)
* `level` (`INFO`, `WARNING`, `ERROR`)
* `method`, `path`, `status_code`, `duration_ms`
* Automatic secret scrubbing: Passwords, JWTs, AWS keys, GitHub tokens, and DB connection strings are automatically scrubbed via [`scrub_log_message`](file:///c:/PROJECTS/dhina%20projects/RepoShield%20AI/backend/app/core/logging.py#L22).

### Key Performance Indicators (KPIs) & Alerts

| Metric | Target / SLA | Alert Threshold | Severity |
| :--- | :--- | :--- | :--- |
| **API Latency (p95)** | `< 250ms` for core endpoints | `> 1000ms` for 5 consecutive minutes | Warning |
| **HTTP 5xx Error Rate**| `< 0.05%` | `> 1.0%` over 5 minutes | Critical |
| **Scan Execution Time**| `< 90s` | `> 180s` | Warning |
| **DB Connection Pool Usage** | `< 60%` | `> 85%` | Critical |
| **Worker Queue Depth** | `< 10` pending scans | `> 50` pending scans | Warning |
| **Disk Space Utilization** | `< 70%` on `/app/data/workspaces` | `> 85%` | Critical |

---

## 9. Rollback Instructions

If an unexpected regression or deployment defect occurs during a rollout:

### Step 1: Revert Traffic to Previous Container Image
Immediately re-route ingress or revert the deployment manifest:
```bash
# Kubernetes rollback to previous revision
kubectl rollout undo deployment/reposhield-api
kubectl rollout undo deployment/reposhield-worker
kubectl rollout undo deployment/reposhield-frontend
```

### Step 2: Database Migration Downgrade (If Necessary)
If the deployment applied a migration that must be backed out:
```bash
# Downgrade by 1 revision
alembic downgrade -1

# Or downgrade to a specific historical revision ID
alembic downgrade 0005_evidence_management
```

### Step 3: Clear Temporary Workspaces & Reconcile Jobs
Execute the safe job reconciliation routine to clean up orphaned running tasks:
```bash
python -c "from app.db.session import SessionLocal; from app.core.quotas import reconcile_interrupted_jobs; reconcile_interrupted_jobs(SessionLocal())"
```

---

## 10. Production Readiness Checklist

### Automated Controls (Verified in Codebase)
- [x] All 87 backend automated unit, security, and integration tests passing (`87 passed, 0 failed`).
- [x] All 23 frontend Vitest component and routing tests passing (`23 passed, 0 failed`).
- [x] Frontend builds cleanly into production bundle (`vite build` in 1.6s).
- [x] SQLite blocked when `APP_ENV=production`.
- [x] Insecure/default `SECRET_KEY` blocked when `APP_ENV=production`.
- [x] Security headers (`nosniff`, `DENY`, `HSTS`, `X-Request-ID`) verified.
- [x] Request payload size limits enforced (`413 Payload Too Large` on oversized requests).
- [x] Sensitive secrets redacted automatically from JSON and standard log outputs.
- [x] Concurrency limits and daily scan quotas enforced.
- [x] Orphaned/interrupted jobs reconciled safely upon service startup.
- [x] Automated workspace cleanup utility implemented.
- [x] Sandboxed worker container definitions drop all Linux capabilities (`cap_drop: ALL`).

### Manual Infrastructure Setup (Operator Action Required)
- [ ] **DNS & TLS Certificates:** Provision DNS records for `reposhield.xerova.com` and obtain managed TLS certificates (AWS Certificate Manager or Let's Encrypt).
- [ ] **PostgreSQL Provisioning:** Create a managed PostgreSQL 16 instance with automated daily snapshots, Multi-AZ replication, and SSL connection enforcement.
- [ ] **Secrets Manager Population:** Generate a 64-character random string (`openssl rand -hex 32`) and store as `SECRET_KEY` in your cloud secrets manager.
- [ ] **Reverse Proxy / WAF:** Configure Cloudflare or AWS WAF rate limiting and DDoS protection in front of ingress.
- [ ] **Automated Backups:** Verify that automated PostgreSQL backups and WAL archiving are active.
