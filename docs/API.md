# RepoShield AI - API Reference

The RepoShield AI backend is powered by FastAPI and exposes OpenAPI/Swagger documentation at `http://127.0.0.1:8000/docs`.

---

## 1. Diagnostics & Health Endpoints

### `GET /api/v1/health`
Returns full service health, version, database connectivity, and uptime.

**Response (200 OK):**
```json
{
  "status": "ok",
  "service": "RepoShield AI",
  "version": "0.1.0",
  "environment": "development",
  "timestamp": "2026-10-10T15:25:55.890451Z",
  "database": {
    "status": "connected",
    "dialect": "sqlite"
  },
  "uptime_seconds": 12.45
}
```

### `GET /api/v1/ready`
Readiness probe for container orchestrators (Kubernetes / Docker health checks).
- `200 OK`: Database connected and responsive.
- `503 Service Unavailable`: Database ping query failed.

### `GET /api/v1/live`
Liveness probe returning `200 OK` indicating the ASGI server is active.

---

## 2. Repositories Management

### `GET /api/v1/repositories`
List registered source code repositories.
- **Query Parameters**:
  - `skip` (int, default 0)
  - `limit` (int, default 100)
  - `active_only` (bool, default true)

### `POST /api/v1/repositories`
Register a repository for AppSec monitoring.
- **Request Body**:
```json
{
  "name": "xerova/auth-gateway",
  "git_url": "https://github.com/xerova/auth-gateway",
  "default_branch": "main",
  "health_score": 84
}
```

---

## 3. Findings Ingestion & Analysis

### `GET /api/v1/findings`
Query ingested scanner findings.
- **Query Parameters**:
  - `repo_id` (string): Filter by repository ID
  - `severity` (string): `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`
  - `cwe` (string): Search string in CWE identifier
  - `status` (string): `open`, `verified`, `remediated`, `false_positive`

### `POST /api/v1/analyze-finding`
Perform objective security evaluation with automated secret redaction and prompt-injection defense.
- **Request Body**:
```json
{
  "finding_id": "FIND-418",
  "scanner_name": "Semgrep OSS",
  "vulnerability_category": "CWE-89: SQL Injection",
  "file_path": "auth-gateway/src/dao/user_query.py",
  "line_number": 42,
  "scanner_severity": "CRITICAL",
  "scanner_message": "Detected unescaped user parameter in raw SQL query string",
  "code_excerpt": "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
  "data_flow_evidence": ["user_id input parameter", "cursor.execute sink"],
  "user_authorized_analysis": true
}
```

---

## 4. Centralized Error Format

All API errors return a standardized JSON envelope with a tracking correlation `request_id`:

```json
{
  "success": false,
  "error": {
    "code": "RESOURCE_NOT_FOUND",
    "message": "Repository with id 'non-existent' not found.",
    "details": []
  },
  "request_id": "8c4599a0-128a-4cfa-8ee2-7b06883ba56e",
  "timestamp": "2026-10-10T15:30:00Z"
}
```
