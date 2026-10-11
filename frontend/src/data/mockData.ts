import { Repository, SecurityFinding, VerificationItem, ComplianceFramework, Integration } from '../types';

export const INITIAL_VERIFICATION_ITEMS: VerificationItem[] = [
  {
    id: 'run-01',
    repo: 'xerova/auth-gateway',
    branch: 'main',
    gitHash: '7f3a9b8',
    engine: 'SAST Semgrep v1.42',
    target: 'AST TAINT ENABLED',
    findingsCount: { critical: 2, high: 1 },
    status: 'verified',
    prNumber: 418,
    prTitle: 'Fix: SQL Injection in user query handler via parameterized statements',
    message: 'Passed 24/24 unit & AST taint security regressions. Ready to auto-merge.',
    executionTime: '1m 42s',
    timestamp: '14 mins ago',
    unitTestsPassRate: '24/24',
    astTaintStatus: 'PASS',
    diff: {
      filePath: 'auth-gateway/src/dao/user_query.py',
      ruleId: 'python.sqlalchemy.security.audit.raw-sql-format',
      oldCode: [
        { line: 41, text: 'cursor.execute(f"SELECT * FROM users WHERE tenant_id = \'{tenant_id}\' AND email = \'{email}\'")' }
      ],
      newCode: [
        { line: 41, text: 'query = "SELECT * FROM users WHERE tenant_id = %s AND email = %s"' },
        { line: 42, text: 'cursor.execute(query, (tenant_id, email))  # AST-verified parameterized tuple' }
      ]
    }
  },
  {
    id: 'run-02',
    repo: 'xerova/billing-service',
    branch: 'v2.4-hotfix',
    gitHash: '4c12aa0',
    engine: 'SCA Snyk & OSV Engine',
    target: 'DEPENDENCY LOCKFILE',
    findingsCount: { high: 4, med: 2 },
    status: 'failed',
    prNumber: 402,
    prTitle: 'Upgrade jsonwebtoken to 9.0.2 to patch CVE-2022-23529',
    message: 'Regression detected in JWT signature verification test harness. Patch quarantined.',
    executionTime: '48s',
    timestamp: '42 mins ago',
    unitTestsPassRate: '19/22 (3 Failures)',
    astTaintStatus: 'FAIL',
    crashReason: 'AssertionError: Token signature verification failed under algorithm fallback test suite (ES256 -> RS256 mismatch in tests/jwt_auth_test.ts:88)',
    crashLogs: [
      '[sandbox-runner] Initializing Node v20.12.0 test container...',
      '[sandbox-runner] Applied diff patch: package.json (jsonwebtoken ^8.5.1 -> ^9.0.2)',
      '[sandbox-runner] Running test suite: npm run test:security',
      'PASS tests/billing_rates.test.ts',
      'PASS tests/stripe_webhook.test.ts',
      'FAIL tests/jwt_auth_test.ts',
      '  ● Authentication Middleware › rejects invalid RS256 signature',
      '    AssertionError: expected error [JsonWebTokenError: invalid signature] but got [TokenExpiredError: jwt expired]',
      '    at Suite.<anonymous> (tests/jwt_auth_test.ts:88:14)',
      '[AST-TAINT] Regression detected in token validation control flow graph.',
      '[QUARANTINE] Automated PR #402 quarantined. Auto-merge revoked.'
    ]
  },
  {
    id: 'run-03',
    repo: 'xerova/core-api',
    branch: 'feature/oauth2',
    gitHash: 'e88b3f1',
    engine: 'AST Fix-Verifier v2.1',
    target: 'DYNAMIC SANDBOX',
    findingsCount: { high: 1, low: 1 },
    status: 'inconclusive',
    prNumber: 391,
    prTitle: 'Remediate CWE-798: Rotate hardcoded OAuth client secret with Vault loader',
    message: 'Sandbox ephemeral mock DB connection timed out at 120s. Awaiting manual rerun.',
    executionTime: '3m 10s',
    timestamp: '2 hours ago',
    unitTestsPassRate: 'Pending sandbox restart',
    astTaintStatus: 'TIMEOUT',
    crashReason: 'ConnectionTimeout: Failed to connect to sandbox mock Postgres db on port 5433 after 120000ms',
    crashLogs: [
      '[sandbox-runner] Spawning ephemeral PostgreSQL instance...',
      '[sandbox-runner] Injecting Vault test token: VAULT_SECRET_ACCESSOR=s.mock4982',
      '[sandbox-runner] Connecting db adapter: pg://sandbox_user:***@127.0.0.1:5433/mock_core',
      '[sandbox-runner] [TIMEOUT] 120.0s elapsed without handshake acknowledgement.',
      '[sandbox-runner] Runner terminated with exit code 143 (SIGTERM).'
    ]
  },
  {
    id: 'run-04',
    repo: 'xerova/payment-gateway',
    branch: 'main',
    gitHash: '910da34',
    engine: 'Secrets Trufflehog v3.1',
    target: 'ENTROPY & REGEX',
    findingsCount: {},
    status: 'clean',
    message: 'Passed all compliance rule gates. No patch required.',
    executionTime: '24s',
    timestamp: '3 hours ago',
    astTaintStatus: 'PASS'
  },
  {
    id: 'run-05',
    repo: 'xerova/identity-provider',
    branch: 'main',
    gitHash: 'b49f10a',
    engine: 'SAST Semgrep v1.42',
    target: 'AST TAINT ENABLED',
    findingsCount: { critical: 1, med: 1 },
    status: 'verified',
    prNumber: 422,
    prTitle: 'Fix: Sanitize redirect_uri in OAuth2 authorization endpoint (CWE-601)',
    message: 'Passed 32/32 SSRF & open-redirect AST taint assertions.',
    executionTime: '1m 15s',
    timestamp: '3 hours ago',
    unitTestsPassRate: '32/32',
    astTaintStatus: 'PASS',
    diff: {
      filePath: 'identity-provider/src/routes/authorize.ts',
      ruleId: 'ts.express.security.audit.open-redirect',
      oldCode: [
        { line: 55, text: 'res.redirect(req.query.redirect_uri as string);' }
      ],
      newCode: [
        { line: 55, text: 'const validatedUrl = validateWhitelistedRedirect(req.query.redirect_uri);' },
        { line: 56, text: 'res.redirect(validatedUrl);' }
      ]
    }
  },
  {
    id: 'run-06',
    repo: 'xerova/data-pipeline',
    branch: 'release/v3.0',
    gitHash: '381acde',
    engine: 'SCA Snyk & OSV Engine',
    target: 'CONTAINER BASE IMAGE',
    findingsCount: { critical: 1, high: 2 },
    status: 'verified',
    prNumber: 415,
    prTitle: 'Upgrade Alpine base image 3.18 to 3.20.1 (patch libssl CVE-2023-5363)',
    message: 'Container SBOM scanned. All 3 high/critical CVEs remediated without regression.',
    executionTime: '2m 04s',
    timestamp: '5 hours ago',
    unitTestsPassRate: '15/15',
    astTaintStatus: 'PASS'
  },
  {
    id: 'run-07',
    repo: 'xerova/order-service',
    branch: 'main',
    gitHash: 'fe902ab',
    engine: 'AST Fix-Verifier v2.1',
    target: 'DYNAMIC SANDBOX',
    findingsCount: { high: 2 },
    status: 'inconclusive',
    prNumber: 409,
    prTitle: 'Fix: Deserialization in RabbitMQ order event consumer (CWE-502)',
    message: 'Kafka ephemeral mock consumer partition rebalance delay.',
    executionTime: '2m 50s',
    timestamp: '6 hours ago',
    unitTestsPassRate: 'Awaiting retry',
    astTaintStatus: 'TIMEOUT'
  },
  {
    id: 'run-08',
    repo: 'xerova/notification-hub',
    branch: 'main',
    gitHash: '19ab482',
    engine: 'Secrets Trufflehog v3.1',
    target: 'GIT REVISION HISTORY',
    findingsCount: { high: 1 },
    status: 'failed',
    prNumber: 398,
    prTitle: 'Scrub Twilio auth token from git history and add BFG repo cleaner recipe',
    message: 'Pre-receive hook reported re-introduced secret in legacy test fixtures.',
    executionTime: '55s',
    timestamp: '7 hours ago',
    unitTestsPassRate: '12/14 (2 Failures)',
    astTaintStatus: 'FAIL'
  }
];

export const MOCK_REPOSITORIES: Repository[] = [
  {
    id: 'repo-1',
    name: 'xerova/auth-gateway',
    branch: 'main',
    gitHash: '7f3a9b8',
    engine: 'SAST Semgrep v1.42',
    target: 'AST TAINT ENABLED',
    health: 'vulnerable',
    findings: { critical: 2, high: 1, medium: 0, low: 2 },
    language: 'Python',
    lastScanned: '14 mins ago',
    coverage: 99.2,
    autoRemediate: true,
    activePr: 'PR #418'
  },
  {
    id: 'repo-2',
    name: 'xerova/billing-service',
    branch: 'v2.4-hotfix',
    gitHash: '4c12aa0',
    engine: 'SCA Snyk & OSV Engine',
    target: 'DEPENDENCY LOCKFILE',
    health: 'at-risk',
    findings: { critical: 0, high: 4, medium: 2, low: 1 },
    language: 'TypeScript / Node',
    lastScanned: '42 mins ago',
    coverage: 96.8,
    autoRemediate: false,
    activePr: 'PR #402'
  },
  {
    id: 'repo-3',
    name: 'xerova/core-api',
    branch: 'feature/oauth2',
    gitHash: 'e88b3f1',
    engine: 'AST Fix-Verifier v2.1',
    target: 'DYNAMIC SANDBOX',
    health: 'at-risk',
    findings: { critical: 0, high: 1, medium: 3, low: 1 },
    language: 'Go',
    lastScanned: '2 hours ago',
    coverage: 98.4,
    autoRemediate: true,
    activePr: 'PR #391'
  },
  {
    id: 'repo-4',
    name: 'xerova/payment-gateway',
    branch: 'main',
    gitHash: '910da34',
    engine: 'Secrets Trufflehog v3.1',
    target: 'ENTROPY & REGEX',
    health: 'secure',
    findings: { critical: 0, high: 0, medium: 0, low: 0 },
    language: 'Java / Spring',
    lastScanned: '3 hours ago',
    coverage: 100.0,
    autoRemediate: true
  },
  {
    id: 'repo-5',
    name: 'xerova/identity-provider',
    branch: 'main',
    gitHash: 'b49f10a',
    engine: 'SAST Semgrep v1.42',
    target: 'AST TAINT ENABLED',
    health: 'vulnerable',
    findings: { critical: 1, high: 0, medium: 2, low: 0 },
    language: 'TypeScript',
    lastScanned: '3 hours ago',
    coverage: 97.5,
    autoRemediate: true,
    activePr: 'PR #422'
  },
  {
    id: 'repo-6',
    name: 'xerova/data-pipeline',
    branch: 'release/v3.0',
    gitHash: '381acde',
    engine: 'SCA Snyk & OSV Engine',
    target: 'CONTAINER BASE IMAGE',
    health: 'vulnerable',
    findings: { critical: 1, high: 2, medium: 5, low: 3 },
    language: 'Python / PySpark',
    lastScanned: '5 hours ago',
    coverage: 95.0,
    autoRemediate: true,
    activePr: 'PR #415'
  },
  {
    id: 'repo-7',
    name: 'xerova/frontend-portal',
    branch: 'main',
    gitHash: 'a12bc90',
    engine: 'SAST Semgrep v1.42',
    target: 'CLIENT-SIDE XSS SCAN',
    health: 'at-risk',
    findings: { critical: 0, high: 3, medium: 4, low: 2 },
    language: 'React / Next.js',
    lastScanned: '5 hours ago',
    coverage: 98.9,
    autoRemediate: true
  },
  {
    id: 'repo-8',
    name: 'xerova/order-service',
    branch: 'main',
    gitHash: 'fe902ab',
    engine: 'AST Fix-Verifier v2.1',
    target: 'DYNAMIC SANDBOX',
    health: 'at-risk',
    findings: { critical: 0, high: 2, medium: 2, low: 0 },
    language: 'Go / gRPC',
    lastScanned: '6 hours ago',
    coverage: 99.1,
    autoRemediate: false,
    activePr: 'PR #409'
  },
  {
    id: 'repo-9',
    name: 'xerova/notification-hub',
    branch: 'main',
    gitHash: '19ab482',
    engine: 'Secrets Trufflehog v3.1',
    target: 'GIT REVISION HISTORY',
    health: 'at-risk',
    findings: { critical: 0, high: 1, medium: 1, low: 4 },
    language: 'Node.js',
    lastScanned: '7 hours ago',
    coverage: 94.2,
    autoRemediate: false,
    activePr: 'PR #398'
  },
  {
    id: 'repo-10',
    name: 'xerova/inventory-db',
    branch: 'main',
    gitHash: '883ad21',
    engine: 'SAST Semgrep v1.42',
    target: 'SQL QUERY TAINT',
    health: 'vulnerable',
    findings: { critical: 1, high: 1, medium: 0, low: 1 },
    language: 'PostgreSQL / Rust',
    lastScanned: '8 hours ago',
    coverage: 99.5,
    autoRemediate: true
  },
  {
    id: 'repo-11',
    name: 'xerova/audit-logger',
    branch: 'main',
    gitHash: '55bc812',
    engine: 'Secrets Trufflehog v3.1',
    target: 'ENTROPY SCAN',
    health: 'secure',
    findings: { critical: 0, high: 0, medium: 0, low: 0 },
    language: 'Go',
    lastScanned: '9 hours ago',
    coverage: 100.0,
    autoRemediate: true
  },
  {
    id: 'repo-12',
    name: 'xerova/search-engine-indexer',
    branch: 'main',
    gitHash: '99201ef',
    engine: 'SCA Snyk & OSV Engine',
    target: 'DEPENDENCY LOCKFILE',
    health: 'secure',
    findings: { critical: 0, high: 0, medium: 2, low: 3 },
    language: 'Java / Elasticsearch',
    lastScanned: '10 hours ago',
    coverage: 98.7,
    autoRemediate: true
  }
];

export const MOCK_FINDINGS: SecurityFinding[] = [
  {
    id: 'FIND-418',
    cve: 'CVE-2023-38501',
    cwe: 'CWE-89',
    cweName: 'SQL Injection Flaws',
    title: 'Raw string formatting in database cursor execution enables unauthenticated SQL injection',
    severity: 'critical',
    cvss: 9.8,
    repo: 'xerova/auth-gateway',
    branch: 'main',
    filePath: 'auth-gateway/src/dao/user_query.py',
    line: 41,
    engine: 'SAST Semgrep v1.42',
    ruleId: 'python.sqlalchemy.security.audit.raw-sql-format',
    description: 'HTTP request parameters tenant_id and email flow unsanitized into raw cursor.execute() call without parameterized binding.',
    taintTrace: {
      source: 'request.args.get("tenant_id") (src/routes/user.py:18)',
      flow: ['user_dao.get_by_tenant(tenant_id, email)', 'user_query.py:cursor.execute(f"SELECT...")'],
      sink: 'DB-API cursor.execute() execution sink (user_query.py:41)'
    },
    remediationStatus: 'verified_patch',
    prNumber: 418
  },
  {
    id: 'FIND-402',
    cve: 'CVE-2022-23529',
    cwe: 'CWE-798',
    cweName: 'Hardcoded Secrets & Tokens',
    title: 'Arbitrary code execution and key confusion via crafted JSON Web Token schema',
    severity: 'high',
    cvss: 8.8,
    repo: 'xerova/billing-service',
    branch: 'v2.4-hotfix',
    filePath: 'billing-service/package.json',
    line: 34,
    engine: 'SCA Snyk & OSV Engine',
    ruleId: 'snyk.npm.jsonwebtoken.cve-2022-23529',
    description: 'Vulnerable jsonwebtoken < 9.0.0 package parsed untrusted public key schema strings resulting in arbitrary method invocation.',
    taintTrace: {
      source: 'Authorization: Bearer <jwt> header',
      flow: ['jwtMiddleware(req, res, next)', 'jwt.verify(token, secretOrPublicKey)'],
      sink: 'jsonwebtoken parser execution environment'
    },
    remediationStatus: 'failed_patch',
    prNumber: 402
  },
  {
    id: 'FIND-391',
    cve: 'CVE-2024-10022',
    cwe: 'CWE-798',
    cweName: 'Hardcoded Secrets & Tokens',
    title: 'Static OAuth Client Secret committed in repository configuration file',
    severity: 'high',
    cvss: 7.5,
    repo: 'xerova/core-api',
    branch: 'feature/oauth2',
    filePath: 'core-api/config/oauth.yaml',
    line: 12,
    engine: 'AST Fix-Verifier v2.1',
    ruleId: 'trufflehog.generic.high-entropy-secret',
    description: 'Production OAuth client secret embedded in source control directly violating Zero Tolerated Secrets policy.',
    taintTrace: {
      source: 'git:e88b3f1 config/oauth.yaml',
      flow: ['viper.GetString("oauth.client_secret")', 'oauth2.NewConfig()'],
      sink: 'OAuth provider token exchange endpoint'
    },
    remediationStatus: 'in_queue',
    prNumber: 391
  },
  {
    id: 'FIND-398',
    cve: 'CVE-2024-21903',
    cwe: 'CWE-79',
    cweName: 'Cross-Site Scripting (XSS)',
    title: 'Reflected XSS via unsanitized search query in error boundary payload',
    severity: 'critical',
    cvss: 9.1,
    repo: 'xerova/frontend-portal',
    branch: 'main',
    filePath: 'frontend-portal/src/components/SearchFallback.tsx',
    line: 28,
    engine: 'SAST Semgrep v1.42',
    ruleId: 'react.security.dangerouslySetInnerHTML',
    description: 'Unescaped user input passed to dangerouslySetInnerHTML allowing DOM script injection.',
    taintTrace: {
      source: 'window.location.search params',
      flow: ['parseQueryParams()', 'SearchFallback.tsx:28 innerHTML'],
      sink: 'Client DOM rendering context'
    },
    remediationStatus: 'needs_patch'
  },
  {
    id: 'FIND-412',
    cve: 'CVE-2023-44487',
    cwe: 'CWE-400',
    cweName: 'Uncontrolled Resource Consumption (HTTP/2 Rapid Reset)',
    title: 'HTTP/2 Rapid Reset denial-of-service vulnerability in reverse proxy listener',
    severity: 'high',
    cvss: 7.5,
    repo: 'xerova/auth-gateway',
    branch: 'main',
    filePath: 'auth-gateway/nginx.conf',
    line: 19,
    engine: 'SAST Semgrep v1.42',
    ruleId: 'nginx.security.http2-rapid-reset',
    description: 'HTTP/2 stream cancellation flood can consume excessive CPU worker cycles.',
    taintTrace: {
      source: 'Client RST_STREAM frames',
      flow: ['http2 listener', 'worker connection buffer'],
      sink: 'nginx worker thread pool exhaustion'
    },
    remediationStatus: 'needs_patch'
  },
  {
    id: 'FIND-388',
    cve: 'CVE-2023-26136',
    cwe: 'CWE-22',
    cweName: 'Path Traversal',
    title: 'Relative path traversal via arbitrary filename parameter in export handler',
    severity: 'high',
    cvss: 7.8,
    repo: 'xerova/data-pipeline',
    branch: 'release/v3.0',
    filePath: 'data-pipeline/src/export/csv_writer.py',
    line: 72,
    engine: 'SAST Semgrep v1.42',
    ruleId: 'python.lang.security.audit.path-traversal-open',
    description: 'filename parameter allows directory traversal sequences ("../") escaping export sandbox directory.',
    taintTrace: {
      source: 'export_job["output_name"]',
      flow: ['os.path.join(EXPORT_DIR, filename)', 'open(full_path, "w")'],
      sink: 'Filesystem write handle'
    },
    remediationStatus: 'verified_patch'
  }
];

export const MOCK_COMPLIANCE_FRAMEWORKS: ComplianceFramework[] = [
  {
    id: 'soc2',
    name: 'SOC 2 Type II (Security & Confidentiality)',
    standard: 'AICPA TSP Section 100',
    complianceScore: 98.2,
    passedControls: 68,
    totalControls: 70,
    status: 'Audit Ready',
    lastEvaluated: 'Today, 06:00 UTC',
    description: 'Continuous validation of vulnerability remediations, branch protection rules, and automated PR verification audit trail.'
  },
  {
    id: 'iso27001',
    name: 'ISO/IEC 27001:2022',
    standard: 'Annex A.8.25 Secure Coding',
    complianceScore: 94.6,
    passedControls: 88,
    totalControls: 93,
    status: 'Compliant',
    lastEvaluated: 'Yesterday, 22:30 UTC',
    description: 'Controls for secure system engineering principles, SAST taint enforcement, and zero-secrets policy compliance.'
  },
  {
    id: 'pci-dss',
    name: 'PCI-DSS v4.0 Requirement 6.3 & 6.4',
    standard: 'Payment Card Industry Security Standards',
    complianceScore: 100.0,
    passedControls: 44,
    totalControls: 44,
    status: 'Compliant',
    lastEvaluated: 'Today, 04:15 UTC',
    description: 'Development of secure systems and software; prevention of SQLi, XSS, and hardcoded authentication credentials.'
  },
  {
    id: 'fedramp',
    name: 'FedRAMP Moderate Baseline (Rev 5)',
    standard: 'NIST SP 800-53 RA-5 / SI-2',
    complianceScore: 91.8,
    passedControls: 112,
    totalControls: 122,
    status: 'Remediation Required',
    lastEvaluated: '2 days ago',
    description: 'Flaw remediation within 30 days for moderate vulnerabilities and 7 days for critical findings.'
  }
];

export const MOCK_INTEGRATIONS: Integration[] = [
  {
    id: 'github',
    name: 'GitHub App / CI/CD Gate',
    category: 'VCS',
    status: 'disconnected',
    version: 'GitHub App API',
    description: 'PR status check webhook synchronization, automated branch protection enforcement, and inline security comments.',
    eventsProcessed: '0 webhook payloads (Unconfigured)',
    lastSync: 'Not Configured — Requires App ID & Private Key'
  },
  {
    id: 'gitlab',
    name: 'GitLab CI / Enterprise',
    category: 'VCS',
    status: 'disconnected',
    version: 'GitLab API v4',
    description: 'Pipeline stage gates, merge request AST taint security audits, and automated merge bot credentials.',
    eventsProcessed: '0 pipeline jobs',
    lastSync: 'Not Configured'
  },
  {
    id: 'bandit',
    name: 'Bandit Python SAST',
    category: 'SAST',
    status: 'active',
    version: 'Bandit v1.9.4',
    description: 'AST-based static security analysis engine for Python code, detecting SQLi, command injection, and insecure crypto.',
    eventsProcessed: 'Integrated & Ready',
    lastSync: 'Local Python Environment'
  },
  {
    id: 'pip-audit',
    name: 'pip-audit Dependency SCA',
    category: 'SCA',
    status: 'active',
    version: 'OSV / PyPI Advisory DB',
    description: 'Software composition analysis auditing Python requirements against real-time advisory databases.',
    eventsProcessed: 'Integrated & Ready',
    lastSync: 'Connected to Advisory DB'
  },
  {
    id: 'secrets',
    name: 'RepoShield Secret Redactor',
    category: 'Secrets',
    status: 'active',
    version: 'Engine v1.0.0',
    description: 'High-entropy and regex verified secret detection and sanitization across AWS, GitHub, JWT, and database keys.',
    eventsProcessed: 'Integrated & Ready',
    lastSync: 'Active Pre-Ingestion Hook'
  },
  {
    id: 'slack',
    name: 'Slack SecOps Incident Channel',
    category: 'Alerting',
    status: 'disconnected',
    version: 'Webhook v2',
    description: 'Real-time notifications for critical zero-day discoveries and failed fix verification regressions.',
    eventsProcessed: '0 alerts dispatched',
    lastSync: 'Not Configured — Awaiting Webhook URL'
  }
];
