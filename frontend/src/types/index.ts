export type Severity = 'critical' | 'high' | 'medium' | 'low';
export type VerificationStatus = 'verified' | 'failed' | 'inconclusive' | 'clean' | 'running';
export type RepoHealth = 'secure' | 'at-risk' | 'vulnerable';

export interface Repository {
  id: string;
  name: string;
  branch: string;
  gitHash: string;
  engine: string;
  target: string;
  health: RepoHealth;
  findings: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  language: string;
  lastScanned: string;
  coverage: number;
  autoRemediate: boolean;
  activePr?: string;
}

export interface SecurityFinding {
  id: string;
  cve: string;
  cwe: string;
  cweName: string;
  title: string;
  severity: Severity;
  cvss: number;
  repo: string;
  branch: string;
  filePath: string;
  line: number;
  engine: string;
  ruleId: string;
  description: string;
  taintTrace: {
    source: string;
    flow: string[];
    sink: string;
  };
  remediationStatus: 'verified_patch' | 'failed_patch' | 'in_queue' | 'needs_patch';
  prNumber?: number;
  contextualPriority?: 'critical' | 'high' | 'medium' | 'low' | 'informational';
  priorityScore?: number;
  evidenceCompleteness?: string;
  remediationReadiness?: string;
}

export interface VerificationItem {
  id: string;
  repo: string;
  branch: string;
  gitHash: string;
  engine: string;
  target: string;
  findingsCount: {
    critical?: number;
    high?: number;
    med?: number;
    low?: number;
  };
  status: VerificationStatus;
  prNumber?: number;
  prTitle?: string;
  message: string;
  executionTime: string;
  timestamp: string;
  unitTestsPassRate?: string;
  astTaintStatus?: 'PASS' | 'FAIL' | 'TIMEOUT';
  diff?: {
    filePath: string;
    oldCode: { line: number; text: string }[];
    newCode: { line: number; text: string }[];
    ruleId: string;
  };
  crashReason?: string;
  crashLogs?: string[];
}

export interface ComplianceFramework {
  id: string;
  name: string;
  standard: string;
  complianceScore: number;
  passedControls: number;
  totalControls: number;
  status: 'Compliant' | 'Remediation Required' | 'Audit Ready';
  lastEvaluated: string;
  description: string;
}

export interface Integration {
  id: string;
  name: string;
  category: 'VCS' | 'SAST' | 'SCA' | 'Secrets' | 'Alerting' | 'Cloud';
  status: 'active' | 'syncing' | 'warning' | 'disconnected';
  version: string;
  description: string;
  eventsProcessed: string;
  lastSync: string;
}
