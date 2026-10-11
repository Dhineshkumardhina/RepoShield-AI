export type ScannerSeverity = 'critical' | 'high' | 'medium' | 'low' | 'informational';
export type ConfidenceLevel = 'low' | 'medium' | 'high';

export interface FindingInput {
  finding_id: string;
  scanner_name: string;
  vulnerability_category: string;
  file_path: string;
  line_number: number;
  scanner_message: string;
  scanner_severity: ScannerSeverity;
  code_excerpt: string;
  data_flow_evidence: string[];
  dependency_info?: string;
  user_authorized_analysis: boolean;
}

export interface AnalysisOutput {
  finding_summary: string;
  vulnerability_category: string;
  evidence_observed: string[];
  reasoning_summary: string;
  potential_impact: string;
  confidence: ConfidenceLevel;
  missing_evidence: string[];
  recommended_remediation: string[];
  suggested_tests: string[];
  limitations: string[];
}

export interface ValidationError {
  field: string;
  message: string;
  ruleViolated?: string;
}

export interface ValidationResult {
  valid: boolean;
  errors: ValidationError[];
  sanitizedInput?: FindingInput;
  warnings?: string[];
}

export interface TestCase {
  id: string;
  name: string;
  description: string;
  category: 'malformed_input' | 'incomplete_input' | 'adversarial_injection' | 'secret_leak' | 'insufficient_context' | 'valid_finding';
  input: Partial<FindingInput>;
  expectedResult: 'validation_error' | 'success';
  expectedErrorField?: string;
  verificationRule: string;
}
