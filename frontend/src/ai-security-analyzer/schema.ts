import { FindingInput, AnalysisOutput, ValidationResult, ValidationError, ScannerSeverity } from './types';
import { redactSecretsFromCode, inspectUntrustedComments } from './redactor';

export const VALID_SEVERITIES: ScannerSeverity[] = ['critical', 'high', 'medium', 'low', 'informational'];
export const VALID_CONFIDENCE = ['low', 'medium', 'high'] as const;

export const OUTPUT_JSON_SCHEMA = {
  type: 'object',
  required: [
    'finding_summary',
    'vulnerability_category',
    'evidence_observed',
    'reasoning_summary',
    'potential_impact',
    'confidence',
    'missing_evidence',
    'recommended_remediation',
    'suggested_tests',
    'limitations'
  ],
  properties: {
    finding_summary: { type: 'string', minLength: 10 },
    vulnerability_category: { type: 'string', minLength: 3 },
    evidence_observed: { type: 'array', items: { type: 'string' } },
    reasoning_summary: { type: 'string', minLength: 10 },
    potential_impact: { type: 'string', minLength: 5 },
    confidence: { type: 'string', enum: ['low', 'medium', 'high'] },
    missing_evidence: { type: 'array', items: { type: 'string' } },
    recommended_remediation: { type: 'array', items: { type: 'string' } },
    suggested_tests: { type: 'array', items: { type: 'string' } },
    limitations: { type: 'array', items: { type: 'string' } }
  },
  additionalProperties: false
};

/**
 * Validates and sanitizes structured security finding input.
 * Enforces Rule 1, 6, 7, 8.
 */
export function validateFindingInput(input: Partial<FindingInput>): ValidationResult {
  const errors: ValidationError[] = [];
  const warnings: string[] = [];

  // Required Field Checks
  if (!input.finding_id || typeof input.finding_id !== 'string' || !input.finding_id.trim()) {
    errors.push({ field: 'finding_id', message: 'Finding identifier is required and must be a non-empty string.' });
  }

  if (!input.scanner_name || typeof input.scanner_name !== 'string' || !input.scanner_name.trim()) {
    errors.push({ field: 'scanner_name', message: 'Scanner name is required and must be a non-empty string.' });
  }

  if (!input.vulnerability_category || typeof input.vulnerability_category !== 'string' || !input.vulnerability_category.trim()) {
    errors.push({ field: 'vulnerability_category', message: 'Vulnerability category is required.' });
  }

  if (!input.file_path || typeof input.file_path !== 'string' || !input.file_path.trim()) {
    errors.push({ field: 'file_path', message: 'File path is required and cannot be empty.' });
  } else if (input.file_path.includes('\0') || input.file_path.length > 512) {
    errors.push({ field: 'file_path', message: 'File path contains illegal characters or exceeds maximum length.' });
  }

  if (typeof input.line_number !== 'number' || isNaN(input.line_number) || input.line_number <= 0 || !Number.isInteger(input.line_number)) {
    errors.push({
      field: 'line_number',
      message: 'Line number must be a positive integer greater than zero (1-indexed).'
    });
  }

  if (!input.scanner_message || typeof input.scanner_message !== 'string' || !input.scanner_message.trim()) {
    errors.push({ field: 'scanner_message', message: 'Scanner message is required.' });
  }

  if (!input.scanner_severity || !VALID_SEVERITIES.includes(input.scanner_severity as ScannerSeverity)) {
    errors.push({
      field: 'scanner_severity',
      message: `Invalid severity '${input.scanner_severity}'. Allowed values: ${VALID_SEVERITIES.join(', ')}.`
    });
  }

  if (typeof input.code_excerpt !== 'string') {
    errors.push({ field: 'code_excerpt', message: 'Code excerpt must be provided as a string.' });
  } else if (!input.code_excerpt.trim()) {
    errors.push({ field: 'code_excerpt', message: 'Code excerpt cannot be empty. Context is required for analysis.' });
  }

  if (!Array.isArray(input.data_flow_evidence)) {
    errors.push({ field: 'data_flow_evidence', message: 'Data flow evidence must be an array of evidence strings.' });
  }

  // Rule 8: Explicit Authorization Check
  if (input.user_authorized_analysis !== true) {
    errors.push({
      field: 'user_authorized_analysis',
      message: 'Analysis blocked: Explicit user authorization is required before processing repository content (Rule #8).',
      ruleViolated: 'RULE_8_EXPLICIT_AUTHORIZATION_REQUIRED'
    });
  }

  if (errors.length > 0) {
    return { valid: false, errors, warnings };
  }

  // Rule 6: Untrusted comments inspection
  const commentCheck = inspectUntrustedComments(input.code_excerpt || '');
  if (commentCheck.hasSuspiciousInstruction) {
    warnings.push(`Rule #6 Warning: Untrusted text or prompt injection attempt detected in code comments. Untrusted instructions will be neutralized.`);
  }

  // Rule 7: Secret redaction
  const redaction = redactSecretsFromCode(input.code_excerpt || '');
  let sanitizedExcerpt = input.code_excerpt || '';
  if (redaction.secretsDetectedCount > 0) {
    sanitizedExcerpt = redaction.redactedText;
    warnings.push(`Rule #7 Notice: ${redaction.secretsDetectedCount} secret(s) (${redaction.detectedTypes.join(', ')}) redacted prior to processing.`);
  }

  const sanitizedInput: FindingInput = {
    finding_id: input.finding_id!.trim(),
    scanner_name: input.scanner_name!.trim(),
    vulnerability_category: input.vulnerability_category!.trim(),
    file_path: input.file_path!.trim(),
    line_number: input.line_number!,
    scanner_message: input.scanner_message!.trim(),
    scanner_severity: input.scanner_severity as ScannerSeverity,
    code_excerpt: sanitizedExcerpt,
    data_flow_evidence: input.data_flow_evidence || [],
    dependency_info: input.dependency_info?.trim(),
    user_authorized_analysis: true
  };

  return {
    valid: true,
    errors: [],
    sanitizedInput,
    warnings
  };
}

/**
 * Validates that an AI response adheres strictly to the required JSON schema.
 */
export function validateAnalysisOutput(output: any): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  if (!output || typeof output !== 'object') {
    return { valid: false, errors: ['Output must be a valid JSON object.'] };
  }

  const requiredFields = [
    'finding_summary',
    'vulnerability_category',
    'evidence_observed',
    'reasoning_summary',
    'potential_impact',
    'confidence',
    'missing_evidence',
    'recommended_remediation',
    'suggested_tests',
    'limitations'
  ];

  for (const field of requiredFields) {
    if (!(field in output)) {
      errors.push(`Missing required field: '${field}'`);
    }
  }

  if (typeof output.finding_summary !== 'string') {
    errors.push("'finding_summary' must be a string.");
  }
  if (typeof output.vulnerability_category !== 'string') {
    errors.push("'vulnerability_category' must be a string.");
  }
  if (!Array.isArray(output.evidence_observed)) {
    errors.push("'evidence_observed' must be an array of strings.");
  }
  if (typeof output.reasoning_summary !== 'string') {
    errors.push("'reasoning_summary' must be a string.");
  }
  if (typeof output.potential_impact !== 'string') {
    errors.push("'potential_impact' must be a string.");
  }
  if (!VALID_CONFIDENCE.includes(output.confidence)) {
    errors.push(`'confidence' must be one of: 'low', 'medium', 'high'. Received: '${output.confidence}'`);
  }
  if (!Array.isArray(output.missing_evidence)) {
    errors.push("'missing_evidence' must be an array of strings.");
  }
  if (!Array.isArray(output.recommended_remediation)) {
    errors.push("'recommended_remediation' must be an array of strings.");
  }
  if (!Array.isArray(output.suggested_tests)) {
    errors.push("'suggested_tests' must be an array of strings.");
  }
  if (!Array.isArray(output.limitations)) {
    errors.push("'limitations' must be an array of strings.");
  }

  return {
    valid: errors.length === 0,
    errors
  };
}
