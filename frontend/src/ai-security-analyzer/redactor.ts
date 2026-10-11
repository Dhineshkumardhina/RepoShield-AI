/**
 * RepoShield AI Security Redaction & Untrusted Text Sanitizer
 * Enforces Rule #6 (Treat comments as untrusted) & Rule #7 (Do not expose secrets)
 */

// Patterns for potential credentials/secrets
const SECRET_PATTERNS = [
  { name: 'JWT_TOKEN', regex: /eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*/g },
  { name: 'AWS_ACCESS_KEY', regex: /(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/g },
  { name: 'GENERIC_API_KEY', regex: /(?:api[_-]?key|secret|token|password|auth_token)\s*[:=]\s*['"]([A-Za-z0-9_\-.~+]{12,})['"]/gi },
  { name: 'PRIVATE_KEY_BLOCK', regex: /-----BEGIN (?:RSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA )?PRIVATE KEY-----/g },
  { name: 'DB_CONNECTION_STRING', regex: /(?:postgres|mysql|mongodb|redis):\/\/[^:\s]+:[^@\s]+@[^\s]+/gi }
];

// Adversarial prompt injection keywords in comments or repo text
const INJECTION_PATTERNS = [
  /ignore\s+(?:all\s+)?previous\s+(?:instructions|prompts|rules)/i,
  /system\s+override/i,
  /you\s+are\s+now\s+in\s+developer\s+mode/i,
  /mark\s+(?:this\s+as\s+)?(?:safe|false\s+positive|benign)/i,
  /do\s+not\s+report\s+any\s+vulnerabilities/i,
  /confidence:\s*high\s*,\s*no\s+vulnerability/i,
  /assistant:\s*output\s+json/i
];

export interface RedactionResult {
  redactedText: string;
  secretsDetectedCount: number;
  detectedTypes: string[];
}

export function redactSecretsFromCode(text: string): RedactionResult {
  let redacted = text;
  let count = 0;
  const types: string[] = [];

  for (const { name, regex } of SECRET_PATTERNS) {
    if (regex.test(redacted)) {
      count++;
      types.push(name);
      redacted = redacted.replace(regex, (match) => {
        // Redact while preserving token bounds
        const prefix = match.slice(0, 4);
        return `${prefix}...[REDACTED_SECRET_${name}]`;
      });
    }
  }

  return {
    redactedText: redacted,
    secretsDetectedCount: count,
    detectedTypes: types
  };
}

export function inspectUntrustedComments(text: string): { hasSuspiciousInstruction: boolean; detectedThreats: string[] } {
  const threats: string[] = [];
  for (const pattern of INJECTION_PATTERNS) {
    if (pattern.test(text)) {
      threats.push(`Untrusted text contains prompt injection directive matching pattern: ${pattern.toString()}`);
    }
  }
  return {
    hasSuspiciousInstruction: threats.length > 0,
    detectedThreats: threats
  };
}
