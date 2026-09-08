/**
 * @file schema.js
 * Normalized Security Finding, Rule definitions and ScanResult schema for Diff Gate.
 */

export const Severity = Object.freeze({
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  INFO: 'info'
});

export const Category = Object.freeze({
  SECRET: 'secret',
  INSECURE_CODE: 'insecure-code',
  PROMPT_INJECTION: 'prompt-injection',
  COMMAND_SAFETY: 'command-safety'
});

export const GateMode = Object.freeze({
  DISABLED: 'disabled',
  WARNING: 'warning',
  BLOCK: 'block'
});

export const RuleRegistry = Object.freeze({
  // Secrets
  'SEC-API-KEY': {
    id: 'SEC-API-KEY',
    category: Category.SECRET,
    severity: Severity.CRITICAL,
    name: 'Hardcoded API Key or Token',
    explanation: 'Detected hardcoded API credential or service token in code modification.',
    remediation: 'Extract the token into an environment variable or secure credential store.'
  },
  'SEC-PRIVATE-KEY': {
    id: 'SEC-PRIVATE-KEY',
    category: Category.SECRET,
    severity: Severity.CRITICAL,
    name: 'Embedded Private Key or Certificate',
    explanation: 'Detected embedded asymmetric private key (RSA, EC, OPENSSH) in diff.',
    remediation: 'Do not commit private keys. Reference key files via path in configuration.'
  },
  'SEC-HIGH-ENTROPY': {
    id: 'SEC-HIGH-ENTROPY',
    category: Category.SECRET,
    severity: Severity.HIGH,
    name: 'High-Entropy Secret Literal',
    explanation: 'Detected high-entropy literal string characteristic of a cryptographic secret.',
    remediation: 'Review string literal and move any sensitive secret to environment configuration.'
  },

  // SAST / Insecure Code Patterns
  'SAST-SQLI-001': {
    id: 'SAST-SQLI-001',
    category: Category.INSECURE_CODE,
    severity: Severity.HIGH,
    name: 'Potential SQL Injection',
    explanation: 'Dynamic string concatenation or interpolation used within a database query.',
    remediation: 'Use parameterized queries or prepared statements instead of string concatenation.'
  },
  'SAST-CMD-001': {
    id: 'SAST-CMD-001',
    category: Category.INSECURE_CODE,
    severity: Severity.CRITICAL,
    name: 'Unsafe Shell Command Interpolation',
    explanation: 'Dynamic string concatenation used within shell execution function (exec/spawn/Popen).',
    remediation: 'Pass arguments as an array without invoking an intermediate shell (shell: false).'
  },
  'SAST-PATH-001': {
    id: 'SAST-PATH-001',
    category: Category.INSECURE_CODE,
    severity: Severity.HIGH,
    name: 'Potential Path Traversal',
    explanation: 'Path traversal indicator (../) in filesystem access without boundary validation.',
    remediation: 'Resolve path and verify it remains within expected base directory (e.g. path.resolve).'
  },
  'SAST-HARDCODED-PASS-001': {
    id: 'SAST-HARDCODED-PASS-001',
    category: Category.INSECURE_CODE,
    severity: Severity.HIGH,
    name: 'Hardcoded Password or Secret Assignment',
    explanation: 'Plaintext password or secret assigned to variable or configuration key.',
    remediation: 'Inject passwords dynamically via environment variables or secret management.'
  },
  'SAST-CODE-EVAL-001': {
    id: 'SAST-CODE-EVAL-001',
    category: Category.INSECURE_CODE,
    severity: Severity.CRITICAL,
    name: 'Unsafe Dynamic Code Evaluation',
    explanation: 'Usage of eval() or new Function() allows arbitrary code execution.',
    remediation: 'Replace dynamic evaluation with explicit mapping or structured parser.'
  },

  // Prompt Injection Indicators
  'PI-JAILBREAK-001': {
    id: 'PI-JAILBREAK-001',
    category: Category.PROMPT_INJECTION,
    severity: Severity.HIGH,
    name: 'Prompt Injection / Instruction Override',
    explanation: 'Text modification contains patterns attempting to override agent instructions or safety policy.',
    remediation: 'Inspect the modified text to ensure it does not contain adversarial instructions.'
  },
  'PI-EXFIL-001': {
    id: 'PI-EXFIL-001',
    category: Category.PROMPT_INJECTION,
    severity: Severity.CRITICAL,
    name: 'Prompt Injection / System Prompt Exfiltration',
    explanation: 'Text pattern attempting to coax the agent into revealing its system prompt or credentials.',
    remediation: 'Sanitize untrusted content before presenting it to agent reasoning contexts.'
  }
});

/**
 * Creates a normalized Finding object.
 */
export function createFinding({ ruleId, file, line, column = 1, evidence, explanation, remediation, severity, category }) {
  const rule = RuleRegistry[ruleId] || {};
  return {
    ruleId,
    category: category || rule.category || Category.INSECURE_CODE,
    severity: severity || rule.severity || Severity.MEDIUM,
    name: rule.name || ruleId,
    file: String(file || 'unknown'),
    line: Number(line) || 1,
    column: Number(column) || 1,
    evidence: String(evidence || ''),
    explanation: explanation || rule.explanation || 'Security rule triggered.',
    remediation: remediation || rule.remediation || 'Review and remediate according to security guidelines.'
  };
}

/**
 * Creates a normalized ScanResult summary.
 */
export function createScanResult({ findings = [], suppressed = [], mode = GateMode.WARNING }) {
  const activeFindings = Array.isArray(findings) ? findings : [];
  const activeSuppressed = Array.isArray(suppressed) ? suppressed : [];

  const stats = {
    total: activeFindings.length,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    suppressedCount: activeSuppressed.length
  };

  for (const f of activeFindings) {
    if (f.severity === Severity.CRITICAL) stats.critical++;
    else if (f.severity === Severity.HIGH) stats.high++;
    else if (f.severity === Severity.MEDIUM) stats.medium++;
    else if (f.severity === Severity.LOW) stats.low++;
    else stats.info++;
  }

  let action = 'allow';
  if (mode === GateMode.DISABLED) {
    action = 'allow';
  } else if (mode === GateMode.BLOCK) {
    // Block if there are critical or high findings
    action = (stats.critical > 0 || stats.high > 0) ? 'block' : (activeFindings.length > 0 ? 'warn' : 'allow');
  } else {
    // Warning mode
    action = activeFindings.length > 0 ? 'warn' : 'allow';
  }

  return {
    passed: action !== 'block',
    action, // 'allow' | 'warn' | 'block'
    mode,
    stats,
    findings: activeFindings,
    suppressed: activeSuppressed,
    timestamp: new Date().toISOString()
  };
}
