/**
 * @file schema.js
 * Normalized Security Finding, Rule definitions and ScanResult schema for Diff Gate.
 * Implements benchmark attack taxonomies, prefix rule catalog (#122), and severity ranking (#123).
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

export const Family = Object.freeze({
  INSTRUCTION_INJECTION: 'instruction-injection',
  JAILBREAK: 'jailbreak',
  CREDENTIAL_LEAK: 'credential-leak',
  WORKSPACE_ESCAPE: 'workspace-escape'
});

export const GateMode = Object.freeze({
  DISABLED: 'disabled',
  WARNING: 'warning',
  BLOCK: 'block'
});

/**
 * Standardized numerical severity ranking (0..3) (#123).
 * low/info -> 0, medium -> 1, high -> 2, critical -> 3.
 * Case-insensitive, robust fallback.
 * @param {string} severity
 * @returns {number}
 */
export function severityRank(severity) {
  if (typeof severity !== 'string') return 0;
  const s = severity.trim().toLowerCase();
  switch (s) {
    case 'critical':
      return 3;
    case 'high':
      return 2;
    case 'medium':
    case 'med':
      return 1;
    case 'low':
    case 'info':
    default:
      return 0;
  }
}

/**
 * Maps numerical rank (0..3) back to canonical severity string.
 * @param {number} rank
 * @returns {string}
 */
export function rankToSeverity(rank) {
  const r = Math.max(0, Math.min(3, Math.floor(Number(rank) || 0)));
  const map = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL];
  return map[r] || Severity.LOW;
}

/**
 * Resolves highest severity string among given severities using Math.max (#123).
 * @param {...(string|string[])} severities
 * @returns {string}
 */
export function maxSeverity(...severities) {
  const list = severities.flat().filter(Boolean);
  if (list.length === 0) return Severity.LOW;
  let highest = 0;
  for (const s of list) {
    const r = severityRank(s);
    if (r > highest) highest = r;
  }
  return rankToSeverity(highest);
}

// Canonical rule catalog structured by benchmark attack taxonomies (#122)
const BASE_RULES = [
  // Credential Leak family
  {
    prefixId: 'leak-001',
    legacyId: 'SEC-API-KEY',
    family: Family.CREDENTIAL_LEAK,
    category: Category.SECRET,
    severity: Severity.CRITICAL,
    name: 'Hardcoded API Key or Token',
    explanation: 'Detected hardcoded API credential or service token in code modification.',
    remediation: 'Extract the token into an environment variable or secure credential store.'
  },
  {
    prefixId: 'leak-002',
    legacyId: 'SEC-PRIVATE-KEY',
    family: Family.CREDENTIAL_LEAK,
    category: Category.SECRET,
    severity: Severity.CRITICAL,
    name: 'Embedded Private Key or Certificate',
    explanation: 'Detected embedded asymmetric private key (RSA, EC, OPENSSH) in diff.',
    remediation: 'Do not commit private keys. Reference key files via path in configuration.'
  },
  {
    prefixId: 'leak-003',
    legacyId: 'SEC-HIGH-ENTROPY',
    family: Family.CREDENTIAL_LEAK,
    category: Category.SECRET,
    severity: Severity.HIGH,
    name: 'High-Entropy Secret Literal',
    explanation: 'Detected high-entropy literal string characteristic of a cryptographic secret.',
    remediation: 'Review string literal and move any sensitive secret to environment configuration.'
  },
  {
    prefixId: 'leak-004',
    legacyId: 'SAST-HARDCODED-PASS-001',
    family: Family.CREDENTIAL_LEAK,
    category: Category.INSECURE_CODE,
    severity: Severity.HIGH,
    name: 'Hardcoded Password or Secret Assignment',
    explanation: 'Plaintext password or secret assigned to variable or configuration key.',
    remediation: 'Inject passwords dynamically via environment variables or secret management.'
  },

  // Workspace Escape / Execution family
  {
    prefixId: 'esc-001',
    legacyId: 'SAST-PATH-001',
    family: Family.WORKSPACE_ESCAPE,
    category: Category.INSECURE_CODE,
    severity: Severity.HIGH,
    name: 'Potential Path Traversal / Boundary Escape',
    explanation: 'Path traversal indicator (../) in filesystem access without boundary validation.',
    remediation: 'Resolve path and verify it remains within expected base directory (e.g. path.resolve).'
  },
  {
    prefixId: 'esc-002',
    legacyId: 'SAST-CMD-001',
    family: Family.WORKSPACE_ESCAPE,
    category: Category.INSECURE_CODE,
    severity: Severity.CRITICAL,
    name: 'Unsafe Shell Command Interpolation',
    explanation: 'Dynamic string concatenation used within shell execution function (exec/spawn/Popen).',
    remediation: 'Pass arguments as an array without invoking an intermediate shell (shell: false).'
  },
  {
    prefixId: 'esc-003',
    legacyId: 'SAST-CODE-EVAL-001',
    family: Family.WORKSPACE_ESCAPE,
    category: Category.INSECURE_CODE,
    severity: Severity.CRITICAL,
    name: 'Unsafe Dynamic Code Evaluation',
    explanation: 'Usage of eval() or new Function() allows arbitrary code execution.',
    remediation: 'Replace dynamic evaluation with explicit mapping or structured parser.'
  },
  {
    prefixId: 'esc-004',
    legacyId: 'SAST-SQLI-001',
    family: Family.WORKSPACE_ESCAPE,
    category: Category.INSECURE_CODE,
    severity: Severity.HIGH,
    name: 'Potential SQL Injection',
    explanation: 'Dynamic string concatenation or interpolation used within a database query.',
    remediation: 'Use parameterized queries or prepared statements instead of string concatenation.'
  },

  // Instruction Injection family
  {
    prefixId: 'inj-001',
    legacyId: 'PI-JAILBREAK-001',
    family: Family.INSTRUCTION_INJECTION,
    category: Category.PROMPT_INJECTION,
    severity: Severity.HIGH,
    name: 'Prompt Injection / Instruction Override',
    explanation: 'Text modification contains patterns attempting to override agent instructions or safety policy.',
    remediation: 'Inspect the modified text to ensure it does not contain adversarial instructions.'
  },
  {
    prefixId: 'inj-002',
    legacyId: 'PI-EXFIL-001',
    family: Family.INSTRUCTION_INJECTION,
    category: Category.PROMPT_INJECTION,
    severity: Severity.CRITICAL,
    name: 'Prompt Injection / System Prompt Exfiltration',
    explanation: 'Text pattern attempting to coax the agent into revealing its system prompt or credentials.',
    remediation: 'Sanitize untrusted content before presenting it to agent reasoning contexts.'
  },

  // Jailbreak family
  {
    prefixId: 'jail-001',
    legacyId: 'PI-ROLE-001',
    family: Family.JAILBREAK,
    category: Category.PROMPT_INJECTION,
    severity: Severity.HIGH,
    name: 'Persona / Role Switching Jailbreak',
    explanation: 'Text pattern attempting to hijack persona or switch agent to unrestricted role.',
    remediation: 'Reject unauthorized role switching and maintain system guardrails.'
  },
  {
    prefixId: 'jail-002',
    legacyId: 'PI-ABUSE-001',
    family: Family.JAILBREAK,
    category: Category.PROMPT_INJECTION,
    severity: Severity.CRITICAL,
    name: 'Tool Abuse / Guard Bypass Jailbreak',
    explanation: 'Pattern attempting to force unauthorized tool execution without safety approval.',
    remediation: 'Validate tool execution parameters and enforce safety checks.'
  }
];

// Build RuleRegistry indexing both prefixId and legacyId for seamless backward compatibility
const registryMap = {};
for (const rule of BASE_RULES) {
  const entry = Object.freeze({
    id: rule.prefixId,
    prefixId: rule.prefixId,
    legacyId: rule.legacyId,
    family: rule.family,
    category: rule.category,
    severity: rule.severity,
    name: rule.name,
    explanation: rule.explanation,
    remediation: rule.remediation
  });
  registryMap[rule.prefixId] = entry;
  if (rule.legacyId) {
    registryMap[rule.legacyId] = entry;
  }
}

export const RuleRegistry = Object.freeze(registryMap);

/**
 * Retrieves rule definition by prefixId or legacyId (#122).
 * @param {string} id
 * @returns {object|undefined}
 */
export function getRuleById(id) {
  if (!id || typeof id !== 'string') return undefined;
  return RuleRegistry[id];
}

/**
 * Returns all rules belonging to a specific Family (#122).
 * @param {string} family
 * @returns {object[]}
 */
export function getRulesByFamily(family) {
  const seen = new Set();
  const res = [];
  for (const rule of Object.values(RuleRegistry)) {
    if (rule.family === family && !seen.has(rule.prefixId)) {
      seen.add(rule.prefixId);
      res.push(rule);
    }
  }
  return res;
}

/**
 * Returns all rules belonging to a specific Category (#122).
 * @param {string} category
 * @returns {object[]}
 */
export function getRulesByCategory(category) {
  const seen = new Set();
  const res = [];
  for (const rule of Object.values(RuleRegistry)) {
    if (rule.category === category && !seen.has(rule.prefixId)) {
      seen.add(rule.prefixId);
      res.push(rule);
    }
  }
  return res;
}

/**
 * Creates a normalized Finding object.
 */
export function createFinding({ ruleId, file, line, column = 1, evidence, explanation, remediation, severity, category, family }) {
  const rule = RuleRegistry[ruleId] || {};
  const effectiveSeverity = severity || rule.severity || Severity.MEDIUM;
  return {
    ruleId,
    prefixId: rule.prefixId || ruleId,
    family: family || rule.family || Family.WORKSPACE_ESCAPE,
    category: category || rule.category || Category.INSECURE_CODE,
    severity: effectiveSeverity,
    severityRank: severityRank(effectiveSeverity),
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
export function createScanResult({ findings = [], suppressed = [], mode = GateMode.WARNING, truncated = false, matchesCapped = false }) {
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
    truncated: Boolean(truncated),
    matchesCapped: Boolean(matchesCapped),
    timestamp: new Date().toISOString()
  };
}
