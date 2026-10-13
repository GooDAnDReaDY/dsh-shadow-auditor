/**
 * @file secrets.js
 * Enhanced Secret Scanner with Shannon Entropy and multi-pattern detection for diff gate (#77).
 */

import { createFinding, Category, Severity } from './schema.js';

/**
 * Computes Shannon entropy (bits per character) of a string (#77).
 * H(X) = - \sum p(x) * log2(p(x))
 * @param {string} str
 * @returns {number}
 */
export function calculateShannonEntropy(str) {
  if (!str || typeof str !== 'string' || str.length === 0) return 0;
  const freqs = new Map();
  for (let i = 0; i < str.length; i++) {
    const ch = str[i];
    freqs.set(ch, (freqs.get(ch) || 0) + 1);
  }
  let entropy = 0;
  const len = str.length;
  for (const count of freqs.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// Alias for compatibility with #77 spec (shannonEntropy)
export const shannonEntropy = calculateShannonEntropy;

/**
 * Checks whether a candidate string is a high-entropy secret token (#77).
 * Criteria:
 * - Length >= 24 characters
 * - Shannon entropy >= 4.5 bits/char
 * - At least 2 character classes (uppercase, lowercase, digits, symbols)
 * - Excludes standard UUID formats and hex SHA digests (which have low character diversity or structure)
 * @param {string} val
 * @returns {boolean}
 */
export function isHighEntropyValue(val) {
  if (typeof val !== 'string' || val.length < 24) return false;

  // Exclude standard UUIDs
  if (/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(val)) {
    return false;
  }

  // Exclude pure hex hashes (e.g. SHA-1, SHA-256, MD5) - max theoretical entropy of hex is 4.0
  if (/^[0-9a-fA-F]+$/.test(val)) {
    return false;
  }

  // Character class count (must have >= 2 classes)
  let classes = 0;
  if (/[a-z]/.test(val)) classes++;
  if (/[A-Z]/.test(val)) classes++;
  if (/[0-9]/.test(val)) classes++;
  if (/[^a-zA-Z0-9]/.test(val)) classes++;
  if (classes < 2) return false;

  const entropy = calculateShannonEntropy(val);
  return entropy >= 4.5;
}

/**
 * Safely masks a secret string to avoid echoing sensitive material.
 */
export function maskSecret(secret) {
  if (!secret) return '[REDACTED]';
  const str = String(secret);
  if (str.length <= 8) return '[REDACTED]';
  return str.slice(0, 4) + '...' + '[REDACTED]' + '...' + str.slice(-3);
}

// Known API key / secret patterns
const SECRET_PATTERNS = [
  {
    ruleId: 'SEC-API-KEY',
    name: 'OpenAI / DeepSeek / Anthropic Key',
    regex: /\b(sk-(?:proj-|ant-|live-)?[a-zA-Z0-9_-]{24,})\b/g,
    explanation: 'Detected AI provider API key format.'
  },
  {
    ruleId: 'SEC-API-KEY',
    name: 'AWS Access Key ID',
    regex: /\b(AKIA[0-9A-Z]{16})\b/g,
    explanation: 'Detected AWS IAM Access Key ID.'
  },
  {
    ruleId: 'SEC-API-KEY',
    name: 'GitHub Personal Access Token',
    regex: /\b(gh[pousr]_[A-Za-z0-9_]{36,})\b/g,
    explanation: 'Detected GitHub access token format.'
  },
  {
    ruleId: 'SEC-API-KEY',
    name: 'Slack Token',
    regex: /\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b/g,
    explanation: 'Detected Slack API token format.'
  },
  {
    ruleId: 'SEC-API-KEY',
    name: 'Generic JWT Token',
    regex: /\b(ey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g,
    explanation: 'Detected JSON Web Token (JWT) in source code.'
  },
  {
    ruleId: 'SEC-PRIVATE-KEY',
    name: 'Private Key Header',
    regex: /(-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----)/g,
    explanation: 'Detected unencrypted private key header.'
  }
];

// Contextual assignment regex for high entropy literals
const ASSIGNMENT_REGEX = /(?:api[_-]?key|secret(?:[_-]?(?:key|token))?|password|passwd|token|auth[_-]?token|access[_-]?token|private[_-]?key)\s*[:=]\s*["'`]([^\s"'`]{20,})["'`]/i;

/**
 * Scans a single line for secrets and returns findings.
 */
export function scanLineForSecrets(line, lineNum, fileName) {
  const findings = [];
  if (!line || typeof line !== 'string') return findings;

  // 1. Direct pattern matching
  for (const pat of SECRET_PATTERNS) {
    pat.regex.lastIndex = 0;
    let match;
    while ((match = pat.regex.exec(line)) !== null) {
      const rawMatch = match[1] || match[0];
      findings.push(createFinding({
        ruleId: pat.ruleId,
        category: Category.SECRET,
        severity: Severity.CRITICAL,
        file: fileName,
        line: lineNum,
        column: match.index + 1,
        evidence: `line ${lineNum}: ${line.slice(0, match.index)} ${maskSecret(rawMatch)}`,
        explanation: pat.explanation
      }));
    }
  }

  // 2. High-entropy assignment check (#77)
  const assignMatch = ASSIGNMENT_REGEX.exec(line);
  if (assignMatch) {
    const candidateVal = assignMatch[1];
    if (isHighEntropyValue(candidateVal)) {
      const alreadyFlagged = findings.some(f => f.line === lineNum && f.ruleId === 'SEC-API-KEY');
      if (!alreadyFlagged) {
        const entropy = calculateShannonEntropy(candidateVal);
        findings.push(createFinding({
          ruleId: 'SEC-HIGH-ENTROPY',
          category: Category.SECRET,
          severity: Severity.HIGH,
          file: fileName,
          line: lineNum,
          column: assignMatch.index + 1,
          evidence: `line ${lineNum}: assignment to secret variable with high entropy value (${entropy.toFixed(2)} bits/char): ${maskSecret(candidateVal)}`,
          explanation: 'Variable name indicates secret and assigned string has high cryptographic entropy.'
        }));
      }
    }
  }

  return findings;
}