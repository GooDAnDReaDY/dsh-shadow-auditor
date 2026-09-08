/**
 * @file secrets.js
 * Enhanced Secret Scanner with Shannon Entropy and multi-pattern detection for diff gate.
 */

import { createFinding, Category, Severity } from './schema.js';

/**
 * Computes Shannon entropy (bits per character) of a string.
 */
export function calculateShannonEntropy(str) {
  if (!str || str.length === 0) return 0;
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
const ASSIGNMENT_REGEX = /(?:api[_-]?key|secret|password|token|auth[_-]?token|access[_-]?token)\s*[:=]\s*["'`]([A-Za-z0-9+/=_-]{20,})["'`]/i;

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

  // 2. High-entropy assignment check
  const assignMatch = ASSIGNMENT_REGEX.exec(line);
  if (assignMatch) {
    const candidateVal = assignMatch[1];
    // Check entropy
    const entropy = calculateShannonEntropy(candidateVal);
    // Typical base64/hex token of length >= 20 has entropy > 4.2
    if (candidateVal.length >= 24 && entropy >= 4.2) {
      const alreadyFlagged = findings.some(f => f.line === lineNum && f.ruleId === 'SEC-API-KEY');
      if (!alreadyFlagged) {
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
