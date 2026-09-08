/**
 * @file sast.js
 * Lightweight, deterministic SAST patterns for diff gate inspection.
 */

import { createFinding, Category, Severity } from './schema.js';

// Deterministic language-aware SAST rules
const SAST_RULES = [
  // 1. SQL Injection via string concatenation or template literal interpolation
  {
    ruleId: 'SAST-SQLI-001',
    category: Category.INSECURE_CODE,
    severity: Severity.HIGH,
    test: (line) => {
      const isDbCall = /(?:\bquery|\bexecute|\brawQuery|\bexecuteQuery)\s*\(/i.test(line);
      const hasSqlKeywords = /(?:SELECT|INSERT\s+INTO|UPDATE\s+[A-Za-z0-9_]+\s+SET|DELETE\s+FROM)/i.test(line);
      if (isDbCall && hasSqlKeywords) {
        if (/\+/.test(line) || /\$\{/.test(line) || /f["'].*\{.*\}/.test(line)) {
          return true;
        }
      }
      return false;
    },
    explanation: 'Detected dynamic string concatenation or template interpolation within database query.',
    remediation: 'Use parameterized queries or prepared statement placeholders (e.g. $1, ?, :param).'
  },

  // 2. Command Injection in shell execution
  {
    ruleId: 'SAST-CMD-001',
    category: Category.INSECURE_CODE,
    severity: Severity.CRITICAL,
    test: (line) => {
      const isShellExec = /(?:\bexec|\bexecSync|\bos\.system|\bsubprocess\.(?:Popen|call|run))\s*\(/i.test(line);
      if (isShellExec) {
        if (/\+/.test(line) || /\$\{/.test(line) || /f["'].*\{.*\}/.test(line) || /%\s*\([a-zA-Z0-9_]+\)/.test(line)) {
          return true;
        }
        if (/shell\s*=\s*True/i.test(line) && (/[a-zA-Z0-9_]+\s*,/i.test(line) || /format\s*\(/i.test(line))) {
          return true;
        }
      }
      return false;
    },
    explanation: 'Detected dynamic command construction passed to shell execution API without argument sanitization.',
    remediation: 'Avoid shell: true and pass arguments as an immutable array to execFile or spawn.'
  },

  // 3. Path Traversal in File Operations
  {
    ruleId: 'SAST-PATH-001',
    category: Category.INSECURE_CODE,
    severity: Severity.HIGH,
    test: (line) => {
      const isFsCall = /(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|open\s*\()/.test(line);
      if (isFsCall && /(?:\.\.\/|\.\.\\\\)/.test(line)) {
        return true;
      }
      return false;
    },
    explanation: 'Detected path traversal pattern (../) within filesystem access operation.',
    remediation: 'Validate resolved target path against a whitelist or enforce base directory boundary.'
  },

  // 4. Hardcoded Password or Secret in Assignment
  {
    ruleId: 'SAST-HARDCODED-PASS-001',
    category: Category.INSECURE_CODE,
    severity: Severity.HIGH,
    test: (line) => {
      const match = /(?:password|passwd|user_password|db_password)\s*[:=]\s*["'`]([A-Za-z0-9!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]{6,})["'`]/.exec(line);
      if (match) {
        const val = match[1].toLowerCase();
        if (['password', 'changeme', 'test', 'example', 'placeholder', 'admin', 'root'].includes(val)) {
          return false;
        }
        return true;
      }
      return false;
    },
    explanation: 'Detected hardcoded plaintext password assigned directly in source code.',
    remediation: 'Inject credentials via environment variables (process.env) or credential management system.'
  },

  // 5. Unsafe Dynamic Code Evaluation
  {
    ruleId: 'SAST-CODE-EVAL-001',
    category: Category.INSECURE_CODE,
    severity: Severity.CRITICAL,
    test: (line) => {
      if (/\beval\s*\([a-zA-Z0-9_$\s+"'`]+\)/.test(line) && !/\beval\s*\(\s*["'](?:\[\]|\{\})["']\s*\)/.test(line)) {
        return true;
      }
      if (/new\s+Function\s*\(/.test(line)) {
        return true;
      }
      return false;
    },
    explanation: 'Detected unsafe dynamic code evaluation (eval / new Function) which can lead to remote code execution.',
    remediation: 'Refactor to eliminate dynamic evaluation; use structured data models or static handlers.'
  }
];

/**
 * Scans a single line for SAST security patterns.
 */
export function scanLineForSast(line, lineNum, fileName) {
  const findings = [];
  if (!line || typeof line !== 'string') return findings;

  for (const rule of SAST_RULES) {
    if (rule.test(line)) {
      findings.push(createFinding({
        ruleId: rule.ruleId,
        category: rule.category,
        severity: rule.severity,
        file: fileName,
        line: lineNum,
        evidence: `line ${lineNum}: ${line.trim().slice(0, 120)}`,
        explanation: rule.explanation,
        remediation: rule.remediation
      }));
    }
  }

  return findings;
}
