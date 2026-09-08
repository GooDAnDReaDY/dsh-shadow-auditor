/**
 * @file prompt-injection.js
 * Prompt injection and jailbreak heuristic scanner for diff gate.
 */

import { createFinding, Category, Severity } from './schema.js';

const PI_PATTERNS = [
  {
    ruleId: 'PI-JAILBREAK-001',
    category: Category.PROMPT_INJECTION,
    severity: Severity.HIGH,
    regex: /\b(?:ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions?|disregard\s+(?:all\s+)?(?:previous|prior)\s+(?:instructions?|guidelines?|rules?)|system\s+prompt\s+override|bypass\s+(?:all\s+)?safety\s+(?:filters?|checks?)|you\s+are\s+now\s+in\s+developer\s+mode)\b/i,
    explanation: 'Detected adversarial prompt injection pattern attempting to override agent instructions.',
    remediation: 'Inspect the modified text to ensure no adversarial prompt instructions are injected.'
  },
  {
    ruleId: 'PI-EXFIL-001',
    category: Category.PROMPT_INJECTION,
    severity: Severity.CRITICAL,
    regex: /\b(?:(?:output|print|reveal|display|dump)\s+(?:the\s+)?(?:full\s+|entire\s+)?(?:system\s+prompt|hidden\s+instructions?|confidential\s+context)|repeat\s+(?:all\s+text\s+)?above\s+verbatim|send\s+(?:all\s+)?(?:env|credentials?|tokens?|keys?)\s+to)\b/i,
    explanation: 'Detected prompt injection pattern attempting to extract confidential system prompt or credentials.',
    remediation: 'Do not allow untrusted text to prompt the agent for sensitive system instructions.'
  }
];

/**
 * Scans a single line for prompt-injection markers.
 */
export function scanLineForPromptInjection(line, lineNum, fileName) {
  const findings = [];
  if (!line || typeof line !== 'string') return findings;

  for (const pat of PI_PATTERNS) {
    if (pat.regex.test(line)) {
      findings.push(createFinding({
        ruleId: pat.ruleId,
        category: pat.category,
        severity: pat.severity,
        file: fileName,
        line: lineNum,
        evidence: `line ${lineNum}: ${line.trim().slice(0, 120)}`,
        explanation: pat.explanation,
        remediation: pat.remediation
      }));
    }
  }

  return findings;
}
