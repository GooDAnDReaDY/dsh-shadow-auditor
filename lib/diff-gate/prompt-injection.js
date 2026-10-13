/**
 * @file prompt-injection.js
 * Multilingual prompt injection and jailbreak heuristic scanner for diff gate (#76).
 * Covers instruction overrides, role switching, system prompt leaks, and tool abuse in en and zh.
 */

import { createFinding, Category, Severity } from './schema.js';

export const PI_PATTERNS = [
  {
    ruleId: 'PI-JAILBREAK-001',
    category: Category.PROMPT_INJECTION,
    severity: Severity.HIGH,
    // instruction_override: en ("ignore previous instructions") + zh (\u5ffd\u7565 / \u65e0\u89c6)
    regex: /(?:\b(?:ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions?|disregard\s+(?:all\s+)?(?:previous|prior)\s+(?:instructions?|guidelines?|rules?)|system\s+prompt\s+override|bypass\s+(?:all\s+)?safety\s+(?:filters?|checks?)|you\s+are\s+now\s+in\s+developer\s+mode)\b|(?:\u5ffd\u7565|\u65e0\u89c6|\u4e22\u5f03)(?:\u4e4b\u524d|\u6240\u6709|\u5148\u524d|\u4ee5\u4e0a)?(?:\u7684)?(?:\u6240\u6709)?(?:\u6307\u4ee4|\u63d0\u793a|\u89c4\u5219|\u8bbe\u5b9a))/i,
    explanation: 'Detected adversarial prompt injection pattern attempting to override agent instructions.',
    remediation: 'Inspect the modified text to ensure no adversarial prompt instructions are injected.'
  },
  {
    ruleId: 'PI-ROLE-001',
    category: Category.PROMPT_INJECTION,
    severity: Severity.HIGH,
    // role_switch: en ("switch role to", "you are now an unrestricted") + zh (\u4f60\u73b0\u5728\u662f, \u626e\u6f14, \u8f6c\u6362\u4e3a)
    regex: /(?:\b(?:you\s+are\s+now\s+(?:an?\s+)?(?:unrestricted\s+)?|you\s+will\s+act\s+as\s+(?:an?\s+)?|switch\s+role\s+to|pretend\s+you\s+are)\b|(?:\u4f60\u73b0\u5728\u662f|\u73b0\u5728\u4f60\u662f|\u4ece\u73b0\u5728\u5f00\u59cb|\u4f60\u626e\u6f14|\u8bf7\u626e\u6f14|\u8f6c\u6362\u4e3a|\u5047\u88c5\u4f60\u662f|\u89d2\u8272\u626e\u6f14|\u4f60\u662f))/i,
    explanation: 'Detected prompt injection attempting to switch agent role or persona.',
    remediation: 'Inspect the input to prevent unauthorized role switching or simulated persona bypasses.'
  },
  {
    ruleId: 'PI-EXFIL-001',
    category: Category.PROMPT_INJECTION,
    severity: Severity.CRITICAL,
    // system_prompt_leak: en ("repeat your system prompt", "output system prompt") + zh (\u8f93\u51fa\u7cfb\u7edf\u63d0\u793a\u8bcd)
    regex: /(?:\b(?:(?:output|print|reveal|display|dump|repeat)\s+(?:the\s+)?(?:full\s+|entire\s+|your\s+)?(?:system\s+prompt|hidden\s+instructions?|confidential\s+context)|repeat\s+(?:all\s+text\s+)?above\s+verbatim|send\s+(?:all\s+)?(?:env|credentials?|tokens?|keys?)\s+to)\b|(?:\u8f93\u51fa|\u6253\u5370|\u663e\u793a|\u544a\u8bc9\u6211|\u900f\u9732)(?:\u4f60\u7684|\u6240\u6709|\u5168\u90e8)?(?:\u7cfb\u7edf\u63d0\u793a\u8bcd|\u7cfb\u7edf\u6307\u4ee4|\u521d\u59cb\u8bbe\u5b9a|\u6838\u5fc3\u8bbe\u5b9a|\u9690\u85cf\u6307\u4ee4))/i,
    explanation: 'Detected prompt injection pattern attempting to extract confidential system prompt or credentials.',
    remediation: 'Do not allow untrusted text to prompt the agent for sensitive system instructions.'
  },
  {
    ruleId: 'PI-ABUSE-001',
    category: Category.PROMPT_INJECTION,
    severity: Severity.CRITICAL,
    // tool_abuse: en ("force call", "execute tool without") + zh (\u5f3a\u5236\u8c03\u7528, \u65e0\u9700\u786e\u8ba4)
    regex: /(?:\b(?:force\s+call|abuse\s+tool|execute\s+arbitrary\s+command|execute\s+tool\s+without)\b|(?:\u5f3a\u5236\u8c03\u7528|\u8c03\u7528|\u6ee5\u7528|\u65e0\u9700\u786e\u8ba4)(?:\u5de5\u5177|tool|\u547d\u4ee4)?.*?(?:bash|exec|run_command|eval|rm\s+-rf|tool|\u5de5\u5177))/i,
    explanation: 'Detected prompt injection pattern attempting to abuse tool invocation or run arbitrary commands.',
    remediation: 'Ensure tool execution arguments are strictly validated against tool-abuse signatures.'
  }
];

/**
 * Scans a single line for prompt-injection markers.
 */
function sanitizePIEvidence(line) {
  let text = line.trim().slice(0, 120);
  text = text.replace(/((?:key|token|secret|password|bearer)\s*[:=]\s*["'`]?)([A-Za-z0-9_\-]{8,})(["'`]?)/gi, '$1[REDACTED]$3');
  return text;
}

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
        evidence: `line ${lineNum}: ${sanitizePIEvidence(line)}`, 
        explanation: pat.explanation,
        remediation: pat.remediation
      }));
    }
  }

  return findings;
}