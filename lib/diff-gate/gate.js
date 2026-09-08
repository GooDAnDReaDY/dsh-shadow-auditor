/**
 * @file gate.js
 * Diff Gate Orchestration: unified diff parser, suppression engine, and scanner runner.
 */

import { GateMode, createScanResult } from './schema.js';
import { scanLineForSecrets } from './secrets.js';
import { scanLineForSast } from './sast.js';
import { scanLineForPromptInjection } from './prompt-injection.js';

const MAX_DIFF_BYTES = 512 * 1024; // 512 KiB limit to protect memory and event loop
const SUPPRESSION_REGEX = /(?:\/\/|#|<!--)\s*shadow-audit-ignore:\s*([A-Za-z0-9_-]+|all)/i;

/**
 * Checks if a rule is suppressed by an inline comment or configuration.
 */
function isRuleSuppressed(ruleId, inlineDirective, ignoredRules = []) {
  if (ignoredRules.includes(ruleId) || ignoredRules.includes('all')) return true;
  if (!inlineDirective) return false;
  const directive = inlineDirective.trim().toLowerCase();
  if (directive === 'all') return true;
  return directive === ruleId.toLowerCase();
}

/**
 * Scans a unified diff string or set of file changes.
 * @param {Object} params
 * @param {string} params.diffText - The unified diff text to scan.
 * @param {string} [params.filePath] - Optional fallback file path.
 * @param {Object} [params.options] - Configuration options.
 * @param {string} [params.options.mode='warning'] - GateMode ('disabled' | 'warning' | 'block').
 * @param {boolean} [params.options.enableSecrets=true] - Enable secret scanning.
 * @param {boolean} [params.options.enableSast=true] - Enable SAST scanning.
 * @param {boolean} [params.options.enablePromptInjection=true] - Enable PI scanning.
 * @param {string[]} [params.options.ignoredRules=[]] - List of suppressed rule IDs.
 * @returns {Object} ScanResult
 */
export function scanDiff({ diffText = '', filePath = 'unknown', options = {} }) {
  const mode = options.mode || GateMode.WARNING;
  if (mode === GateMode.DISABLED) {
    return createScanResult({ findings: [], suppressed: [], mode });
  }

  // Guard against massive payloads
  const text = typeof diffText === 'string' ? diffText.slice(0, MAX_DIFF_BYTES) : '';
  const lines = text.split('\n');

  const enableSecrets = options.enableSecrets !== false;
  const enableSast = options.enableSast !== false;
  const enablePromptInjection = options.enablePromptInjection !== false;
  const ignoredRules = Array.isArray(options.ignoredRules) ? options.ignoredRules : [];

  const findings = [];
  const suppressed = [];

  let currentFile = filePath;
  let currentLineNum = 1;
  let lastDirective = null;

  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i];

    // Diff header parsing (e.g. +++ b/path/to/file)
    if (rawLine.startsWith('+++ b/')) {
      currentFile = rawLine.slice(6).trim();
      currentLineNum = 1;
      lastDirective = null;
      continue;
    }

    // Hunk header parsing (e.g. @@ -10,4 +15,6 @@)
    if (rawLine.startsWith('@@')) {
      const match = /\+(\d+)/.exec(rawLine);
      if (match) {
        currentLineNum = parseInt(match[1], 10);
      }
      lastDirective = null;
      continue;
    }

    // We only inspect added/modified lines in the diff (starting with '+')
    // Or all lines if it's raw content (not a diff starting with '---' / '+++')
    const isUnifiedDiff = text.includes('--- a/') || text.includes('+++ b/') || text.includes('@@');
    let lineToScan = rawLine;
    let isAddition = true;

    if (isUnifiedDiff) {
      if (rawLine.startsWith('+') && !rawLine.startsWith('+++')) {
        lineToScan = rawLine.slice(1);
        isAddition = true;
      } else {
        isAddition = false;
        // Still track line numbers and inline directives in context lines
        if (!rawLine.startsWith('-')) {
          currentLineNum++;
        }
      }
    }

    // Check for inline suppression directive on current line or context line
    const dirMatch = SUPPRESSION_REGEX.exec(rawLine);
    if (dirMatch) {
      lastDirective = dirMatch[1];
    }

    if (!isAddition) continue;

    // Run enabled analyzers
    const lineFindings = [];
    if (enableSecrets) {
      lineFindings.push(...scanLineForSecrets(lineToScan, currentLineNum, currentFile));
    }
    if (enableSast) {
      lineFindings.push(...scanLineForSast(lineToScan, currentLineNum, currentFile));
    }
    if (enablePromptInjection) {
      lineFindings.push(...scanLineForPromptInjection(lineToScan, currentLineNum, currentFile));
    }

    for (const f of lineFindings) {
      if (isRuleSuppressed(f.ruleId, lastDirective, ignoredRules)) {
        suppressed.push({ ...f, suppressionReason: lastDirective ? `inline: ${lastDirective}` : 'configured' });
      } else {
        findings.push(f);
      }
    }

    // Consume directive if applied, or advance line number
    currentLineNum++;
    if (!rawLine.includes('shadow-audit-ignore')) {
      lastDirective = null;
    }
  }

  return createScanResult({ findings, suppressed, mode });
}

/**
 * Scans raw file content line by line.
 */
export function scanFileContent({ content = '', filePath = 'unknown', options = {} }) {
  return scanDiff({ diffText: content, filePath, options });
}
