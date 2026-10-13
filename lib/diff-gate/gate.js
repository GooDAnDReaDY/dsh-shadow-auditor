/**
 * @file gate.js
 * Diff Gate Orchestration: unified diff parser, suppression engine, and scanner runner.
 * Includes LRU caching by sha256(content) + rulesetVersion (#98).
 */

import { createHash } from 'node:crypto';
import { GateMode, createScanResult } from './schema.js';
import { scanLineForSecrets } from './secrets.js';
import { scanLineForSast } from './sast.js';
import { scanLineForPromptInjection } from './prompt-injection.js';

const MAX_DIFF_BYTES = 512 * 1024; // 512 KiB limit to protect memory and event loop
const MAX_LINE_LENGTH = 2048; // Protect regex engines from minified lines
const SUPPRESSION_REGEX = /(?:\/\/|#|<!--)\s*shadow-audit-ignore:\s*([A-Za-z0-9_-]+|all)/i;

const DIFF_CACHE_LIMIT = 512;
const diffScanCache = new Map();
let currentRulesetVersion = 'v1.0.0';

/**
 * Updates or invalidates the ruleset version, causing cache misses for obsolete rules (#98).
 * @param {string} version
 */
export function setRulesetVersion(version) {
  if (version && typeof version === 'string') {
    currentRulesetVersion = version;
    diffScanCache.clear();
  }
}

/**
 * Clears the diff scan cache (#98).
 */
export function clearDiffScanCache() {
  diffScanCache.clear();
}

/**
 * Returns the current cache size (#98).
 * @returns {number}
 */
export function getDiffScanCacheSize() {
  return diffScanCache.size;
}

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
 * Test files (test/**, *.test.*, *.spec.*) often test prompt injection payloads intentionally.
 * Markdown and text documentation files may also document prompt injection patterns.
 */
function isTestOrDocFile(filename) {
  if (!filename || typeof filename !== 'string') return false;
  return /(?:^|[\\/])(?:test|tests|__tests__|fixtures)[\\/]/.test(filename) ||
    /\.(?:test|spec)\.[a-z0-9]+$/i.test(filename);
}

/**
 * Scans a unified diff string or set of file changes with LRU caching (#98).
 * @param {Object} params
 * @param {string} params.diffText - The unified diff text to scan.
 * @param {string} [params.filePath] - Optional fallback file path.
 * @param {Object} [params.options] - Configuration options.
 * @param {string} [params.options.mode='warning'] - GateMode ('disabled' | 'warning' | 'block').
 * @param {boolean} [params.options.enableSecrets=true] - Enable secret scanning.
 * @param {boolean} [params.options.enableSast=true] - Enable SAST scanning.
 * @param {boolean} [params.options.enablePromptInjection=true] - Enable PI scanning.
 * @param {string[]} [params.options.ignoredRules=[]] - List of suppressed rule IDs.
 * @param {boolean} [params.options.useCache=true] - Whether to consult the LRU cache.
 * @returns {Object} ScanResult
 */
export function scanDiff({ diffText = '', filePath = 'unknown', options = {} }) {
  const mode = options.mode || GateMode.WARNING;
  if (mode === GateMode.DISABLED) {
    return createScanResult({ findings: [], suppressed: [], mode });
  }

  const useCache = options.useCache !== false;
  const ignoredRules = Array.isArray(options.ignoredRules) ? options.ignoredRules : [];
  const enableSecrets = options.enableSecrets !== false;
  const enableSast = options.enableSast !== false;
  const enablePromptInjection = options.enablePromptInjection !== false;

  let cacheKey = null;
  if (useCache && typeof diffText === 'string') {
    const hash = createHash('sha256').update(diffText).digest('hex');
    const optTag = `${filePath}:${mode}:${enableSecrets}:${enableSast}:${enablePromptInjection}:${ignoredRules.sort().join(',')}`;
    cacheKey = `${currentRulesetVersion}:${hash}:${optTag}`;

    if (diffScanCache.has(cacheKey)) {
      const cached = diffScanCache.get(cacheKey);
      // Refresh key for LRU eviction order
      diffScanCache.delete(cacheKey);
      diffScanCache.set(cacheKey, cached);
      return cached;
    }
  }

  // Guard against massive payloads
  const text = typeof diffText === 'string' ? diffText.slice(0, MAX_DIFF_BYTES) : '';
  const lines = text.split('\n');

  const findings = [];
  const suppressed = [];

  let currentFile = filePath;
  let currentLineNum = 1;
  let lastDirective = null;

  // We only inspect added/modified lines in the diff (starting with '+')
  // Or all lines if it's raw content (not a diff starting with '---' / '+++').
  // Hoisted outside loop to avoid O(N*M) redundant scans on large diffs (#66).
  const isUnifiedDiff = options.isUnifiedDiff !== undefined
    ? Boolean(options.isUnifiedDiff)
    : (text.includes('--- a/') || text.includes('+++ b/') || /^@@\s+-\d+(?:,\d+)?\s+\+\d+(?:,\d+)?\s+@@/m.test(text));

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

    // Truncate overly long lines (e.g. minified bundles) to protect CPU
    if (lineToScan.length > MAX_LINE_LENGTH) {
      lineToScan = lineToScan.slice(0, MAX_LINE_LENGTH);
    }

    // Run enabled analyzers
    const lineFindings = [];
    if (enableSecrets) {
      lineFindings.push(...scanLineForSecrets(lineToScan, currentLineNum, currentFile));
    }
    if (enableSast) {
      lineFindings.push(...scanLineForSast(lineToScan, currentLineNum, currentFile));
    }
    // Skip prompt injection scans on unit tests and fixtures
    if (enablePromptInjection && !isTestOrDocFile(currentFile)) {
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

  const result = createScanResult({ findings, suppressed, mode });

  if (cacheKey) {
    if (diffScanCache.size >= DIFF_CACHE_LIMIT) {
      const oldestKey = diffScanCache.keys().next().value;
      diffScanCache.delete(oldestKey);
    }
    diffScanCache.set(cacheKey, result);
  }

  return result;
}

/**
 * Scans raw file content line by line.
 */
export function scanFileContent({ content = '', filePath = 'unknown', options = {} }) {
  return scanDiff({ diffText: content, filePath, options: { ...options, isUnifiedDiff: false } });
}
