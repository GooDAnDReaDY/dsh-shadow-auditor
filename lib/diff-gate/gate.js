/**
 * @file gate.js
 * Diff Gate Orchestration: unified diff parser, suppression engine, and scanner runner.
 * Includes LRU caching by sha256(content) + rulesetVersion (#98).
 * Features NFKC unicode normalization (#113), maxScanChars bounding (#114), and maxMatches capping (#115).
 */

import { createHash } from 'node:crypto';
import { GateMode, createScanResult } from './schema.js';
import { scanLineForSecrets } from './secrets.js';
import { scanLineForSast } from './sast.js';
import { scanLineForPromptInjection } from './prompt-injection.js';

export const DEFAULT_MAX_SCAN_CHARS = 10000; // 10k characters head limit for huge bundles (#114)
export const DEFAULT_MAX_MATCHES = 100; // Capped findings limit to prevent memory blowout (#115)
const MAX_DIFF_BYTES = 512 * 1024; // 512 KiB limit to protect memory and event loop
const MAX_LINE_LENGTH = 2048; // Protect regex engines from minified lines
const SUPPRESSION_REGEX = /(?:\/\/|#|<!--)\s*shadow-audit-ignore:\s*([A-Za-z0-9_-]+|all)/i;

const DIFF_CACHE_LIMIT = 512;
const diffScanCache = new Map();
let currentRulesetVersion = 'v1.0.0';

/**
 * Normalizes unicode string using NFKC compatibility decomposition (#113).
 * Neutralizes mathematical alphanumeric symbols and homoglyphic font evasion attempts.
 * @param {string} str
 * @returns {string}
 */
export function normalizeNfkc(str) {
  if (typeof str !== 'string' || str.length === 0) return '';
  return str.normalize('NFKC');
}

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
 * @param {number} [params.options.maxScanChars=10000] - Head scan limit for large documents (#114).
 * @param {number} [params.options.maxMatches=100] - Cap on accumulated findings (#115).
 * @param {string[]} [params.options.ignoredRules=[]] - List of suppressed rule IDs.
 * @param {boolean} [params.options.useCache=true] - Whether to consult the LRU cache.
 * @returns {Object} ScanResult
 */
export function scanDiff({ diffText = '', filePath = 'unknown', options = {} }) {
  const mode = options.mode || GateMode.WARNING;
  if (mode === GateMode.DISABLED) {
    return createScanResult({ findings: [], suppressed: [], mode, truncated: false, matchesCapped: false });
  }

  const useCache = options.useCache !== false;
  const ignoredRules = Array.isArray(options.ignoredRules) ? options.ignoredRules : [];
  const enableSecrets = options.enableSecrets !== false;
  const enableSast = options.enableSast !== false;
  const enablePromptInjection = options.enablePromptInjection !== false;

  const isUnifiedDiff = options.isUnifiedDiff !== undefined
    ? Boolean(options.isUnifiedDiff)
    : (diffText.includes('--- a/') || diffText.includes('+++ b/') || /^@@\s+-\d+(?:,\d+)?\s+\+\d+(?:,\d+)?\s+@@/m.test(diffText));

  const maxScanChars = typeof options.maxScanChars === 'number'
    ? options.maxScanChars
    : (isUnifiedDiff ? MAX_DIFF_BYTES : DEFAULT_MAX_SCAN_CHARS);

  const maxMatches = typeof options.maxMatches === 'number'
    ? options.maxMatches
    : DEFAULT_MAX_MATCHES;

  let cacheKey = null;
  if (useCache && typeof diffText === 'string') {
    const hash = createHash('sha256').update(diffText).digest('hex');
    const optTag = `${filePath}:${mode}:${enableSecrets}:${enableSast}:${enablePromptInjection}:${maxScanChars}:${maxMatches}:${ignoredRules.sort().join(',')}`;
    cacheKey = `${currentRulesetVersion}:${hash}:${optTag}`;

    if (diffScanCache.has(cacheKey)) {
      const cached = diffScanCache.get(cacheKey);
      diffScanCache.delete(cacheKey);
      diffScanCache.set(cacheKey, cached);
      return cached;
    }
  }

  // Guard against massive payloads via maxScanChars (#114)
  let truncated = false;
  let text = typeof diffText === 'string' ? diffText : '';
  if (text.length > maxScanChars) {
    text = text.slice(0, maxScanChars);
    truncated = true;
  }
  const lines = text.split('\n');

  const findings = [];
  const suppressed = [];
  let matchesCapped = false;

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

    let lineToScan = rawLine;
    let isAddition = true;

    if (isUnifiedDiff) {
      if (rawLine.startsWith('+') && !rawLine.startsWith('+++')) {
        lineToScan = rawLine.slice(1);
        isAddition = true;
      } else {
        isAddition = false;
        if (!rawLine.startsWith('-')) {
          currentLineNum++;
        }
      }
    }

    const dirMatch = SUPPRESSION_REGEX.exec(rawLine);
    if (dirMatch) {
      lastDirective = dirMatch[1];
    }

    if (!isAddition) continue;

    // Apply Unicode NFKC normalization to counter homoglyph evasion (#113)
    lineToScan = normalizeNfkc(lineToScan);

    // Truncate overly long lines to protect regex evaluation
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
    if (enablePromptInjection && !isTestOrDocFile(currentFile)) {
      lineFindings.push(...scanLineForPromptInjection(lineToScan, currentLineNum, currentFile));
    }

    for (const f of lineFindings) {
      if (findings.length >= maxMatches) {
        matchesCapped = true;
        break;
      }
      if (isRuleSuppressed(f.ruleId, lastDirective, ignoredRules)) {
        suppressed.push({ ...f, suppressionReason: lastDirective ? `inline: ${lastDirective}` : 'configured' });
      } else {
        findings.push(f);
      }
    }

    if (matchesCapped) {
      break;
    }

    currentLineNum++;
    if (!rawLine.includes('shadow-audit-ignore')) {
      lastDirective = null;
    }
  }

  const result = createScanResult({ findings, suppressed, mode, truncated, matchesCapped });

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
  return scanDiff({
    diffText: content,
    filePath,
    options: {
      maxScanChars: options?.maxScanChars ?? DEFAULT_MAX_SCAN_CHARS,
      isUnifiedDiff: false,
      ...options
    }
  });
}
