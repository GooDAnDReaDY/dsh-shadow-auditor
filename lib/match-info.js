/**
 * @file match-info.js
 * Zero-Leak Matches architecture (#112).
 * Ensures finding/event data structures never hold plaintext secret values.
 */

/**
 * Generates a masked safe snippet for diagnostics and logging without leaking the token (#112).
 * @param {string} val
 * @param {object} [options]
 * @returns {string}
 */
export function safeSnippet(val, options = {}) {
  if (typeof val !== 'string' || val.length === 0) return '[REDACTED]';
  const prefixLen = options.prefixLen ?? 4;
  const suffixLen = options.suffixLen ?? 4;

  if (val.startsWith('-----BEGIN')) {
    const firstLine = val.split('\n')[0] || '-----BEGIN PRIVATE KEY-----';
    return `${firstLine}... [REDACTED KEY]`;
  }

  if (val.length <= prefixLen + suffixLen) {
    return '[REDACTED]';
  }

  return `${val.slice(0, prefixLen)}...****...${val.slice(-suffixLen)}`;
}

/**
 * Creates an immutable Zero-Leak MatchInfo object (#112).
 * Guarantees by design that raw secret values are not stored.
 *
 * @param {object} params
 * @returns {Readonly<{ secretType: string, start: number, end: number, length: number, safeSnippet: string, line?: number, column?: number, description?: string }>}
 */
export function createMatchInfo(params = {}) {
  const {
    secretType,
    type,
    ruleId,
    start = 0,
    end = 0,
    length,
    line,
    column,
    rawSecret,
    snippet,
    description
  } = params;

  const actualType = secretType || type || ruleId || 'generic-secret';
  const actualLength = length ?? (end >= start ? end - start : 0);
  const actualSnippet = snippet || (rawSecret ? safeSnippet(rawSecret) : '[REDACTED]');

  const matchInfo = {
    secretType: String(actualType),
    start: Number(start),
    end: Number(end || (start + actualLength)),
    length: Number(actualLength),
    safeSnippet: String(actualSnippet)
  };

  if (typeof line === 'number') matchInfo.line = line;
  if (typeof column === 'number') matchInfo.column = column;
  if (description) matchInfo.description = String(description);

  // Invariant assertion: strictly remove any field that could leak the secret
  delete matchInfo.rawSecret;
  delete matchInfo.secret;
  delete matchInfo.raw;
  delete matchInfo.match;
  delete matchInfo.value;

  return Object.freeze(matchInfo);
}

/**
 * Converts a generic hit/finding into a Zero-Leak MatchInfo object (#112).
 *
 * @param {object} item
 * @param {string} [rawText]
 * @returns {object}
 */
export function toZeroLeakMatch(item, rawText) {
  if (!item || typeof item !== 'object') return item;

  const start = item.index ?? item.start ?? 0;
  const len = item.length ?? (item.end ? item.end - start : 0);
  const end = item.end ?? (start + len);
  const secretType = item.secretType || item.type || item.ruleId || 'secret';
  const rawSecret = rawText && len > 0 ? rawText.slice(start, end) : (item.match || item.raw);

  return createMatchInfo({
    secretType,
    start,
    end,
    length: len || (rawSecret ? rawSecret.length : 0),
    line: item.line,
    column: item.column,
    description: item.label || item.description,
    rawSecret,
    snippet: item.safeSnippet || (typeof item.match === 'string' && item.match.includes('****') ? item.match : undefined)
  });
}
