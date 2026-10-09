/**
 * @file engine.js
 * Reversible Masking & Placeholder Engine (#126, #127, #128, #129).
 * Provides reversible stripping of PII and secrets with monotonic session-scoped
 * placeholders <TYPE_N>, co-reference value reuse, overlap resolution, and
 * prefix-collision-safe demasking in descending order of length.
 */

import { SECRET_PATTERNS } from '../guards/secrets.js';

export const PII_PATTERNS = [
  { id: 'email', type: 'EMAIL', label: 'Email Address', regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, score: 90 },
  { id: 'phone', type: 'PHONE', label: 'Phone Number', regex: /\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g, score: 80 },
  { id: 'ip', type: 'IP', label: 'IPv4 Address', regex: /\b(?:192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/g, score: 85 },
];

/**
 * Resolves overlapping match intervals (#129).
 * Sorts primarily by start asc, score desc, and span length desc.
 * Discards any candidate that overlaps with an already accepted interval.
 *
 * @param {Array<{start: number, end: number, score?: number}>} matches
 * @returns {Array} Non-overlapping matches
 */
export function resolveOverlaps(matches) {
  if (!Array.isArray(matches) || matches.length <= 1) {
    return Array.isArray(matches) ? [...matches] : [];
  }

  // Sort: start ascending, score descending, length descending
  const sorted = [...matches].sort((a, b) => {
    if (a.start !== b.start) return a.start - b.start;
    const scoreA = Number.isFinite(a.score) ? a.score : 50;
    const scoreB = Number.isFinite(b.score) ? b.score : 50;
    if (scoreB !== scoreA) return scoreB - scoreA;
    return (b.end - b.start) - (a.end - a.start);
  });

  const resolved = [];
  let lastEnd = -1;

  for (const m of sorted) {
    if (m.start >= lastEnd) {
      resolved.push(m);
      lastEnd = m.end;
    }
  }

  return resolved;
}

/**
 * Extracts all sensitive matches (secrets and PII) from raw text.
 * @param {string} text
 * @returns {Array<{start: number, end: number, type: string, value: string, score: number}>}
 */
export function findSensitiveMatches(text) {
  if (typeof text !== 'string' || text.length === 0) return [];
  const matches = [];

  // 1. Secrets patterns from guards/secrets.js
  for (const p of SECRET_PATTERNS) {
    p.regex.lastIndex = 0;
    let m;
    while ((m = p.regex.exec(text)) !== null) {
      const val = m[0];
      if (val.length === 0) {
        p.regex.lastIndex += 1;
        continue;
      }
      let type = 'KEY';
      if (p.id === 'jwt') type = 'JWT';
      else if (p.id.startsWith('github')) type = 'TOKEN';
      else if (p.id === 'private-key') type = 'PRIVATE_KEY';
      else if (p.id === 'aws') type = 'AWS_KEY';

      matches.push({
        start: m.index,
        end: m.index + val.length,
        type,
        value: val,
        score: 100, // Secrets take highest precedence over PII
      });
    }
  }

  // 2. PII patterns (email, phone, ip)
  for (const p of PII_PATTERNS) {
    p.regex.lastIndex = 0;
    let m;
    while ((m = p.regex.exec(text)) !== null) {
      const val = m[0];
      if (val.length === 0) {
        p.regex.lastIndex += 1;
        continue;
      }
      matches.push({
        start: m.index,
        end: m.index + val.length,
        type: p.type,
        value: val,
        score: p.score ?? 80,
      });
    }
  }

  return resolveOverlaps(matches);
}

/**
 * Stripper performs reversible masking with monotonic session-scoped
 * placeholders and descending-length demasking.
 */
export class Stripper {
  /**
   * @param {object} [options]
   * @param {string} [options.sessionId]
   * @param {object} [options.storageAdapter]
   */
  constructor(options = {}) {
    this.sessionId = String(options.sessionId || 'default');
    this.storageAdapter = options.storageAdapter || null;
    this.counters = new Map();
    this.valueToPlaceholder = new Map();
    this.placeholderToValue = new Map();
  }

  /**
   * Generates monotonically numbered placeholder or reuses existing one for identical value (#127).
   * @param {string} type
   * @param {string} originalValue
   * @returns {string} Placeholder e.g. <KEY_1>
   */
  getOrCreatePlaceholder(type, originalValue) {
    if (this.valueToPlaceholder.has(originalValue)) {
      return this.valueToPlaceholder.get(originalValue);
    }

    const normType = String(type || 'SECRET').toUpperCase().replace(/[^A-Z0-9_]/g, '_');
    const nextCount = (this.counters.get(normType) || 0) + 1;
    this.counters.set(normType, nextCount);

    const placeholder = `<${normType}_${nextCount}>`;
    this.valueToPlaceholder.set(originalValue, placeholder);
    this.placeholderToValue.set(placeholder, originalValue);

    if (this.storageAdapter && typeof this.storageAdapter.saveSessionMap === 'function') {
      try {
        this.storageAdapter.saveSessionMap(this.sessionId, this.exportTable());
      } catch (_) {}
    }

    return placeholder;
  }

  /**
   * Reversibly masks sensitive entities in text with placeholders (#126, #129).
   * @param {string} text
   * @returns {{ text: string, strippedCount: number, placeholders: string[] }}
   */
  strip(text) {
    if (typeof text !== 'string' || text.length === 0) {
      return { text: String(text || ''), strippedCount: 0, placeholders: [] };
    }

    const matches = findSensitiveMatches(text);
    if (matches.length === 0) {
      return { text, strippedCount: 0, placeholders: [] };
    }

    // Sort descending by start offset to replace without skewing indexes
    const sortedDesc = [...matches].sort((a, b) => b.start - a.start);
    const appliedPlaceholders = [];
    let result = text;

    for (const m of sortedDesc) {
      const ph = this.getOrCreatePlaceholder(m.type, m.value);
      appliedPlaceholders.push(ph);
      result = result.slice(0, m.start) + ph + result.slice(m.end);
    }

    return {
      text: result,
      strippedCount: matches.length,
      placeholders: appliedPlaceholders.reverse(),
    };
  }

  /**
   * Demasks placeholders back to original cleartext in strict descending order of length (#128).
   * Prevents prefix collision (e.g. <KEY_1> corrupting <KEY_10>).
   * @param {string} text
   * @returns {string} Restored text
   */
  restore(text) {
    if (typeof text !== 'string' || text.length === 0 || this.placeholderToValue.size === 0) {
      return String(text || '');
    }

    // Sort entries descending by placeholder length, tie-break alphabetically
    const entries = Array.from(this.placeholderToValue.entries());
    entries.sort((a, b) => b[0].length - a[0].length || b[0].localeCompare(a[0]));

    let restored = text;
    for (const [placeholder, original] of entries) {
      if (restored.includes(placeholder)) {
        restored = restored.replaceAll(placeholder, original);
      }
    }

    return restored;
  }

  /**
   * Exports current restoration table as a plain key-value object.
   * @returns {Record<string, string>}
   */
  exportTable() {
    return Object.fromEntries(this.placeholderToValue.entries());
  }

  /**
   * Imports an existing restoration table, restoring state and monotonic counters.
   * @param {Record<string, string>} table
   */
  importTable(table) {
    if (!table || typeof table !== 'object') return;
    for (const [placeholder, originalValue] of Object.entries(table)) {
      if (typeof placeholder !== 'string' || typeof originalValue !== 'string') continue;
      this.placeholderToValue.set(placeholder, originalValue);
      this.valueToPlaceholder.set(originalValue, placeholder);

      // Extract type and index: e.g. <KEY_12>
      const match = placeholder.match(/^<([A-Z0-9_]+)_(\d+)>$/);
      if (match) {
        const type = match[1];
        const num = Number.parseInt(match[2], 10);
        if (Number.isFinite(num)) {
          const current = this.counters.get(type) || 0;
          if (num > current) {
            this.counters.set(type, num);
          }
        }
      }
    }
  }

  /**
   * Clears in-memory restoration mapping.
   */
  clear() {
    this.counters.clear();
    this.valueToPlaceholder.clear();
    this.placeholderToValue.clear();
  }
}
