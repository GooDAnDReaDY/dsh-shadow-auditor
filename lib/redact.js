import { createHash } from 'node:crypto';

export { calculateShannonEntropy, shannonEntropy, isHighEntropyValue } from './diff-gate/secrets.js';

const URL_CREDENTIALS = /(https?:\/\/)([^:\s/@]+):([^@\s/]+)@([a-zA-Z0-9.\-_]+(?::\d+)?)/gi;
const GITHUB_TOKEN = /\bgh[psuo]_[A-Za-z0-9]{20,}\b/g;
const API_KEY = /\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{16,}\b/g;
const AWS_KEY = /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g;
const PRIVATE_KEY = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g;
const BEARER = /\bBearer\s+[A-Za-z0-9._~+/-]{8,}\b/gi;
const JWT = /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g;
const NPM_TOKEN = /\bnpm_[A-Za-z0-9]{30,}\b/g;
const SLACK_TOKEN = /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g;
const GENERIC_ASSIGNMENT = /\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|private[_-]?key)\b["']?\s*[:=]\s*["']?[^\s,;"']+/gi;
const ENV_LINE = /(^|\n)\s*([A-Z][A-Z0-9_]{2,})\s*=\s*[^\r\n]+/g;

// Credit card candidate regex: 13 to 19 digits, possibly grouped by - or spaces (#78)
const CREDIT_CARD = /\b\d(?:[ -]?\d){12,18}\b/g;

// CN-ID candidate regex: 18 chars (17 digits + 1 digit/X) (#79)
const CN_ID = /\b\d{6}(\d{8})\d{3}[0-9Xx]\b/g;

// IPv4 candidate regex: 4 numbers separated by dots (#80)
const IPV4 = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g;

/**
 * Validates a credit card number using Luhn checksum algorithm (#78).
 * @param {string|number} val
 * @returns {boolean}
 */
export function luhnValid(val) {
  if (typeof val !== 'string' && typeof val !== 'number') return false;
  const digits = String(val).replace(/[\s-]/g, '');
  if (!/^\d{13,19}$/.test(digits)) return false;

  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let digit = parseInt(digits.charAt(digits.length - 1 - i), 10);
    if (i % 2 === 1) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
  }
  return sum % 10 === 0;
}

/**
 * Validates embedded calendar date in CN ID or document numbers (YYYYMMDD) (#79).
 * Verifies month 1-12, days within calendar limits, and leap years.
 * @param {string} dateStr
 * @returns {boolean}
 */
export function isValidCalendarDate(dateStr) {
  if (!/^\d{8}$/.test(dateStr)) return false;
  const year = parseInt(dateStr.slice(0, 4), 10);
  const month = parseInt(dateStr.slice(4, 6), 10);
  const day = parseInt(dateStr.slice(6, 8), 10);

  if (year < 1900 || year > 2100) return false;
  if (month < 1 || month > 12) return false;

  const daysInMonth = [31, (year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0)) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return day >= 1 && day <= daysInMonth[month - 1];
}

/**
 * Validates an IPv4 address string (each octet in 0..255) (#80).
 * Excludes local loopback/any address signatures if protected (#96).
 * @param {string} ip
 * @returns {boolean}
 */
export function isValidIpv4(ip) {
  if (typeof ip !== 'string') return false;
  const parts = ip.split('.');
  if (parts.length !== 4) return false;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return false;
    const num = parseInt(part, 10);
    if (num < 0 || num > 255) return false;
  }
  return true;
}

/**
 * Sanitizes IPv4 addresses in text using octet range validation (#80, #96).
 * @param {string} text
 * @param {object} [options]
 * @returns {string}
 */
export function redactIpv4(text, options = {}) {
  if (typeof text !== 'string') return '';
  return text.replace(IPV4, (match) => {
    if (!isValidIpv4(match)) {
      return match;
    }
    if (options.preserveLoopback && (match === '127.0.0.1' || match === '0.0.0.0')) {
      return match;
    }
    return options.replacement || '[IP_REDACTED]';
  });
}

function maskUrlCredentials(match, proto, user, pass, host) {
  return `${proto}***:***@${host}`;
}

function maskGeneric(match) {
  return match.replace(/[=:]\s*["']?[^\s,;"']+$/, '=[REDACTED]');
}

function maskEnvLine(match, prefix, key) {
  return `${prefix}${key}=[REDACTED]`;
}

function redactTextOnce(text) {
  let res = text
    .replace(URL_CREDENTIALS, maskUrlCredentials)
    .replace(PRIVATE_KEY, '-----BEGIN PRIVATE KEY-----[REDACTED]')
    .replace(GITHUB_TOKEN, 'gh[REDACTED]')
    .replace(API_KEY, 'sk-[REDACTED]')
    .replace(AWS_KEY, 'AKIA[REDACTED]')
    .replace(BEARER, 'Bearer [REDACTED]')
    .replace(JWT, 'eyJ[REDACTED]')
    .replace(NPM_TOKEN, 'npm_[REDACTED]')
    .replace(SLACK_TOKEN, 'xox[REDACTED]')
    .replace(GENERIC_ASSIGNMENT, maskGeneric)
    .replace(ENV_LINE, maskEnvLine);

  // Credit card redaction with Luhn verification (#78)
  res = res.replace(CREDIT_CARD, (match) => {
    const raw = match.replace(/[\s-]/g, '');
    if (raw.length >= 13 && raw.length <= 19 && luhnValid(raw)) {
      return '[CARD_REDACTED]';
    }
    return match;
  });

  // CN-ID / Document number redaction with calendar date validation (#79)
  res = res.replace(CN_ID, (match, birthDate) => {
    if (isValidCalendarDate(birthDate)) {
      return '[ID_REDACTED]';
    }
    return match;
  });

  return res;
}

/**
 * Redact one text value iteratively until it contains no known secret shape.
 * @param {string} text
 * @param {object} [options]
 * @returns {string}
 */
export function redactText(text, options = {}) {
  if (typeof text !== 'string') return '';
  let current = text;
  let next = redactTextOnce(current);
  while (next !== current) {
    current = next;
    next = redactTextOnce(current);
  }
  if (options && (options.maskIpv4 || options.redactIp)) {
    current = redactIpv4(current, options);
  }
  return current;
}

/**
 * Recursively redact secret-shaped strings inside any JSON-serializable value.
 */
export function redactValue(value, options = {}) {
  if (typeof value === 'string') return redactText(value, options);
  if (Array.isArray(value)) return value.map((item) => redactValue(item, options));
  if (value !== null && typeof value === 'object') {
    const out = {};
    for (const [key, item] of Object.entries(value)) {
      out[key] = redactValue(item, options);
    }
    return out;
  }
  return value;
}

/**
 * Stable sha-256 digest (16 hex chars) of the canonical redacted value.
 */
export function digestOf(value, options = {}) {
  const sanitized = options?.alreadyRedacted ? value : redactValue(value, options);
  return createHash('sha256')
    .update(JSON.stringify(sanitized))
    .digest('hex')
    .slice(0, 16);
}