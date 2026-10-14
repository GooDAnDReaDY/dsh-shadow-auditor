/**
 * @file sanitize.js
 * Irreversible sanitization and data redaction module (#147).
 * Dedicated to permanent scrubbing of secrets, PII, and sensitive tokens
 * for disk logging, billing metrics, and report serialization.
 */

export {
  redactText,
  redactValue,
  digestOf,
  PROTECTED_SIGNALS,
  protectSignals,
  luhnValid,
  isValidCalendarDate,
  isValidIpv4,
  redactIpv4,
  calculateShannonEntropy,
  shannonEntropy,
  isHighEntropyValue
} from './redact.js';
