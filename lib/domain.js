/**
 * @file domain.js
 * Strict domain schema validation at persistence boundaries (#140).
 * Validates persistent audit records, session mappings, and plugin configurations
 * without external dependencies, reporting descriptive errors via AuditorError.
 */

import { AuditorError } from './errors.js';

/**
 * Creates a lightweight schema with parse and safeParse (#140).
 * @param {Function} validator
 * @param {string} schemaName
 */
export function createSchema(validator, schemaName = 'Schema') {
  return {
    name: schemaName,
    parse(input) {
      const res = this.safeParse(input);
      if (!res.success) {
        throw new AuditorError(
          AuditorError.ERR_VALIDATION_FAILED,
          `Validation failed for ${schemaName}: ${res.error.message}`,
          { errors: res.error.issues, target: schemaName }
        );
      }
      return res.data;
    },
    safeParse(input) {
      const issues = [];
      try {
        const data = validator(input, issues);
        if (issues.length > 0) {
          return {
            success: false,
            error: {
              message: issues.map(i => `${i.path.join('.')}: ${i.message}`).join('; '),
              issues
            }
          };
        }
        return { success: true, data };
      } catch (err) {
        return {
          success: false,
          error: {
            message: err?.message || 'Unknown validation failure',
            issues: [{ path: [], message: err?.message || 'Validator threw exception' }]
          }
        };
      }
    }
  };
}

/**
 * Validates AuditRecord structure before persistence or ingestion (#140).
 */
export const AuditRecordSchema = createSchema((input, issues) => {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    issues.push({ path: [], message: 'Expected object for AuditRecord' });
    return input;
  }

  // 1. time: must be ISO string or valid date
  if (typeof input.time !== 'string' || isNaN(Date.parse(input.time))) {
    issues.push({ path: ['time'], message: 'Must be a valid ISO-8601 timestamp string' });
  }

  // 2. sessionId: required string
  if (typeof input.sessionId !== 'string' || input.sessionId.trim().length === 0) {
    issues.push({ path: ['sessionId'], message: 'Must be a non-empty string' });
  }

  // 3. score: required number 0..100
  if (typeof input.score !== 'number' || isNaN(input.score) || input.score < 0 || input.score > 100) {
    issues.push({ path: ['score'], message: 'Score must be a number between 0 and 100' });
  }

  // 4. blocked: optional/required boolean
  if (input.blocked !== undefined && typeof input.blocked !== 'boolean') {
    issues.push({ path: ['blocked'], message: 'Blocked flag must be boolean if present' });
  }

  // 5. findings: optional array of finding objects
  if (input.findings !== undefined && !Array.isArray(input.findings)) {
    issues.push({ path: ['findings'], message: 'Findings must be an array if present' });
  }

  return {
    time: input.time,
    sessionId: String(input.sessionId),
    score: Number(input.score),
    callId: input.callId ? String(input.callId) : undefined,
    toolName: input.toolName ? String(input.toolName) : undefined,
    command: input.command ? String(input.command) : undefined,
    blocked: Boolean(input.blocked),
    reason: input.reason ? String(input.reason) : undefined,
    checksum: input.checksum ? String(input.checksum) : undefined,
    findings: Array.isArray(input.findings) ? input.findings : []
  };
}, 'AuditRecordSchema');

/**
 * Validates session placeholder mapping table before storage save (#140).
 */
export const SessionMappingSchema = createSchema((input, issues) => {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    issues.push({ path: [], message: 'Expected key-value object for SessionMapping' });
    return input;
  }

  const out = {};
  for (const [key, val] of Object.entries(input)) {
    if (typeof key !== 'string' || !key.startsWith('<') || !key.endsWith('>')) {
      issues.push({ path: [key], message: 'Placeholder key must match <TYPE_N> envelope' });
    }
    if (typeof val !== 'string') {
      issues.push({ path: [key], message: 'Mapped value must be string' });
    }
    out[key] = String(val);
  }
  return out;
}, 'SessionMappingSchema');

/**
 * Validates plugin configuration (#140).
 */
export const ConfigSchema = createSchema((input, issues) => {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    issues.push({ path: [], message: 'Expected object for Config' });
    return input;
  }

  const validGateModes = ['disabled', 'warning', 'block'];
  if (input.gateMode !== undefined && !validGateModes.includes(input.gateMode)) {
    issues.push({ path: ['gateMode'], message: `Must be one of: ${validGateModes.join(', ')}` });
  }

  const validShellModes = ['disabled', 'warning', 'enforce'];
  if (input.shellGuardMode !== undefined && !validShellModes.includes(input.shellGuardMode)) {
    issues.push({ path: ['shellGuardMode'], message: `Must be one of: ${validShellModes.join(', ')}` });
  }

  if (input.alertScoreThreshold !== undefined) {
    if (typeof input.alertScoreThreshold !== 'number' || input.alertScoreThreshold < 0 || input.alertScoreThreshold > 100) {
      issues.push({ path: ['alertScoreThreshold'], message: 'Must be number 0..100' });
    }
  }

  return {
    gateMode: input.gateMode || 'warning',
    shellGuardMode: input.shellGuardMode || 'enforce',
    autoUpdate: Boolean(input.autoUpdate ?? true),
    updateChannel: input.updateChannel || 'latest',
    alertScoreThreshold: Number(input.alertScoreThreshold ?? 70),
    secretsDetection: Boolean(input.secretsDetection ?? true),
    sastDetection: Boolean(input.sastDetection ?? true),
    promptInjectionDetection: Boolean(input.promptInjectionDetection ?? true)
  };
}, 'ConfigSchema');

export function validateAuditRecord(record) {
  return AuditRecordSchema.parse(record);
}

export function validateSessionMapping(map) {
  return SessionMappingSchema.parse(map);
}

export function validateConfig(config) {
  return ConfigSchema.parse(config);
}
