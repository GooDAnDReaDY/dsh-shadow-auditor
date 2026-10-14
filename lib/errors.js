/**
 * @file errors.js
 * Safe error sanitization and diagnostic formatting (#100).
 * Prevents host directory paths and internal stack traces from leaking to clients.
 */

export const ERROR_CODES = {
  INTERNAL: 'ERR_AUDITOR_INTERNAL',
  SCAN_FAILED: 'ERR_AUDITOR_SCAN_FAILED',
  VALIDATION_FAILED: 'ERR_VALIDATION_FAILED',
  UNAUTHORIZED: 'ERR_AUDITOR_UNAUTHORIZED',
  TIMEOUT: 'ERR_AUDITOR_TIMEOUT',
  CONFIG_ERROR: 'ERR_AUDITOR_CONFIG_ERROR',
  BOUNDS_EXCEEDED: 'ERR_BOUNDS_EXCEEDED',
  RESTORE_FAILED: 'ERR_RESTORE_FAILED',
  STORAGE_UNAVAILABLE: 'ERR_STORAGE_UNAVAILABLE'
};

/**
 * Domain error class with stable machine-readable codes and sanitized details (#141).
 */
export class AuditorError extends Error {
  /**
   * @param {string} code Stable machine-readable error code
   * @param {string} message Human-readable error description
   * @param {object} [details] Sanitized contextual metadata
   */
  constructor(code, message, details = {}) {
    super(sanitizeErrorMessage(message));
    this.name = 'AuditorError';
    this.code = String(code || ERROR_CODES.INTERNAL);
    this.details = details && typeof details === 'object' ? { ...details } : {};
    for (const [k, v] of Object.entries(this.details)) {
      if (typeof v === 'string') {
        this.details[k] = sanitizeErrorMessage(v);
      }
    }
  }

  static isAuditorError(err) {
    return Boolean(
      err &&
      (err instanceof AuditorError ||
        err.name === 'AuditorError' ||
        (typeof err.code === 'string' && (err.code.startsWith('ERR_') || err.code.startsWith('ERR_AUDITOR_'))))
    );
  }
}

AuditorError.ERR_BOUNDS_EXCEEDED = ERROR_CODES.BOUNDS_EXCEEDED;
AuditorError.ERR_RESTORE_FAILED = ERROR_CODES.RESTORE_FAILED;
AuditorError.ERR_STORAGE_UNAVAILABLE = ERROR_CODES.STORAGE_UNAVAILABLE;
AuditorError.ERR_VALIDATION_FAILED = ERROR_CODES.VALIDATION_FAILED;
AuditorError.ERR_INTERNAL = ERROR_CODES.INTERNAL;
AuditorError.ERR_SCAN_FAILED = ERROR_CODES.SCAN_FAILED;
AuditorError.ERR_TIMEOUT = ERROR_CODES.TIMEOUT;
AuditorError.ERR_CONFIG_ERROR = ERROR_CODES.CONFIG_ERROR;

const PATH_MASKS = [
  { regex: /node_modules\/[A-Za-z0-9_.\-]+(?:\/[A-Za-z0-9_.\-]+)*/g, replacement: '<module>' },
  { regex: /\/home\/[A-Za-z0-9_.\-]+(?:\/[A-Za-z0-9_.\-]+)*/g, replacement: '<home>' },
  { regex: /\/mnt\/[A-Za-z0-9_.\-]+(?:\/[A-Za-z0-9_.\-]+)*/g, replacement: '<storage>' },
  { regex: /\/opt\/[A-Za-z0-9_.\-]+(?:\/[A-Za-z0-9_.\-]+)*/g, replacement: '<system>' },
  { regex: /[A-Za-z]:[\\/][^\\/\s"']+(?:[\\/][^\\/\s"']+)*/g, replacement: '<drive>' }
];

/**
 * Sanitizes a message string by replacing internal host paths with safe aliases (#100).
 * @param {string} msg
 * @returns {string}
 */
export function sanitizeErrorMessage(msg) {
  if (typeof msg !== 'string') return 'An error occurred';
  let clean = msg;
  for (const { regex, replacement } of PATH_MASKS) {
    clean = clean.replace(regex, replacement);
  }
  return clean;
}

/**
 * Formats an exception into a sanitized diagnostic response without raw stack trace (#100).
 * Raw stack traces are only included when process.env.DSH_AUDITOR_DEBUG === '1' or options.debug === true.
 *
 * @param {Error|string|unknown} err
 * @param {object} [options]
 * @returns {{ success: false, error: { code: string, message: string, stack?: string } }}
 */
export function sanitizeError(err, options = {}) {
  const isDebug = options.debug ?? (process.env.DSH_AUDITOR_DEBUG === '1' || process.env.DSH_AUDITOR_DEBUG === 'true');
  const code = options.code || (err && typeof err === 'object' && err.code) || ERROR_CODES.INTERNAL;
  const rawMessage = typeof err === 'string' ? err : (err && typeof err === 'object' && err.message) || 'Internal auditor error';
  const safeMessage = sanitizeErrorMessage(rawMessage);

  const errorObj = {
    code: String(code),
    message: safeMessage
  };

  if (isDebug && err && typeof err === 'object' && err.stack) {
    errorObj.stack = String(err.stack);
  }

  const logger = options.logger;
  if (logger && typeof logger.error === 'function') {
    if (isDebug && err && typeof err === 'object' && err.stack) {
      logger.error(`[shadow-auditor] ${code}: ${err.stack}`);
    } else {
      logger.error(`[shadow-auditor] ${code}: ${safeMessage}`);
    }
  }

  return {
    success: false,
    error: errorObj
  };
}

/**
 * Wraps an async or sync execution block in a safe diagnostic boundary.
 *
 * @param {Function} fn
 * @param {object} [options]
 * @returns {Promise<any>}
 */
export async function safeExecute(fn, options = {}) {
  try {
    return await fn();
  } catch (err) {
    return sanitizeError(err, options);
  }
}
