/**
 * @file events.js
 * Typed audit detection event registry and session event wrapper (#116, #117).
 */

export const DETECTION_EVENT_NAME = 'dsh-shadow-auditor/detection';
export const DETECTION_EVENT_TYPE = DETECTION_EVENT_NAME;

export const DetectionKind = Object.freeze({
  DIFF: 'diff',
  COMMAND: 'command',
  SYSTEM: 'system',
  LIFECYCLE: 'lifecycle'
});

/**
 * Creates a discriminated DetectionEvent object (#117).
 *
 * @param {object} params
 * @returns {object}
 */
export function createDetectionEvent(params = {}) {
  const {
    kind = DetectionKind.DIFF,
    level = 'green',
    score = 100,
    hits = [],
    sessionId = 'unknown',
    callId,
    toolName,
    metadata = {}
  } = params;

  return {
    type: DETECTION_EVENT_NAME,
    kind,
    level,
    score: Number(score),
    hits: Array.isArray(hits) ? hits : [],
    sessionId: String(sessionId),
    callId: callId ? String(callId) : undefined,
    toolName: toolName ? String(toolName) : undefined,
    timestamp: new Date().toISOString(),
    ...metadata
  };
}

/**
 * Validates whether an event object conforms to the DetectionEvent structure (#117).
 *
 * @param {any} event
 * @returns {boolean}
 */
export function isDetectionEvent(event) {
  return Boolean(
    event &&
    typeof event === 'object' &&
    event.type === DETECTION_EVENT_NAME &&
    typeof event.kind === 'string' &&
    typeof event.level === 'string' &&
    Array.isArray(event.hits)
  );
}

/**
 * Appends an audit event to a session with `{ ignorable: true }` envelope (#116).
 * Ensures older DSH host cores ignore custom audit events without failing session deserialization.
 *
 * @param {object} session
 * @param {object} eventPayload
 * @param {object} [options]
 * @returns {Promise<any>}
 */
export async function appendSessionEvent(session, eventPayload, options = {}) {
  if (!session) return undefined;

  const envelope = {
    ...eventPayload,
    ignorable: true,
    timestamp: eventPayload?.timestamp || new Date().toISOString()
  };

  if (typeof session.append === 'function') {
    return session.append(envelope, { ignorable: true, ...options });
  }
  if (typeof session.record === 'function') {
    return session.record(envelope, { ignorable: true, ...options });
  }
  if (typeof session.push === 'function') {
    return session.push(envelope);
  }
  return undefined;
}
