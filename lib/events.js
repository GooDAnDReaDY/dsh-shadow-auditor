/**
 * @file events.js
 * Typed audit detection event registry, session event wrapper, adaptive runtime probe,
 * and deduplicated event gate (#116, #117, #130, #131).
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
 * Probes whether the host session/runtime supports the ignorable envelope (#130).
 * Prevents session corruption on incompatible DSH host runtimes.
 *
 * @param {object} session
 * @returns {Promise<boolean>}
 */
export async function probeIgnorableAppend(session) {
  if (!session) return false;
  if (typeof session.supportsIgnorable === 'boolean') {
    return session.supportsIgnorable;
  }
  if (session.features && typeof session.features.ignorable === 'boolean') {
    return session.features.ignorable;
  }
  if (typeof session.append !== 'function' && typeof session.record !== 'function' && typeof session.push !== 'function') {
    return false;
  }
  if (typeof session.probeAppend === 'function') {
    try {
      return Boolean(await session.probeAppend({ type: 'probe/ignorable', ignorable: true }));
    } catch (_) {
      return false;
    }
  }
  return true;
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

/**
 * Creates an adaptive EventGate with session-level warning deduplication (#130, #131).
 *
 * @param {object} [options]
 * @param {object} [options.logger]
 * @param {boolean} [options.enabled]
 * @returns {object} EventGate instance
 */
export function makeEventGate(options = {}) {
  const logger = options.logger || console;
  let supported = options.enabled !== false;
  const warned = new Set();

  return {
    isSupported() {
      return supported;
    },
    setSupported(val) {
      supported = Boolean(val);
    },
    async probe(session) {
      const probeResult = await probeIgnorableAppend(session);
      supported = probeResult;
      return supported;
    },
    async append(session, eventPayload, appendOptions = {}) {
      if (!supported) {
        const sid = String(session?.id || session?.header?.id || 'unknown');
        const eventType = String(eventPayload?.type || DETECTION_EVENT_NAME);
        const warnKey = `${sid}:${eventType}`;
        if (!warned.has(warnKey)) {
          warned.add(warnKey);
          logger.warn?.(`[shadow-auditor] Host runtime does not support ignorable envelope for session ${sid}. Event '${eventType}' skipped to prevent session corruption.`);
        }
        return undefined;
      }
      return appendSessionEvent(session, eventPayload, appendOptions);
    },
    hasWarned(sessionId, eventType = DETECTION_EVENT_NAME) {
      return warned.has(`${sessionId}:${eventType}`);
    },
    resetWarned(sessionId) {
      if (sessionId) {
        for (const k of warned) {
          if (k.startsWith(`${sessionId}:`)) warned.delete(k);
        }
      } else {
        warned.clear();
      }
    }
  };
}
