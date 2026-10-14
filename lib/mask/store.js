/**
 * @file store.js
 * Storage adapter and registry for reversible placeholder tables (#132, #133, #134).
 * Integrates with DSH storageDomain service when available and degrades smoothly
 * to in-memory storage when absent, with race-condition-safe unloading.
 */

import { Stripper } from './engine.js';

export class InMemoryStorageAdapter {
  constructor() {
    this.sessions = new Map();
  }

  async getSessionMap(sessionId) {
    return this.sessions.get(String(sessionId)) || {};
  }

  async saveSessionMap(sessionId, map) {
    this.sessions.set(String(sessionId), { ...(map || {}) });
  }

  async close() {
    this.sessions.clear();
  }
}

export class DomainStorageAdapter {
  /**
   * @param {Promise<any>} domainPromise
   * @param {object} [logger]
   */
  constructor(domainPromise, logger = console) {
    this.domainPromise = domainPromise;
    this.logger = logger;
    this.closed = false;
    this.domain = null;

    // Attach catch to prevent unhandled rejections on startup failure (#134)
    this.domainPromise
      .then((domain) => {
        if (this.closed) {
          try { domain?.close?.(); } catch (_) {}
        } else {
          this.domain = domain;
        }
      })
      .catch((err) => {
        if (!this.closed) {
          this.logger.debug?.('[shadow-auditor] Storage domain initialization failed: ' + (err?.message || err));
        }
      });
  }

  async getSessionMap(sessionId) {
    if (this.closed) return {};
    try {
      const domain = this.domain || await this.domainPromise;
      if (!domain) return {};
      const key = `session_${sessionId}`;
      if (typeof domain.get === 'function') {
        const val = await domain.get(key);
        return typeof val === 'object' && val !== null ? val : {};
      }
      return {};
    } catch (_) {
      return {};
    }
  }

  async saveSessionMap(sessionId, map) {
    if (this.closed) return;
    try {
      const domain = this.domain || await this.domainPromise;
      if (!domain) return;
      const key = `session_${sessionId}`;
      if (typeof domain.set === 'function') {
        await domain.set(key, map);
      }
    } catch (_) {}
  }

  async close() {
    this.closed = true;
    try {
      const domain = this.domain || await this.domainPromise;
      if (domain && typeof domain.close === 'function') {
        domain.close();
      }
    } catch (_) {}
    this.domain = null;
  }
}

/**
 * Creates storage adapter with automatic graceful fallback to memory (#132, #133, #134).
 * @param {object} ctx Cordis context
 * @param {object} [logger]
 * @returns {InMemoryStorageAdapter | DomainStorageAdapter}
 */
export function createStorageAdapter(ctx, logger = console) {
  try {
    if (ctx && ctx.storageDomain && typeof ctx.storageDomain.open === 'function') {
      const domainPromise = Promise.resolve(ctx.storageDomain.open('dsh_shadow_auditor'));
      return new DomainStorageAdapter(domainPromise, logger);
    }
  } catch (err) {
    logger.debug?.('[shadow-auditor] Failed to access storageDomain, falling back to memory: ' + (err?.message || err));
  }

  logger.debug?.('[shadow-auditor] storageDomain service not available, running in-memory session mode.');
  return new InMemoryStorageAdapter();
}

/**
 * StripperRegistry manages session-scoped Stripper instances.
 */
export class StripperRegistry {
  /**
   * @param {object} [options]
   * @param {object} [options.storageAdapter]
   * @param {Function} [options.detector]
   * @param {number} [options.maxSessions]
   * @param {number} [options.maxRestoreEntriesPerSession]
   */
  constructor(options = {}) {
    this.storageAdapter = options.storageAdapter || new InMemoryStorageAdapter();
    this.detector = typeof options.detector === 'function' ? options.detector : null;
    const maxSess = Number(options.maxSessions);
    this.maxSessions = (Number.isFinite(maxSess) && maxSess > 0) ? maxSess : 100;
    const maxEntries = Number(options.maxRestoreEntriesPerSession);
    this.maxRestoreEntriesPerSession = (Number.isFinite(maxEntries) && maxEntries > 0) ? maxEntries : 500;
    this.strippers = new Map();
  }

  setDetector(detector) {
    this.detector = typeof detector === 'function' ? detector : null;
    for (const stripper of this.strippers.values()) {
      if (this.detector) stripper.detector = this.detector;
    }
  }

  getStats() {
    return {
      activeSessions: this.strippers.size,
      maxSessions: this.maxSessions,
      maxRestoreEntriesPerSession: this.maxRestoreEntriesPerSession
    };
  }

  /**
   * Gets or initializes Stripper for a given session with LRU caching (#126, #127, #139).
   * @param {string} sessionId
   * @returns {Stripper}
   */
  getStripper(sessionId) {
    const sid = String(sessionId || 'default');
    if (this.strippers.has(sid)) {
      const existing = this.strippers.get(sid);
      // Move to most-recently-used position
      this.strippers.delete(sid);
      this.strippers.set(sid, existing);
      return existing;
    }

    // LRU eviction if cache exceeds maxSessions (#139)
    if (this.strippers.size >= this.maxSessions) {
      const lruSid = this.strippers.keys().next().value;
      if (lruSid !== undefined) {
        this.strippers.delete(lruSid);
      }
    }

    const stripper = new Stripper({
      sessionId: sid,
      storageAdapter: this.storageAdapter,
      detector: this.detector,
      maxRestoreEntriesPerSession: this.maxRestoreEntriesPerSession
    });
    this.strippers.set(sid, stripper);

    // Asynchronously rehydrate from persistent store if available
    if (this.storageAdapter && typeof this.storageAdapter.getSessionMap === 'function') {
      this.storageAdapter.getSessionMap(sid).then((table) => {
        if (table && Object.keys(table).length > 0) {
          stripper.importTable(table);
        }
      }).catch(() => {});
    }

    return stripper;
  }

  /**
   * Demasks text for a given session (#128, #136).
   * @param {string} sessionId
   * @param {string} text
   * @returns {string}
   */
  restore(sessionId, text) {
    const stripper = this.getStripper(sessionId);
    return stripper.restore(text);
  }

  /**
   * Reversibly strips text for a given session (#126, #135).
   * @param {string} sessionId
   * @param {string} text
   * @returns {{ text: string, strippedCount: number, placeholders: string[] }}
   */
  strip(sessionId, text) {
    const stripper = this.getStripper(sessionId);
    return stripper.strip(text);
  }

  /**
   * Closes storage adapter and clears cache.
   */
  async close() {
    this.strippers.clear();
    if (this.storageAdapter && typeof this.storageAdapter.close === 'function') {
      await this.storageAdapter.close();
    }
  }
}
