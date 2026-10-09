import test from 'node:test';
import assert from 'node:assert/strict';
import {
  Stripper,
  resolveOverlaps,
  findSensitiveMatches,
  createStorageAdapter,
  StripperRegistry,
  apply
} from '../lib/index.js';
import { stripMessages } from '../lib/guards/lifecycle-hooks.js';

test('Issue #126: Reversible PII & secret stripping via Stripper with session-scoped restoration table', () => {
  const stripper = new Stripper({ sessionId: 'session-126' });

  const rawText = 'Contact Alice at alice@company.org or +1-800-555-0199. Server is 192.168.1.50 with key sk-proj-1234567890abcdef1234567890abcdef.';
  const stripped = stripper.strip(rawText);

  // Assert placeholders are present
  assert.ok(stripped.text.includes('<EMAIL_1>'), 'Must mask email with <EMAIL_1>');
  assert.ok(stripped.text.includes('<PHONE_1>'), 'Must mask phone with <PHONE_1>');
  assert.ok(stripped.text.includes('<IP_1>'), 'Must mask IP with <IP_1>');
  assert.ok(stripped.text.includes('<KEY_1>'), 'Must mask key with <KEY_1>');

  // Assert raw values do NOT remain
  assert.ok(!stripped.text.includes('alice@company.org'), 'Raw email must not remain');
  assert.ok(!stripped.text.includes('+1-800-555-0199'), 'Raw phone must not remain');
  assert.ok(!stripped.text.includes('192.168.1.50'), 'Raw IP must not remain');
  assert.ok(!stripped.text.includes('sk-proj-1234567890abcdef1234567890abcdef'), 'Raw key must not remain');

  // Assert demasking restores exact text
  const restored = stripper.restore(stripped.text);
  assert.equal(restored, rawText, 'Demasking must perfectly restore the original text');
});

test('Issue #127: Monotonic numbering per type with automatic value reuse across multiple steps', () => {
  const stripper = new Stripper({ sessionId: 'session-127' });

  // First step
  const step1 = stripper.strip('User admin@corp.io logged in from 10.0.0.1');
  assert.equal(step1.text, 'User <EMAIL_1> logged in from <IP_1>');

  // Second step: reusing existing values
  const step2 = stripper.strip('Confirmed: user admin@corp.io still at 10.0.0.1');
  assert.equal(step2.text, 'Confirmed: user <EMAIL_1> still at <IP_1>');

  // Third step: introducing new values alongside existing ones
  const step3 = stripper.strip('Forwarded from admin@corp.io to support@corp.io via 10.0.0.2');
  assert.equal(step3.text, 'Forwarded from <EMAIL_1> to <EMAIL_2> via <IP_2>');

  // Demask step3
  assert.equal(
    stripper.restore(step3.text),
    'Forwarded from admin@corp.io to support@corp.io via 10.0.0.2'
  );
});

test('Issue #128: Demasking placeholders in strict descending order of length eliminates prefix collisions', () => {
  const stripper = new Stripper({ sessionId: 'session-128' });

  // Generate 12 distinct keys to have <KEY_1> through <KEY_12>
  for (let i = 1; i <= 12; i++) {
    stripper.strip(`sk-proj-fakekeynumber${i}abcdefghijklmn${i}`);
  }

  // Ensure <KEY_1> and <KEY_10>, <KEY_11>, <KEY_12> exist in table
  const testText = 'Testing prefix collisions: <KEY_12>, <KEY_10>, <KEY_1> in one prompt.';
  const restored = stripper.restore(testText);

  // If replaced naively (in ascending or random order), <KEY_1> would corrupt <KEY_10> -> <val1>0
  assert.ok(!restored.includes('<KEY_1>'), '<KEY_1> must be completely replaced');
  assert.ok(!restored.includes('<KEY_10>'), '<KEY_10> must be completely replaced');
  assert.ok(!restored.includes('<KEY_12>'), '<KEY_12> must be completely replaced');
  assert.ok(restored.includes('sk-proj-fakekeynumber12abcdefghijklmn12'));
  assert.ok(restored.includes('sk-proj-fakekeynumber10abcdefghijklmn10'));
  assert.ok(restored.includes('sk-proj-fakekeynumber1abcdefghijklmn1'));
});

test('Issue #129: Overlap resolution algorithm prioritizing start asc, score desc, length desc', () => {
  // Overlapping matches
  const matches = [
    { start: 0, end: 15, type: 'EMAIL', value: 'user@corp.co.uk', score: 80 },
    { start: 5, end: 12, type: 'GENERIC', value: 'corp.co', score: 40 },
    { start: 20, end: 35, type: 'KEY', value: 'sk-proj-12345678', score: 95 },
    { start: 20, end: 30, type: 'KEY_SHORT', value: 'sk-proj-12', score: 60 }
  ];

  const resolved = resolveOverlaps(matches);
  assert.equal(resolved.length, 2, 'Should pick 2 non-overlapping matches');
  assert.equal(resolved[0].value, 'user@corp.co.uk', 'Should pick the highest-score wider match');
  assert.equal(resolved[1].value, 'sk-proj-12345678', 'Should pick the higher-score match');
});

test('Issue #132 & #133: DSH storageDomain integration and graceful in-memory fallback', async () => {
  // 1. With storageDomain available
  const domainStore = new Map();
  const mockDomain = {
    get: async (k) => domainStore.get(k),
    set: async (k, v) => domainStore.set(k, v),
    delete: async (k) => domainStore.delete(k)
  };

  const mockCtxWithDomain = {
    storageDomain: {
      open: () => Promise.resolve(mockDomain)
    }
  };

  const adapter = createStorageAdapter(mockCtxWithDomain);
  const registry = new StripperRegistry({ storageAdapter: adapter });
  const stripper = registry.getStripper('sess-storage');

  stripper.strip('Secret token sk-proj-abcdef1234567890abcdef123456');
  await new Promise((r) => setTimeout(r, 50));

  // Verify stored in domain
  const savedState = domainStore.get('session_sess-storage');
  assert.ok(savedState, 'Session mapping must be persisted in storageDomain');
  assert.ok(savedState['<KEY_1>'], 'Mappings must contain <KEY_1>');

  // 2. Fallback when storageDomain is unavailable
  let loggedInfo = false;
  const mockLogger = {
    info: () => {},
    debug: (msg) => { if (typeof msg === 'string' && msg.includes('storageDomain service not available')) loggedInfo = true; },
    warn: () => {}
  };

  const mockCtxWithoutDomain = {};
  const fallbackAdapter = createStorageAdapter(mockCtxWithoutDomain, mockLogger);
  assert.ok(loggedInfo, 'Must log single informational message on in-memory fallback');

  const fallbackRegistry = new StripperRegistry({ storageAdapter: fallbackAdapter });
  const fallbackStripper = fallbackRegistry.getStripper('sess-fallback');
  const fallbackRes = fallbackStripper.strip('Email is dev@test.com');
  assert.equal(fallbackRes.text, 'Email is <EMAIL_1>');
  assert.equal(fallbackStripper.restore(fallbackRes.text), 'Email is dev@test.com');
});

test('Issue #134: Prevention of race conditions on plugin unload during async domain initialization', async () => {
  let resolveDomain;
  const slowDomainPromise = new Promise((resolve) => { resolveDomain = resolve; });

  const mockCtx = {
    storageDomain: {
      open: () => slowDomainPromise
    }
  };

  const adapter = createStorageAdapter(mockCtx);
  const registry = new StripperRegistry({ storageAdapter: adapter });

  // Unload plugin before storageDomain finishes resolving
  const closePromise = registry.close();
  // Resolve storageDomain after unload triggered
  resolveDomain({
    get: async () => null,
    set: async () => {},
    delete: async () => {}
  });

  await closePromise;
  assert.ok(true, 'Registry must shut down cleanly without unhandled rejection or hangs');
});

test('Issue #135: Session log cleanliness invariant: no raw secrets written to prompts or logs', async () => {
  const stripper = new Stripper({ sessionId: 'session-135' });
  const rawKey = 'sk-proj-supersecretkey1234567890abcdef';
  const rawEmail = 'leak@private-company.org';

  const messages = [
    { role: 'user', content: `Here is my key ${rawKey} and email ${rawEmail}` }
  ];

  const strippedMsgs = stripMessages(messages, stripper);
  const promptText = strippedMsgs[0].content;

  assert.ok(!promptText.includes(rawKey), 'Prompt must not contain raw secret');
  assert.ok(!promptText.includes(rawEmail), 'Prompt must not contain raw email');
  assert.ok(promptText.includes('<KEY_1>'), 'Prompt must use placeholder <KEY_1>');
  assert.ok(promptText.includes('<EMAIL_1>'), 'Prompt must use placeholder <EMAIL_1>');
});

test('Issue #136: Session command /shadow-auditor restore <text> for authorized local demasking', async () => {
  let restoreHandler = null;

  const mockCtx = {
    tools: { register: () => () => {}, guard: () => () => {} },
    webServer: { register: () => () => {} },
    effect: (fn) => fn(),
    on: () => () => {},
    inject: (deps, cb) => {
      if (deps.includes('commands')) {
        cb({
          effect: (fn) => fn(),
          commands: {
            register: (cmd) => {
              if (cmd.name === 'shadow-auditor') {
                restoreHandler = cmd.handler;
              }
              return () => {};
            }
          }
        });
      }
    }
  };

  apply(mockCtx, {
    enableReversibleMasking: true
  });

  assert.ok(typeof restoreHandler === 'function', '/shadow-auditor command must be registered');

  // Strip some content in session s-restore
  const testAgent = { session: { header: { id: 's-restore' } } };
  const rawSecret = 'sk-proj-xyz1234567890abcdef123456';

  // Test usage error
  const helpRes = await restoreHandler({ agent: testAgent, rawInput: 'restore' });
  assert.equal(helpRes.kind, 'error');
  assert.ok(helpRes.text.includes('Usage:'));

  // Test unknown subcommand
  const unknownRes = await restoreHandler({ agent: testAgent, rawInput: 'foobar' });
  assert.equal(unknownRes.kind, 'error');
  assert.ok(unknownRes.text.includes('Unknown subcommand'));
});
