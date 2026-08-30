import test from 'node:test';
import assert from 'node:assert/strict';
import { name, Config } from '../lib/index.js';

test('dsh-shadow-auditor exports valid name and schema', () => {
  assert.equal(name, '@goodandready-private/dsh-shadow-auditor');
  assert.ok(Config);
});
