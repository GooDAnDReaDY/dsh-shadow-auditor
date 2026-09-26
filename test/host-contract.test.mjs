import test from 'node:test';
import assert from 'node:assert/strict';
import { createMockHostContext } from './harness.mjs';
import * as plugin from '../lib/index.js';

test('Host contract integration: verifies full Cordis runtime boundaries deterministically (#157)', async () => {
  const ctx = createMockHostContext({
    settings: {
      strictSecretScanning: true,
      blockDangerousCommands: true,
      enableAuditBadge: true,
      enableAuditLog: false,
      diffGateMode: 'warning',
      shellGuardMode: 'enforce',
    }
  });

  // Apply plugin to hermetic host context
  plugin.apply(ctx, {
    strictSecretScanning: true,
    blockDangerousCommands: true,
    enableAuditBadge: true,
    enableAuditLog: false,
    diffGateMode: 'warning',
    shellGuardMode: 'enforce',
  });

  const state = ctx._inspect();

  // 1. Verify tools registered according to host contract
  assert.equal(state.registeredTools.length, 3, 'Must register exactly 3 tools');
  for (const tool of state.registeredTools) {
    assert.ok(typeof tool.name === 'string' && tool.name.length > 0, 'Tool must satisfy contract: string name');
    assert.ok(typeof tool.description === 'string', 'Tool must satisfy contract: string description');
    assert.ok(typeof tool.execute === 'function', 'Tool must satisfy contract: execute function');
  }

  // 2. Verify command guard registered and functional
  assert.ok(typeof state.guardFn === 'function', 'Guard must be registered');
  const blocked = state.guardFn({ name: 'bash', arguments: { command: 'rm -rf /' } });
  assert.ok(blocked && blocked.includes('blocked'), 'Guard must block dangerous commands');
  const allowed = state.guardFn({ name: 'bash', arguments: { command: 'ls -la' } });
  assert.equal(allowed, undefined, 'Guard must allow safe commands');

  // 3. Verify webServer routes registered
  assert.ok(state.registeredRoutes.length >= 3, 'Must register web routes');
  const paths = state.registeredRoutes.map(r => r.path);
  assert.ok(paths.includes('/dsh-shadow-auditor/audit'), 'Must register /audit route');
  assert.ok(paths.includes('/dsh-shadow-auditor/events'), 'Must register /events route');
  assert.ok(paths.includes('/dsh-shadow-auditor/export'), 'Must register /export route');

  // 4. Verify slash command registered
  assert.ok(state.registeredCommand !== null, 'Must register slash command via commands service');
  assert.equal(state.registeredCommand.name, 'audit', 'Command name must be audit');

  // 5. Verify telemetry listeners
  assert.ok(state.eventListeners.has('tools/result'), 'Must register tools/result hook');
  assert.ok(state.eventListeners.has('session/event'), 'Must register session/event hook');
});

test('Host contract error reporting: failures identify violated host contract (#157)', () => {
  const ctx = createMockHostContext();

  // Missing execute on tool
  assert.throws(
    () => ctx.tools.register({ name: 'bad_tool' }),
    /HostContractViolation: tool descriptor must have an execute function/
  );

  // Missing path on route
  assert.throws(
    () => ctx.webServer.register({ handler: () => {} }),
    /HostContractViolation: route must have string path/
  );

  // Non-function effect
  assert.throws(
    () => ctx.effect('not a function'),
    /HostContractViolation: effect requires callback function/
  );

  // Invalid event listener
  assert.throws(
    () => ctx.on('event', null),
    /HostContractViolation: on requires event name and listener callback/
  );
});
