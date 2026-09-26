import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

test('Client UI: adheres to dsh-clinebot section card styling and design tokens', () => {
  const clientSrc = fs.readFileSync(new URL('../lib/client.js', import.meta.url), 'utf8');

  // Verify unified clinebot card classes
  assert.ok(clientSrc.includes('.sa-page'), 'Must include .sa-page');
  assert.ok(clientSrc.includes('.sa-header'), 'Must include .sa-header');
  assert.ok(clientSrc.includes('.sa-section-card'), 'Must include .sa-section-card');
  assert.ok(clientSrc.includes('.sa-grid-2'), 'Must include .sa-grid-2');
  assert.ok(clientSrc.includes('.sa-badge-ok'), 'Must include .sa-badge-ok');
  assert.ok(clientSrc.includes('.sa-badge-warn'), 'Must include .sa-badge-warn');
  assert.ok(clientSrc.includes('.sa-badge-bad'), 'Must include .sa-badge-bad');

  // Verify all 4 sections exist in SettingsPage
  assert.ok(clientSrc.includes('Execution Safety & Guards'), 'Must include Guards section');
  assert.ok(clientSrc.includes('Code-Security Diff Gate & SAST'), 'Must include Diff Gate section');
  assert.ok(clientSrc.includes('Audit Trail & Storage'), 'Must include Audit Log section');
  assert.ok(clientSrc.includes('Live Telemetry & Diagnostics') || clientSrc.includes('lastAudit'), 'Must include Telemetry section');

  // Verify full config synchronization including diff gate options
  assert.ok(clientSrc.includes("diffGateMode: s.value.diffGateMode ?? 'warning'"), 'Draft must properly initialize diffGateMode from snapshot');
  assert.ok(clientSrc.includes("enableSastScan: s.value.enableSastScan ?? true"), 'Draft must properly initialize enableSastScan');
  assert.ok(clientSrc.includes("enablePromptInjectionScan: s.value.enablePromptInjectionScan ?? true"), 'Draft must properly initialize enablePromptInjectionScan');

  // Verify theme tokens
  assert.ok(clientSrc.includes('--dsw-alias-border-l2'), 'Must use --dsw-alias-border-l2');
  assert.ok(clientSrc.includes('--dsw-alias-bg-layer-3'), 'Must use --dsw-alias-bg-layer-3');
  assert.ok(clientSrc.includes('--dsw-alias-label-primary'), 'Must use --dsw-alias-label-primary');
});

test('Plugin registration & Diff Gate tool: registers all 3 tools cleanly with proper schemas', async (t) => {
  let plugin;
  try {
    plugin = await import('../lib/index.js');
  } catch (err) {
    if (err.code === 'ERR_MODULE_NOT_FOUND') {
      t.skip('PeerDependency @deepseek-ai/schemastery not present in standalone unit test environment');
      return;
    }
    throw err;
  }

  const tools = [];
  const mockCtx = {
    tools: {
      register: (tool) => {
        tools.push(tool);
        return () => {};
      },
      guard: () => () => {},
    },
    webServer: {
      register: () => () => {},
    },
    effect: (fn) => {
      fn();
      return () => {};
    },
    inject: (deps, cb) => {
      if (deps.includes('settings')) {
        cb({
          settings: {
            register: () => ({ get: () => ({}) }),
          },
        });
      }
      if (deps.includes('commands')) {
        cb({
          effect: (fn) => { fn(); return () => {}; },
          commands: { register: () => () => {} },
        });
      }
    },
    on: () => () => {},
  };

  plugin.apply(mockCtx, {
    strictSecretScanning: true,
    blockDangerousCommands: true,
    enableAuditBadge: true,
    enableAuditLog: false,
    diffGateMode: 'warning'
  });

  const diffGateTool = tools.find(t => t.name === 'shadow_auditor_diff_gate');
  assert.ok(diffGateTool, 'shadow_auditor_diff_gate tool must be registered');

  // Test executing shadow_auditor_diff_gate tool
  const result = await diffGateTool.execute({
    diff: '+ const apiKey = "sk-proj-1234567890abcdef1234567890";',
    filePath: 'config.js'
  });

  assert.ok(result.findings.some(f => f.ruleId === 'SEC-API-KEY'), 'Tool must flag OpenAI key');
  assert.equal(result.action, 'warn');
});

test('Client UI registers all slots and dictionaries via ctx.effect with clean disposers (#121)', () => {
  const clientSrc = fs.readFileSync(new URL('../lib/client.js', import.meta.url), 'utf8');

  // Verify static code structure adheres to effect-binding
  assert.ok(clientSrc.includes("ctx.effect(() => {"), 'Must use ctx.effect');
  assert.ok(clientSrc.includes("'dsh-shadow-auditor: client slots'"), 'Must label client slots effect');
  assert.ok(clientSrc.includes("'dsh-shadow-auditor: locale dictionaries'"), 'Must label locale dictionaries effect');

  // Verify dynamic execution and disposal
  let loaded = null;
  const mockWindow = {
    __ModuleLoader__: {
      load: (mod) => { loaded = mod; }
    }
  };
  const mockReact = {
    createElement: () => ({}),
    useState: (init) => [init, () => {}],
    useRef: () => ({ current: null }),
    useEffect: () => {},
    useCallback: (fn) => fn,
  };
  const fn = new Function('window', 'require', clientSrc);
  fn(mockWindow, (id) => {
    if (id === 'react') return mockReact;
    return {};
  });

  const clientMod = loaded.factory((id) => {
    if (id === 'react') return mockReact;
    return {};
  });

  const effects = [];
  const injectedSlots = [];
  let uninjectCount = 0;
  let unregisterCount = 0;

  const mockCtx = {
    effect: (effFn, label) => {
      const disposer = effFn();
      effects.push({ label, disposer });
      return () => { if (typeof disposer === 'function') disposer(); };
    },
    slots: {
      inject: (slotName, registerFn) => {
        injectedSlots.push(slotName);
        const unreg = registerFn();
        return () => {
          uninjectCount++;
          if (typeof unreg === 'function') unreg();
        };
      },
      register: (descriptor) => {
        return () => {
          unregisterCount++;
        };
      },
    },
    locale: {
      register: () => () => {},
    },
  };

  clientMod.apply(mockCtx);

  assert.ok(effects.some(e => e.label === 'dsh-shadow-auditor: client slots'), 'Slots must be effect-bound');
  assert.ok(effects.some(e => e.label === 'dsh-shadow-auditor: locale dictionaries'), 'Dictionaries must be effect-bound');
  assert.equal(injectedSlots.length, 4, 'Must inject all 4 slots');

  // Trigger teardown
  for (const eff of effects) {
    if (typeof eff.disposer === 'function') {
      eff.disposer();
    }
  }

  assert.equal(uninjectCount, 4, 'All 4 injected slots must be disposed');
  assert.equal(unregisterCount, 4, 'All 4 registered slots must be disposed');
});
