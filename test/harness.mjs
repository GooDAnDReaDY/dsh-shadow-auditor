// Deterministic host-contract test harness for @goodandready/dsh-shadow-auditor (#157)
// Provides a hermetic Cordis host context mock validating runtime boundaries without network/service requirements.

export function createMockHostContext(options = {}) {
  const registeredTools = [];
  let guardFn = null;
  const eventListeners = new Map();
  let registeredCommand = null;
  const registeredRoutes = [];
  const injectedDeps = new Map();
  const effects = [];

  const ctx = {
    tools: {
      register: (tool) => {
        if (!tool || typeof tool !== 'object') {
          throw new TypeError('HostContractViolation: tools.register requires tool descriptor object');
        }
        if (!tool.name || typeof tool.name !== 'string') {
          throw new TypeError('HostContractViolation: tool descriptor must have a string name');
        }
        if (typeof tool.execute !== 'function') {
          throw new TypeError('HostContractViolation: tool descriptor must have an execute function');
        }
        registeredTools.push(tool);
        return () => {
          const idx = registeredTools.indexOf(tool);
          if (idx !== -1) registeredTools.splice(idx, 1);
        };
      },
      guard: (fn) => {
        if (typeof fn !== 'function') {
          throw new TypeError('HostContractViolation: tools.guard requires guard handler function');
        }
        guardFn = fn;
        return () => { guardFn = null; };
      },
    },
    webServer: {
      register: (route) => {
        if (!route || typeof route !== 'object') {
          throw new TypeError('HostContractViolation: webServer.register requires route descriptor object');
        }
        if (!route.path || typeof route.path !== 'string') {
          throw new TypeError('HostContractViolation: route must have string path');
        }
        if (typeof route.handler !== 'function') {
          throw new TypeError('HostContractViolation: route must have handler function');
        }
        registeredRoutes.push(route);
        return () => {
          const idx = registeredRoutes.indexOf(route);
          if (idx !== -1) registeredRoutes.splice(idx, 1);
        };
      },
    },
    effect: (fn, label) => {
      if (typeof fn !== 'function') {
        throw new TypeError('HostContractViolation: effect requires callback function');
      }
      const undo = fn();
      effects.push({ fn, undo, label });
      return () => { if (typeof undo === 'function') undo(); };
    },
    inject: (deps, cb) => {
      if (!Array.isArray(deps) || typeof cb !== 'function') {
        throw new TypeError('HostContractViolation: inject requires dependencies array and callback');
      }
      if (deps.includes('settings')) {
        injectedDeps.set('settings', true);
        cb({
          settings: {
            register: () => ({
              get: () => (options.settings || {
                strictSecretScanning: true,
                blockDangerousCommands: true,
                enableAuditBadge: true,
                enableAuditLog: false
              })
            }),
          },
        });
      }
      if (deps.includes('commands')) {
        injectedDeps.set('commands', true);
        cb({
          effect: (fn, label) => {
            const undo = fn();
            return () => { if (typeof undo === 'function') undo(); };
          },
          commands: {
            register: (cmd) => {
              if (!cmd || typeof cmd !== 'object') {
                throw new TypeError('HostContractViolation: commands.register requires command descriptor');
              }
              registeredCommand = cmd;
              return () => { registeredCommand = null; };
            },
          },
        });
      }
    },
    on: (evt, cb) => {
      if (!evt || typeof cb !== 'function') {
        throw new TypeError('HostContractViolation: on requires event name and listener callback');
      }
      eventListeners.set(evt, cb);
      return () => { eventListeners.delete(evt); };
    },
    _inspect: () => ({
      registeredTools,
      get guardFn() { return guardFn; },
      eventListeners,
      get registeredCommand() { return registeredCommand; },
      registeredRoutes,
      injectedDeps,
      effects,
    }),
  };

  return ctx;
}
