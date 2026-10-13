import { homedir } from 'node:os';
import { join } from 'node:path';
import Schema from '@deepseek-ai/schemastery';
import { scanSecrets } from './guards/secrets.js';
import { scanDiff } from './diff-gate/gate.js';
import { findDangerous } from './guards/command.js';
import { registerLifecycleHooks } from './guards/lifecycle-hooks.js';
import { AuditRecorder } from './recorder.js';
import { redactValue, redactText, digestOf } from './redact.js';
import { evaluateRisk, applyCumulative } from './score.js';
import { registerAuditCommand, registerRestoreCommand } from './report.js';
import { registerHttpRoutes } from './routes.js';
import { createStorageAdapter, StripperRegistry } from './mask/store.js';
import { runSystemAudit, checkConfigSecrets } from './system-audit.js';
import { classifyCommand } from './classifier.js';

export const name = '@goodandready/dsh-shadow-auditor';
export const inject = ['tools', 'settings', 'webServer'];

export const Config = Schema.object({
  strictSecretScanning: Schema.boolean().default(true).volatile().description('Block execution if API keys or private tokens detected in diff'),
  blockDangerousCommands: Schema.boolean().default(true).volatile().description('Block destructive flags like --force, rm -rf /, etc.'),
  secretBlockCritical: Schema.boolean().default(true).volatile().description('Unconditionally block critical destructive threats bypassing soft audit modes'),
  enableReversibleMasking: Schema.boolean().default(true).volatile().description('Reversibly replace detected PII and secrets with <TYPE_N> placeholders'),
  enableAuditBadge: Schema.boolean().default(true).volatile().description('Display security shield badge in approval dialogs'),
  enableAuditLog: Schema.boolean().default(true).volatile().description('Record persistent JSONL audit logs with rotation under DSH_HOME'),
  maxFileSizeMb: Schema.number().default(50).volatile().description('Archive and compress audit log above this size in MB'),
  retentionDays: Schema.number().default(30).volatile().description('Retention period for archived audit logs in days'),
  diffGateMode: Schema.union(['disabled', 'warning', 'block']).default('warning').volatile().description('Diff gate mode: disabled, warning, or block'),
  shellGuardMode: Schema.union(['enforce', 'audit_only', 'ask']).default('enforce').volatile().description('Shell guard policy: enforce blocks command, audit_only logs warning, ask prompts approval'),
  enableSastScan: Schema.boolean().default(true).volatile().description('Scan diffs for insecure code patterns (SQLi, command injection, path traversal, eval)'),
  enablePromptInjectionScan: Schema.boolean().default(true).volatile().description('Scan diffs for prompt-injection and adversarial instructions'),
  timeoutMs: Schema.number().default(100).volatile().description('Cooperative timeout budget in ms for synchronous audit checks'),
  onTimeout: Schema.union(['allow', 'review']).default('allow').volatile().description('Action when timeout budget exceeded: allow or review'),
  customBlockedCommands: Schema.string().default('').volatile().description('Custom regex patterns or commands to block (one per line)'),
  sensitivePathPatterns: Schema.string().default('').volatile().description('Custom sensitive file patterns or paths to monitor (one per line)'),
});

const NS = 'dsh-shadow-auditor';

export function plainConfig(value) {
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(plainConfig);
  if (typeof value.get === 'function') return plainConfig(value.get());
  return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, plainConfig(v)]));
}

export function recordGuardHit(recorder, { sessionId, callId, toolName, args, success = false, blocked = '', score = 50, tags = ['command-blocked'], reason, stripper }) {
  if (!recorder || typeof recorder.record !== 'function') return;
  const safeArgs = (stripper && typeof stripper.strip === 'function' && typeof args === 'string')
    ? stripper.strip(args).text
    : (typeof args === 'object' && args !== null && stripper
      ? JSON.parse(JSON.stringify(args, (_, v) => typeof v === 'string' ? stripper.strip(v).text : v))
      : redactValue(args));
  recorder.record({
    time: new Date().toISOString(),
    sessionId,
    callId,
    toolName,
    args: safeArgs,
    argsDigest: digestOf(safeArgs, { alreadyRedacted: true }),
    success,
    blockedByGuard: blocked,
    score,
    tags,
    reasons: [reason || (blocked ? `Blocked by guard: ${blocked}` : 'Guard inspection warning')],
  }).catch(() => {});
}

function isCommandTool(name) {
  return name === 'bash' || name === 'sh' || name === 'shell' || name === 'exec' || name === 'terminal' || name === 'run_command';
}

function isFileReadTool(name) {
  return name === 'read_file' || name === 'readFile' || name === 'view_file' || name === 'cat';
}

function isFileWriteTool(name) {
  return name === 'write_file' || name === 'writeFile' || name === 'edit_file' || name === 'editFile' || name === 'apply_patch' || name === 'replace_file_content';
}

export function apply(ctx, config) {
  const logger = ctx.logger ? ctx.logger(name) : console;
  let currentConfig = plainConfig(config) || {};
  let storageAdapter = null;
  let stripperRegistry = null;

  try {
    if (ctx.storageDomain && typeof ctx.storageDomain === 'function') {
      const domainPromise = ctx.storageDomain('dsh_shadow_auditor');
      if (domainPromise && typeof domainPromise.then === 'function') {
        domainPromise
          .then((domain) => {
            if (domain) {
              storageAdapter = createStorageAdapter(domain);
              stripperRegistry = new StripperRegistry({ storageAdapter, logger });
            }
          })
          .catch((err) => {
            logger.debug?.('[shadow-auditor] storageDomain resolution error:', err);
          });
      }
    }
  } catch (err) {
    logger.debug?.('[shadow-auditor] storageDomain access error:', err);
  }

  if (!stripperRegistry) {
    storageAdapter = createStorageAdapter(null);
    stripperRegistry = new StripperRegistry({ storageAdapter, logger });
    logger.info?.('[shadow-auditor] storageDomain service not available, running in-memory session mode.');
  }

  const getConfig = () => currentConfig;
  const dshHome = process.env.DSH_HOME || join(homedir(), '.dsh');
  const recorder = new AuditRecorder({
    dir: join(dshHome, 'logs', 'shadow-auditor'),
    maxFileSizeMb: currentConfig.maxFileSizeMb,
    retentionDays: currentConfig.retentionDays,
    logger,
  });

  const recentEvents = new Map();
  const turnEnds = new Map();
  let lastAudit = { level: 'green', hits: [], at: Date.now() };

  if (ctx.settings && typeof ctx.settings.subscribe === 'function') {
    ctx.effect(() => {
      const off = ctx.settings.subscribe((raw) => {
        const plain = plainConfig(raw);
        if (plain) {
          const cfg = (typeof plain === 'object' && plain !== null && NS in plain) ? plain[NS] : plain;
          currentConfig = Object.assign({}, currentConfig, plainConfig(cfg));
          recorder.rotateIfNecessary(currentConfig.maxFileSizeMb);
        }
      });
      return () => { try { off && off(); } catch (err) { logger.debug?.('[shadow-auditor] Settings subscription cleanup failed (error type: ' + (err?.name || 'Error') + ').'); } };
    }, 'shadow-auditor: settings');
  }

  // Tools registration wrapped in ctx.effect for clean hot-reload lifecycle (#87)
  if (ctx.tools) {
    ctx.effect(() => {
      const offs = [];
      try {
        offs.push(ctx.tools.register({
          name: 'shadow_auditor_scan_diff',
          description: 'Scan diff or text for leaked secrets, private paths and credentials. Returns level green/yellow/red and hits.',
          parameters: { type: 'object', properties: { diff: { type: 'string', description: 'Diff or text to scan' } }, required: ['diff'] },
          execute: async ({ diff }) => {
            const cfg = getConfig();
            if (!cfg.strictSecretScanning) return { level: 'green', hits: [], skipped: true };
            const res = scanSecrets(String(diff || ''));
            lastAudit = {
              level: res.level,
              hits: res.hits.map(h => ({ type: h.type, label: h.label, match: h.match })),
              at: Date.now(),
              source: 'scan_diff'
            };
            return res;
          }
        }));

        offs.push(ctx.tools.register({
          name: 'shadow_auditor_diff_gate',
          description: 'Scan diff or code change against code-security gate (secrets, SAST vulnerabilities, prompt injections). Returns findings and action allow/warn/block.',
          parameters: {
            type: 'object',
            properties: {
              diff: { type: 'string', description: 'Diff or file content to scan' },
              filePath: { type: 'string', description: 'Target file path' }
            },
            required: ['diff']
          },
          execute: async ({ diff, filePath }) => {
            const cfg = getConfig();
            const res = scanDiff({
              diffText: String(diff || ''),
              filePath: filePath || 'unknown',
              options: {
                mode: cfg.diffGateMode || 'warning',
                enableSecrets: cfg.strictSecretScanning,
                enableSast: cfg.enableSastScan !== false,
                enablePromptInjection: cfg.enablePromptInjectionScan !== false
              }
            });
            lastAudit = {
              level: res.action === 'block' ? 'red' : (res.findings.length > 0 ? 'yellow' : 'green'),
              hits: res.findings.map(f => ({ type: f.category, label: f.ruleId, match: f.evidence, remediation: f.remediation, explanation: f.explanation })),
              diffGate: { action: res.action, stats: res.stats, findings: res.findings },
              at: Date.now(),
              source: 'diff_gate'
            };
            return res;
          }
        }));

        offs.push(ctx.tools.register({
          name: 'shadow_auditor_check_command',
          description: 'Check shell command for dangerous patterns (rm -rf, systemctl, DB drop, force-push, curl|bash, exfiltration). Returns blocked + hit.',
          parameters: { type: 'object', properties: { command: { type: 'string', description: 'Shell command to check' } }, required: ['command'] },
          execute: async ({ command }) => {
            const cfg = getConfig();
            if (!cfg.blockDangerousCommands) return { blocked: false, hit: null, skipped: true };
            let dryRunInfo = null;
            let urlCredInfo = null;
            const hit = findDangerous(String(command || ''), {
              customBlockedCommands: cfg.customBlockedCommands,
              sensitivePathPatterns: cfg.sensitivePathPatterns,
              logger,
              onDryRun: (info) => { dryRunInfo = info; },
              onUrlCredentials: (info) => { urlCredInfo = info; }
            });
            const res = hit
              ? { blocked: true, hit }
              : { blocked: false, hit: null, dryRun: Boolean(dryRunInfo), dryRunInfo: dryRunInfo || undefined, urlCredentials: Boolean(urlCredInfo), urlCredentialsInfo: urlCredInfo || undefined };
            lastAudit = {
              level: hit ? 'red' : 'green',
              hits: hit ? [hit] : (dryRunInfo ? [{ type: 'dry-run-verification', label: dryRunInfo.label, match: dryRunInfo.match }] : []),
              at: Date.now(),
              source: 'check_command'
            };
            return res;
          }
        }));

        offs.push(ctx.tools.register({
          name: 'shadow_auditor_system_audit',
          description: 'Perform read-only security audit of host environment (config secrets, permissions, network bindings, env). Returns structured audit findings.',
          parameters: {
            type: 'object',
            properties: {
              scopes: {
                type: 'array',
                items: { type: 'string' },
                description: 'Audit scopes to inspect (config, plugins, paths, network, env, all)'
              },
              sampleLimit: {
                type: 'number',
                description: 'Maximum number of findings to report'
              }
            }
          },
          execute: async ({ scopes, sampleLimit } = {}) => {
            return runSystemAudit({ scopes, sampleLimit });
          }
        }));
      } catch (err) { logger.warn?.('[shadow-auditor] Failed to register tools:', err); }
      return () => {
        for (const off of offs) {
          try { off?.(); } catch (err) { logger.debug?.('[shadow-auditor] Effect cleanup failed (error type: ' + (err?.name || 'Error') + ').'); }
        }
      };
    }, 'shadow-auditor: tools');
  }

  // Multi-surface lifecycle interception engine (#84, #108, #109, #110, #111, #124, #125, #126, #135)
  registerLifecycleHooks(ctx, {
    getConfig,
    recorder,
    isCommandTool,
    isFileReadTool,
    isFileWriteTool,
    recordGuardHit,
    setLastAudit: (audit) => { lastAudit = audit; },
    logger,
    stripperRegistry
  });

  // Telemetry hook: tools/result with { global: true }
  try {
    ctx.effect(() => {
      const off = ctx.on('tools/result', (execution, result) => {
        try {
          const cfg = getConfig();
          if (!cfg.enableAuditLog) return;
          const sessionId = String(execution.agent?.session?.header?.id ?? 'unknown');
          const evalRes = evaluateRisk(execution.name, execution.arguments);

          const history = recentEvents.get(sessionId) || [];
          const cumulative = applyCumulative(evalRes.score, evalRes.tags, history, Date.now());
          history.push({ time: Date.now(), tags: evalRes.tags, score: cumulative.score });
          if (history.length > 200) history.splice(0, history.length - 200);
          recentEvents.set(sessionId, history);

          const isError = result && result.isError === true;
          const errMessage = isError && result.error ? String(result.error.message || result.error) : undefined;
          const safeArgs = redactValue(execution.arguments);

          const record = {
            time: new Date().toISOString(),
            sessionId,
            callId: String(execution.callId || ''),
            toolName: String(execution.name || ''),
            args: safeArgs,
            argsDigest: digestOf(safeArgs, { alreadyRedacted: true }),
            success: !isError,
            resultDigest: digestOf(result),
            error: errMessage ? redactText(errMessage) : undefined,
            blockedByGuard: errMessage && errMessage.includes('[shadow-auditor]')
              ? errMessage.replace(/^.*\[shadow-auditor\]\s*/, '')
              : undefined,
            score: cumulative.score,
            tags: evalRes.tags,
            reasons: [...evalRes.reasons, ...cumulative.extraReasons],
          };

          recorder.record(record).catch(err => logger.warn?.("[shadow-auditor] Failed to record audit event:", err));
        } catch (err) {
          logger.debug?.('[shadow-auditor] Event handler failed (error type: ' + (err?.name || 'Error') + ').');
        }
      }, { global: true });
      return () => { try { off?.(); } catch (err) { logger.debug?.('[shadow-auditor] Effect cleanup failed (error type: ' + (err?.name || 'Error') + ').'); } };
    }, 'shadow-auditor: tools/result listener');
  } catch (err) {
    logger.debug?.('[shadow-auditor] Audit telemetry listener registration failed (error type: ' + (err?.name || 'Error') + ').');
  }

  // Turn boundary tracker: session/event (turn/end)
  try {
    ctx.effect(() => {
      const off = ctx.on('session/event', (session, event) => {
        try {
          const sid = String(session.id || session.header?.id || 'unknown');
          if (event && event.type === 'turn/end') {
            const ends = turnEnds.get(sid) || [];
            ends.push(event.time || Date.now());
            if (ends.length > 20) ends.splice(0, ends.length - 20);
            turnEnds.set(sid, ends);
          } else if (event && (event.type === 'session/destroy' || event.type === 'session/dispose' || event.type === 'close')) {
            turnEnds.delete(sid);
            recentEvents.delete(sid);
          }
        } catch (err) {
          logger.debug?.('[shadow-auditor] Event handler failed (error type: ' + (err?.name || 'Error') + ').');
        }
      }, { global: true });
      return () => { try { off?.(); } catch (err) { logger.debug?.('[shadow-auditor] Effect cleanup failed (error type: ' + (err?.name || 'Error') + ').'); } };
    }, 'shadow-auditor: session turn/end listener');
  } catch (err) {
    logger.debug?.('[shadow-auditor] Session listener registration failed (error type: ' + (err?.name || 'Error') + ').');
  }

  registerRestoreCommand(ctx, { stripperRegistry, logger });
  registerAuditCommand(ctx, { recorder, turnEnds, logger, stripperRegistry });

  // HTTP endpoints: audit state, real-time events feed, compliance export
  registerHttpRoutes(ctx, {
    logger,
    recorder,
    getConfig,
    getLastAudit: () => lastAudit
  });

  // Host-side one-click updater endpoint
  try {
    ctx.effect(() => import('./updater.js').then(m => m.registerPluginUpdater(ctx, {
      packageName: '@goodandready/dsh-shadow-auditor',
      endpoint: '/dsh-shadow-auditor/update',
      manifestUrl: new URL('../package.json', import.meta.url)
    })), 'shadow-auditor: updater');
  } catch (_) {}
}

export {
  isLoopbackAddress,
  extractBearerToken,
  extractTokenFromCookie,
  isTrustedRequest,
  sanitizeExportConfig,
  registerHttpRoutes
} from './routes.js';

export {
  Stripper,
  resolveOverlaps,
  findSensitiveMatches
} from './mask/engine.js';

export {
  createStorageAdapter,
  StripperRegistry
} from './mask/store.js';

export {
  registerRestoreCommand
} from './report.js';

export {
  runSystemAudit,
  checkConfigSecrets
} from './system-audit.js';

export {
  classifyCommand
} from './classifier.js';
