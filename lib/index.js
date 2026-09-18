import { registerPluginUpdater } from './updater.js';
import { homedir } from 'node:os';
import { join } from 'node:path';
import Schema from '@deepseek-ai/schemastery';
import { scanSecrets, SECRET_PATTERNS, INFRA_PATTERNS, maskSecret } from './guards/secrets.js';
import { scanDiff, scanFileContent } from './diff-gate/gate.js';
import { findDangerous, isSensitivePath, DANGEROUS_PATTERNS } from './guards/command.js';
import { AuditRecorder } from './recorder.js';
import { redactValue, redactText, digestOf } from './redact.js';
import { evaluateRisk, applyCumulative } from './score.js';
import { parseBillFlags, buildBill, buildSessionBills, billToMarkdown, billsToMarkdown } from './report.js';

export const name = '@goodandready/dsh-shadow-auditor';
export const inject = ['tools', 'settings', 'webServer'];

export const Config = Schema.object({
  strictSecretScanning: Schema.boolean().default(true).description('Block execution if API keys or private tokens detected in diff'),
  blockDangerousCommands: Schema.boolean().default(true).description('Block destructive flags like --force, rm -rf /, etc.'),
  enableAuditBadge: Schema.boolean().default(true).description('Display security shield badge in approval dialogs'),
  enableAuditLog: Schema.boolean().default(true).description('Record persistent JSONL audit logs with rotation under DSH_HOME'),
  maxFileSizeMb: Schema.number().default(50).description('Archive and compress audit log above this size in MB'),
  retentionDays: Schema.number().default(30).description('Retention period for archived audit logs in days'),
  diffGateMode: Schema.union(['disabled', 'warning', 'block']).default('warning').description('Diff gate mode: disabled, warning, or block'),
  shellGuardMode: Schema.union(['enforce', 'audit_only']).default('enforce').description('Shell guard policy: enforce blocks command, audit_only logs warning'),
  enableSastScan: Schema.boolean().default(true).description('Scan diffs for insecure code patterns (SQLi, command injection, path traversal, eval)'),
  enablePromptInjectionScan: Schema.boolean().default(true).description('Scan diffs for prompt-injection and adversarial instructions'),
  customBlockedCommands: Schema.string().default('').description('Custom regex patterns or commands to block (one per line)'),
  sensitivePathPatterns: Schema.string().default('').description('Custom sensitive file patterns or paths to monitor (one per line)'),
});

const NS = '@goodandready/dsh-shadow-auditor';

let lastAudit = { level: 'green', hits: [], at: 0, source: 'init' };

export function apply(ctx, config) {
  const logger = ctx.logger || console;
  let getConfig = () => config;

  ctx.inject(['settings'], (sctx) => {
    const scope = sctx.settings.register(NS, Config, { base: config });
    getConfig = () => scope.get() ?? config;
  });

  const dshHome = process.env.DSH_HOME || join(homedir(), '.dsh');
  const recorder = new AuditRecorder({
    dir: join(dshHome, 'shadow-auditor'),
    logger,
    maxFileSizeMb: config.maxFileSizeMb ?? 50,
    retentionDays: config.retentionDays ?? 30,
  });

  const recentEvents = new Map();
  const turnEnds = new Map();

  // Tools registration wrapped in ctx.effect for clean hot-reload lifecycle
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
            const hit = findDangerous(String(command || ''), {
              customBlockedCommands: cfg.customBlockedCommands,
              sensitivePathPatterns: cfg.sensitivePathPatterns,
              logger
            });
            const res = hit ? { blocked: true, hit } : { blocked: false, hit: null };
            lastAudit = { level: hit ? 'red' : 'green', hits: hit ? [hit] : [], at: Date.now(), source: 'check_command' };
            return res;
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

  // Mandatory guards - block even if agent forgets to call tools
  try {
    if (ctx.tools && typeof ctx.tools.guard === 'function') {
      ctx.effect(() => {
        const off = ctx.tools.guard((execution) => {
          try {
            const cfg = getConfig();
            const name = String(execution.name || '');
            const args = execution.arguments;
            const sessionId = String(execution.agent?.session?.header?.id ?? 'unknown');

            // 1. Shell and execution command guard
            if (name === 'bash' || name.endsWith('/bash') || name.includes('bash') || name.includes('exec') || name.includes('run_command') || name.includes('shell')) {
              if (cfg.blockDangerousCommands) {
                const cmd = typeof args === 'object' && args !== null
                  ? String(args.command || args.cmd || args.CommandLine || '')
                  : String(args || '');
                if (cmd.trim()) {
                  const hit = findDangerous(cmd, {
                    customBlockedCommands: cfg.customBlockedCommands,
                    sensitivePathPatterns: cfg.sensitivePathPatterns,
                    logger
                  });
                  if (hit) {
                    const isAuditOnly = cfg.shellGuardMode === 'audit_only';
                    lastAudit = { level: isAuditOnly ? 'yellow' : 'red', hits: [hit], at: Date.now(), source: 'guard:command' };
                    if (cfg.enableAuditLog) {
                      void recorder.record({
                        time: new Date().toISOString(),
                        sessionId,
                        callId: String(execution.callId || ''),
                        toolName: name,
                        args: redactValue(args),
                        argsDigest: digestOf(args),
                        success: isAuditOnly,
                        blockedByGuard: isAuditOnly ? undefined : `${hit.label}: ${String(hit.match).slice(0, 100)}`,
                        score: 95,
                        tags: ['destructive', 'command-safety'],
                        reasons: [isAuditOnly ? `Audit-only warning: ${hit.label}` : `Blocked by security guard: ${hit.label}`],
                      });
                    }
                    if (!isAuditOnly) {
                      return '\u26d4 [shadow-auditor] Command blocked: `' + String(hit.match).slice(0, 120) + '` (' + hit.label + ').';
                    }
                  }
                }
              }
            }

            // 2. File integrity & sensitive anchor protection
            if (name.includes('read') || name.includes('view') || name.includes('cat') || name.includes('file') || name.includes('fs')) {
              const targetPath = args && typeof args === 'object'
                ? (args.path || args.filePath || args.targetFile || args.file || args.AbsolutePath || '')
                : (typeof args === 'string' ? args : '');
              if (targetPath && isSensitivePath(targetPath, cfg.sensitivePathPatterns, logger)) {
                const isWrite = name.includes('write') || name.includes('edit') || name.includes('patch') || name.includes('create') || name.includes('delete') || name.includes('unlink');
                lastAudit = {
                  level: isWrite ? 'red' : 'yellow',
                  hits: [{ type: 'file-integrity', label: isWrite ? 'sensitive file modification' : 'sensitive file read', match: targetPath }],
                  at: Date.now(),
                  source: 'guard:file_integrity'
                };
                if (cfg.enableAuditLog) {
                  void recorder.record({
                    time: new Date().toISOString(),
                    sessionId,
                    callId: String(execution.callId || ''),
                    toolName: name,
                    args: redactValue(args),
                    argsDigest: digestOf(args),
                    success: !isWrite,
                    blockedByGuard: isWrite ? `File Integrity: protected sensitive file modification (${targetPath})` : undefined,
                    score: isWrite ? 95 : 60,
                    tags: ['file-integrity', 'sensitive-anchor'],
                    reasons: [isWrite ? `Blocked: attempt to modify protected sensitive file (${targetPath})` : `Warning: read access to sensitive anchor file (${targetPath})`],
                  });
                }
                if (isWrite && cfg.blockDangerousCommands) {
                  return '\u26d4 [shadow-auditor] File operation blocked: Attempt to modify protected sensitive anchor file (`' + targetPath + '`).';
                }
              }
            }

            // 3. Diff Gate check for source edits
            if (name.includes('edit') || name.includes('write') || name.includes('patch') || name.includes('apply')) {
              const gateMode = cfg.diffGateMode || 'warning';
              if (gateMode !== 'disabled' || cfg.strictSecretScanning) {
                let text = '';
                let targetPath = 'unknown';
                if (typeof args === 'string') {
                  text = args;
                } else if (args && typeof args === 'object') {
                  targetPath = args.path || args.filePath || args.targetFile || args.file || args.AbsolutePath || 'unknown';
                  if (typeof args.content === 'string') text = args.content;
                  else if (typeof args.patch === 'string') text = args.patch;
                  else if (typeof args.diff === 'string') text = args.diff;
                  else if (typeof args.ReplacementContent === 'string') text = args.ReplacementContent;
                  else if (typeof args.CodeContent === 'string') text = args.CodeContent;
                  else text = JSON.stringify(args);
                }

                // Diff gate evaluation (detect full file content vs patch diff)
                const isDiff = text.includes('--- a/') || text.includes('+++ b/') || text.includes('@@');
                const gateOptions = {
                  mode: gateMode,
                  enableSecrets: cfg.strictSecretScanning,
                  enableSast: cfg.enableSastScan !== false,
                  enablePromptInjection: cfg.enablePromptInjectionScan !== false
                };
                const scanRes = isDiff
                  ? scanDiff({ diffText: text, filePath: targetPath, options: gateOptions })
                  : scanFileContent({ content: text, filePath: targetPath, options: gateOptions });

                if (scanRes.findings.length > 0) {
                  const hits = scanRes.findings.map(f => ({
                    type: f.category,
                    label: f.ruleId,
                    match: f.evidence,
                    explanation: f.explanation,
                    remediation: f.remediation,
                    line: f.line
                  }));
                  lastAudit = {
                    level: scanRes.action === 'block' ? 'red' : 'yellow',
                    hits,
                    diffGate: { action: scanRes.action, stats: scanRes.stats, findings: scanRes.findings },
                    at: Date.now(),
                    source: 'guard:diff_gate'
                  };

                  if (scanRes.action === 'block') {
                    const top = scanRes.findings[0];
                    if (cfg.enableAuditLog) {
                      void recorder.record({
                        time: new Date().toISOString(),
                        sessionId,
                        callId: String(execution.callId || ''),
                        toolName: name,
                        args: redactValue(args),
                        argsDigest: digestOf(args),
                        success: false,
                        blockedByGuard: `DiffGate [${top.ruleId}]: ${top.explanation}`,
                        score: 95,
                        tags: [top.category],
                        reasons: [`Blocked by security diff gate: [${top.ruleId}] ${top.explanation}`],
                      });
                    }
                    return '\u26d4 [shadow-auditor] Code-security gate BLOCKED diff (' + top.ruleId + '): ' + top.explanation + '. Remediation: ' + top.remediation;
                  }
                }
              }
            }
          } catch (err) { logger.warn?.('[shadow-auditor] Guard execution error:', err); }
          return undefined;
        });
        return () => { try { off && off(); } catch (err) { logger.debug?.('[shadow-auditor] Guard cleanup failed (error type: ' + (err?.name || 'Error') + ').'); } };
      }, 'shadow-auditor: mandatory guard');
    }
  } catch (err) {
    logger.debug?.('[shadow-auditor] Mandatory guard registration failed (error type: ' + (err?.name || 'Error') + ').');
  }

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

          const record = {
            time: new Date().toISOString(),
            sessionId,
            callId: String(execution.callId || ''),
            toolName: String(execution.name || ''),
            args: redactValue(execution.arguments),
            argsDigest: digestOf(execution.arguments),
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

  // Chat slash command /audit
  try {
    ctx.inject(['commands'], (cctx) => {
      cctx.effect(() => {
        const off = cctx.commands.register({
          name: 'audit',
          description: 'Show security audit operational bill (Operation Bill)',
          input: { hint: 'audit [--turn] [--all] [--json] [--since=YYYY-MM-DD]' },
          handler: async ({ agent, rawInput }) => {
            try {
              const flags = parseBillFlags(rawInput);
              const sessionId = String(agent?.session?.header?.id ?? 'unknown');
              let records = flags.all ? await recorder.readAll() : await recorder.readRecent(flags.limit ?? 50);

              if (flags.since !== undefined) {
                records = records.filter(r => new Date(r.time).getTime() >= (flags.since || 0));
              }

              let text;
              if (flags.all) {
                const bills = buildSessionBills(records);
                text = flags.json ? JSON.stringify(bills, null, 2) : billsToMarkdown(bills);
              } else {
                const sessionRecords = records.filter(r => r.sessionId === sessionId);
                const bill = buildBill(sessionRecords, sessionId, {
                  lastTurnOnly: flags.turn,
                  turnEnds: turnEnds.get(sessionId),
                });
                text = flags.json ? JSON.stringify(bill, null, 2) : billToMarkdown(bill);
              }

              return { kind: 'success', text };
            } catch (err) {
              return { kind: 'error', text: `Audit generation error: ${err && err.message ? err.message : String(err)}` };
            }
          },
        });
        return () => { try { off?.(); } catch (err) { logger.debug?.('[shadow-auditor] Effect cleanup failed (error type: ' + (err?.name || 'Error') + ').'); } };
      }, 'shadow-auditor: /audit command');
    });
  } catch (err) {
    logger.debug?.('[shadow-auditor] Audit command registration failed (error type: ' + (err?.name || 'Error') + ').');
  }

function isTrustedRequest(req) {
  const rawAuth = req.headers['authorization'];
  if (typeof rawAuth === 'string' && rawAuth.startsWith('Bearer ')) return true;
  const cookieHeader = req.headers['cookie'];
  if (typeof cookieHeader === 'string' && (cookieHeader.includes('token=') || cookieHeader.includes('dsh_token='))) {
    return true;
  }
  const secFetch = req.headers['sec-fetch-site'];
  if (secFetch === 'same-origin') return true;
  const ip = req.socket?.remoteAddress || '';
  if (ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1') return true;
  return false;
}

function sanitizeExportConfig(cfg) {
  if (!cfg || typeof cfg !== 'object') return {};
  const copy = { ...cfg };
  // Redact potentially sensitive custom patterns from public config readout
  if (Array.isArray(copy.sensitivePathPatterns)) {
    copy.sensitivePathPatterns = copy.sensitivePathPatterns.map(p => typeof p === 'string' && p.length > 50 ? p.slice(0, 50) + '...' : p);
  }
  return copy;
}

  // HTTP endpoints: audit state, real-time events feed, compliance export
  try {
    ctx.effect(() => ctx.webServer.register({
      kind: 'exact',
      path: '/dsh-shadow-auditor/audit',
      handler: (req, res) => {
        if (req.method !== 'GET' && req.method !== 'HEAD') {
          res.writeHead(405, { allow: 'GET, HEAD', 'content-type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify({ error: 'Method Not Allowed' }));
          return;
        }
        if (!isTrustedRequest(req)) {
          res.writeHead(403, { 'content-type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify({ error: 'Access denied: untrusted caller' }));
          return;
        }
        res.setHeader('content-type', 'application/json');
        res.setHeader('cache-control', 'no-store');
        res.end(JSON.stringify({ ...lastAudit, stats: recorder.getStats(), config: sanitizeExportConfig(getConfig()) }));
      }
    }), 'shadow-auditor: audit route');

    ctx.effect(() => ctx.webServer.register({
      kind: 'exact',
      path: '/dsh-shadow-auditor/events',
      handler: async (req, res) => {
        if (req.method !== 'GET' && req.method !== 'HEAD') {
          res.writeHead(405, { allow: 'GET, HEAD', 'content-type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify({ error: 'Method Not Allowed' }));
          return;
        }
        if (!isTrustedRequest(req)) {
          res.writeHead(403, { 'content-type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify({ error: 'Access denied: untrusted caller' }));
          return;
        }
        try {
          res.setHeader('content-type', 'application/json');
          res.setHeader('cache-control', 'no-store');
          const url = new URL(req.url || '', 'http://localhost');
          const limit = Math.min(parseInt(url.searchParams.get('limit') || '50', 10), 200);
          const filter = url.searchParams.get('filter') || 'all';
          const sid = url.searchParams.get('sessionId');

          let records = await recorder.readRecent(limit * 3);
          if (sid) {
            records = records.filter(r => r.sessionId === sid);
          }
          if (filter === 'guard') {
            records = records.filter(r => r.blockedByGuard !== undefined || (r.tags && r.tags.includes('command-safety')));
          } else if (filter === 'diff_gate') {
            records = records.filter(r => (r.blockedByGuard && r.blockedByGuard.includes('DiffGate')) || (r.tags && (r.tags.includes('secret') || r.tags.includes('insecure_code') || r.tags.includes('prompt_injection'))));
          } else if (filter === 'high_risk') {
            records = records.filter(r => (r.score || 0) >= 40);
          }
          res.end(JSON.stringify({ records: records.slice(0, limit), total: records.length }));
        } catch (err) {
          res.statusCode = 500;
          res.end(JSON.stringify({ error: String(err && err.message ? err.message : err) }));
        }
      }
    }), 'shadow-auditor: events route');

    ctx.effect(() => ctx.webServer.register({
      kind: 'exact',
      path: '/dsh-shadow-auditor/export',
      handler: async (req, res) => {
        if (req.method !== 'GET' && req.method !== 'HEAD') {
          res.writeHead(405, { allow: 'GET, HEAD', 'content-type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify({ error: 'Method Not Allowed' }));
          return;
        }
        if (!isTrustedRequest(req)) {
          res.writeHead(403, { 'content-type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify({ error: 'Access denied: untrusted caller' }));
          return;
        }
        try {
          const url = new URL(req.url || '', 'http://localhost');
          const format = url.searchParams.get('format') || 'markdown';
          const sid = url.searchParams.get('sessionId');
          let records = await recorder.readAll();
          if (sid) {
            records = records.filter(r => r.sessionId === sid);
          }
          if (format === 'json') {
            res.setHeader('content-type', 'application/json; charset=utf-8');
            res.setHeader('content-disposition', 'attachment; filename="shadow-audit-export.json"');
            res.end(JSON.stringify(records, null, 2));
          } else {
            const bills = buildSessionBills(records);
            const md = billsToMarkdown(bills);
            res.setHeader('content-type', 'text/markdown; charset=utf-8');
            res.setHeader('content-disposition', 'attachment; filename="shadow-audit-bill.md"');
            res.end(md);
          }
        } catch (err) {
          res.statusCode = 500;
          res.end('Export error: ' + String(err && err.message ? err.message : err));
        }
      }
    }), 'shadow-auditor: export route');
  } catch (err) {
    logger.warn?.('[shadow-auditor] Failed to register web endpoints:', err);
  }

  // Host-side one-click updater endpoint
  try {
    ctx.effect(() => registerPluginUpdater(ctx, {
      packageName: '@goodandready/dsh-shadow-auditor',
      endpoint: '/dsh-shadow-auditor/update',
      manifestUrl: new URL('../package.json', import.meta.url)
    }), 'shadow-auditor: updater');
  } catch (err) {
    logger.debug?.('[shadow-auditor] Updater registration failed (error type: ' + (err?.name || 'Error') + ').');
  }

}
