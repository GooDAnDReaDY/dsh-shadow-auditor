import { homedir } from 'node:os';
import { join } from 'node:path';
import Schema from '@deepseek-ai/schemastery';
import { scanSecrets, SECRET_PATTERNS, INFRA_PATTERNS, maskSecret } from './guards/secrets.js';
import { findDangerous, DANGEROUS_PATTERNS } from './guards/command.js';
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
});

const NS = '@goodandready/dsh-shadow-auditor';

let lastAudit = { level: 'green', hits: [], at: 0, source: 'init' };

export function apply(ctx, config) {
  let getConfig = () => config;

  ctx.inject(['settings'], (sctx) => {
    const scope = sctx.settings.register(NS, Config, { base: config });
    getConfig = () => scope.get() ?? config;
  });

  const dshHome = process.env.DSH_HOME || join(homedir(), '.dsh');
  const recorder = new AuditRecorder({
    dir: join(dshHome, 'shadow-auditor'),
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
          description: 'Scan diff/text for leaked secrets, private paths and IPs. Returns level green/yellow/red and hits.',
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
          name: 'shadow_auditor_check_command',
          description: 'Check shell command for dangerous patterns (rm -rf, systemctl, DB drop, force-push, curl|bash, exfiltration). Returns blocked + hit.',
          parameters: { type: 'object', properties: { command: { type: 'string', description: 'Shell command to check' } }, required: ['command'] },
          execute: async ({ command }) => {
            const cfg = getConfig();
            if (!cfg.blockDangerousCommands) return { blocked: false, hit: null, skipped: true };
            const hit = findDangerous(String(command || ''));
            const res = hit ? { blocked: true, hit } : { blocked: false, hit: null };
            lastAudit = { level: hit ? 'red' : 'green', hits: hit ? [hit] : [], at: Date.now(), source: 'check_command' };
            return res;
          }
        }));

        offs.push(ctx.tools.register({
          name: 'shadow_auditor_rules_list',
          description: 'List active security rules (names only, no values).',
          parameters: { type: 'object', properties: {} },
          execute: async () => {
            return {
              secrets: SECRET_PATTERNS.map((p) => ({ id: p.id, label: p.label })),
              infra: INFRA_PATTERNS.map((p) => ({ id: p.id, label: p.label })),
              commands: DANGEROUS_PATTERNS.map((p) => ({ id: p.id, label: p.label })),
            };
          }
        }));
      } catch (_) {}

      return () => {
        for (const off of offs) {
          try { off?.(); } catch {}
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

            if (name === 'bash' || name.endsWith('/bash') || name.includes('bash')) {
              if (!cfg.blockDangerousCommands) return undefined;
              const cmd = typeof args === 'object' && args !== null ? String(args.command || '') : String(args || '');
              if (!cmd.trim()) return undefined;
              const hit = findDangerous(cmd);
              if (hit) {
                lastAudit = { level: 'red', hits: [hit], at: Date.now(), source: 'guard:command' };
                if (cfg.enableAuditLog) {
                  void recorder.record({
                    time: new Date().toISOString(),
                    sessionId,
                    callId: String(execution.callId || ''),
                    toolName: name,
                    args: redactValue(args),
                    argsDigest: digestOf(args),
                    success: false,
                    blockedByGuard: `${hit.label}: ${String(hit.match).slice(0, 100)}`,
                    score: 95,
                    tags: ['destructive'],
                    reasons: [`Заблокировано: ${hit.label}`],
                  });
                }
                return '\u26d4 [shadow-auditor] Команда заблокирована: `' + String(hit.match).slice(0, 120) + '` (' + hit.label + ').';
              }
            }

            if (name.includes('edit') || name.includes('write') || name.includes('patch') || name.includes('apply')) {
              if (!cfg.strictSecretScanning) return undefined;
              let text = '';
              if (typeof args === 'string') {
                text = args;
              } else if (args && typeof args === 'object') {
                if (typeof args.content === 'string') text = args.content;
                else if (typeof args.patch === 'string') text = args.patch;
                else if (typeof args.diff === 'string') text = args.diff;
                else text = JSON.stringify(args);
              }
              const sec = scanSecrets(text);
              if (sec.level === 'red') {
                const safeHits = sec.hits.map(h => ({ type: h.type, label: h.label, match: h.match }));
                lastAudit = { level: sec.level, hits: safeHits, at: Date.now(), source: 'guard:secrets' };
                const first = safeHits[0];
                if (cfg.enableAuditLog) {
                  void recorder.record({
                    time: new Date().toISOString(),
                    sessionId,
                    callId: String(execution.callId || ''),
                    toolName: name,
                    args: redactValue(args),
                    argsDigest: digestOf(args),
                    success: false,
                    blockedByGuard: `Секрет (${first.label}): ${String(first.match)}`,
                    score: 95,
                    tags: ['credential-read'],
                    reasons: [`Заблокирована запись секрета: ${first.label}`],
                  });
                }
                return '\u26d4 [shadow-auditor] Обнаружен секрет (' + (first.label || first.type) + '): удалите ключи/токены из diff. Фрагмент: `' + String(first.match) + '`.';
              }
            }
          } catch {}
          return undefined;
        });
        return () => { try { off && off(); } catch {} };
      }, 'shadow-auditor: mandatory guard');
    }
  } catch {}

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

          void recorder.record(record);
        } catch (_) {}
      }, { global: true });
      return () => { try { off?.(); } catch {} };
    }, 'shadow-auditor: tools/result listener');
  } catch {}

  // Turn boundary tracker: session/event (turn/end)
  try {
    ctx.effect(() => {
      const off = ctx.on('session/event', (session, event) => {
        try {
          if (event && event.type === 'turn/end') {
            const sid = String(session.id || session.header?.id || 'unknown');
            const ends = turnEnds.get(sid) || [];
            ends.push(event.time || Date.now());
            turnEnds.set(sid, ends);
          }
        } catch (_) {}
      }, { global: true });
      return () => { try { off?.(); } catch {} };
    }, 'shadow-auditor: session turn/end listener');
  } catch {}

  // Chat slash command /audit
  try {
    ctx.inject(['commands'], (cctx) => {
      cctx.effect(() => {
        const off = cctx.commands.register({
          name: 'audit',
          description: 'Показать операционный отчёт аудита безопасности (Operation Bill)',
          input: { hint: 'audit [--turn] [--all] [--json] [--since=YYYY-MM-DD]' },
          handler: async ({ agent, rawInput }) => {
            try {
              const flags = parseBillFlags(rawInput);
              const sessionId = String(agent?.session?.header?.id ?? 'unknown');
              let records = await recorder.readAll();

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
              return { kind: 'error', text: `Ошибка формирования аудита: ${err && err.message ? err.message : String(err)}` };
            }
          },
        });
        return () => { try { off?.(); } catch {} };
      }, 'shadow-auditor: /audit command');
    });
  } catch {}

  // HTTP endpoint for badge polling with no-store cache control
  try {
    ctx.effect(() => ctx.webServer.register({
      kind: 'exact',
      path: '/dsh-shadow-auditor/audit',
      handler: (req, res) => {
        res.setHeader('content-type', 'application/json');
        res.setHeader('cache-control', 'no-store');
        res.end(JSON.stringify({ ...lastAudit, config: getConfig() }));
      }
    }), 'shadow-auditor: audit route');
  } catch {}
}