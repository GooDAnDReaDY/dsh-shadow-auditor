import Schema from '@deepseek-ai/schemastery';
import { scanSecrets, SECRET_PATTERNS, INFRA_PATTERNS, maskSecret } from './guards/secrets.js';
import { findDangerous, DANGEROUS_PATTERNS } from './guards/command.js';

export const name = '@goodandready/dsh-shadow-auditor';
export const inject = ['tools', 'settings', 'webServer'];

export const Config = Schema.object({
  strictSecretScanning: Schema.boolean().default(true).description("Block execution if API keys or private tokens detected in diff"),
  blockDangerousCommands: Schema.boolean().default(true).description("Block destructive flags like --force, rm -rf /, etc."),
  enableAuditBadge: Schema.boolean().default(true).description("Display security shield badge in approval dialogs")
});

const NS = '@goodandready/dsh-shadow-auditor';

let lastAudit = { level: 'green', hits: [], at: 0, source: 'init' };

export function apply(ctx, config) {
  let getConfig = () => config;

  ctx.inject(['settings'], (sctx) => {
    const scope = sctx.settings.register(NS, Config, { base: config });
    getConfig = () => scope.get() ?? config;
  });

  // tools wrapped in ctx.effect for proper lifecycle disposal
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
          description: 'Check shell command for dangerous patterns (rm -rf, systemctl, DB drop, --force, curl|bash). Returns blocked + hit.',
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

  // mandatory guards - block even if agent forgets to call tools
  try {
    if (ctx.tools && typeof ctx.tools.guard === "function") {
      ctx.effect(() => {
        const off = ctx.tools.guard((execution) => {
          try {
            const cfg = getConfig();
            const name = String(execution.name || "");
            const args = execution.arguments;
            if (name === "bash" || name.endsWith("/bash") || name.includes("bash")) {
              if (!cfg.blockDangerousCommands) return undefined;
              const cmd = typeof args === "object" && args !== null ? String(args.command || "") : String(args || "");
              if (!cmd.trim()) return undefined;
              const hit = findDangerous(cmd);
              if (hit) {
                lastAudit = { level: "red", hits: [hit], at: Date.now(), source: "guard:command" };
                return "\u26d4 [shadow-auditor] Команда заблокирована: `" + String(hit.match).slice(0, 120) + "` (" + hit.label + "). Требуется подтверждение перед выполнением опасных действий.";
              }
            }
            if (name.includes("edit") || name.includes("write") || name.includes("patch") || name.includes("apply")) {
              if (!cfg.strictSecretScanning) return undefined;
              let text = "";
              if (typeof args === "string") {
                text = args;
              } else if (args && typeof args === "object") {
                if (typeof args.content === "string") text = args.content;
                else if (typeof args.patch === "string") text = args.patch;
                else if (typeof args.diff === "string") text = args.diff;
                else text = JSON.stringify(args);
              }
              const sec = scanSecrets(text);
              if (sec.level === "red") {
                const safeHits = sec.hits.map(h => ({ type: h.type, label: h.label, match: h.match }));
                lastAudit = { level: sec.level, hits: safeHits, at: Date.now(), source: "guard:secrets" };
                const first = safeHits[0];
                return "\u26d4 [shadow-auditor] Обнаружен секрет (" + (first.label || first.type) + "): удалите ключи/токены из diff перед записью. Фрагмент: `" + String(first.match) + "`.";
              }
            }
          } catch {}
          return undefined;
        });
        return () => { try { off && off(); } catch {} };
      }, "shadow-auditor: mandatory guard");
    }
  } catch {}

  // enrich approval/asked if events available - does not block, only audits
  try {
    const tryEvents = (ectx) => {
      const ev = ectx.events || ctx.events;
      if (!ev || typeof ev.on !== 'function') return;
      ectx.effect(() => {
        const off = ev.on('approval/asked', (payload) => {
          try {
            const cfg = getConfig();
            if (!cfg.enableAuditBadge) return;
            const args = payload?.arguments || payload?.toolArgs || {};
            const text = typeof args === 'string' ? args : JSON.stringify(args);
            const cmd = typeof args.command === 'string' ? args.command : text;
            const sec = scanSecrets(text);
            const danger = findDangerous(cmd);
            if (danger) {
              lastAudit = { level: 'red', hits: [danger], at: Date.now(), source: 'approval' };
            } else if (sec.level !== 'green') {
              const safeHits = sec.hits.map(h => ({ type: h.type, label: h.label, match: h.match }));
              lastAudit = { level: sec.level, hits: safeHits, at: Date.now(), source: 'approval' };
            } else {
              lastAudit = { level: 'green', hits: [], at: Date.now(), source: 'approval' };
            }
          } catch {}
        });
        return () => { try { off?.(); } catch {} };
      }, 'shadow-auditor: approval listener');
    };
    if (ctx.events) tryEvents(ctx);
    else ctx.inject(['events'], tryEvents);
  } catch {}

  // web route for badge polling with no-store cache control
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