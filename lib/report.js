import { createHash } from 'node:crypto';
import path from 'node:path';
import os from 'node:os';
import { calculateSecurityScore } from './score.js';
import { testMasking } from './mask/engine.js';

function timeOf(record) {
  return new Date(record.time).getTime();
}

/**
 * Normalizes filesystem paths in audit reports and events (#95).
 * Replaces user home directory with `<base>` and workspace directory with `<workspace>`.
 * Handles cross-platform separators (/ and \).
 * @param {string} base - Base / home directory path.
 * @param {string} workspace - Workspace / project root directory path.
 * @param {string} targetPath - Path to normalize.
 * @returns {string}
 */
export function norm(base, workspace, targetPath) {
  if (typeof targetPath !== 'string') return '';
  const homeDir = base || process.env.DSH_HOME || os.homedir();
  const wsDir = workspace || process.cwd();

  // Normalize all backslashes to forward slashes for uniform prefix comparison
  const uniformPath = targetPath.replace(/\\/g, '/');
  const uniformWs = wsDir.replace(/\\/g, '/').replace(/\/+$/, '');
  const uniformHome = homeDir.replace(/\\/g, '/').replace(/\/+$/, '');

  // Workspace has higher specificity than home directory
  if (uniformWs && uniformPath.startsWith(uniformWs)) {
    const rel = uniformPath.slice(uniformWs.length);
    return `<workspace>${rel.startsWith('/') ? rel : '/' + rel}`;
  }

  if (uniformHome && uniformPath.startsWith(uniformHome)) {
    const rel = uniformPath.slice(uniformHome.length);
    return `<base>${rel.startsWith('/') ? rel : '/' + rel}`;
  }

  return targetPath;
}

/**
 * Calculates a deterministic SHA-256 integrity checksum for an audit bill (#86).
 * @param {object} bill
 * @returns {string}
 */
export function calculateReportChecksum(bill) {
  if (!bill || typeof bill !== 'object') return '';
  const canonical = {
    sessionId: bill.sessionId || '',
    from: bill.from || '',
    to: bill.to || '',
    turnCount: bill.turnCount || 0,
    callCount: bill.callCount || 0,
    maxScore: bill.maxScore || 0,
    totalScore: bill.totalScore || 0,
    securityScore: bill.securityScore || 0,
    highRiskCount: bill.highRiskCount || 0,
    blockedCount: bill.blockedCount || 0,
    riskLevels: bill.riskLevels || { low: 0, medium: 0, high: 0 },
    tagCounts: bill.tagCounts || {},
    recordCount: Array.isArray(bill.records) ? bill.records.length : 0
  };
  return 'sha256:' + createHash('sha256').update(JSON.stringify(canonical)).digest('hex');
}

/**
 * Verifies that a report has not been tampered with by validating its checksum (#86).
 * @param {object} bill
 * @returns {boolean}
 */
export function verifyReportChecksum(bill) {
  if (!bill || typeof bill !== 'object' || !bill.reportChecksum) return false;
  return bill.reportChecksum === calculateReportChecksum(bill);
}

export function parseBillFlags(rawInput = '') {
  const flags = String(rawInput).split(/\s+/).filter(Boolean);
  const sinceFlag = flags.find(f => f.startsWith('--since='));
  const sinceVal = sinceFlag ? sinceFlag.slice('--since='.length) : undefined;
  const parsed = sinceVal ? Date.parse(sinceVal) : undefined;
  const limitFlag = flags.find(f => f.startsWith('--limit='));
  const limitVal = limitFlag ? Number(limitFlag.slice('--limit='.length)) : undefined;
  return {
    limit: Number.isFinite(limitVal) ? limitVal : 50,
    turn: flags.includes('--turn'),
    all: flags.includes('--all'),
    json: flags.includes('--json'),
    since: Number.isNaN(parsed) ? undefined : parsed,
  };
}

export function buildBill(records = [], sessionId = 'unknown', options = {}) {
  const sorted = [...records].sort((a, b) => String(a.time).localeCompare(String(b.time)));
  let selected = sorted;
  if (options.since !== undefined) {
    selected = selected.filter(r => timeOf(r) >= (options.since || 0));
  }
  if (options.lastTurnOnly && options.turnEnds && options.turnEnds.length > 0) {
    const sortedEnds = [...options.turnEnds].sort((a, b) => a - b);
    const lastEnd = sortedEnds[sortedEnds.length - 1];
    const prevEnd = sortedEnds.length > 1 ? sortedEnds[sortedEnds.length - 2] : 0;
    const inFlight = selected.filter(r => timeOf(r) > lastEnd);
    if (inFlight.length > 0) {
      selected = inFlight;
    } else {
      selected = selected.filter(r => {
        const t = timeOf(r);
        return t > prevEnd && t <= lastEnd;
      });
    }
  }

  const limit = options.limit || 50;
  if (selected.length > limit) {
    selected = selected.slice(-limit);
  }

  // Path normalization for safe report sharing (#95)
  if (options.normalizePaths !== false) {
    const base = options.baseDir || os.homedir();
    const ws = options.workspaceDir || process.cwd();
    selected = selected.map(r => {
      if (!r || typeof r !== 'object') return r;
      const clone = { ...r };
      if (clone.args && typeof clone.args === 'object') {
        const newArgs = { ...clone.args };
        for (const [k, v] of Object.entries(newArgs)) {
          if (typeof v === 'string' && (v.includes('/') || v.includes('\\'))) {
            newArgs[k] = norm(base, ws, v);
          }
        }
        clone.args = newArgs;
      }
      return clone;
    });
  }

  const tagCounts = {};
  for (const r of selected) {
    for (const t of r.tags || []) tagCounts[t] = (tagCounts[t] || 0) + 1;
  }

  const totalScore = selected.reduce((sum, r) => sum + (r.score || 0), 0);
  const maxScore = selected.reduce((max, r) => Math.max(max, r.score || 0), 0);
  const highRiskCount = selected.filter(r => (r.score || 0) >= 40).length;
  const blockedCount = selected.filter(r => r.blockedByGuard !== undefined).length;
  const riskLevels = { low: 0, medium: 0, high: 0 };
  for (const r of selected) {
    const s = r.score || 0;
    if (s >= 80) riskLevels.high += 1;
    else if (s >= 40) riskLevels.medium += 1;
    else riskLevels.low += 1;
  }

  // Calculate weighted Security Score (#97)
  const securityRating = calculateSecurityScore({ riskLevels });

  const bill = {
    sessionId,
    from: selected[0] ? selected[0].time : undefined,
    to: selected[selected.length - 1] ? selected[selected.length - 1].time : undefined,
    turnCount: options.turnEnds ? options.turnEnds.length : 0,
    callCount: selected.length,
    maxScore,
    totalScore,
    securityScore: securityRating.score,
    securityRating: securityRating.rating,
    securityStatus: securityRating.status,
    highRiskCount,
    blockedCount,
    riskLevels,
    tagCounts,
    records: selected,
  };
  bill.reportChecksum = calculateReportChecksum(bill);
  return bill;
}

export function buildSessionBills(records = [], options = {}) {
  const bySession = new Map();
  for (const r of records) {
    const sid = r.sessionId || 'unknown';
    const list = bySession.get(sid) || [];
    list.push(r);
    bySession.set(sid, list);
  }
  return [...bySession.entries()]
    .map(([sid, list]) => buildBill(list, sid, options))
    .sort((a, b) => String(b.to || '').localeCompare(String(a.to || '')));
}

function argsSummary(record) {
  const text = JSON.stringify(record.args || {});
  return text.length > 90 ? `${text.slice(0, 90)}…` : text;
}

export function billToMarkdown(bill) {
  const lines = [
    `### 🛡️ Shadow Security Audit Bill — \`${bill.sessionId}\``,
    '',
    `- **Period:** ${bill.from || '–'} → ${bill.to || '–'}`,
    `- **Tools:** ${bill.callCount} calls | **Turns:** ${bill.turnCount} | **High Risk (≥40):** ${bill.highRiskCount} | **Blocked:** ${bill.blockedCount}`,
    `- **Security Score:** **${bill.securityScore ?? 100}/100** (${bill.securityRating || 'Safe'})`,
    `- **Risk Levels:** Low = ${bill.riskLevels.low} | Medium = ${bill.riskLevels.medium} | High = ${bill.riskLevels.high}`,
    `- **Max Score:** ${bill.maxScore} | **Total Score:** ${bill.totalScore}`,
    `- **Integrity Checksum:** \`${bill.reportChecksum || 'none'}\``,
    `- **Tags:** ${Object.entries(bill.tagCounts).map(([t, c]) => `${t}: ${c}`).join(', ') || 'none'}`,
  ];

  const risky = (bill.records || []).filter(r => (r.score || 0) >= 40);
  if (risky.length > 0) {
    lines.push('', '#### ⚠️ High Risk Operations', '', '| Time | Tool | Score | Tags | Reason | Arguments |', '| --- | --- | ---: | --- | --- | --- |');
    for (const r of risky.slice(0, 25)) {
      const timeStr = (r.time || '').slice(11, 19);
      lines.push(`| ${timeStr} | \`${r.toolName}\` | ${r.score} | ${(r.tags || []).join(',')} | ${(r.reasons || []).join('; ')} | \`${argsSummary(r)}\` |`);
    }
  }

  const blocked = (bill.records || []).filter(r => r.blockedByGuard !== undefined);
  if (blocked.length > 0) {
    lines.push('', '#### ⛔ Intercepted Commands (Guard)', '');
    for (const r of blocked) {
      lines.push(`- **${(r.time || '').slice(11, 19)}** \`${r.toolName}\`: ${r.blockedByGuard}`);
    }
  }

  if ((bill.records || []).length === 0) {
    lines.push('', '_No audit entries recorded for this session yet._');
  }

  return lines.join('\n');
}

export function billsToMarkdown(bills = []) {
  if (bills.length === 0) return '### 🛡️ Shadow Security Audit History\n\n_No audit entries recorded yet._';
  return bills.map(b => billToMarkdown(b)).join('\n\n---\n\n');
}

export function registerAuditCommand(ctx, deps = {}) {
  const { recorder, turnEnds = new Map(), logger = console } = deps;
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
}

const AUDITOR_I18N = {
  en: {
    statusTitle: '### 🛡️ Shadow Auditor Status',
    securityScore: 'Security Score',
    totalCalls: 'Total Monitored Calls',
    highRisk: 'High-Risk Events (≥40)',
    blocked: 'Blocked Actions',
    policies: 'Active Security Policies',
    diffGate: 'Diff Gate Mode',
    secretScan: 'Strict Secret Scanning',
    shellGuard: 'Shell Guard Policy',
    sast: 'SAST Vulnerability Scan',
    memoryRing: 'In-Memory Ring Buffer',
    reportTitle: '### 🛡️ Shadow Auditor Incident Report',
    noIncidents: 'No security incidents or blocked actions recorded for this session.',
    usage: 'Usage: /shadow-auditor <status|report|restore <masked-text>>',
    restoreUsage: 'Usage: /shadow-auditor restore <masked-text>'
  },
  zh: {
    statusTitle: '### 🛡️ 影子审计器运行状态',
    securityScore: '安全评分',
    totalCalls: '监控调用总数',
    highRisk: '高风险事件 (≥40)',
    blocked: '已拦截操作',
    policies: '生效安全策略',
    diffGate: 'Diff 门禁模式',
    secretScan: '严格密钥扫描',
    shellGuard: 'Shell 拦截策略',
    sast: 'SAST 漏洞扫描',
    memoryRing: '内存环形缓冲区',
    reportTitle: '### 🛡️ 影子审计器事件报告',
    noIncidents: '当前会话未记录到安全事件或拦截动作。',
    usage: '用法: /shadow-auditor <status|report|restore <脱敏文本>>',
    restoreUsage: '用法: /shadow-auditor restore <脱敏文本>'
  }
};

function formatStatusMarkdown(locale, bill, cfg = {}, stats = {}) {
  const t = AUDITOR_I18N[locale] || AUDITOR_I18N.en;
  return [
    `${t.statusTitle} — \`${bill.sessionId}\``,
    '',
    `- **${t.securityScore}:** **${bill.securityScore ?? 100}/100** (${bill.securityRating || 'Safe'})`,
    `- **${t.totalCalls}:** ${bill.callCount} | **${t.highRisk}:** ${bill.highRiskCount} | **${t.blocked}:** ${bill.blockedCount}`,
    `- **${t.memoryRing}:** ${stats.memoryEntries ?? 0} / ${stats.maxReportEntries ?? 200}`,
    '',
    `#### ${t.policies}`,
    `- **${t.diffGate}:** \`${cfg.diffGateMode || 'warning'}\``,
    `- **${t.secretScan}:** \`${cfg.strictSecretScanning !== false ? 'enabled' : 'disabled'}\``,
    `- **${t.shellGuard}:** \`${cfg.shellGuardMode || 'enforce'}\``,
    `- **${t.sast}:** \`${cfg.enableSastScan !== false ? 'enabled' : 'disabled'}\``,
  ].join('\n');
}

export function registerRestoreCommand(ctx, deps = {}) {
  const { stripperRegistry, logger = console, recorder, getConfig } = deps;
  try {
    ctx.inject(['commands'], (cctx) => {
      cctx.effect(() => {
        const off = cctx.commands.register({
          name: 'shadow-auditor',
          description: 'Shadow auditor security utilities (/shadow-auditor status|report|restore <text>)',
          input: { hint: 'status | report | restore <masked-text>' },
          handler: async ({ agent, rawInput }) => {
            try {
              const input = String(rawInput || '').trim();
              const sessionId = String(agent?.session?.header?.id ?? 'unknown');
              const localeStr = String(agent?.session?.locale || agent?.locale || 'en').toLowerCase();
              const locale = localeStr.startsWith('zh') ? 'zh' : 'en';
              const t = AUDITOR_I18N[locale];

              if (input.startsWith('restore ') || input.startsWith('restore\t')) {
                const textToRestore = input.slice('restore'.length).trim();
                const restored = stripperRegistry ? stripperRegistry.restore(sessionId, textToRestore) : textToRestore;
                return { kind: 'success', text: restored };
              }
              if (input === 'restore') {
                return { kind: 'error', text: t.restoreUsage };
              }
              if (input === 'status' || input === '') {
                const records = (recorder?.getRecentMemory && recorder.ringBuffer?.length > 0)
                  ? recorder.getRecentMemory(50)
                  : (recorder?.readRecent ? await recorder.readRecent(50) : []);
                const sessionRecords = records.filter(r => r.sessionId === sessionId);
                const bill = buildBill(sessionRecords, sessionId);
                const cfg = getConfig ? getConfig() : {};
                const stats = recorder?.getStats ? recorder.getStats() : {};
                return { kind: 'success', text: formatStatusMarkdown(locale, bill, cfg, stats) };
              }
              if (input === 'report') {
                const records = (recorder?.getRecentMemory && recorder.ringBuffer?.length > 0)
                  ? recorder.getRecentMemory(50)
                  : (recorder?.readRecent ? await recorder.readRecent(50) : []);
                const sessionRecords = records.filter(r => r.sessionId === sessionId);
                const bill = buildBill(sessionRecords, sessionId);
                if (bill.blockedCount > 0 || bill.highRiskCount > 0) {
                  return { kind: 'success', text: billToMarkdown(bill) };
                }
                return { kind: 'success', text: `${t.reportTitle} — \`${sessionId}\`\n\n_${t.noIncidents}_` };
              }
              return { kind: 'error', text: `Unknown subcommand. Supported: ${t.usage}` };
            } catch (err) {
              return { kind: 'error', text: `Shadow auditor command error: ${err && err.message ? err.message : String(err)}` };
            }
          },
        });
        return () => { try { off?.(); } catch (err) { logger.debug?.('[shadow-auditor] Effect cleanup failed (error type: ' + (err?.name || 'Error') + ').'); } };
      }, 'shadow-auditor: /shadow-auditor command');
    });
  } catch (err) {
    logger.debug?.('[shadow-auditor] Restore command registration failed (error type: ' + (err?.name || 'Error') + ').');
  }
}

export function createAuditorReportTool(deps = {}) {
  const { recorder, turnEnds } = deps;
  return {
    name: 'shadow_auditor_report',
    description: 'Query security audit status, aggregated metrics, risk score, and list of blocked actions for the current session or host.',
    parameters: {
      type: 'object',
      properties: {
        sessionId: {
          type: 'string',
          description: 'Optional session ID to inspect (defaults to current session)'
        },
        limit: {
          type: 'number',
          description: 'Maximum number of recent findings to return (default: 50)'
        },
        includeRecords: {
          type: 'boolean',
          description: 'Whether to include detailed individual audit records in the report'
        }
      }
    },
    execute: async ({ sessionId, limit = 50, includeRecords = false } = {}) => {
      const maxLimit = Math.min(Math.max(1, Number(limit) || 50), 200);
      let records = (recorder?.getRecentMemory && recorder.ringBuffer?.length > 0)
        ? recorder.getRecentMemory(maxLimit * 2)
        : (recorder?.readRecent ? await recorder.readRecent(maxLimit * 2) : []);
      if (sessionId) {
        records = records.filter(r => r.sessionId === sessionId);
      }
      const bill = buildBill(records, sessionId || 'global', {
        limit: maxLimit,
        turnEnds: (turnEnds && turnEnds.get && sessionId) ? turnEnds.get(sessionId) : undefined
      });
      const blockedActions = records
        .filter(r => r.blockedByGuard !== undefined)
        .map(r => ({
          time: r.time,
          toolName: r.toolName,
          blockedByGuard: r.blockedByGuard,
          reasons: r.reasons
        }));
      const highRiskActions = records
        .filter(r => (r.score || 0) >= 40)
        .map(r => ({
          time: r.time,
          toolName: r.toolName,
          score: r.score,
          tags: r.tags,
          reasons: r.reasons
        }));

      return {
        sessionId: sessionId || 'global',
        securityScore: bill.securityScore,
        securityRating: bill.securityRating,
        securityStatus: bill.securityStatus,
        callCount: bill.callCount,
        highRiskCount: bill.highRiskCount,
        blockedCount: bill.blockedCount,
        riskLevels: bill.riskLevels,
        blockedActions,
        highRiskActions,
        tagCounts: bill.tagCounts,
        records: includeRecords ? bill.records : undefined
      };
    }
  };
}

export function createMaskTestTool(deps = {}) {
  const { stripperRegistry } = deps;
  return {
    name: 'shadow_auditor_mask_test',
    description: 'Test text masking rules statelessly and return masked text with entity replacement statistics.',
    parameters: {
      type: 'object',
      properties: {
        text: {
          type: 'string',
          description: 'Text snippet to test masking on'
        }
      },
      required: ['text']
    },
    execute: async ({ text } = {}) => {
      const input = String(text || '');
      const detector = stripperRegistry?.detector || null;
      return testMasking(input, { detector });
    }
  };
}
