function timeOf(record) {
  return new Date(record.time).getTime();
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

  return {
    sessionId,
    from: selected[0] ? selected[0].time : undefined,
    to: selected[selected.length - 1] ? selected[selected.length - 1].time : undefined,
    turnCount: options.turnEnds ? options.turnEnds.length : 0,
    callCount: selected.length,
    maxScore,
    totalScore,
    highRiskCount,
    blockedCount,
    riskLevels,
    tagCounts,
    records: selected,
  };
}

export function buildSessionBills(records = []) {
  const bySession = new Map();
  for (const r of records) {
    const sid = r.sessionId || 'unknown';
    const list = bySession.get(sid) || [];
    list.push(r);
    bySession.set(sid, list);
  }
  return [...bySession.entries()]
    .map(([sid, list]) => buildBill(list, sid))
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
    `- **Risk Levels:** Low = ${bill.riskLevels.low} | Medium = ${bill.riskLevels.medium} | High = ${bill.riskLevels.high}`,
    `- **Max Score:** ${bill.maxScore} | **Total Score:** ${bill.totalScore}`,
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

export function registerRestoreCommand(ctx, deps = {}) {
  const { stripperRegistry, logger = console } = deps;
  try {
    ctx.inject(['commands'], (cctx) => {
      cctx.effect(() => {
        const off = cctx.commands.register({
          name: 'shadow-auditor',
          description: 'Shadow auditor session security utilities (/shadow-auditor restore <text>)',
          input: { hint: 'restore <masked-text>' },
          handler: async ({ agent, rawInput }) => {
            try {
              const input = String(rawInput || '').trim();
              if (input.startsWith('restore ') || input.startsWith('restore\t')) {
                const textToRestore = input.slice('restore'.length).trim();
                const sessionId = String(agent?.session?.header?.id ?? 'unknown');
                const restored = stripperRegistry ? stripperRegistry.restore(sessionId, textToRestore) : textToRestore;
                return { kind: 'success', text: restored };
              }
              if (input === 'restore') {
                return { kind: 'error', text: 'Usage: /shadow-auditor restore <masked-text>' };
              }
              return { kind: 'error', text: 'Unknown subcommand. Supported: /shadow-auditor restore <text>' };
            } catch (err) {
              return { kind: 'error', text: `Restore error: ${err && err.message ? err.message : String(err)}` };
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

