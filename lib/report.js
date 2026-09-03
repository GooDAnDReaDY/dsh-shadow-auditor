function timeOf(record) {
  return new Date(record.time).getTime();
}

export function parseBillFlags(rawInput = '') {
  const flags = String(rawInput).split(/\s+/).filter(Boolean);
  const sinceFlag = flags.find(f => f.startsWith('--since='));
  const sinceVal = sinceFlag ? sinceFlag.slice('--since='.length) : undefined;
  const parsed = sinceVal ? Date.parse(sinceVal) : undefined;
  return {
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
    const lastEnd = Math.max(...options.turnEnds);
    selected = selected.filter(r => timeOf(r) > lastEnd);
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
    `### 🛡️ Ведомость безопасности аудитора — \`${bill.sessionId}\``,
    '',
    `- **Период:** ${bill.from || '–'} → ${bill.to || '–'}`,
    `- **Инструменты:** ${bill.callCount} вызовов | **Ходов:** ${bill.turnCount} | **Высокий риск (≥40):** ${bill.highRiskCount} | **Заблокировано:** ${bill.blockedCount}`,
    `- **Уровни риска:** Низкий = ${bill.riskLevels.low} | Средний = ${bill.riskLevels.medium} | Высокий = ${bill.riskLevels.high}`,
    `- **Максимальный балл:** ${bill.maxScore} | **Суммарный балл:** ${bill.totalScore}`,
    `- **Теги:** ${Object.entries(bill.tagCounts).map(([t, c]) => `${t}: ${c}`).join(', ') || 'нет'}`,
  ];

  const risky = (bill.records || []).filter(r => (r.score || 0) >= 40);
  if (risky.length > 0) {
    lines.push('', '#### ⚠️ Операции с повышенным риском', '', '| Время | Инструмент | Баллы | Теги | Причина | Параметры |', '| --- | --- | ---: | --- | --- | --- |');
    for (const r of risky.slice(0, 25)) {
      const timeStr = (r.time || '').slice(11, 19);
      lines.push(`| ${timeStr} | \`${r.toolName}\` | ${r.score} | ${(r.tags || []).join(',')} | ${(r.reasons || []).join('; ')} | \`${argsSummary(r)}\` |`);
    }
  }

  const blocked = (bill.records || []).filter(r => r.blockedByGuard !== undefined);
  if (blocked.length > 0) {
    lines.push('', '#### ⛔ Перехваченные команды (Guard)', '');
    for (const r of blocked) {
      lines.push(`- **${(r.time || '').slice(11, 19)}** \`${r.toolName}\`: ${r.blockedByGuard}`);
    }
  }

  if ((bill.records || []).length === 0) {
    lines.push('', '_В этой сессии пока нет записей аудита._');
  }

  return lines.join('\n');
}

export function billsToMarkdown(bills = []) {
  if (bills.length === 0) return '### 🛡️ История аудита безопасности\n\n_Записей аудита пока нет._';
  return bills.map(b => billToMarkdown(b)).join('\n\n---\n\n');
}