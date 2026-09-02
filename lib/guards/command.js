// ponytail: reuse DANGEROUS_PATTERNS from dsh-approval-gate + robust compound command analysis
export const DANGEROUS_PATTERNS = [
  { id: 'rm-rf', label: 'rm -rf', regex: /\brm\s+(-[a-zA-Z]*[rf][a-zA-Z]*\s+)+\S+/i },
  { id: 'kill', label: 'kill', regex: /\b(?:kill|pkill|killall)\b/i },
  { id: 'systemctl', label: 'systemctl', regex: /\bsystemctl\s+(?:stop|restart|disable|enable|mask|unmask|reboot|halt|poweroff|shutdown)\b/i },
  { id: 'service', label: 'service', regex: /\bservice\s+\S+\s+(?:stop|restart|force-stop|force-reload)\b/i },
  { id: 'db-destructive', label: 'DB destructive', regex: /\b(?:sqlite3|mysql|psql|pg_restore|mongo|mongosh|redis-cli|clickhouse-client)\b.*\b(?:ALTER|DROP|TRUNCATE|DELETE\s+FROM|CREATE\s+(?:TABLE|DATABASE|INDEX))\b/i },
  { id: 'env-write', label: '.env write', regex: /(?:\s(?:>>|>)\s|\|\s*tee\s+|\bsed\s+-i\b).*\.env\b/i },
  { id: 'secret-write', label: 'secret write', regex: /(?:\s(?:>>|>)\s|\|\s*tee\s+|\bsed\s+-i\b).*(?:secret|token|credential|api[_-]?key|passwd)\S*/i },
  // extras
  { id: 'force-flag', label: '--force', regex: /\b(?:git|pnpm|npm|dsh)\b[^;\n|&]*\s--force\b/i },
  { id: 'short-force', label: '-f force', regex: /\b(?:git\s+push|pnpm\s+publish|npm\s+publish)\b[^;\n]*\s-f\b/i },
  { id: 'curl-pipe', label: 'curl pipe', regex: /\b(?:curl|wget)\b[^|]*\|\s*(?:sudo\s+)?(?:bash|sh|zsh)\b/i },
  { id: 'mkfs-dd', label: 'mkfs/dd', regex: /\b(?:mkfs\b|dd\s+if=)/i },
  { id: 'chmod-777', label: 'chmod 777', regex: /\bchmod\s+777\b/ },
  { id: 'chown-r', label: 'chown -R', regex: /\bchown\s+-R\b/ },
];

export function findDangerous(command) {
  if (typeof command !== 'string' || command.trim() === '') return undefined;

  // Normalize escaped line continuations
  const normalized = command.replace(/\\\r?\n/g, ' ');

  // 1. Direct scan across the full normalized command (catches pipes, redirects, cross-token patterns)
  for (const p of DANGEROUS_PATTERNS) {
    p.regex.lastIndex = 0;
    const m = p.regex.exec(normalized);
    if (m) {
      return { id: p.id, label: p.label, match: m[0].slice(0, 160) };
    }
  }

  // 2. Chained subcommand segmentation (&&, ||, ;, newline)
  const segments = normalized.split(/(?:&&|\|\||;|\r?\n)/);
  for (const seg of segments) {
    const trimmed = seg.trim();
    if (!trimmed) continue;
    for (const p of DANGEROUS_PATTERNS) {
      p.regex.lastIndex = 0;
      const m = p.regex.exec(trimmed);
      if (m) {
        return { id: p.id, label: p.label, match: m[0].slice(0, 160) };
      }
    }
  }

  return undefined;
}