export const DEFAULT_CREDENTIAL_FILES = [
  '.env',
  '.env.local',
  '.git-credentials',
  '.netrc',
  '.npmrc',
  '.pgpass',
  'credentials',
  'id_rsa',
  'id_ed25519',
  'key.pem',
  'server.key',
  'client.key',
  'service-account.json',
  '.aws/credentials',
];

const NETWORK_TOOLS = /\b(?:curl|wget|nc|ncat|socat|scp|rsync|ssh|ftp|sftp|telnet)\b/i;
const SHELL_AUTOSTART_ESCAPE = /(?:>>|>)\s*(?:~[\\/]\.(?:bash|zsh|profile|bashrc|zshrc)|(?:\/etc\/|\/var\/cron|\/usr\/|[A-Za-z]:[\\/](?:Windows|Program Files)))/i;

export const DANGEROUS_PATTERNS = [
  { id: 'rm-rf', label: 'rm -rf', regex: /\brm\s+(-[a-zA-Z]*[rf][a-zA-Z]*\s+)+\S+/i },
  { id: 'kill', label: 'kill', regex: /\b(?:kill|pkill|killall)\b/i },
  { id: 'systemctl', label: 'systemctl', regex: /\bsystemctl\s+(?:stop|restart|disable|enable|mask|unmask|reboot|halt|poweroff|shutdown)\b/i },
  { id: 'service', label: 'service', regex: /\bservice\s+\S+\s+(?:stop|restart|force-stop|force-reload)\b/i },
  { id: 'db-destructive', label: 'DB destructive', regex: /\b(?:sqlite3|mysql|psql|pg_restore|mongo|mongosh|redis-cli|clickhouse-client)\b.*\b(?:ALTER|DROP|TRUNCATE|DELETE\s+FROM|CREATE\s+(?:TABLE|DATABASE|INDEX))\b/i },
  { id: 'env-write', label: '.env write', regex: /(?:\s(?:>>|>)\s|\|\s*tee\s+|\bsed\s+-i\b).*\.env\b/i },
  { id: 'secret-write', label: 'secret write', regex: /(?:\s(?:>>|>)\s|\|\s*tee\s+|\bsed\s+-i\b).*(?:secret|token|credential|api[_-]?key|passwd)\S*/i },
  { id: 'curl-pipe', label: 'curl pipe', regex: /\b(?:curl|wget)\b[^|]*\|\s*(?:sudo\s+)?(?:bash|sh|zsh)\b/i },
  { id: 'mkfs-dd', label: 'mkfs/dd', regex: /\b(?:mkfs\b|mkfs\.|dd\b[\s\S]{0,160}of=\/dev\/(?!null|zero|urandom|random)\S+|wipefs|diskpart|format\s+[A-Za-z]:)/i },
  { id: 'chmod-777', label: 'chmod 777', regex: /\bchmod\s+(?:777|a\+w)\b/ },
  { id: 'chown-r', label: 'chown -R', regex: /\bchown\s+-R\b/ },
  // Git protection
  { id: 'git-reset-hard', label: 'git reset --hard', regex: /\bgit\s+reset\s+--hard\b[^;\n|&]*(?:\b(?:main|master|origin\/main|origin\/master)\b|\s*$)/i },
  { id: 'git-clean-force', label: 'деструктивный git clean', regex: /\bgit\s+clean\b[^;\n|&]*-(?:[a-zA-Z]*[fdx][a-zA-Z]*)/i },
];

function checkExfiltration(command, credentialFiles = DEFAULT_CREDENTIAL_FILES) {
  if (!NETWORK_TOOLS.test(command)) return undefined;
  const lower = command.toLowerCase();
  for (const cred of credentialFiles) {
    if (lower.includes(cred.toLowerCase())) {
      return {
        id: 'network-exfiltration',
        label: `сетевая передача файла секретов (${cred})`,
        match: command.slice(0, 160)
      };
    }
  }
  return undefined;
}

function checkWorkspaceEscape(command) {
  const m = SHELL_AUTOSTART_ESCAPE.exec(command);
  if (m) {
    return {
      id: 'workspace-escape',
      label: 'перенаправление вывода в системные пути/автозапуск',
      match: m[0].slice(0, 160)
    };
  }
  return undefined;
}

function checkProtectedForcePush(command) {
  if (!/\bgit\s+push\b/i.test(command)) return undefined;
  if (!/(?:^|\s)(?:--force|-f|--force-with-lease)(?:\s|$)/i.test(command)) return undefined;

  const afterPush = command.replace(/^.*?\bgit\s+push\b/i, '').trim();
  const tokens = afterPush.split(/\s+/).filter(t => !t.startsWith('-'));

  // If no branch specified (e.g. 'git push -f' or 'git push -f origin')
  if (tokens.length === 0 || (tokens.length === 1 && (tokens[0] === 'origin' || tokens[0] === 'upstream'))) {
    return {
      id: 'force-push-protected',
      label: 'force-push в защищённую ветку',
      match: command.slice(0, 160)
    };
  }

  const target = tokens[tokens.length - 1];
  const protectedBranches = ['main', 'master', 'prod', 'production', 'release'];
  for (const pb of protectedBranches) {
    if (target === pb || target.endsWith('/' + pb) || target.endsWith(':' + pb)) {
      return {
        id: 'force-push-protected',
        label: 'force-push в защищённую ветку',
        match: command.slice(0, 160)
      };
    }
  }

  return undefined;
}

export function findDangerous(command, options = {}) {
  if (typeof command !== 'string' || command.trim() === '') return undefined;

  const normalized = command.replace(/\\\r?\n/g, ' ');

  // 1. Network exfiltration check
  const exfil = checkExfiltration(normalized, options.credentialFiles);
  if (exfil) return exfil;

  // 2. Workspace escape redirect check
  const escapeHit = checkWorkspaceEscape(normalized);
  if (escapeHit) return escapeHit;

  // 3. Protected branch force push check
  const forcePushHit = checkProtectedForcePush(normalized);
  if (forcePushHit) return forcePushHit;

  // 4. Scan across full command
  for (const p of DANGEROUS_PATTERNS) {
    p.regex.lastIndex = 0;
    const m = p.regex.exec(normalized);
    if (m) {
      return { id: p.id, label: p.label, match: m[0].slice(0, 160) };
    }
  }

  // 5. Subcommand segmentation (&&, ||, ;, newline)
  const segments = normalized.split(/(?:&&|\|\||;|\r?\n)/);
  for (const seg of segments) {
    const trimmed = seg.trim();
    if (!trimmed) continue;

    const segExfil = checkExfiltration(trimmed, options.credentialFiles);
    if (segExfil) return segExfil;

    const segEscape = checkWorkspaceEscape(trimmed);
    if (segEscape) return segEscape;

    const segForcePush = checkProtectedForcePush(trimmed);
    if (segForcePush) return segForcePush;

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