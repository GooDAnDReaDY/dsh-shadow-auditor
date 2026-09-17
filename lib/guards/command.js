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
  'settings.yaml',
  'credentials.yaml',
];

const DEFAULT_CRED_PATTERNS = [
  '\\.env',
  '\\.env\\.local',
  '\\.git-credentials',
  '\\.netrc',
  '\\.npmrc',
  '\\.pgpass',
  '\\.?credentials',
  'id_rsa',
  'id_ed25519',
  'key\\.pem',
  'server\\.key',
  'client\\.key',
  'service-account\\.json',
  '\\.aws[\\\\/]credentials',
  'settings\\.ya?ml',
  'credentials\\.ya?ml',
];

const CRED_RE = new RegExp('(?:^|[\\\\/\\s@"\'=])(?:' + DEFAULT_CRED_PATTERNS.join('|') + ')(?:\\.[a-zA-Z0-9_-]+)?(?=$|[\\\\/\\s"\'`;|&])', 'i');

const UPLOAD_FLAGS = /(?:--data(?:-binary|-raw)?|-d|-F|--form|-T|--upload-file|--post-file)\s*=?\s*['"]?@?([^\s;'"]+)/gi;
const PIPE_EXFIL = /\b(?:cat|head|tail|more|less)\s+([^|;]+)\|\s*(?:sudo\s+)?(?:curl|wget|nc|ncat|socat|telnet|ssh)\b/i;
const REDIRECT_EXFIL = /\b(?:curl|wget|nc|ncat|socat|telnet)\b[^;\n|&]*<\s*([^\s;&|]+)/i;
const TRANSFER_EXFIL = /\b(?:scp|rsync|sftp)\b/i;

const SHELL_AUTOSTART_ESCAPE = /(?:>>|>)\s*(?:~[\\/]\.(?:bash|zsh|profile|bashrc|zshrc)|(?:\/etc\/|\/var\/cron|\/usr\/|[A-Za-z]:[\\/](?:Windows|Program Files)))/i;

export const DANGEROUS_PATTERNS = [
  { id: 'rm-rf', label: 'recursive rm', regex: /\brm\s+(?:-[a-zA-Z]*r[a-zA-Z]*|--recursive)(?:\s+|$)\S+/i },
  { id: 'kill', label: 'kill', regex: /(?:^|[;&|\n]\s*)(?:sudo\s+)?(?:kill|pkill|killall)\s+(-[a-zA-Z0-9]+\s+)*(?:--\S+|[0-9]+|SIG[A-Z0-9]+)\b/i },
  { id: 'systemctl', label: 'systemctl', regex: /(?:^|[;&|\n]\s*)(?:sudo\s+)?systemctl\s+(?:stop|restart|disable|mask|unmask|reboot|halt|poweroff|shutdown)\b/i },
  { id: 'service', label: 'service', regex: /\bservice\s+\S+\s+(?:stop|restart|force-stop|force-reload)\b/i },
  { id: 'db-destructive', label: 'DB destructive', regex: /\b(?:sqlite3|mysql|psql|pg_restore|mongo|mongosh|redis-cli|clickhouse-client)\b.*\b(?:ALTER|DROP|TRUNCATE|DELETE\s+FROM|CREATE\s+(?:TABLE|DATABASE|INDEX))\b/i },
  { id: 'env-write', label: '.env write', regex: /(?:\s(?:>>|>)\s|\|\s*tee\s+|\bsed\s+-i\b).*\.env\b/i },
  { id: 'secret-write', label: 'secret write', regex: /(?:\btee\s+(?:-a\s+)?|>>|>|\bsed\s+-i\b)\s*.*?(?:\.env|\.?credentials|\.git-credentials|\.netrc|\.pgpass|id_rsa|id_ed25519|[a-zA-Z0-9_.-]*key\.pem|settings\.ya?ml)\b/i },
  { id: 'curl-pipe', label: 'curl pipe', regex: /\b(?:curl|wget)\b[^|]*\|\s*(?:sudo\s+)?(?:bash|sh|zsh)\b/i },
  { id: 'mkfs-dd', label: 'mkfs/dd', regex: /\b(?:mkfs\b|mkfs\.|dd\b[\s\S]{0,160}of=\/dev\/(?!null|zero|urandom|random)\S+|wipefs|diskpart|format\s+[A-Za-z]:)/i },
  { id: 'chmod-777', label: 'chmod 777', regex: /\bchmod\s+(?:777|a\+w)\b/ },
  { id: 'chown-r', label: 'chown -R', regex: /\bchown\s+-R\b/ },
  // Git protection
  { id: 'git-reset-hard', label: 'git reset --hard', regex: /\bgit\s+reset\s+--hard\b[^;\n|&]*(?:\b(?:main|master|origin\/main|origin\/master)\b|\s*$)/i },
  { id: 'git-clean-force', label: 'destructive git clean', regex: /\bgit\s+clean\b[^;\n|&]*-(?:[a-zA-Z]*[fdx][a-zA-Z]*)/i },
];

export function isSensitivePath(targetPath, customPatterns = [], logger = null) {
  if (!targetPath || typeof targetPath !== 'string') return false;
  const normalized = targetPath.replace(/\\/g, '/');
  const basename = normalized.split('/').pop() || '';

  // Check default credential files
  for (const f of DEFAULT_CREDENTIAL_FILES) {
    if (basename === f || normalized.endsWith('/' + f)) return true;
  }
  if (CRED_RE.test(normalized)) return true;

  // Check custom sensitive patterns (wildcards or regex strings)
  const patterns = Array.isArray(customPatterns) ? customPatterns : (typeof customPatterns === 'string' ? customPatterns.split(/\r?\n/) : []);
  for (const p of patterns) {
    const trimmed = String(p || '').trim();
    if (!trimmed) continue;
    try {
      if (trimmed.includes('*')) {
        const regexStr = '^' + trimmed.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$';
        if (new RegExp(regexStr, 'i').test(basename) || new RegExp(regexStr, 'i').test(normalized)) return true;
      } else {
        if (new RegExp(trimmed, 'i').test(normalized)) return true;
      }
    } catch (err) {
      logger?.debug?.('[shadow-auditor] Ignoring invalid sensitive-path pattern (error type: ' + (err?.name || 'Error') + ').');
    }
  }
  return false;
}

function checkExfiltration(command, customCredRegex) {
  const credRe = customCredRegex || CRED_RE;

  // 1. Upload/payload flags in curl/wget: -d @.env, -F file=@id_rsa, --post-file=id_rsa
  UPLOAD_FLAGS.lastIndex = 0;
  let m;
  while ((m = UPLOAD_FLAGS.exec(command)) !== null) {
    const target = m[1];
    if (credRe.test(target)) {
      return {
        id: 'network-exfiltration',
        label: `network secret exfiltration (${m[0].slice(0, 50)})`,
        match: m[0].slice(0, 160)
      };
    }
  }

  // 2. Piping file content into network tools: cat .env | curl
  const pipeHit = PIPE_EXFIL.exec(command);
  if (pipeHit && credRe.test(pipeHit[1])) {
    return {
      id: 'network-exfiltration',
      label: `piped network secret exfiltration (${pipeHit[0].slice(0, 50)})`,
      match: pipeHit[0].slice(0, 160)
    };
  }

  // 3. Input redirection: curl ... < .env
  const redirectHit = REDIRECT_EXFIL.exec(command);
  if (redirectHit && credRe.test(redirectHit[1])) {
    return {
      id: 'network-exfiltration',
      label: `redirected network secret exfiltration (${redirectHit[0].slice(0, 50)})`,
      match: redirectHit[0].slice(0, 160)
    };
  }

  // 4. Direct transfer via scp/rsync to remote
  if (TRANSFER_EXFIL.test(command) && /\S+@\S+|\S+:\S+/.test(command)) {
    if (credRe.test(command)) {
      return {
        id: 'network-exfiltration',
        label: `remote secret transfer (${command.slice(0, 50)})`,
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
      label: 'redirect output to system path or autostart',
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
      label: 'force push to protected branch',
      match: command.slice(0, 160)
    };
  }

  const target = tokens[tokens.length - 1];
  const protectedBranches = ['main', 'master', 'prod', 'production', 'release'];
  for (const pb of protectedBranches) {
    if (target === pb || target.endsWith('/' + pb) || target.endsWith(':' + pb)) {
      return {
        id: 'force-push-protected',
        label: 'force push to protected branch',
        match: command.slice(0, 160)
      };
    }
  }

  return undefined;
}

function checkCustomPatterns(text, customPatterns = [], logger = null) {
  const list = Array.isArray(customPatterns)
    ? customPatterns
    : (typeof customPatterns === 'string' ? customPatterns.split(/\r?\n/) : []);

  for (const item of list) {
    const trimmed = String(item || '').trim();
    if (!trimmed) continue;
    try {
      const re = new RegExp(trimmed, 'i');
      const m = re.exec(text);
      if (m) {
        return {
          id: 'custom-rule-violation',
          label: `custom security rule violation (${trimmed})`,
          match: m[0].slice(0, 160)
        };
      }
    } catch (err) {
      logger?.debug?.('[shadow-auditor] Ignoring invalid custom command pattern (error type: ' + (err?.name || 'Error') + ').');
    }
  }
  return undefined;
}

function splitShellStages(command) {
  const stages = [];
  let start = 0;
  let quote = "";
  let escaped = false;
  for (let i = 0; i < command.length; i += 1) {
    const c = command[i];
    if (escaped) { escaped = false; continue; }
    if (c.charCodeAt(0) === 92) { escaped = true; continue; }
    if (quote) {
      if (c === quote) quote = "";
      continue;
    }
    if (c === "'" || c === '"' || c === String.fromCharCode(96)) { quote = c; continue; }
    if (command.startsWith("&&", i) || command.startsWith("||", i)) {
      stages.push(command.slice(start, i));
      i += 1;
      start = i + 1;
      continue;
    }
    if (c === ";" || c === "|" || c === "\n" || c === "\r" || (c === "&" && command[i + 1] !== ">")) {
      stages.push(command.slice(start, i));
      start = i + 1;
    }
  }
  stages.push(command.slice(start));
  return stages;
}

function findRecursiveRm(command) {
  const optionGroup = /\brm\s+((?:(?:-[a-zA-Z]+|--[a-z-]+)\s+)+)(?:--\s+)?\S+/ig;
  let match;
  while ((match = optionGroup.exec(command)) !== null) {
    const options = match[1].trim().split(/\s+/);
    if (options.some((option) => option === "--recursive" || /^-[a-zA-Z]*r[a-zA-Z]*$/i.test(option))) {
      return { id: "rm-rf", label: "recursive rm", match: match[0].slice(0, 160) };
    }
  }
  return undefined;
}

export function findDangerous(command, options = {}) {
  if (typeof command !== 'string' || command.trim() === '') return undefined;

  const normalized = command.replace(/\\\r?\n/g, ' ');

  // Custom regex blocklists check
  if (options.customBlockedCommands) {
    const customHit = checkCustomPatterns(normalized, options.customBlockedCommands, options.logger);
    if (customHit) return customHit;
  }

  // 1. Network exfiltration check
  const exfil = checkExfiltration(normalized);
  if (exfil) return exfil;

  // 2. Workspace escape redirect check
  const escapeHit = checkWorkspaceEscape(normalized);
  if (escapeHit) return escapeHit;

  // 3. Protected branch force push check
  const forcePushHit = checkProtectedForcePush(normalized);
  if (forcePushHit) return forcePushHit;

  const recursiveRm = findRecursiveRm(normalized);
  if (recursiveRm) return recursiveRm;

  const sensitiveWrites = new Set(['env-write', 'secret-write']);

  // Scan whole command only for rules whose meaning spans a pipeline.
  for (const p of DANGEROUS_PATTERNS) {
    if (sensitiveWrites.has(p.id)) continue;
    p.regex.lastIndex = 0;
    const m = p.regex.exec(normalized);
    if (m) return { id: p.id, label: p.label, match: m[0].slice(0, 160) };
  }

  // Split commands and pipeline stages without splitting quoted or escaped separators.
  const segments = splitShellStages(normalized);
  for (const seg of segments) {
    const trimmed = seg.trim();
    if (!trimmed) continue;

    if (options.customBlockedCommands) {
      const segCustom = checkCustomPatterns(trimmed, options.customBlockedCommands, options.logger);
      if (segCustom) return segCustom;
    }

    const segExfil = checkExfiltration(trimmed);
    if (segExfil) return segExfil;

    const segEscape = checkWorkspaceEscape(trimmed);
    if (segEscape) return segEscape;

    const segForcePush = checkProtectedForcePush(trimmed);
    if (segForcePush) return segForcePush;

    for (const p of DANGEROUS_PATTERNS) {
      p.regex.lastIndex = 0;
      const m = p.regex.exec(trimmed);
      if (m) return { id: p.id, label: p.label, match: m[0].slice(0, 160) };
    }
  }

  return undefined;
}
