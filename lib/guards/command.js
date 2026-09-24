import path from 'node:path';
import os from 'node:os';

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


const DESTRUCTIVE_CMD_PATTERNS = [
  // POSIX rm with recursive flag
  {
    regex: /\brm\s+((?:(?:-[a-zA-Z]+|--[a-z-]+)\s+)+)(?:--\s+)?(.*)/i,
    isRecursive: (flags) => flags.split(/\s+/).some((f) => f === '--recursive' || /^-[a-zA-Z]*r[a-zA-Z]*$/i.test(f)),
    extractTargets: (match) => match[2]
  },
  // PowerShell Remove-Item / rmdir / rd / del / erase with -Recurse
  {
    regex: /\b(?:Remove-Item|rmdir|rd|del|erase)\b([^|;&\n]*)/i,
    isRecursive: (args) => /(?:^|\s)-(?:Recurse|r)\b/i.test(args),
    extractTargets: (match) => match[1]
  },
  // Windows cmd rd / rmdir / del / erase with /s
  {
    regex: /\b(?:rd|rmdir|del|erase)\b([^|;&\n]*)/i,
    isRecursive: (args) => /(?:^|\s)\/s\b/i.test(args),
    extractTargets: (match) => match[1]
  },
  // git clean with force flags
  {
    regex: /\bgit\s+clean\b([^|;&\n]*)/i,
    isRecursive: (args) => /(?:^|\s)-(?:[a-zA-Z]*[fdx][a-zA-Z]*|--force)\b/i.test(args),
    extractTargets: (match) => match[1]
  }
];

function resolvePathToken(token) {
  const trimmed = token.trim().replace(/^['"]|['"]$/g, '');
  if (!trimmed) return '';
  const home = os.homedir();
  if (trimmed === '~' || trimmed === '$HOME' || trimmed === '%USERPROFILE%') return home;
  if (trimmed.startsWith('~/') || trimmed.startsWith('~\\')) return path.join(home, trimmed.slice(2));
  if (trimmed.startsWith('$HOME/') || trimmed.startsWith('$HOME\\')) return path.join(home, trimmed.slice(6));
  return trimmed;
}

export function getProtectedPrefixes() {
  const home = os.homedir();
  const temp = os.tmpdir();
  const prefixes = [
    path.join(home, '.dsh'),
    path.join(home, '.claude'),
    path.join(home, '.ssh'),
    path.join(home, 'AppData', 'Roaming', 'PowerShell'),
    path.join(home, 'Documents', 'WindowsPowerShell'),
    path.join(temp, 'dsh-subprocess-'),
    '/etc',
    '/usr',
    '/boot',
    '/sys',
    '/proc',
    '/dev',
    '/var',
    '/bin',
    '/sbin'
  ];
  const root = path.parse(home).root;
  if (root) {
    prefixes.push(path.join(root, 'Windows'), path.join(root, 'Program Files'), path.join(root, 'Program Files (x86)'));
  }
  return prefixes;
}

export function isProtectedPrefix(targetPath) {
  if (!targetPath || typeof targetPath !== 'string') return { protected: false };
  const normTarget = targetPath.replace(/\\/g, '/').replace(/\/+$/, '').toLowerCase();
  const prefixes = getProtectedPrefixes();

  for (const prefix of prefixes) {
    const normPrefix = prefix.replace(/\\/g, '/').replace(/\/+$/, '').toLowerCase();
    if (normTarget === normPrefix || normTarget.startsWith(normPrefix + '/')) {
      return { protected: true, prefix };
    }
  }
  return { protected: false };
}

function isTargetOutsideWorkspace(target, workspaceDir) {
  const normWs = workspaceDir.replace(/\\/g, '/').replace(/\/+$/, '').toLowerCase();
  let normTarget = target.replace(/\\/g, '/').replace(/\/+$/, '').toLowerCase();

  if (normTarget === '/' || normTarget === '~' || normTarget === '$home' || /^[a-z]:\/?$/.test(normTarget)) {
    return { outside: true, isRoot: true };
  }

  const isAbs = normTarget.startsWith('/') || /^[a-z]:\//.test(normTarget);
  let resolved;
  if (isAbs) {
    resolved = normTarget;
  } else {
    resolved = path.posix.resolve(normWs, normTarget);
  }

  if (resolved === normWs) {
    return { outside: true, isRoot: true };
  }

  const expectedPrefix = normWs + '/';
  if (!resolved.startsWith(expectedPrefix)) {
    return { outside: true, isRoot: false };
  }

  return { outside: false, isRoot: false };
}


export function isDryRunCommand(command) {
  if (typeof command !== 'string' || !command.trim()) return false;
  // 1. PowerShell dry-run / confirmation markers (-WhatIf, -Confirm, -WhatIf:$true, etc.)
  if (/(?:^|\s)-(?:WhatIf|Confirm)(?::\$?(?:true|1))?\b/i.test(command)) {
    return true;
  }
  // 2. Generic GNU / CLI dry-run flag
  if (/(?:^|\s)--dry-run\b/i.test(command)) {
    return true;
  }
  // 3. Git clean dry-run (-n, -ndx, -fdn, --dry-run)
  if (/\bgit\s+clean\b/i.test(command)) {
    if (/(?:^|\s)-[a-zA-Z]*n[a-zA-Z]*\b/.test(command)) {
      return true;
    }
  }
  return false;
}

export function extractDryRunFlag(command) {
  if (typeof command !== 'string') return '';
  const pw = command.match(/(?:^|\s)(-(?:WhatIf|Confirm)(?::\$?(?:true|1))?)\b/i);
  if (pw) return pw[1].trim();
  const dr = command.match(/(?:^|\s)(--dry-run)\b/i);
  if (dr) return dr[1].trim();
  if (/\bgit\s+clean\b/i.test(command)) {
    const gc = command.match(/(?:^|\s)(-[a-zA-Z]*n[a-zA-Z]*)\b/);
    if (gc) return gc[1].trim();
  }
  return '';
}

export function checkDestructiveDeletion(command, options = {}) {
  if (typeof command !== 'string' || !command.trim()) return undefined;

  if (isDryRunCommand(command)) {
    if (options.onDryRun) {
      options.onDryRun({
        command,
        flag: extractDryRunFlag(command),
        label: 'destructive command dry-run',
        match: command.slice(0, 160)
      });
    }
    return undefined;
  }

  for (const item of DESTRUCTIVE_CMD_PATTERNS) {
    const m = item.regex.exec(command);
    if (!m) continue;

    if (!item.isRecursive(m[0])) continue;

    const rawArgs = item.extractTargets ? item.extractTargets(m) : '';
    const isFlag = (t) => t.startsWith('-') || (/^\/[a-zA-Z](?::\S+)?$/.test(t));
    const tokens = rawArgs
      .split(/\s+/)
      .map((t) => t.trim())
      .filter((t) => t && !isFlag(t) && !['&&', '||', ';', '|', '>', '>>', '2>&1'].includes(t));

    const workspace = options.workspace ? String(options.workspace) : null;

    if (tokens.length === 0 || tokens.some((t) => t === '/*' || t === '~/*' || t === '/' || t === '~')) {
      return {
        id: 'destructive-delete-outside-workspace',
        label: 'destructive delete outside workspace',
        match: m[0].slice(0, 160)
      };
    }

    for (const rawToken of tokens) {
      const resolvedToken = resolvePathToken(rawToken);

      // Unconditionally protected system prefixes (#105)
      const candidateAbs = workspace
        ? path.resolve(workspace, resolvedToken)
        : path.resolve(resolvedToken);

      const protCheck = isProtectedPrefix(candidateAbs).protected
        ? isProtectedPrefix(candidateAbs)
        : isProtectedPrefix(resolvedToken);

      if (protCheck.protected) {
        return {
          id: 'destructive-delete-protected-prefix',
          label: 'destructive delete: protected system prefix',
          match: m[0].slice(0, 160),
          target: rawToken,
          prefix: protCheck.prefix
        };
      }

      if (workspace) {
        const check = isTargetOutsideWorkspace(resolvedToken, workspace);
        if (check.outside) {
          return {
            id: 'destructive-delete-outside-workspace',
            label: 'destructive delete outside workspace',
            match: m[0].slice(0, 160),
            target: rawToken
          };
        }
      } else {
        if (resolvedToken === '/' || resolvedToken === os.homedir() || /^[a-zA-Z]:[\\/]?$/.test(resolvedToken) ||
            resolvedToken.startsWith('..') || resolvedToken.includes('/../') || resolvedToken.includes('\\..\\') ||
            /^(\/etc|\/usr|\/var|\/home|\/root|\/boot|\/sys|\/proc|C:\\Windows|C:\\Program Files)/i.test(resolvedToken)) {
          return {
            id: 'destructive-delete-outside-workspace',
            label: 'destructive delete outside workspace',
            match: m[0].slice(0, 160),
            target: rawToken
          };
        }
      }
    }

    return {
      id: 'rm-rf',
      label: 'recursive rm',
      match: m[0].slice(0, 160)
    };
  }

  return undefined;
}

function findRecursiveRm(command) {
  if (isDryRunCommand(command)) return undefined;
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

  const destructiveHit = checkDestructiveDeletion(normalized, options);
  if (destructiveHit) return destructiveHit;
  const recursiveRm = findRecursiveRm(normalized);
  if (recursiveRm) return recursiveRm;

  const sensitiveWrites = new Set(['env-write', 'secret-write']);

  // Scan whole command only for rules whose meaning spans a pipeline.
  for (const p of DANGEROUS_PATTERNS) {
    if (sensitiveWrites.has(p.id)) continue;
    if ((p.id === 'rm-rf' || p.id === 'git-clean-force') && isDryRunCommand(normalized)) {
      if (options.onDryRun) {
        options.onDryRun({
          command: normalized,
          flag: extractDryRunFlag(normalized),
          label: `${p.label} dry-run`,
          match: normalized.slice(0, 160)
        });
      }
      continue;
    }
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
      if ((p.id === 'rm-rf' || p.id === 'git-clean-force') && isDryRunCommand(trimmed)) {
        if (options.onDryRun) {
          options.onDryRun({
            command: trimmed,
            flag: extractDryRunFlag(trimmed),
            label: `${p.label} dry-run`,
            match: trimmed.slice(0, 160)
          });
        }
        continue;
      }
      p.regex.lastIndex = 0;
      const m = p.regex.exec(trimmed);
      if (m) return { id: p.id, label: p.label, match: m[0].slice(0, 160) };
    }
  }

  return undefined;
}
