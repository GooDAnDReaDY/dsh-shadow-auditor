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
  { id: 'kill', label: 'kill', regex: /(?:^|[;&|\n]\s*)(?:sudo\s+)?(?:kill|pkill|killall|Stop-Process|spps|taskkill)\s+(?:-[a-zA-Z0-9:]+\s+|\/[a-zA-Z0-9:]+\s+)*(?:--\S+|[0-9]+|SIG[A-Z0-9]+|\S+)\b/i },
  { id: 'systemctl', label: 'systemctl', regex: /(?:^|[;&|\n]\s*)(?:sudo\s+)?systemctl\s+(?:stop|restart|disable|mask|unmask|reboot|halt|poweroff|shutdown)\b/i },
  { id: 'service', label: 'service', regex: /\bservice\s+\S+\s+(?:stop|restart|force-stop|force-reload)\b/i },
  { id: 'db-destructive', label: 'DB destructive', regex: /\b(?:sqlite3|mysql|psql|pg_restore|mongo|mongosh|redis-cli|clickhouse-client)\b.*\b(?:ALTER|DROP|TRUNCATE|DELETE\s+FROM|CREATE\s+(?:TABLE|DATABASE|INDEX))\b/i },
  { id: 'env-write', label: '.env write', regex: /(?:\s(?:>>|>)\s|\|\s*tee\s+|\bsed\s+-i\b).*\.env\b/i },
  { id: 'secret-write', label: 'secret write', regex: /(?:\btee\s+(?:-a\s+)?|>>|>|\bsed\s+-i\b)\s*.*?(?:\.env|\.?credentials|\.git-credentials|\.netrc|\.pgpass|id_rsa|id_ed25519|[a-zA-Z0-9_.-]*key\.pem|settings\.ya?ml)\b/i },
  { id: 'curl-pipe', label: 'curl pipe', regex: /\b(?:curl|wget)\b[^|]*\|\s*(?:sudo\s+)?(?:bash|sh|zsh)\b/i },
  { id: 'mkfs-dd', label: 'mkfs/dd', regex: /\b(?:mkfs\b|mkfs\.|dd\b[\s\S]{0,160}of=\/dev\/(?!null|zero|urandom|random)\S+|wipefs|diskpart|format\s+[A-Za-z]:)/i },
  { id: 'chmod-777', label: 'chmod 777', regex: /\bchmod\s+(?:777|a\+w)\b/ },
  { id: 'chown-r', label: 'chown -R', regex: /\bchown\s+-R\b/ },
  { id: 'reg-delete', label: 'registry delete', regex: /\breg\s+delete\b.*(?:\/f|-f)\b/i },
  // Git protection
  { id: 'git-reset-hard', label: 'git reset --hard', regex: /\bgit\s+reset\s+--hard\b[^;\n|&]*(?:\b(?:main|master|origin\/main|origin\/master)\b|\s*$)/i },
  { id: 'git-clean-force', label: 'destructive git clean', regex: /\bgit\s+clean\b[^;\n|&]*-(?:[a-zA-Z]*[fdx][a-zA-Z]*)/i },
];

const REGEX_CACHE = new Map();
const MAX_REGEX_LEN = 256;
const DANGEROUS_QUANTIFIERS = /(\+|\*|\{.+?\})\s*(\+|\*|\{.+?\})|(\([^)]+?[+*]\)[+*])/;

function getSafeRegExp(pattern, flags = 'i', logger = null, context = 'custom pattern') {
  const key = `${flags}:${pattern}`;
  if (REGEX_CACHE.has(key)) return REGEX_CACHE.get(key);

  if (pattern.length > MAX_REGEX_LEN || DANGEROUS_QUANTIFIERS.test(pattern)) {
    logger?.debug?.(`[shadow-auditor] Rejecting potentially catastrophic or oversized ${context}: ${pattern.slice(0, 50)}`);
    return null;
  }

  try {
    const re = new RegExp(pattern, flags);
    if (REGEX_CACHE.size >= 100) {
      const firstKey = REGEX_CACHE.keys().next().value;
      REGEX_CACHE.delete(firstKey);
    }
    REGEX_CACHE.set(key, re);
    return re;
  } catch (err) {
    logger?.debug?.('[shadow-auditor] Ignoring invalid ' + context + ' (error type: ' + (err?.name || 'Error') + ').');
    return null;
  }
}

// Zero-width and formatting characters to strip (#82)
const ZERO_WIDTH_RE = /[\u200B-\u200D\uFEFF\u2060\u00AD\u200E\u200F\u202A-\u202E]/g;

// Homoglyphs map to Latin ASCII (all keys escaped to maintain zero Cyrillic literals invariant in lib/)
const HOMOGLYPH_MAP = {
  '\u0430': 'a', '\u0441': 'c', '\u0435': 'e', '\u043E': 'o', '\u0440': 'p',
  '\u0445': 'x', '\u0443': 'y', '\u0456': 'i', '\u0458': 'j', '\u0455': 's',
  '\u043A': 'k', '\u043C': 'm', '\u0442': 't', '\u0432': 'v', '\u043D': 'n',
  '\u0431': 'b', '\u0434': 'd', '\u0451': 'e', '\u0444': 'f',
  '\u0410': 'A', '\u0421': 'C', '\u0415': 'E', '\u041E': 'O', '\u0420': 'P',
  '\u0425': 'X', '\u0423': 'Y', '\u0406': 'I', '\u0408': 'J', '\u0405': 'S',
  '\u041A': 'K', '\u041C': 'M', '\u0422': 'T', '\u0412': 'B', '\u041D': 'H',
  '\u0411': 'B', '\u0414': 'D', '\u0401': 'E', '\u0424': 'F',
  '\u03B1': 'a', '\u0391': 'A',
  '\u03B2': 'b', '\u0392': 'B',
  '\u03BF': 'o', '\u039F': 'O',
  '\u03C1': 'p', '\u03A1': 'P',
  '\u03BD': 'v', '\u039D': 'N',
  '\u03C4': 't', '\u03A4': 'T',
};

/**
 * Normalizes command text by stripping zero-width characters,
 * converting fullwidth ASCII, and transliterating visual homoglyphs (#82).
 */
export function normalizeForScan(str) {
  if (typeof str !== 'string' || !str) return '';
  if (!/[^\x20-\x7E\t\r\n]/.test(str)) {
    return str;
  }
  let out = str.replace(ZERO_WIDTH_RE, '').replace(/\u3000/g, ' ');
  let res = '';
  for (let i = 0; i < out.length; i++) {
    const code = out.charCodeAt(i);
    if (code >= 0xFF01 && code <= 0xFF5E) {
      res += String.fromCharCode(code - 0xFEE0);
    } else {
      const char = out[i];
      res += HOMOGLYPH_MAP[char] || char;
    }
  }
  return res;
}

// Embedded URL credentials detection (#81)
const URL_CREDENTIALS_RE = /https?:\/\/([^:\s/@]+):([^@\s/]+)@([a-zA-Z0-9.\-_]+(?::\d+)?(?:\/[^\s"']*)?)/i;

export function detectUrlCredentials(command) {
  if (typeof command !== 'string') return null;
  const m = URL_CREDENTIALS_RE.exec(command);
  if (!m) return null;
  const masked = m[0].replace(/:\/\/[^:\s/@]+:[^@\s/]+@/, '://***:***@');
  return {
    id: 'url-credentials',
    label: 'embedded URL credentials',
    match: masked,
    rawMatch: m[0]
  };
}

// Base64 hidden payload inspection (#83)
const MAX_BASE64_TOKENS = 4;
const MAX_BASE64_LEN = 4096;
const BASE64_TOKEN_RE = /\b[A-Za-z0-9+/]{8,}={0,2}\b/g;

function isPrintableText(str) {
  if (!str || str.length < 4) return false;
  let printableCount = 0;
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i);
    if ((c >= 32 && c <= 126) || c === 9 || c === 10 || c === 13) {
      printableCount++;
    }
  }
  return (printableCount / str.length) >= 0.8;
}

function tryDecodeBase64Payload(token) {
  if (typeof token !== 'string' || token.length < 8 || token.length > MAX_BASE64_LEN) return null;
  try {
    const buf = Buffer.from(token, 'base64');
    if (buf.length < 4) return null;

    // 1. Check UTF-16LE (PowerShell -EncodedCommand)
    if (buf.length % 2 === 0) {
      let zeroBytePairs = 0;
      for (let i = 1; i < buf.length; i += 2) {
        if (buf[i] === 0) zeroBytePairs++;
      }
      if (zeroBytePairs >= (buf.length / 2) * 0.7) {
        const utf16Str = buf.toString('utf16le');
        if (isPrintableText(utf16Str)) return utf16Str;
      }
    }

    // 2. Check UTF-8
    const utf8Str = buf.toString('utf8');
    if (isPrintableText(utf8Str)) return utf8Str;

    return null;
  } catch {
    return null;
  }
}

export function inspectBase64Payloads(command, options = {}) {
  if (options._isSubscan) return undefined;

  BASE64_TOKEN_RE.lastIndex = 0;
  let m;
  let inspected = 0;
  while ((m = BASE64_TOKEN_RE.exec(command)) !== null && inspected < MAX_BASE64_TOKENS) {
    const token = m[0];
    inspected++;
    const decoded = tryDecodeBase64Payload(token);
    if (!decoded) continue;

    const subHit = findDangerous(decoded, {
      ...options,
      _isSubscan: true
    });

    if (subHit) {
      return {
        id: subHit.id,
        label: `${subHit.label} (hidden in base64 payload)`,
        match: subHit.match,
        payload: decoded.slice(0, 160)
      };
    }
  }
  return undefined;
}

/**
 * Static environment variable expansion for path targets (#107).
 */
export function resolveEnvToken(token) {
  if (typeof token !== 'string') return '';
  let str = token.trim().replace(/^['"]|['"]$/g, '');
  if (!str) return '';

  const home = os.homedir();
  const temp = os.tmpdir();
  const root = path.parse(home).root || (process.platform === 'win32' ? 'C:\\' : '/');
  const windir = process.env.SystemRoot || process.env.windir || (process.platform === 'win32' ? path.join(root, 'Windows') : '/');

  const envMap = {
    home,
    userprofile: home,
    temp,
    tmp: temp,
    appdata: process.env.APPDATA || path.join(home, 'AppData', 'Roaming'),
    localappdata: process.env.LOCALAPPDATA || path.join(home, 'AppData', 'Local'),
    windir,
    systemroot: windir,
    systemdrive: process.env.SystemDrive || root,
  };

  if (str === '~') return home;
  if (str.startsWith('~/') || str.startsWith('~\\')) {
    str = path.join(home, str.slice(2));
  }

  // 1. $env:VAR (PowerShell)
  str = str.replace(/\$env:([a-zA-Z_][a-zA-Z0-9_]*)/gi, (full, name) => {
    const k = name.toLowerCase();
    if (envMap[k]) return envMap[k];
    if (process.env[name]) return process.env[name];
    return full;
  });

  // 2. %VAR% (Windows cmd)
  str = str.replace(/%([a-zA-Z_][a-zA-Z0-9_]*)%/gi, (full, name) => {
    const k = name.toLowerCase();
    if (envMap[k]) return envMap[k];
    if (process.env[name]) return process.env[name];
    return full;
  });

  // 3. ${VAR} and $VAR (POSIX)
  str = str.replace(/\$\{([a-zA-Z_][a-zA-Z0-9_]*)\}/g, (full, name) => {
    const k = name.toLowerCase();
    if (envMap[k]) return envMap[k];
    if (process.env[name]) return process.env[name];
    return full;
  });
  str = str.replace(/\$([a-zA-Z_][a-zA-Z0-9_]*)/g, (full, name) => {
    const k = name.toLowerCase();
    if (envMap[k]) return envMap[k];
    if (process.env[name]) return process.env[name];
    return full;
  });

  if (process.platform !== 'win32') {
    str = str.replace(/\\/g, '/');
  }

  return str;
}

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
        const re = getSafeRegExp(regexStr, 'i', logger, 'sensitive-path pattern');
        if (re && (re.test(basename) || re.test(normalized))) return true;
      } else {
        const re = getSafeRegExp(trimmed, 'i', logger, 'sensitive-path pattern');
        if (re && re.test(normalized)) return true;
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
      const re = getSafeRegExp(trimmed, 'i', logger, 'custom command pattern');
      if (re) {
        const m = re.exec(text);
        if (m) {
          return {
            id: 'custom-rule-violation',
            label: `custom security rule violation (${trimmed})`,
            match: m[0].slice(0, 160)
          };
        }
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
  // PowerShell Remove-Item / ri / rmdir / rd / del / erase with -Recurse or -r
  {
    regex: /\b(?:Remove-Item|ri|rmdir|rd|del|erase)\b([^|;&\n]*)/i,
    isRecursive: (args) => /(?:^|\s)[-/](?:Recurse|r|s)\b/i.test(args),
    extractTargets: (match) => match[1]
  },
  // Windows cmd rd / rmdir / del / erase with /s or -s
  {
    regex: /\b(?:rd|rmdir|del|erase)\b([^|;&\n]*)/i,
    isRecursive: (args) => /(?:^|\s)[-/]s\b/i.test(args),
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
  return resolveEnvToken(token);
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
    const matches = prefix.endsWith('-')
      ? normTarget.startsWith(normPrefix)
      : (normTarget === normPrefix || normTarget.startsWith(normPrefix + '/'));
    if (matches) {
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
    // Filter flags and PowerShell/cmd switch parameters (#106)
    const isFlag = (t) => t.startsWith('-') || (/^\/[a-zA-Z](?::\S+)?$/.test(t)) || /^(?:-Path|-LiteralPath|-Force|-fo|-f|-Recurse|-r|-Confirm|-WhatIf)(?::\S+)?$/i.test(t);
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

      // Unconditionally protected system prefixes (#105, #107)
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

function checkStage(trimmed, options = {}) {
  if (!trimmed) return undefined;

  if (options.customBlockedCommands) {
    const segCustom = checkCustomPatterns(trimmed, options.customBlockedCommands, options.logger);
    if (segCustom) return segCustom;
  }

  const segExfil = checkExfiltration(trimmed);
  if (segExfil) return segExfil;

  const segDestructive = checkDestructiveDeletion(trimmed, options);
  if (segDestructive) return segDestructive;

  const segRecursiveRm = findRecursiveRm(trimmed);
  if (segRecursiveRm) return segRecursiveRm;

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

  return undefined;
}

export function findDangerous(command, options = {}) {
  if (typeof command !== 'string' || command.trim() === '') return undefined;

  // Intercept and mask embedded URL credentials (#81)
  const urlCred = detectUrlCredentials(command);
  if (urlCred) {
    if (options.onUrlCredentials) {
      options.onUrlCredentials(urlCred);
    }
    if (options.blockUrlCredentials) {
      return urlCred;
    }
  }

  // 1. Homoglyph, zero-width & fullwidth normalization (#82)
  const normalized = normalizeForScan(command.replace(/\\\r?\n/g, ' '));

  // 2. Base64 hidden payload inspection (#83)
  const b64Hit = inspectBase64Payloads(normalized, options);
  if (b64Hit) return b64Hit;

  // 3. Global composite command checks (#68)
  const exfil = checkExfiltration(normalized);
  if (exfil) return exfil;

  const escapeHit = checkWorkspaceEscape(normalized);
  if (escapeHit) return escapeHit;

  const forcePushHit = checkProtectedForcePush(normalized);
  if (forcePushHit) return forcePushHit;

  // 4. Pipeline segmentation (#68)
  const segments = splitShellStages(normalized);
  if (segments.length <= 1) {
    // Single stage: check stage rules once on normalized (#68)
    return checkStage(normalized, options);
  }

  // Multi-stage pipeline checks
  // A. Check cross-pipeline spanning curl-pipe
  const curlPipe = DANGEROUS_PATTERNS.find(p => p.id === 'curl-pipe');
  if (curlPipe && curlPipe.regex.test(normalized)) {
    const m = curlPipe.regex.exec(normalized);
    if (m) return { id: curlPipe.id, label: curlPipe.label, match: m[0].slice(0, 160) };
  }

  // B. Per-stage verification
  for (const seg of segments) {
    const hit = checkStage(seg.trim(), options);
    if (hit) return hit;
  }

  return undefined;
}
