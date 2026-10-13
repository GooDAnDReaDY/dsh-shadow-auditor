/**
 * @file system-audit.js
 * Host security audit, configuration scanner, permissions check, and supply chain verification (#87, #88, #89, #90, #91, #92, #93).
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import zlib from 'node:zlib';
import child_process from 'node:child_process';
import { maskSecret } from './guards/secrets.js';

// Placeholders that indicate template / unconfigured values, not leaked secrets
const PLACEHOLDER_PATTERNS = [
  /changeme/i,
  /your[_-]?api[_-]?key/i,
  /your[_-]?secret/i,
  /your[_-]?token/i,
  /dummy/i,
  /example/i,
  /placeholder/i,
  /<[^>]+>/,
  /\$\{([^}]+)\}/,
  /process\.env\./i,
  /sk-placeholder/i,
  /xxx+/i,
  /\*\*\*+/
];

export function isPlaceholder(val) {
  if (!val || typeof val !== 'string') return true;
  const trimmed = val.trim();
  if (trimmed.length < 8) return true;
  for (const pat of PLACEHOLDER_PATTERNS) {
    if (pat.test(trimmed)) return true;
  }
  return false;
}

export const CONFIG_SECRET_PATTERNS = [
  { ruleId: 'CONF-API-KEY', regex: /\b(sk-(?:proj-|ant-|live-)?[a-zA-Z0-9_-]{20,})\b/g, severity: 'critical' },
  { ruleId: 'CONF-AWS-KEY', regex: /\b(AKIA[0-9A-Z]{16})\b/g, severity: 'critical' },
  { ruleId: 'CONF-GH-TOKEN', regex: /\b(gh[pousr]_[A-Za-z0-9_]{30,})\b/g, severity: 'critical' },
  { ruleId: 'CONF-SLACK-TOKEN', regex: /\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b/g, severity: 'high' },
  { ruleId: 'CONF-PRIVATE-KEY', regex: /(-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----)/g, severity: 'critical' },
  { ruleId: 'CONF-GENERIC-SECRET', regex: /(?:api[_-]?key|secret|password|passwd|token|auth[_-]?token)\s*[:=]\s*["']?([A-Za-z0-9+/=_\-@#$%^&!~]{16,})["']?/gi, severity: 'high' }
];

/**
 * Scans DSH configuration files for open secrets (#88).
 * Recursively inspects YAML/JSON/env files, skipping placeholders and masking findings.
 * @param {object} [options]
 * @param {string} [options.baseDir]
 * @param {number} [options.sampleLimit]
 * @param {number} [options.maxFiles]
 * @returns {object}
 */
export function checkConfigSecrets(options = {}) {
  const baseDir = options.baseDir || process.env.DSH_HOME || path.join(os.homedir(), '.dsh');
  const sampleLimit = options.sampleLimit || 50;
  const maxFiles = options.maxFiles || 200;
  const findings = [];
  let filesScanned = 0;
  const startTime = performance.now();

  function scanDir(dir, depth = 0) {
    if (depth > 4 || filesScanned >= maxFiles) return;
    if (!fs.existsSync(dir)) return;

    let entries = [];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      if (filesScanned >= maxFiles || findings.length >= sampleLimit) break;
      const fullPath = path.join(dir, entry.name);

      if (entry.isDirectory()) {
        if (entry.name === 'node_modules' || entry.name === '.git' || entry.name === 'logs' || entry.name === 'cache') {
          continue;
        }
        scanDir(fullPath, depth + 1);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        const base = entry.name.toLowerCase();
        if (['.yml', '.yaml', '.json', '.env', '.toml'].includes(ext) || base.startsWith('.env')) {
          scanFile(fullPath);
        }
      }
    }
  }

  function scanFile(filePath) {
    filesScanned++;
    try {
      const content = fs.readFileSync(filePath, 'utf8');
      const lines = content.split('\n');

      for (let i = 0; i < lines.length; i++) {
        if (findings.length >= sampleLimit) break;
        const line = lines[i];
        if (!line.trim() || line.trim().startsWith('#') || line.trim().startsWith('//')) {
          continue;
        }

        let lineMatched = false;
        for (const pat of CONFIG_SECRET_PATTERNS) {
          pat.regex.lastIndex = 0;
          let match;
          while ((match = pat.regex.exec(line)) !== null) {
            const raw = match[1] || match[0];
            if (isPlaceholder(raw)) continue;

            findings.push({
              ruleId: pat.ruleId,
              severity: pat.severity,
              file: filePath,
              line: i + 1,
              maskedValue: maskSecret(raw),
              sample: line.replace(raw, maskSecret(raw)).trim().slice(0, 100)
            });
            lineMatched = true;
            break;
          }
          if (lineMatched) break;
        }
      }
    } catch {
      // Fail-safe: silently continue scanning other files
    }
  }

  scanDir(baseDir);

  return {
    findings,
    filesScanned,
    baseDir,
    durationMs: Math.round(performance.now() - startTime)
  };
}

/**
 * Checks POSIX file permissions on audit logs, configs, and socket paths (#89).
 * Warns if permissions exceed 0700 for directories or 0600 for files.
 * Returns safe no-op on Windows.
 * @param {object} [options]
 * @param {string} [options.baseDir]
 * @returns {object}
 */
export function checkConfigPermissions(options = {}) {
  const startTime = performance.now();
  const findings = [];
  const isWindows = process.platform === 'win32';

  if (isWindows) {
    return {
      platform: 'win32',
      skipped: true,
      findings: [],
      durationMs: Math.round(performance.now() - startTime)
    };
  }

  const baseDir = options.baseDir || process.env.DSH_HOME || path.join(os.homedir(), '.dsh');
  const checkTargets = [
    { targetPath: path.join(baseDir, 'shadow-auditor'), isDir: true, maxMode: 0o700, desc: 'Audit log directory' },
    { targetPath: path.join(baseDir, 'secrets'), isDir: true, maxMode: 0o700, desc: 'Secrets directory' },
    { targetPath: path.join(baseDir, 'cordis.yml'), isDir: false, maxMode: 0o600, desc: 'Core config file' },
    { targetPath: path.join(baseDir, 'dsh.sock'), isDir: false, maxMode: 0o600, desc: 'DSH UNIX socket' }
  ];

  if (options.extraTargets && Array.isArray(options.extraTargets)) {
    checkTargets.push(...options.extraTargets);
  }

  for (const item of checkTargets) {
    if (!fs.existsSync(item.targetPath)) continue;
    try {
      const stat = fs.statSync(item.targetPath);
      const perm = stat.mode & 0o777;
      const groupOrOtherBits = perm & (item.isDir ? 0o077 : 0o077);

      if (groupOrOtherBits !== 0) {
        findings.push({
          path: item.targetPath,
          description: item.desc,
          currentMode: '0' + perm.toString(8),
          expectedMode: '0' + item.maxMode.toString(8),
          severity: (perm & 0o007) !== 0 ? 'high' : 'medium',
          warning: `Insecure file permissions 0${perm.toString(8)} (exceeds 0${item.maxMode.toString(8)})`
        });
      }
    } catch {
      // Ignore stat failures
    }
  }

  return {
    platform: process.platform,
    skipped: false,
    findings,
    durationMs: Math.round(performance.now() - startTime)
  };
}

/**
 * Audits process environment variables for leaked credentials (#90).
 * Inspects process.env keys and values, masking raw secrets.
 * @param {object} [options]
 * @param {object} [options.env]
 * @param {number} [options.sampleLimit]
 * @returns {object}
 */
export function checkEnvSecrets(options = {}) {
  const startTime = performance.now();
  const envSource = options.env || process.env;
  const sampleLimit = options.sampleLimit || 50;
  const findings = [];
  const envKeys = Object.keys(envSource);

  for (const key of envKeys) {
    if (findings.length >= sampleLimit) break;
    const val = envSource[key];
    if (typeof val !== 'string' || val.length < 8) continue;

    // Check key name relevance or value length
    const keySuspicious = /secret|key|token|password|auth|credential|api[_-]?key/i.test(key);
    if (!keySuspicious && val.length < 20) continue;

    if (isPlaceholder(val)) continue;

    // Pattern matching against known token structures
    let matchedRule = null;
    let severity = 'high';

    for (const pat of CONFIG_SECRET_PATTERNS) {
      pat.regex.lastIndex = 0;
      if (pat.regex.test(val)) {
        matchedRule = pat.ruleId;
        severity = pat.severity;
        break;
      }
    }

    if (!matchedRule && keySuspicious && val.length >= 16) {
      matchedRule = 'ENV-SUSPICIOUS-KEY';
      severity = 'high';
    }

    if (matchedRule) {
      findings.push({
        variable: key,
        ruleId: matchedRule,
        severity,
        maskedValue: maskSecret(val)
      });
    }
  }

  return {
    scannedCount: envKeys.length,
    findings,
    durationMs: Math.round(performance.now() - startTime)
  };
}

/**
 * Live dependency vulnerability check via npm audit API (#91).
 * Queries npm registry security endpoint with a timeout (default 3000ms).
 * Degrades gracefully when offline or network fails.
 * @param {object} [options]
 * @param {object} [options.packages] Dictionary of packageName: version
 * @param {number} [options.timeoutMs]
 * @returns {Promise<object>}
 */
export async function checkDepsSupplyChain(options = {}) {
  const startTime = performance.now();
  const timeoutMs = options.timeoutMs || 3000;
  const packages = options.packages || {
    '@goodandready/dsh-shadow-auditor': '0.2.26'
  };

  const payload = {
    name: 'dsh-supply-chain-audit',
    version: '1.0.0',
    requires: packages,
    dependencies: {}
  };

  for (const [pkg, ver] of Object.entries(packages)) {
    payload.dependencies[pkg] = { version: ver };
  }

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    const res = await fetch('https://registry.npmjs.org/-/npm/v1/security/audits', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'accept': 'application/json'
      },
      body: JSON.stringify(payload),
      signal: controller.signal
    });
    clearTimeout(timer);

    if (!res.ok) {
      return {
        ok: false,
        status: res.status,
        vulnerabilities: [],
        offline: false,
        durationMs: Math.round(performance.now() - startTime)
      };
    }

    const data = await res.json();
    const vulns = [];
    if (data.metadata && data.metadata.vulnerabilities) {
      vulns.push({
        total: data.metadata.totalDependencies || 0,
        summary: data.metadata.vulnerabilities
      });
    }

    return {
      ok: true,
      status: 200,
      advisories: data.advisories || {},
      metadata: data.metadata || {},
      vulnerabilities: vulns,
      offline: false,
      durationMs: Math.round(performance.now() - startTime)
    };
  } catch (err) {
    return {
      ok: false,
      offline: true,
      error: err.name === 'AbortError' ? 'Timeout reaching npm registry' : err.message,
      vulnerabilities: [],
      durationMs: Math.round(performance.now() - startTime)
    };
  }
}

/**
 * Checks network interface bindings for wildcard listener exposures (#92).
 * Inspects Linux /proc/net/tcp and node os.networkInterfaces.
 * Flags bindings to 0.0.0.0 or :: that expose DSH services externally.
 * @param {object} [options]
 * @param {number[]} [options.watchedPorts]
 * @returns {object}
 */
export function checkNetworkBindings(options = {}) {
  const startTime = performance.now();
  const watchedPorts = options.watchedPorts || [3000, 3080, 5173, 8080];
  const findings = [];
  const listeningSockets = [];

  // 1. Linux procfs TCP listener inspection
  if (process.platform === 'linux' && fs.existsSync('/proc/net/tcp')) {
    try {
      const parseProcTcp = (filePath, isIpv6 = false) => {
        if (!fs.existsSync(filePath)) return;
        const lines = fs.readFileSync(filePath, 'utf8').split('\n');
        for (let i = 1; i < lines.length; i++) {
          const line = lines[i].trim();
          if (!line) continue;
          const parts = line.split(/\s+/);
          const state = parts[3]; // '0A' is TCP_LISTEN
          if (state !== '0A') continue;

          const localAddr = parts[1];
          const [ipHex, portHex] = localAddr.split(':');
          const port = parseInt(portHex, 16);

          let isWildcard = false;
          let isLoopback = false;

          if (!isIpv6) {
            // IPv4 hex is little-endian: 00000000 is 0.0.0.0, 0100007F is 127.0.0.1
            if (ipHex === '00000000') isWildcard = true;
            else if (ipHex.startsWith('0100007F')) isLoopback = true;
          } else {
            // IPv6 wildcard is all zeros
            if (/^0+$/.test(ipHex)) isWildcard = true;
            else if (ipHex.endsWith('000000000000000000000001')) isLoopback = true;
          }

          listeningSockets.push({
            port,
            isWildcard,
            isLoopback,
            proto: isIpv6 ? 'tcp6' : 'tcp'
          });

          if (watchedPorts.includes(port) && isWildcard) {
            findings.push({
              port,
              protocol: isIpv6 ? 'IPv6' : 'IPv4',
              binding: isIpv6 ? '::' : '0.0.0.0',
              severity: 'high',
              warning: `Port ${port} listens on wildcard interface ${isIpv6 ? '::' : '0.0.0.0'} without loopback restriction`,
              recommendation: `Bind DSH server explicitly to 127.0.0.1 or localhost`
            });
          }
        }
      };

      parseProcTcp('/proc/net/tcp', false);
      parseProcTcp('/proc/net/tcp6', true);
    } catch {
      // Silently proceed
    }
  }

  // 2. Fallback / supplementary network interfaces check
  const interfaces = os.networkInterfaces();
  const externalIps = [];
  for (const [ifName, addrs] of Object.entries(interfaces)) {
    for (const addr of addrs || []) {
      if (!addr.internal && (addr.family === 'IPv4' || addr.family === 4)) {
        externalIps.push({ interface: ifName, address: addr.address });
      }
    }
  }

  return {
    listeningSocketsCount: listeningSockets.length,
    findings,
    externalInterfaces: externalIps,
    durationMs: Math.round(performance.now() - startTime)
  };
}

/**
 * Scans historical DSH session archives for sensitive data and leaked secrets (#93).
 * Supports plain JSON/JSONL, .gz (gzip), and .zst (zstd) streams.
 * Includes sample bounds and per-file size limits to prevent memory bloat.
 * @param {object} [options]
 * @param {string} [options.sessionsDir]
 * @param {number} [options.sampleLimit]
 * @param {number} [options.maxFileSizeMb]
 * @returns {object}
 */
export function checkSessionsSensitive(options = {}) {
  const startTime = performance.now();
  const sessionsDir = options.sessionsDir || path.join(os.homedir(), '.dsh', 'sessions-archive');
  const sampleLimit = options.sampleLimit || 30;
  const maxBytes = (options.maxFileSizeMb || 10) * 1024 * 1024;
  const findings = [];
  let filesInspected = 0;

  if (!fs.existsSync(sessionsDir)) {
    return {
      filesInspected: 0,
      findings: [],
      sessionsDir,
      durationMs: Math.round(performance.now() - startTime)
    };
  }

  function readDecompressed(filePath) {
    const ext = path.extname(filePath).toLowerCase();
    const stat = fs.statSync(filePath);
    if (stat.size > maxBytes) return null;

    if (ext === '.gz') {
      const buf = fs.readFileSync(filePath);
      return zlib.gunzipSync(buf).toString('utf8');
    } else if (ext === '.zst') {
      // Attempt decompress via child_process spawn of zstd if available
      try {
        const out = child_process.spawnSync('zstd', ['-d', '-c', filePath], {
          maxBuffer: maxBytes,
          timeout: 2000
        });
        if (out.status === 0 && out.stdout) {
          return out.stdout.toString('utf8');
        }
      } catch {
        return null;
      }
      return null;
    } else if (['.json', '.jsonl', '.txt', '.log'].includes(ext)) {
      return fs.readFileSync(filePath, 'utf8');
    }
    return null;
  }

  function scanFolder(dir, depth = 0) {
    if (depth > 4 || filesInspected >= 100 || findings.length >= sampleLimit) return;
    let list = [];
    try {
      list = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const item of list) {
      if (findings.length >= sampleLimit) break;
      const full = path.join(dir, item.name);

      if (item.isDirectory()) {
        scanFolder(full, depth + 1);
      } else if (item.isFile()) {
        filesInspected++;
        try {
          const text = readDecompressed(full);
          if (!text) continue;

          const lines = text.split('\n');
          for (let i = 0; i < lines.length; i++) {
            if (findings.length >= sampleLimit) break;
            const line = lines[i];
            if (!line.trim()) continue;

            for (const pat of CONFIG_SECRET_PATTERNS) {
              pat.regex.lastIndex = 0;
              let m;
              let found = false;
              while ((m = pat.regex.exec(line)) !== null) {
                const raw = m[1] || m[0];
                if (isPlaceholder(raw)) continue;

                findings.push({
                  sessionFile: full,
                  line: i + 1,
                  ruleId: pat.ruleId,
                  severity: pat.severity,
                  maskedValue: maskSecret(raw)
                });
                found = true;
                break;
              }
              if (found) break;
            }
          }
        } catch {
          // Fail-safe per file
        }
      }
    }
  }

  scanFolder(sessionsDir);

  return {
    filesInspected,
    findings,
    sessionsDir,
    durationMs: Math.round(performance.now() - startTime)
  };
}

/**
 * Runs host security audit across requested scopes (#87, #89, #90, #91, #92, #93).
 * Scopes: 'config', 'plugins', 'paths', 'network', 'env', 'permissions', 'supply_chain', 'sessions' or 'all'.
 * @param {object} [options]
 * @param {string[]} [options.scopes]
 * @param {number} [options.sampleLimit]
 * @param {string} [options.baseDir]
 * @returns {Promise<object>}
 */
export async function runSystemAudit(options = {}) {
  const startTime = performance.now();
  const rawScopes = options.scopes || ['all'];
  const allScopes = ['config', 'plugins', 'paths', 'network', 'env', 'permissions', 'supply_chain', 'sessions'];
  const scopes = rawScopes.includes('all') ? allScopes : rawScopes;
  const sampleLimit = options.sampleLimit || 50;
  const baseDir = options.baseDir || process.env.DSH_HOME || path.join(os.homedir(), '.dsh');

  const report = {
    timestamp: new Date().toISOString(),
    scopes,
    summary: { totalFindings: 0, critical: 0, high: 0, medium: 0, low: 0 },
    sections: {}
  };

  // 1. Config Scope (#88)
  if (scopes.includes('config')) {
    const configResult = checkConfigSecrets({ baseDir, sampleLimit });
    report.sections.config = {
      filesScanned: configResult.filesScanned,
      findingsCount: configResult.findings.length,
      findings: configResult.findings
    };
    for (const f of configResult.findings) {
      report.summary.totalFindings++;
      if (f.severity === 'critical') report.summary.critical++;
      else if (f.severity === 'high') report.summary.high++;
      else if (f.severity === 'medium') report.summary.medium++;
      else report.summary.low++;
    }
  }

  // 2. Env Scope (#90)
  if (scopes.includes('env')) {
    const envResult = checkEnvSecrets({ sampleLimit });
    report.sections.env = {
      scannedVariables: envResult.scannedCount,
      findingsCount: envResult.findings.length,
      findings: envResult.findings
    };
    for (const f of envResult.findings) {
      report.summary.totalFindings++;
      if (f.severity === 'critical') report.summary.critical++;
      else if (f.severity === 'high') report.summary.high++;
      else if (f.severity === 'medium') report.summary.medium++;
      else report.summary.low++;
    }
  }

  // 3. Permissions Scope (#89)
  if (scopes.includes('permissions')) {
    const permResult = checkConfigPermissions({ baseDir });
    report.sections.permissions = {
      skipped: permResult.skipped,
      platform: permResult.platform,
      findingsCount: permResult.findings.length,
      findings: permResult.findings
    };
    for (const f of permResult.findings) {
      report.summary.totalFindings++;
      if (f.severity === 'high') report.summary.high++;
      else if (f.severity === 'medium') report.summary.medium++;
    }
  }

  // 4. Paths Scope
  if (scopes.includes('paths')) {
    const sensitiveLocations = [
      path.join(os.homedir(), '.ssh'),
      path.join(os.homedir(), '.gnupg'),
      path.join(os.homedir(), '.dsh'),
      path.join(os.homedir(), '.aws')
    ];
    const pathFindings = [];
    for (const p of sensitiveLocations) {
      if (fs.existsSync(p)) {
        try {
          const stat = fs.statSync(p);
          const mode = (stat.mode & 0o777).toString(8);
          pathFindings.push({ path: p, exists: true, permissions: mode });
        } catch {
          pathFindings.push({ path: p, exists: true, permissions: 'unknown' });
        }
      }
    }
    report.sections.paths = { pathsChecked: sensitiveLocations.length, details: pathFindings };
  }

  // 5. Plugins Scope
  if (scopes.includes('plugins')) {
    const profilesDir = path.join(baseDir, 'profiles');
    const installed = [];
    if (fs.existsSync(profilesDir)) {
      try {
        const entries = fs.readdirSync(profilesDir);
        installed.push(...entries);
      } catch {}
    }
    report.sections.plugins = { profilesFound: installed };
  }

  // 6. Network Scope (#92)
  if (scopes.includes('network')) {
    const netResult = checkNetworkBindings();
    report.sections.network = {
      defaultLoopbackOnly: true,
      listeningSocketsCount: netResult.listeningSocketsCount,
      findingsCount: netResult.findings.length,
      findings: netResult.findings,
      externalInterfaces: netResult.externalInterfaces
    };
    for (const f of netResult.findings) {
      report.summary.totalFindings++;
      if (f.severity === 'high') report.summary.high++;
      else if (f.severity === 'medium') report.summary.medium++;
    }
  }

  // 7. Supply Chain Scope (#91)
  if (scopes.includes('supply_chain')) {
    const supplyResult = await checkDepsSupplyChain(options.supplyChainOptions);
    report.sections.supply_chain = supplyResult;
  }

  // 8. Sessions Scope (#93)
  if (scopes.includes('sessions')) {
    const sessResult = checkSessionsSensitive({ sampleLimit });
    report.sections.sessions = {
      filesInspected: sessResult.filesInspected,
      findingsCount: sessResult.findings.length,
      findings: sessResult.findings
    };
    for (const f of sessResult.findings) {
      report.summary.totalFindings++;
      if (f.severity === 'critical') report.summary.critical++;
      else if (f.severity === 'high') report.summary.high++;
      else report.summary.medium++;
    }
  }

  report.durationMs = Math.round(performance.now() - startTime);
  return report;
}
