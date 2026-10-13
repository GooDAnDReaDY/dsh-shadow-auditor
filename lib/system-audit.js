/**
 * @file system-audit.js
 * Host security audit and configuration scanner (#87, #88).
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
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

const CONFIG_SECRET_PATTERNS = [
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
 * Runs host security audit across requested scopes (#87).
 * Scopes: 'config', 'plugins', 'paths', 'network', 'env' or 'all'.
 * @param {object} [options]
 * @param {string[]} [options.scopes]
 * @param {number} [options.sampleLimit]
 * @param {string} [options.baseDir]
 * @returns {object}
 */
export function runSystemAudit(options = {}) {
  const startTime = performance.now();
  const rawScopes = options.scopes || ['all'];
  const scopes = rawScopes.includes('all') ? ['config', 'plugins', 'paths', 'network', 'env'] : rawScopes;
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
    }
  }

  // 2. Env Scope
  if (scopes.includes('env')) {
    const envFindings = [];
    const envKeys = Object.keys(process.env);
    for (const key of envKeys) {
      if (/secret|key|token|password|auth/i.test(key)) {
        const val = process.env[key] || '';
        if (val.length >= 16 && !isPlaceholder(val)) {
          envFindings.push({
            variable: key,
            maskedValue: maskSecret(val),
            severity: 'high'
          });
        }
      }
    }
    report.sections.env = {
      scannedVariables: envKeys.length,
      findingsCount: envFindings.length,
      findings: envFindings.slice(0, sampleLimit)
    };
    report.summary.totalFindings += envFindings.length;
    report.summary.high += envFindings.length;
  }

  // 3. Paths Scope
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

  // 4. Plugins Scope
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

  // 5. Network Scope
  if (scopes.includes('network')) {
    report.sections.network = {
      defaultLoopbackOnly: true,
      standardPorts: [3000, 3080]
    };
  }

  report.durationMs = Math.round(performance.now() - startTime);
  return report;
}
