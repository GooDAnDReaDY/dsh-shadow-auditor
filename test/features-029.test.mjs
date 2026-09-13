import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { findDangerous, isSensitivePath, DEFAULT_CREDENTIAL_FILES } from '../lib/guards/command.js';
import { scanDiff } from '../lib/diff-gate/gate.js';
import { buildBill, buildSessionBills, billToMarkdown, billsToMarkdown } from '../lib/report.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.join(__dirname, '..');

test('Feature 2: Custom blocked commands and shellGuardMode', () => {
  // Custom regex blocklist
  const customPatterns = ['^sudo\\s+iptables', 'docker\\s+system\\s+prune', 'nmap\\s+.*'];

  const hit1 = findDangerous('sudo iptables -F', { customBlockedCommands: customPatterns });
  assert.ok(hit1, 'Should detect custom blocked regex command');
  assert.equal(hit1.id, 'custom-rule-violation');

  const hit2 = findDangerous('docker system prune -a --volumes', { customBlockedCommands: customPatterns });
  assert.ok(hit2, 'Should detect docker system prune');

  const hit3 = findDangerous('ls -la && nmap 192.168.1.1', { customBlockedCommands: customPatterns });
  assert.ok(hit3, 'Should detect custom command in segmented pipeline');

  const hitSafe = findDangerous('git status', { customBlockedCommands: customPatterns });
  assert.equal(hitSafe, undefined, 'Safe command should not trigger custom rule');
});

test('Feature 4: File Integrity & Secret Anchor Monitor', () => {
  // Default credential files
  assert.ok(isSensitivePath('.env'));
  assert.ok(isSensitivePath('subdir/.env.local'));
  assert.ok(isSensitivePath('/home/user/.ssh/id_rsa'));
  assert.ok(isSensitivePath('config/settings.yaml'));
  assert.ok(isSensitivePath('credentials.yaml'));
  assert.ok(isSensitivePath('server.key'));

  // Custom sensitive patterns
  const customPatterns = ['*.token', 'internal_secrets/*', 'production.json'];
  assert.ok(isSensitivePath('auth.token', customPatterns));
  assert.ok(isSensitivePath('internal_secrets/db.conf', customPatterns));
  assert.ok(isSensitivePath('production.json', customPatterns));

  // Non-sensitive files
  assert.equal(isSensitivePath('src/app.js', customPatterns), false);
  assert.equal(isSensitivePath('README.md', customPatterns), false);
  assert.equal(isSensitivePath('package.json', customPatterns), false);
});

test('Feature 3: Diff Gate Visual Inspector & Safe Remediation Preview', () => {
  const diffWithSast = `
--- a/src/db.js
+++ b/src/db.js
@@ -10,3 +10,3 @@
-  return pool.query('SELECT * FROM users WHERE id = $1', [id]);
+  return pool.query('SELECT * FROM users WHERE id = ' + req.params.id);
`;

  const res = scanDiff({ diffText: diffWithSast, filePath: 'src/db.js', options: { mode: 'block' } });
  assert.equal(res.action, 'block');
  assert.ok(res.findings.length > 0);

  const finding = res.findings[0];
  assert.equal(finding.ruleId, 'SAST-SQLI-001');
  assert.ok(finding.explanation.includes('dynamic string concatenation'));
  assert.ok(finding.remediation.includes('parameterized queries'), 'Remediation must offer safe alternative');
  assert.ok(finding.evidence.includes('SELECT * FROM users'));
});

test('Feature 5: Compliance Export and Markdown Report in English', () => {
  const records = [
    { time: '2026-09-13T12:00:00Z', toolName: 'run_command', score: 95, tags: ['destructive'], blockedByGuard: 'rm -rf' },
    { time: '2026-09-13T12:05:00Z', toolName: 'read_file', score: 60, tags: ['file-integrity'], reasons: ['Read access to sensitive credential file: .env'] },
  ];

  const bill = buildBill(records, 'session-test-029');
  assert.equal(bill.blockedCount, 1);
  assert.equal(bill.highRiskCount, 2);

  const md = billToMarkdown(bill);
  assert.ok(md.includes('Shadow Security Audit Bill'));
  assert.ok(md.includes('High Risk Operations'));
  assert.ok(md.includes('Intercepted Commands (Guard)'));
  assert.ok(md.includes('Risk Levels:'));
  assert.ok(!md.includes('Операции с повышенным риском'), 'No Russian in report output');
});

test('Client UI: 100% Locale Key Parity (en + zh) and Zero Russian in code', () => {
  const clientSrc = fs.readFileSync(path.join(root, 'lib/client.js'), 'utf8');

  // Verify __ModuleLoader__
  assert.ok(clientSrc.includes("id: '@goodandready/dsh-shadow-auditor'"));

  // Check that NO ru locale dictionary is registered in code
  assert.ok(!clientSrc.includes('ru: {'), 'No Russian locale dictionary in runtime code');

  // Parse en and zh dictionaries
  let enDict = null;
  let zhDict = null;

  const mockCtx = {
    locale: {
      register: (ns, dicts) => {
        enDict = dicts.en;
        zhDict = dicts.zh;
      }
    },
    slots: { inject: () => {}, register: () => {} }
  };

  let captured;
  const mockWindow = {
    __ModuleLoader__: { load: (obj) => { captured = obj; } }
  };

  const fn = new Function('require', 'window', clientSrc);
  fn(() => ({ createElement: () => ({}) }), mockWindow);

  const factory = captured.factory;
  const mod = factory(() => ({ createElement: () => ({}) }));
  mod.apply(mockCtx);

  assert.ok(enDict, 'en dictionary must be registered');
  assert.ok(zhDict, 'zh dictionary must be registered');

  const enKeys = Object.keys(enDict);
  const zhKeys = Object.keys(zhDict);

  assert.ok(enKeys.length >= 50, 'Must have at least 50 translation keys');
  assert.equal(enKeys.length, zhKeys.length, 'Key counts must match');

  for (const k of enKeys) {
    assert.ok(k in zhDict, `Key "${k}" missing in zh dictionary`);
    assert.ok(zhDict[k] && zhDict[k].trim().length > 0, `Key "${k}" in zh must not be empty`);
  }
});

test('Package & Distribution Hygiene: v0.2.9 file limits, no AGENTS.md, no index.md', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  assert.equal(pkg.version, '0.2.9', 'Version must be 0.2.9');

  // Strict whitelist in package.json files
  assert.ok(Array.isArray(pkg.files));
  assert.ok(!pkg.files.includes('AGENTS.md'), 'AGENTS.md must not be in files');
  assert.ok(!pkg.files.includes('index.md'), 'index.md must not be in files');
  assert.ok(!fs.existsSync(path.join(root, 'AGENTS.md')), 'AGENTS.md must not exist in tracked tree');
  assert.ok(!fs.existsSync(path.join(root, 'index.md')), 'index.md must not exist in tracked tree');

  // Verify all files in package are under 256 KiB
  const maxBytes = 256 * 1024;
  for (const entry of pkg.files) {
    const full = path.join(root, entry);
    if (fs.existsSync(full)) {
      const st = fs.statSync(full);
      if (st.isFile()) {
        assert.ok(st.size <= maxBytes, `${entry} exceeds 256 KiB (${st.size} bytes)`);
      }
    }
  }
});
