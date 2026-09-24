import os from 'node:os';
import test from 'node:test';
import assert from 'node:assert/strict';
import { findDangerous, checkDestructiveDeletion } from '../lib/guards/command.js';

test('Destructive Delete: blocks recursive rm outside workspace or targeting root (#103)', () => {
  const ws = '/home/user/project';

  // Root or outside workspace deletions
  const hit1 = findDangerous('rm -rf /', { workspace: ws });
  assert.ok(hit1);
  assert.strictEqual(hit1.id, 'destructive-delete-outside-workspace');

  const hit2 = findDangerous('rm -r ../outside', { workspace: ws });
  assert.ok(hit2);
  assert.strictEqual(hit2.id, 'destructive-delete-outside-workspace');

  const hit3 = findDangerous('rm -rf ~', { workspace: ws });
  assert.ok(hit3);
  assert.strictEqual(hit3.id, 'destructive-delete-outside-workspace');

  // Attempting to delete workspace root itself
  const hit4 = findDangerous('rm -rf .', { workspace: ws });
  assert.ok(hit4);
  assert.strictEqual(hit4.id, 'destructive-delete-outside-workspace');

  const hit5 = findDangerous('rm -rf /home/user/project', { workspace: ws });
  assert.ok(hit5);
  assert.strictEqual(hit5.id, 'destructive-delete-outside-workspace');
});

test('Destructive Delete: blocks PowerShell and cmd recursive deletions outside workspace (#103)', () => {
  const ws = 'C:\\Users\\User\\Project';

  const hitPs = findDangerous('Remove-Item -Recurse -Force C:\\Windows', { workspace: ws });
  assert.ok(hitPs);
  assert.strictEqual(hitPs.id, 'destructive-delete-outside-workspace');

  const hitCmd = findDangerous('rd /s /q ..\\outside', { workspace: ws });
  assert.ok(hitCmd);
  assert.strictEqual(hitCmd.id, 'destructive-delete-outside-workspace');

  const hitGit = findDangerous('git clean -fdx /', { workspace: ws });
  assert.ok(hitGit);
  assert.strictEqual(hitGit.id, 'destructive-delete-outside-workspace');
});

test('Destructive Delete: allows non-recursive and safe commands without false positives (#103)', () => {
  assert.strictEqual(findDangerous('rm -f /tmp/test.txt'), undefined);
  assert.strictEqual(findDangerous('git status'), undefined);
  assert.strictEqual(findDangerous('grep -i "Remove-Item" script.ps1'), undefined);
  assert.strictEqual(findDangerous('cat ./rd/notes.txt'), undefined);
});

test('Destructive Delete: unconditionally blocks deletion of protected system prefixes (#105)', () => {
  const ws = '/home/user/project';
  const home = os.homedir();

  const hit1 = findDangerous('rm -rf ~/.dsh', { workspace: ws });
  assert.ok(hit1);
  assert.strictEqual(hit1.id, 'destructive-delete-protected-prefix');

  const hit2 = findDangerous('rm -rf ~/.claude/session', { workspace: ws });
  assert.ok(hit2);
  assert.strictEqual(hit2.id, 'destructive-delete-protected-prefix');

  const hit3 = findDangerous('Remove-Item -Recurse ~/.ssh', { workspace: ws });
  assert.ok(hit3);
  assert.strictEqual(hit3.id, 'destructive-delete-protected-prefix');

  const hit4 = findDangerous('rm -rf /etc/hosts', { workspace: ws });
  assert.ok(hit4);
  assert.strictEqual(hit4.id, 'destructive-delete-protected-prefix');

  // Even if workspace is home directory itself, ~/.dsh is protected!
  const hit5 = findDangerous('rm -rf .dsh', { workspace: home });
  assert.ok(hit5);
  assert.strictEqual(hit5.id, 'destructive-delete-protected-prefix');
});

test('Destructive Delete: recognizes dry-run verification flags and allows them safely (#104)', () => {
  const ws = '/home/user/project';

  // 1. PowerShell -WhatIf and -Confirm pass without blocking
  let psDryRun = null;
  const psHit = findDangerous('Remove-Item -Recurse -Force -WhatIf C:\\Windows', {
    workspace: ws,
    onDryRun: (info) => { psDryRun = info; }
  });
  assert.strictEqual(psHit, undefined);
  assert.ok(psDryRun);
  assert.strictEqual(psDryRun.flag, '-WhatIf');

  let psConfirm = null;
  const psConfirmHit = findDangerous('Remove-Item -Recurse -Confirm $HOME', {
    workspace: ws,
    onDryRun: (info) => { psConfirm = info; }
  });
  assert.strictEqual(psConfirmHit, undefined);
  assert.ok(psConfirm);
  assert.strictEqual(psConfirm.flag, '-Confirm');

  // 2. POSIX rm with --dry-run
  let rmDryRun = null;
  const rmHit = findDangerous('rm -rf --dry-run /tmp/tree', {
    workspace: ws,
    onDryRun: (info) => { rmDryRun = info; }
  });
  assert.strictEqual(rmHit, undefined);
  assert.ok(rmDryRun);
  assert.strictEqual(rmDryRun.flag, '--dry-run');

  // 3. git clean with -n or --dry-run
  let gitDryRun = null;
  const gitHit1 = findDangerous('git clean -fdx -n', {
    workspace: ws,
    onDryRun: (info) => { gitDryRun = info; }
  });
  assert.strictEqual(gitHit1, undefined);
  assert.ok(gitDryRun);

  let gitDryRun2 = null;
  const gitHit2 = findDangerous('git clean -ndx', {
    workspace: ws,
    onDryRun: (info) => { gitDryRun2 = info; }
  });
  assert.strictEqual(gitHit2, undefined);
  assert.ok(gitDryRun2);

  let gitDryRun3 = null;
  const gitHit3 = findDangerous('git clean --dry-run -f', {
    workspace: ws,
    onDryRun: (info) => { gitDryRun3 = info; }
  });
  assert.strictEqual(gitHit3, undefined);
  assert.ok(gitDryRun3);

  // 4. Non-dry-run destructive commands must still be strictly blocked!
  assert.ok(findDangerous('rm -rf /tmp/tree'));
  assert.ok(findDangerous('Remove-Item -Recurse -Force C:\\Windows', { workspace: ws }));
  assert.ok(findDangerous('git clean -fdx /', { workspace: ws }));
});
