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
