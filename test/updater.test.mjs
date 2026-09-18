import test from 'node:test';
import assert from 'node:assert/strict';
import { isNewerVersion, isLoopback, isTrustedUpdateRequest } from '../lib/updater.js';

test('Updater semver comparisons: detects newer patch, minor, major and prerelease transitions', () => {
  assert.equal(isNewerVersion('0.2.10', '0.2.11'), true);
  assert.equal(isNewerVersion('0.2.10', '0.3.0'), true);
  assert.equal(isNewerVersion('0.2.10', '1.0.0'), true);
  assert.equal(isNewerVersion('0.2.10', '0.2.10'), false);
  assert.equal(isNewerVersion('0.2.11', '0.2.10'), false);

  // Prereleases
  assert.equal(isNewerVersion('0.2.11-rc.1', '0.2.11'), true);
  assert.equal(isNewerVersion('0.2.11', '0.2.11-rc.1'), false);
  assert.equal(isNewerVersion('0.2.11-rc.1', '0.2.11-rc.2'), true);
});

test('Updater request verification: requires loopback, same-origin, and special update header', () => {
  assert.equal(isLoopback('127.0.0.1'), true);
  assert.equal(isLoopback('::1'), true);
  assert.equal(isLoopback('::ffff:127.0.0.1'), true);
  assert.equal(isLoopback('192.168.1.111'), false);

  const validReq = {
    headers: {
      'x-dsh-plugin-update': '1',
      'sec-fetch-site': 'same-origin',
      origin: 'http://localhost:5173',
      host: 'localhost:5173',
    },
    socket: { remoteAddress: '127.0.0.1' },
  };
  assert.equal(isTrustedUpdateRequest(validReq), true);

  const missingHeader = { ...validReq, headers: { ...validReq.headers, 'x-dsh-plugin-update': undefined } };
  assert.equal(isTrustedUpdateRequest(missingHeader), false);

  const externalIp = { ...validReq, socket: { remoteAddress: '192.168.1.111' } };
  assert.equal(isTrustedUpdateRequest(externalIp), false);

  const crossSite = { ...validReq, headers: { ...validReq.headers, 'sec-fetch-site': 'cross-site' } };
  assert.equal(isTrustedUpdateRequest(crossSite), false);
});
