import test from 'node:test';
import assert from 'node:assert/strict';
import { isNewerVersion, isLoopback, isTrustedUpdateRequest } from '../lib/updater.js';
import { isTrustedRequest } from '../lib/index.js';

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

test('Audit endpoint request verification: rejects cross-site, compares tokens, and allows same-origin card reads (#73)', () => {
  const secret = 'prod-secret-token-12345';

  // 1. Sec-Fetch-Site: cross-site receives rejection even from 127.0.0.1 and with token
  assert.equal(isTrustedRequest({
    headers: { 'sec-fetch-site': 'cross-site', authorization: `Bearer ${secret}` },
    socket: { remoteAddress: '127.0.0.1' }
  }, { expectedToken: secret }), false);

  // 2. Sec-Fetch-Site: same-site is rejected
  assert.equal(isTrustedRequest({
    headers: { 'sec-fetch-site': 'same-site' },
    socket: { remoteAddress: '127.0.0.1' }
  }), false);

  // 3. Authorization: Bearer x and cookie token=x receive rejection
  assert.equal(isTrustedRequest({
    headers: { authorization: 'Bearer x' }
  }, { expectedToken: secret }), false);

  assert.equal(isTrustedRequest({
    headers: { authorization: 'Bearer x' }
  }), false);

  assert.equal(isTrustedRequest({
    headers: { cookie: 'token=x' }
  }, { expectedToken: secret }), false);

  assert.equal(isTrustedRequest({
    headers: { cookie: 'dsh_token=x' }
  }), false);

  // 4. Valid Bearer token and valid cookie matching expectedToken are accepted
  assert.equal(isTrustedRequest({
    headers: { authorization: `Bearer ${secret}` }
  }, { expectedToken: secret }), true);

  assert.equal(isTrustedRequest({
    headers: { cookie: `token=${secret}` }
  }, { expectedToken: secret }), true);

  assert.equal(isTrustedRequest({
    headers: { cookie: `foo=bar; dsh_token=${secret}; baz=qux` }
  }, { expectedToken: secret }), true);

  // 5. Card in the same interface (same-origin browser request on loopback) is trusted
  assert.equal(isTrustedRequest({
    headers: {
      'sec-fetch-site': 'same-origin',
      host: '127.0.0.1:3080',
      origin: 'http://127.0.0.1:3080'
    },
    socket: { remoteAddress: '127.0.0.1' }
  }), true);

  // 6. Loopback address alone does not grant access without same-origin or valid token
  assert.equal(isTrustedRequest({
    headers: {},
    socket: { remoteAddress: '127.0.0.1' }
  }), false);

  // 7. Mismatched origin is rejected even on same-origin header
  assert.equal(isTrustedRequest({
    headers: {
      'sec-fetch-site': 'same-origin',
      host: '127.0.0.1:3080',
      origin: 'http://malicious.local:3080'
    },
    socket: { remoteAddress: '127.0.0.1' }
  }), false);
});
