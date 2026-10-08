import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const read = (p) => readFileSync(join(root, p), 'utf8')
const client = read('lib/client.js')
const host = read('lib/index.js')
const { Config, plainConfig } = await import('../lib/index.js')

const ENTRY_ID = 'dsh-shadow-auditor'
const PKG = '@goodandready/dsh-shadow-auditor'

// Strip comments before asserting on code, so prose describing a removed call
// cannot read as the call itself.
const code = (s) => s.replace(/^\s*\/\/.*$/gm, '').replace(/\/\*[\s\S]*?\*\//g, '')

// DSH builds a namespace's settings form from the volatile fields of its profile
// entry schema, and volatileForm() returns undefined when there are none: a schema
// with no volatile field yields no form at all.
function volatileKeys(schema = Config) {
  if (schema.meta?.volatile) return []
  if (schema.type !== 'object') return []
  return Object.entries(schema.dict ?? {}).flatMap(([key, child]) => {
    const nested = volatileKeys(child)
    return nested.length === 0 && child.meta?.volatile ? [key] : nested
  })
}

test('schema serves a settings form, so the card can mount at all', () => {
  assert.ok(volatileKeys().length > 0, 'Config needs at least one .volatile() field')
})

test('the namespace is the profile entry id, not the package name', () => {
  const entryId = read('cordis.patch.yml').match(/^\s*- id:\s*([\w-]+)/m)[1]
  assert.equal(entryId, ENTRY_ID, 'the id declared in cordis.patch.yml is the namespace')
  assert.ok(code(host).includes("const NS = '" + entryId + "'"), 'host NS must be the entry id')
  assert.ok(code(client).includes("const NS = '" + entryId + "'"), 'client NS must be the entry id')
  // the package name is still the bundle identity, just not the settings namespace
  assert.equal(JSON.parse(read('package.json')).name, PKG)
})

test('volatile boxes unwrap to the plain values the host reads', () => {
  const keys = volatileKeys()
  assert.ok(keys.length > 0)
  const first = keys[0]
  const defaultVal = plainConfig(Config({}))[first]
  const testVal = typeof defaultVal === 'boolean' ? !defaultVal : 42
  const raw = Config({ [first]: testVal })
  assert.equal(typeof raw[first].get, 'function', 'a volatile field holds a Volatile box')
  const plain = plainConfig(raw)
  assert.notEqual(typeof plain[first], 'object', 'plainConfig must yield a value, not a box')
})

test('the host never calls the removed settings.register', () => {
  const c = code(host)
  assert.doesNotMatch(c, /settings\s*\.\s*register\s*\(/, 'settings.register exists in neither release')
})

test('the card is on the live seats and the retired one is gone', () => {
  const c = code(client)
  const live = [...c.matchAll(/name:\s*'(plugins\.[a-z.]+)'/g)].map((m) => m[1])
  assert.ok(live.length > 0, 'the card must register on at least one live seat')
  assert.doesNotMatch(c, /name:\s*'settings\.plugin\.item'/,
    'settings.plugin.item was retired before DSH 0.1.7-rc.2')
})

test('the card reads the form through the contract both releases share', () => {
  const c = code(client)
  if (/configForms/.test(c)) {
    assert.ok(c.includes('getSnapshot'), 'ConfigForm read path')
    assert.doesNotMatch(c, /scope\.get\(\)/, 'ConfigForm has no get() in either release')
    assert.doesNotMatch(c, /scope\.watch\(/, 'ConfigForm has no watch() in either release')
  }
})

test('peer ranges accept the 0.1.7 and 0.2.0 DSH package lines', async () => {
  const pkg = JSON.parse(read('package.json'))
  const semver = await import('semver')
  for (const [name, range] of Object.entries(pkg.peerDependencies || {})) {
    if (name === '@deepseek-ai/cordis') {
      assert.ok(semver.satisfies('4.0.4', range), name + ' must accept the shipped cordis')
      continue
    }
    if (name === '@deepseek-ai/schemastery') {
      assert.ok(semver.satisfies('3.18.4', range), 'schemastery must accept the .volatile() line')
      assert.ok(!semver.satisfies('3.18.1', range), '3.18.1 lacks .volatile() and must be rejected')
      continue
    }
    assert.ok(semver.satisfies('0.2.0-rc.1', range), name + ' ' + range + ' must accept 0.2.0-rc.1')
    assert.ok(semver.satisfies('0.1.7-rc.2', range), name + ' ' + range + ' must accept 0.1.7-rc.2')
  }
})
