import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'
import assert from 'node:assert/strict'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const client = readFileSync(join(root, 'lib/client.js'), 'utf8')
const patch = readFileSync(join(root, 'cordis.patch.yml'), 'utf8')
const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'))

test('row seat key is the package name plus the row id from cordis.patch.yml', () => {
  const rowId = patch.match(/^\s*- id:\s*(\S+)\s*$/m)
  assert.ok(rowId, 'cordis.patch.yml declares a row id')
  assert.equal(pkg.name, '@goodandready/dsh-shadow-auditor')
  assert.match(client, /const PKG = '@goodandready\/dsh-shadow-auditor'/)
  assert.match(client, new RegExp("const ROW_ID = '" + rowId[1] + "'"))
  assert.match(client, /const ROW_CONFIG_KEY = PKG \+ '#' \+ ROW_ID/)
})

test('settings register into plugins.row.config first, legacy seat stays as fallback', () => {
  const rowSeat = client.indexOf("name: 'plugins.row.config'")
  const legacySeat = client.indexOf("name: 'settings.plugin.item'")
  assert.ok(rowSeat > -1, 'row seat is registered')
  assert.ok(legacySeat > -1, 'legacy seat is kept for older cores')
  assert.ok(rowSeat < legacySeat, 'row seat goes first')
  assert.match(client, /key: ROW_CONFIG_KEY/)
})

test('the page view drops the card chrome, the summary view is a one-liner', () => {
  assert.match(client, /props\.view === 'summary'/)
  assert.match(client, /const page = !!\(props && props\.view === 'page'\)/)
  assert.match(client, /page \? 'sa-page' : 'sa-section-card'/)
  assert.match(client, /display: page \? 'none' : 'flex'/)
  assert.doesNotMatch(client, /name: 'settings\.section'/)
})
