import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { test } from 'node:test'
import { ensureIdentity, uuidV5 } from '../rootfs/oci/unifi-core/werewolf/identity.mjs'

async function fixture(t) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'unifi-identity-'))
  t.after(() => fs.rm(directory, { recursive: true, force: true }))
  return path.join(directory, 'uuid')
}

test('UUIDv5 matches the DNS namespace reference vector', () => {
  assert.equal(uuidV5('www.widgets.com'), '21f7f8de-8051-5b89-8680-0195ef798b6a')
})

test('fresh identity is private and survives repeated initialization', async t => {
  const file = await fixture(t)
  const identity = await ensureIdentity(file)
  assert.match(identity, /^[0-9a-f-]{14}5[0-9a-f]{3}-[89ab][0-9a-f-]{16}$/)
  assert.equal(await ensureIdentity(file), identity)
  assert.equal((await fs.stat(file)).mode & 0o777, 0o600)
  assert.deepEqual(await fs.readdir(path.dirname(file)), ['uuid'])
})

test('concurrent initializers publish one complete, persistent identity', async t => {
  const file = await fixture(t)
  const identities = await Promise.all(Array.from({ length: 16 }, () => ensureIdentity(file)))
  assert.equal(new Set(identities).size, 1)
  assert.equal(await fs.readFile(file, 'utf8'), identities[0])
  assert.deepEqual(await fs.readdir(path.dirname(file)), ['uuid'])
})

test('legacy or corrupt identity is refused without changing its bytes', async t => {
  const file = await fixture(t)
  for (const value of ['', '12345678-1234-4234-8234-123456789abc',
    '12345678-1234-5234-7234-123456789abc', uuidV5('test') + '\n']) {
    await fs.writeFile(file, value, { mode: 0o600 })
    await assert.rejects(ensureIdentity(file))
    assert.equal(await fs.readFile(file, 'utf8'), value)
  }
})

test('shared identity permissions and symlink substitution are refused', async t => {
  const file = await fixture(t)
  const identity = await ensureIdentity(file)
  await fs.chmod(file, 0o640)
  await assert.rejects(ensureIdentity(file), /private/)
  await fs.rename(file, file + '.original')
  await fs.symlink(file + '.original', file)
  await assert.rejects(ensureIdentity(file))
  assert.equal(await fs.readFile(file + '.original', 'utf8'), identity)
})
