import fs from 'node:fs/promises'
import { constants } from 'node:fs'
import { createHash, randomUUID } from 'node:crypto'

// RFC 9562 DNS namespace. The random name avoids depending on host hardware.
const namespace = Buffer.from('6ba7b8109dad11d180b400c04fd430c8', 'hex')
const valid = /^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

export function uuidV5(name) {
  const bytes = createHash('sha1').update(namespace).update(name).digest().subarray(0, 16)
  bytes[6] = (bytes[6] & 0x0f) | 0x50
  bytes[8] = (bytes[8] & 0x3f) | 0x80
  const hex = bytes.toString('hex')
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
}

async function readIdentity(path) {
  const file = await fs.open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
  try {
    const stat = await file.stat()
    if (!stat.isFile() || stat.size !== 36 || (stat.mode & 0o777) !== 0o600) {
      throw new Error('identity must be a private, 36-byte regular file')
    }
    const value = await file.readFile('utf8')
    if (!valid.test(value)) {
      throw new Error('identity must be a version-5 UUID; existing identities are never replaced; use a fresh prototype data disk')
    }
    return value
  } finally {
    await file.close()
  }
}

export async function ensureIdentity(path) {
  try {
    return await readIdentity(path)
  } catch (error) {
    if (error.code !== 'ENOENT') throw error
  }
  const temporary = `${path}.${randomUUID()}.tmp`
  try {
    const file = await fs.open(temporary, 'wx', 0o600)
    try {
      await file.writeFile(uuidV5(randomUUID()))
      await file.sync()
    } finally {
      await file.close()
    }
    // link publishes complete bytes without replacing a concurrent identity.
    await fs.link(temporary, path)
  } catch (error) {
    if (error.code !== 'EEXIST') throw error
  } finally {
    await fs.unlink(temporary)
  }
  const directory = await fs.open(path.slice(0, path.lastIndexOf('/')), 'r')
  try {
    await directory.sync()
  } finally {
    await directory.close()
  }
  return readIdentity(path)
}
