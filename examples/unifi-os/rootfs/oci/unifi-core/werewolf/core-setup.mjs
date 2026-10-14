import fs from 'node:fs/promises'
import { randomUUID } from 'node:crypto'

// Replace the vendor's privileged pre-start hook with writes to this
// service's own directories. PostgreSQL initialization belongs to its form.
for (const directory of [
  '/data/unifi-core/config/overrides', '/data/unifi-core/config/http',
  '/data/unifi-core/logs', '/data/unifi-core/supportFile', '/run/unifi-core',
]) {
  await fs.mkdir(directory, { recursive: true, mode: 0o700 })
}
try {
  await fs.writeFile('/data/unifi-core/uuid', randomUUID(), { flag: 'wx', mode: 0o600 })
} catch (error) {
  if (error.code !== 'EEXIST') throw error
}
await fs.writeFile('/data/unifi-core/config/overrides/local.json', JSON.stringify({
  postgres: { host: '127.0.0.1', database: 'postgres', user: 'unifi-core' },
}), { mode: 0o600 })
await fs.copyFile('/usr/share/unifi-core/http/ssl-nist.conf',
  '/data/unifi-core/config/http/ssl-dynamic.conf')
const timezoneSource = await fs.readFile('/usr/share/zoneinfo/tzdata.zi', 'utf8')
const zones = new Set(timezoneSource.split('\n').flatMap(line => {
  const fields = line.split(/\s+/)
  return fields[0] === 'Z' ? [fields[1]] : fields[0] === 'L' ? [fields[2]] : []
}))
await fs.writeFile('/data/unifi-core/timezones.txt', [...zones].sort().join('\n') + '\n')
console.log('unifi-core-setup: local configuration prepared')
