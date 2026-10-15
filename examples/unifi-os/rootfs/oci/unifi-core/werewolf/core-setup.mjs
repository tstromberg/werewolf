import fs from 'node:fs/promises'
import { ensureIdentity } from './identity.mjs'

// Replace the vendor's privileged pre-start hook with writes to this
// service's own directories. PostgreSQL initialization belongs to its form.
// The shared socket directory admits the adapter's group. Core's
// application data keeps the default private permissions.
await fs.chmod('/werewolf/bus', 0o2770)
await fs.chmod('/werewolf/config', 0o2750)
await fs.chmod('/werewolf/reload', 0o2770)
for (const directory of [
  '/data/unifi-core/config/overrides', '/werewolf/config/http',
  '/data/unifi-core/logs', '/data/unifi-core/supportFile', '/run/unifi-core',
]) {
  await fs.mkdir(directory, { recursive: true, mode: 0o700 })
}
for (const directory of ['http', 'tls']) {
  await fs.mkdir(`/werewolf/config/${directory}`, { recursive: true, mode: 0o2750 })
  await fs.chmod(`/werewolf/config/${directory}`, 0o2750)
}
try {
  await fs.symlink('/werewolf/reload/uos-internal.sock', '/werewolf/config/http/uos-internal.sock')
} catch (error) {
  if (error.code !== 'EEXIST') throw error
}
await ensureIdentity('/data/unifi-core/uuid')
await fs.writeFile('/data/unifi-core/config/overrides/local.json', JSON.stringify({
  configPath: '/werewolf/config',
  ssl: {
    crt: '/werewolf/config/tls/unifi-core.crt',
    key: '/werewolf/config/tls/unifi-core.key',
    directCrt: '/werewolf/config/tls/unifi-core-direct.crt',
    directKey: '/werewolf/config/tls/unifi-core-direct.key',
  },
  logs: { enableConsole: true },
  postgres: { host: '127.0.0.1', database: 'postgres', user: 'unifi-core' },
}), { mode: 0o600 })
await fs.copyFile('/usr/share/unifi-core/http/ssl-nist.conf',
  '/werewolf/config/http/ssl-dynamic.conf')
const timezoneSource = await fs.readFile('/usr/share/zoneinfo/tzdata.zi', 'utf8')
const zones = new Set(timezoneSource.split('\n').flatMap(line => {
  const fields = line.split(/\s+/)
  return fields[0] === 'Z' ? [fields[1]] : fields[0] === 'L' ? [fields[2]] : []
}))
await fs.writeFile('/data/unifi-core/timezones.txt', [...zones].sort().join('\n') + '\n')
console.log('unifi-core-setup: local configuration prepared')
