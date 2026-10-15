import fs from 'node:fs/promises'

for (const directory of ['/data/unifi/logs', '/data/unifi/run', '/var/lib/unifi']) {
  await fs.mkdir(directory, { recursive: true, mode: 0o700 })
}
try {
  await fs.writeFile('/var/lib/unifi/system.properties', [
    'db.mongo.local=false',
    'db.mongo.uri=mongodb://127.0.0.1:27017/ace',
    'statdb.mongo.uri=mongodb://127.0.0.1:27017/ace_stat',
    'unifi.db.name=ace',
    'unifi.http.port=8080',
    'unifi.local.http.port=8081',
    '',
  ].join('\n'), { flag: 'wx', mode: 0o600 })
} catch (error) {
  if (error.code !== 'EEXIST') throw error
}
console.log('unifi-network-setup: external MongoDB configured')
