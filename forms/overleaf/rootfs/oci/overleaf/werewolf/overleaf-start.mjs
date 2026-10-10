// overleaf-start: the overleaf form's start for Overleaf's services, in
// place of the image's runit, bash and setuser, none of which may run.
// leash starts it as _oci-overleaf in the image's root (etc/sv/overleaf/
// service). Before anything serves, it makes the secrets only Overleaf's
// services share, once, in /var/lib/overleaf (the service's /data); makes
// MongoDB a replica set of one; runs Overleaf's migrations; and makes the
// administrator from the config. Then it runs each service as Overleaf's
// runit would, and if one exits, stops the rest and exits, so runsv starts
// them all again. It also does what the image's cron did: history flushes
// and retries. Compiles are the clsi service's, under a user of its own.
// See forms/overleaf/README.md.
import { spawn } from 'node:child_process'
import { createRequire } from 'node:module'
import crypto from 'node:crypto'
import fs from 'node:fs'
import net from 'node:net'

const data = '/var/lib/overleaf'
const secretsFile = `${data}/secrets.json`

function say(event, fields = {}) {
  console.log(`overleaf-start: ${JSON.stringify({ event, ...fields })}`)
}

function fail(why, fields = {}) {
  say('failed', { why, ...fields })
  process.exit(1)
}

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms))

// secrets returns the secrets Overleaf's services share, made once: the
// image's 100_generate_secrets.sh kept them in the container; here they
// are in /data, 0600, so a reboot keeps sessions and invites valid.
function secrets() {
  try {
    return JSON.parse(fs.readFileSync(secretsFile, 'utf8'))
  } catch (err) {
    if (err.code !== 'ENOENT') fail('secrets unreadable', { file: secretsFile, error: err.message })
  }
  const random = () => crypto.randomBytes(32).toString('base64url')
  const s = {
    WEB_API_PASSWORD: random(),
    STAGING_PASSWORD: random(),
    CRYPTO_RANDOM: random(),
    OT_JWT_AUTH_KEY: random(),
    OVERLEAF_SESSION_SECRET: random(),
    OVERLEAF_INVITE_TOKEN_SECRET: random(),
  }
  fs.writeFileSync(`${secretsFile}.new`, JSON.stringify(s), { mode: 0o600 })
  fs.renameSync(`${secretsFile}.new`, secretsFile)
  say('secrets', { made: secretsFile })
  return s
}

// waitPort waits up to two minutes for a loopback port to take a
// connection: MongoDB and Valkey are services of their own, started
// alongside.
async function waitPort(name, port) {
  for (let i = 0; i < 120; i++) {
    const up = await new Promise(resolve => {
      const c = net.connect({ host: '127.0.0.1', port })
      c.setTimeout(2000)
      c.on('connect', () => {
        c.destroy()
        resolve(true)
      })
      c.on('timeout', () => {
        c.destroy()
        resolve(false)
      })
      c.on('error', () => resolve(false))
    })
    if (up) return
    await sleep(1000)
  }
  fail(`no ${name} on 127.0.0.1:${port} in 120 s`)
}

// replicaSet makes MongoDB a replica set of one, as Overleaf requires
// (its transactions and change streams), and waits until it is primary.
async function replicaSet() {
  const { MongoClient } = createRequire('/overleaf/services/web/package.json')('mongodb')
  const client = new MongoClient('mongodb://127.0.0.1:27017/?directConnection=true', {
    serverSelectionTimeoutMS: 5000,
  })
  try {
    await client.connect()
    const admin = client.db('admin')
    try {
      await admin.command({ replSetGetStatus: 1 })
    } catch (err) {
      if (err.codeName !== 'NotYetInitialized') throw err
      await admin.command({
        replSetInitiate: { _id: 'overleaf', members: [{ _id: 0, host: '127.0.0.1:27017' }] },
      })
      say('replica-set', { initiated: 'overleaf' })
    }
    for (let i = 0; i < 120; i++) {
      if ((await admin.command({ hello: 1 })).isWritablePrimary) return
      await sleep(1000)
    }
    fail('MongoDB is not primary after 120 s')
  } finally {
    await client.close()
  }
}

// run runs a program to its end, its output on ours, and fails unless it
// exits 0.
function run(name, args, opts) {
  return new Promise(resolve => {
    const child = spawn(process.execPath, args, { stdio: 'inherit', ...opts })
    child.on('error', err => fail(`${name}: ${err.message}`))
    child.on('exit', (code, signal) => {
      if (code !== 0) fail(`${name} exited`, { code, signal })
      resolve()
    })
  })
}

// The services, as the image's /etc/service/*/run start them, each on
// loopback; nginx's part is Caddy's, outside the image.
const services = [
  ['web', 'web/app.mjs', { ENABLED_SERVICES: 'web', WEB_PORT: '4000' }],
  ['web-api', 'web/app.mjs', { ENABLED_SERVICES: 'api', METRICS_APP_NAME: 'web-api' }],
  ['real-time', 'real-time/app.js'],
  ['document-updater', 'document-updater/app.js'],
  ['docstore', 'docstore/app.js'],
  ['filestore', 'filestore/app.js'],
  ['history-v1', 'history-v1/app.js', { NODE_CONFIG_DIR: '/overleaf/services/history-v1/config' }],
  ['project-history', 'project-history/app.js'],
  ['notifications', 'notifications/app.ts'],
  ['chat', 'chat/app.js'],
]

const children = new Map()
let stopping = null

// stop asks every service to stop, and exits once all have, or after 10
// s; leash-reap then kills what is left in the cgroup.
function stop(code) {
  if (stopping !== null) return
  stopping = code
  for (const c of children.values()) c.kill('SIGTERM')
  if (children.size === 0) process.exit(code)
  setTimeout(() => process.exit(code), 10000).unref()
}

function start(env) {
  for (const [name, main, own = {}] of services) {
    const child = spawn(process.execPath, [`/overleaf/services/${main}`], {
      cwd: `/overleaf/services/${main.split('/')[0]}`,
      env: { ...env, ...own },
      stdio: 'inherit',
    })
    children.set(name, child)
    child.on('error', err => say('error', { service: name, error: err.message }))
    child.on('exit', (code, signal) => {
      children.delete(name)
      if (stopping === null) say('exited', { service: name, code, signal })
      stop(1)
      if (children.size === 0) process.exit(stopping)
    })
  }
  say('started', { services: services.map(s => s[0]) })
}

// Every 20 minutes, flush project histories that have waited; each hour,
// retry those that failed; each day, flush all. The image's cron did so
// with curl and bash. Deleting expired projects and users stays off, as
// it is by default upstream (ENABLE_CRON_RESOURCE_DELETION).
function timers(env) {
  const post = path => () =>
    fetch(`http://127.0.0.1:3054${path}`, { method: 'POST' })
      .then(r => r.ok || say('history', { path, status: r.status }))
      .catch(err => say('history', { path, error: err.message }))
  setInterval(post('/flush/old?timeout=3600000&limit=5000&background=1'), 20 * 60e3).unref()
  setInterval(post('/retry/failures?failureType=soft&timeout=3600000&limit=10000'), 60 * 60e3).unref()
  setInterval(post('/retry/failures?failureType=hard&timeout=3600000&limit=10000'), 60 * 60e3).unref()
  setInterval(() => {
    const c = spawn(process.execPath, ['scripts/flush_all.js'], {
      cwd: '/overleaf/services/project-history',
      env,
      stdio: 'inherit',
    })
    c.on('exit', code => code === 0 || say('history', { flushAll: 'exited', code }))
  }, 24 * 60 * 60e3).unref()
}

async function main() {
  for (const d of ['data', 'data/compiles', 'data/output', 'data/cache', 'data/template_files',
    'data/history', 'tmp', 'tmp/uploads', 'tmp/dumpFolder', 'tmp/projectHistories']) {
    fs.mkdirSync(`${data}/${d}`, { recursive: true, mode: 0o700 })
  }
  const s = secrets()
  // The image's env.sh, its run scripts' words, and the secrets. Settings
  // (base URL, administrator, mail) leash has put in our environment.
  const env = {
    ...process.env,
    ...s,
    V1_HISTORY_PASSWORD: s.STAGING_PASSWORD,
    OVERLEAF_MONGO_URL: 'mongodb://127.0.0.1:27017/sharelatex',
    OVERLEAF_REDIS_HOST: '127.0.0.1',
    OVERLEAF_REDIS_PORT: '6379',
    LISTEN_ADDRESS: '127.0.0.1',
  }
  // Behind Caddy's TLS, cookies go over HTTPS alone; a plain HTTP base URL
  // would get none back.
  if (env.OVERLEAF_SITE_URL?.startsWith('https://')) env.OVERLEAF_SECURE_COOKIE = 'true'
  for (const h of ['CHAT', 'CLSI', 'DOCSTORE', 'DOCUMENT_UPDATER', 'DOCUPDATER', 'FILESTORE',
    'HISTORY_V1', 'NOTIFICATIONS', 'PROJECT_HISTORY', 'REALTIME', 'WEB', 'WEB_API']) {
    env[`${h}_HOST`] = '127.0.0.1'
  }
  await waitPort('MongoDB', 27017)
  await waitPort('Valkey', 6379)
  await replicaSet()
  const east = createRequire('/overleaf/tools/migrations/package.json').resolve('east/bin/east.js')
  await run('migrations', [east, '--es-modules', 'migrate', '-t', 'server-ce'], {
    cwd: '/overleaf/tools/migrations',
    env: { ...env, MONGO_SOCKET_TIMEOUT: '0' },
  })
  say('migrated')
  await run('overleaf-admin', ['/werewolf/overleaf-admin.mjs'], {
    cwd: '/overleaf/services/web',
    env,
  })
  process.on('SIGTERM', () => stop(0))
  process.on('SIGINT', () => stop(0))
  start(env)
  timers(env)
}

main().catch(err => fail(err.message))
