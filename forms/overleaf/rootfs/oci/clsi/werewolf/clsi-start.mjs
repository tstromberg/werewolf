// clsi-start: the overleaf form's start for Overleaf's compiler (clsi) and
// the nginx that serves what it makes, in place of the image's runit.
// leash starts it as _oci-clsi in its own copy of the image's root
// (etc/sv/clsi/service), so TeX, which runs what its users write, shares
// no user, file or secret with the rest of Overleaf. TeX may read only
// its project and TeX's own files (openin_any=p), write only beneath it
// (openout_any=p), and run only TeX Live's short list of helpers
// (shell_escape=p). If either program exits, the other is stopped and
// this exits, so runsv starts both again. See forms/overleaf/README.md.
import { spawn } from 'node:child_process'
import fs from 'node:fs'

const data = '/var/lib/overleaf'

function say(event, fields = {}) {
  console.log(`clsi-start: ${JSON.stringify({ event, ...fields })}`)
}

for (const d of ['data/compiles', 'data/output', 'data/cache', 'tmp/texmf-var', 'tmp/nginx']) {
  fs.mkdirSync(`${data}/${d}`, { recursive: true, mode: 0o700 })
}

const env = {
  ...process.env,
  LISTEN_ADDRESS: '127.0.0.1',
  openin_any: 'p',
  openout_any: 'p',
  shell_escape: 'p',
}
const programs = [
  ['nginx', '/usr/sbin/nginx', ['-e', 'stderr', '-c', '/werewolf/nginx.conf'], '/'],
  ['clsi', process.execPath, ['/overleaf/services/clsi/app.js'], '/overleaf/services/clsi'],
]

const children = new Map()
let stopping = null

function stop(code) {
  if (stopping !== null) return
  stopping = code
  for (const c of children.values()) c.kill('SIGTERM')
  if (children.size === 0) process.exit(code)
  setTimeout(() => process.exit(code), 10000).unref()
}

for (const [name, program, args, cwd] of programs) {
  const child = spawn(program, args, { cwd, env, stdio: 'inherit' })
  children.set(name, child)
  child.on('error', err => say('error', { program: name, error: err.message }))
  child.on('exit', (code, signal) => {
    children.delete(name)
    if (stopping === null) say('exited', { program: name, code, signal })
    stop(1)
    if (children.size === 0) process.exit(stopping)
  })
}
process.on('SIGTERM', () => stop(0))
process.on('SIGINT', () => stop(0))
say('started', { programs: programs.map(p => p[0]) })
