// Build-only smoke test: load the full server and migrate a fresh SQLite DB.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const {spawn} = require('node:child_process');
const {once} = require('node:events');

(async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'n8n-build-'));
  const socket = net.createServer();
  socket.listen(0, '127.0.0.1');
  await once(socket, 'listening');
  const port = socket.address().port;
  await new Promise(resolve => socket.close(resolve));
  let output = '';
  const child = spawn(process.execPath, ['--no-node-snapshot', 'node_modules/n8n/bin/n8n', 'start'], {
    env: {...process.env, HOME: home, N8N_USER_FOLDER: home, TMPDIR: home,
      N8N_LISTEN_ADDRESS: '127.0.0.1', N8N_PORT: String(port),
      N8N_DIAGNOSTICS_ENABLED: 'false', N8N_VERSION_NOTIFICATIONS_ENABLED: 'false',
      N8N_TEMPLATES_ENABLED: 'false', N8N_COMMUNITY_PACKAGES_ENABLED: 'false',
      N8N_RUNNERS_ENABLED: 'false', N8N_ENFORCE_SETTINGS_FILE_PERMISSIONS: 'true'},
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const exited = once(child, 'exit');
  for (const stream of [child.stdout, child.stderr]) stream.on('data', value => {
    output = (output + value.toString()).slice(-16384);
  });
  try {
    const deadline = Date.now() + 120000;
    while (true) {
      if (child.exitCode !== null || child.signalCode !== null) throw new Error('server exited before readiness');
      try {
        const ready = await fetch(`http://127.0.0.1:${port}/healthz/readiness`, {signal: AbortSignal.timeout(1000)});
        const settings = await fetch(`http://127.0.0.1:${port}/rest/settings`, {signal: AbortSignal.timeout(1000)});
        if (ready.ok && settings.ok && (await settings.json()).data.versionCli === '1.120.0') break;
      } catch {}
      if (Date.now() > deadline) throw new Error('server did not become ready');
      await new Promise(resolve => setTimeout(resolve, 250));
    }
    console.log('n8n-build-startup: ok');
  } catch (error) {
    console.error(output);
    throw error;
  } finally {
    child.kill('SIGTERM');
    const force = setTimeout(() => child.kill('SIGKILL'), 10000);
    await exited;
    clearTimeout(force);
    fs.rmSync(home, {recursive: true, force: true});
  }
})().catch(error => {console.error(error); process.exitCode = 1;});
