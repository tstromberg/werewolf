// werewolf-setup readies Umami before it serves, in place of its image's
// shell script: it waits for PostgreSQL, applies Prisma's migrations, and
// sets the password of the administrator Umami's first migration makes to
// the bcrypt hash in the config, so its default (admin, umami) never
// works. leash runs it before the server. See forms/umami/README.md.
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaClient } from '../generated/prisma/client.js';

const admin = '41e2b680-648e-4b09-bcd7-3e2b10c06264';

function say(fields) {
  console.log(`werewolf-setup: ${JSON.stringify(fields)}`);
}

function fail(why) {
  say({ event: 'setup', why });
  process.exit(1);
}

// htpasswd writes $2y$, which is bcrypt's $2b$ under another name.
const hash = fs.readFileSync('/tmp/admin-hash', 'utf8').trim().replace(/^\$2y\$/, '$2b$');
if (!/^\$2[ab]\$(0[4-9]|[12][0-9]|3[01])\$[./A-Za-z0-9]{53}$/.test(hash)) {
  fail('admin-hash is not a bcrypt hash');
}

// PostgreSQL starts beside Umami, and a failed step parks Umami for good.
const url = new URL(process.env.DATABASE_URL);
function reachable() {
  return new Promise((resolve) => {
    const s = net.connect(Number(url.port), url.hostname);
    s.once('connect', () => {
      s.end();
      resolve(true);
    });
    s.once('error', () => resolve(false));
  });
}
const until = Date.now() + 120_000;
while (!(await reachable())) {
  if (Date.now() > until) fail(`no PostgreSQL at ${url.host} in 120 s`);
  await new Promise((r) => setTimeout(r, 1000));
}

const m = spawnSync(process.execPath, ['/app/node_modules/prisma/build/index.js', 'migrate', 'deploy'], {
  stdio: 'inherit',
});
if (m.status !== 0) fail(`prisma migrate deploy: ${m.error?.message ?? `exit ${m.status}`}`);

const prisma = new PrismaClient({
  adapter: new PrismaPg({ connectionString: url.toString() }, { schema: url.searchParams.get('schema') }),
});
const n = await prisma.$executeRaw`UPDATE "user" SET password = ${hash}, updated_at = now() WHERE user_id = ${admin}::uuid AND deleted_at IS NULL`;
await prisma.$disconnect();
// An administrator removed in Umami stays removed; its other users keep
// their own passwords.
say({ event: 'admin', user: admin, set: n === 1 });
