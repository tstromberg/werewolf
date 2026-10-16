// Only the upstream Node version guard changes. Application code is intact.
const fs = require('node:fs');
const path = 'node_modules/n8n/package.json';
const pkg = JSON.parse(fs.readFileSync(path, 'utf8'));
if (!pkg.engines || !pkg.engines.node) throw new Error('missing Node version guard');
pkg.engines.node += ' || >=26.0.0 <27.0.0';
fs.writeFileSync(path, JSON.stringify(pkg, null, 2) + '\n');

// Some integrations bundle binaries for every platform. Only glibc binaries
// for the build architecture belong in this package or its ELF dependencies.
const paths = require('node:path');
const machine = { arm64: 183, x64: 62 }[process.arch];
if (!machine) throw new Error('unsupported build architecture');
function prune(dir) {
  for (const entry of fs.readdirSync(dir, {withFileTypes: true})) {
    const name = paths.join(dir, entry.name);
    if (entry.isDirectory()) { prune(name); continue; }
    if (!entry.isFile()) continue;
    const fd = fs.openSync(name, 'r');
    const header = Buffer.alloc(64);
    const length = fs.readSync(fd, header);
    fs.closeSync(fd);
    const elf = length >= 20 && header.subarray(0, 4).equals(Buffer.from([127,69,76,70]));
    const foreign = elf && (header[5] !== 1 || header.readUInt16LE(18) !== machine);
    const musl = elf && (name.includes('musl') || fs.readFileSync(name).includes(Buffer.from('libc.musl-')));
    if (foreign || musl || /\.(dll|dylib|exe)$/.test(name) || (name.endsWith('.node') && !elf)) fs.unlinkSync(name);
  }
}
prune('node_modules');
