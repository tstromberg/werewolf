// Only the upstream Node version guard changes. Application code is intact.
const fs = require('node:fs');
const path = 'node_modules/n8n/package.json';
const pkg = JSON.parse(fs.readFileSync(path, 'utf8'));
if (!pkg.engines || !pkg.engines.node) throw new Error('missing Node version guard');
pkg.engines.node += ' || >=26.0.0 <27.0.0';
fs.writeFileSync(path, JSON.stringify(pkg, null, 2) + '\n');
