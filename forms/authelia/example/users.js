// users.js writes Authelia's users file. Argon2id, m=65536 t=3 p=4,
// which is what Authelia's file backend expects. Node 24 or newer.
const crypto = require("node:crypto");
const fs = require("node:fs");

const password = fs.readFileSync(process.argv[2], "utf8").trim();
const salt = crypto.randomBytes(16);
const tag = crypto.argon2Sync("argon2id", {
	message: password,
	nonce: salt,
	parallelism: 4,
	tagLength: 32,
	memory: 65536,
	passes: 3,
});
const b64 = (buf) => buf.toString("base64").replace(/=+$/, "");
const hash = "$argon2id$v=19$m=65536,t=3,p=4$" + b64(salt) + "$" + b64(tag);
process.stdout.write(
	"users:\n" +
		"  alice:\n" +
		"    displayname: Alice\n" +
		"    email: alice@example.com\n" +
		"    password: '" + hash + "'\n" +
		"    groups: [admins]\n",
);
