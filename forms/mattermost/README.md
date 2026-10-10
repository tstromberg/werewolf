# Mattermost

The `mattermost` form is team chat: [Mattermost](https://mattermost.com)
Team Edition 11.7, its extended support release, with PostgreSQL beside
it and Caddy in front, serving HTTPS at your URL with a certificate from
Let's Encrypt, each part on a leash of its own
([design/startup.md](../../docs/design/startup.md)).

## Run your own

You need a domain name you can point at the machine.

```sh
openssl rand -base64 24 >admin-password      # you sign in with it; keep it
howl create chat --with mattermost --on gcp --allow-from 0.0.0.0/0 \
	--base-url https://chat.example.com --admin alice \
	--admin-email alice@example.com --admin-password admin-password
```

Point `chat.example.com` at the address howl prints, with an `A` record,
sign in at `https://chat.example.com` as `alice`, make a team, and invite
the others with its invitation link, or by mail once SMTP is set under
System Console.

| Flag | |
| --- | --- |
| `--base-url URL` | required. Where Mattermost is served, `https://NAME`, at the root of the name: Caddy's site and Mattermost's Site URL |
| `--admin NAME` | required. The system admin, made on the first start: 3 to 22 lowercase letters, digits, `.`, `-`, `_` |
| `--admin-email ADDRESS` | required. Its address |
| `--admin-password FILE` | required. Its password, 12 to 72 bytes, never printed or logged |

The admin is made before Caddy opens the port, so no visitor claims a
fresh machine; a later start keeps the admin as it is.

## How the parts are held

| Part | Runs as | Reaches |
| --- | --- | --- |
| Caddy | `caddy` | :80 and :443; Mattermost on loopback; the ACME CA |
| Mattermost | `mattermost` | PostgreSQL's socket; public addresses on 80, 443, 465 and 587 |
| PostgreSQL | `postgres` | nothing |

- **By invitation.** Open sign-up is off: after the admin, an account is
  made only from a team's invitation.
- **No plugins.** A plugin is a program the server starts. Plugins,
  their uploads and the marketplace are off, set in the environment,
  which wins over the System Console, so a stolen admin session cannot
  turn them on.
- **Nothing sent home.** No telemetry, security or product notices, and
  no push notifications, which go through Mattermost's proxy with the
  message in them. Mail is off until the admin sets an SMTP server
  ([rootfs/etc/mattermost/defaults.json](rootfs/etc/mattermost/defaults.json)).
- **Public addresses alone.** Link previews, webhooks and mail go to
  addresses users name; fence lets Mattermost reach public ones alone,
  as Mattermost's own check of internal addresses does.
- **Its own schema.** Its tables and its configuration are in the schema
  `mattermost` of the `postgres` database, owned by the role of its
  name, which logs in by peer authentication over the socket
  ([rootfs/usr/share/werewolf-postgres/mattermost.sql](rootfs/usr/share/werewolf-postgres/mattermost.sql)).
  Uploads are in `/data/svc/mattermost/files`.
- **Upstream's build.** Mattermost publishes a tarball for each arch and
  images for amd64 alone; melange packages the tarball, pinned by
  sha256, leaving out mmctl and the prepackaged plugins, and writes the
  page's script policy as Mattermost would at its first start, its own
  scripts alone ([melange/mattermost-team.yaml](melange/mattermost-team.yaml)).
- PostgreSQL's `allow: [jit]` turns MDWE off for the whole machine, a
  weakness this form names.

## Drawbacks

- No push notifications to phones until a form runs Mattermost's push
  proxy; the desktop apps and browsers notify.
- No plugins: Boards, Playbooks and Calls are plugins.
- Calls would need UDP and a TURN server: not served.
- Served at the root of its name alone: the web app is read-only, so
  Mattermost cannot rewrite it for a path such as `/chat`.
- 11.7's support ends 2027-05; the next extended release is a new pin,
  and its migrations cannot be rolled back.

## Checked

`make check-mattermost` boots it with its test config
([test/config](test/config)), base URL `https://localhost`, for which
Caddy's own CA signs: Mattermost answers through Caddy over HTTPS, runs
as its own user with no capabilities and reaches public addresses alone,
keeps its tables and configuration in its schema, and the config's admin
logs in as system admin. The attacks: a stranger's sign-up is refused
and leaves no account, and the admin's plugin upload is refused, with
nothing in the plugin directory. `make check-shellfree-mattermost` boots
it as it ships, with no config: no posture failure but those named,
PostgreSQL up, and Caddy and Mattermost parked, saying why.
