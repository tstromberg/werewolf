# Umami

The `umami` form is web analytics: [Umami](https://umami.is) 3.4, which
counts visits without cookies, with PostgreSQL beside it and Caddy in
front, serving HTTPS for your domain with a certificate from Let's
Encrypt, each part on a leash of its own
([design/startup.md](../../docs/design/startup.md)).

| | |
| --- | --- |
| Listens | tcp/80 and tcp/443, Caddy's; Umami and PostgreSQL on loopback alone |
| Sends | nothing but Caddy's ACME requests |
| Runs as | `_oci-umami` in Umami's own image, `postgres` and `caddy`, each leashed |
| Keeps | its tables in the schema `umami` of PostgreSQL, in `/data/svc/postgres` |
| Config | `umami/app-secret`, a random key; `umami/admin-hash`, a bcrypt hash; setting `domain` (required) |

## Run your own

You need a domain name you can point at the machine.

```sh
openssl rand -base64 32 >app-secret
htpasswd -nBC 10 admin | cut -d: -f2 >admin-hash   # asks for the password
howl create stats --with umami --on gcp --allow-from 0.0.0.0/0 \
	--domain stats.example.com --app-secret app-secret --admin-hash admin-hash
```

Point `stats.example.com` at the address howl prints, sign in at
`https://stats.example.com` as `admin`, add your site, and put the
`<script>` Umami shows you on its pages.

## Defaults

- **No default administrator.** Umami's first migration makes `admin`
  with the password `umami`. Before Umami serves, `werewolf-setup`
  ([rootfs/oci/umami/app/scripts/werewolf-setup.mjs](rootfs/oci/umami/app/scripts/werewolf-setup.mjs))
  gives it the config's hash, on every start: the config is its
  password, so change it there and run the create line again. The
  machine never holds the password itself, only its hash.
- **Logins signed with your key.** Without `APP_SECRET` Umami signs with a
  hash of its database URL, which anyone reading this file knows; with
  no `app-secret` Umami parks before it migrates, saying so.
- **Strangers see nothing** but the tracker (`/script.js`) and the
  collector (`/api/send`), which keeps events only for sites you added.
- **Nothing sent home**: Umami's telemetry and update checks are off, and
  Prisma's. fence has no line for its user but PostgreSQL's port.
- **The visitor's address** is Caddy's `X-Forwarded-For`, which Caddy
  sets afresh, not a header a visitor sends.
- **Umami's own image**, pinned by digest, run in a tree of its own
  ([oci.md](../../docs/design/oci.md)). Its start script needs a shell,
  so `werewolf-setup` does its work: it waits for PostgreSQL and has
  Prisma apply the migrations, Node and Prisma's schema engine being the
  programs it may start; then leash starts the server.

## How it reaches PostgreSQL

An image's service cannot yet reach another service's socket
([adhoc.md](../../docs/design/adhoc.md)), so PostgreSQL also listens on
127.0.0.1:5432, where its `pg_hba.conf` lets in the role `umami`, to the
`postgres` database, and nothing else
([rootfs/etc/postgresql/pg_hba.conf](rootfs/etc/postgresql/pg_hba.conf)).
It takes no password: leash lets no service but Umami connect to 5432,
and fence lets nothing off the machine reach it, so the password would
guard against root alone, who could read it.

## Drawbacks

- `COLLECT_API_ENDPOINT` is not taken: Umami writes it into its tracker
  script, and its image is read-only. `TRACKER_SCRIPT_NAME` works.
- No mail: Umami sends none. More users are made by the administrator.
- Open: a link from an image to PostgreSQL's socket, so PostgreSQL would
  name its peer and need no TCP port.

## Checked

`make check-umami` boots it with its test config ([test/config](test/config)),
domain `localhost`, for which Caddy's own CA signs: Umami answers
through Caddy over HTTPS as `_oci-umami` with no capabilities; plain HTTP
is sent to HTTPS; `admin` with `umami` is refused and the config's
password signs in; a stranger gets 401 for the list of sites; an event
for an added site is kept, one for an unknown site is refused and not
kept; PostgreSQL refuses its superuser and other databases over TCP; and
fence has no line for Umami but PostgreSQL's port.
`make check-shellfree-umami` boots it as it ships, with no config: no
posture failure but those named, PostgreSQL up, and Umami and Caddy
parked, each saying why.
