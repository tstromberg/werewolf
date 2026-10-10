# Miniflux

The `miniflux` form is a feed reader: [Miniflux](https://miniflux.app)
2.3, with PostgreSQL beside it and Caddy in front, serving HTTPS at your
URL with a certificate from Let's Encrypt, each part on a leash of its own
([design/forms-catalog.md](../../docs/design/forms-catalog.md)).

## Run your own

You need a domain name you can point at the machine.

```sh
openssl rand -base64 24 >admin-password      # you sign in with it; keep it
howl create feeds --with miniflux --on gcp --allow-from 0.0.0.0/0 \
	--base-url https://feeds.example.com --admin alice \
	--admin-password admin-password
```

Point `feeds.example.com` at the address howl prints, with an `A` record,
and sign in at `https://feeds.example.com` as `alice`. Caddy gets the
certificate once the name resolves to the machine, and retries until it
does.

| Flag | |
| --- | --- |
| `--base-url URL` | required. Where Miniflux is served, `https://NAME`: Caddy's site and Miniflux's own links |
| `--admin NAME` | required. The administrator, made on the first start |
| `--admin-password FILE` | required. Its password, never printed or logged |

The administrator is made before Miniflux serves anything, so no visitor
claims a fresh machine; more users are made by the administrator, under
Settings. A later start keeps the administrator as it is: change its
password in Miniflux. To change a running machine's flags, run its create
line again.

## How the parts are held

| Part | Runs as | Reaches |
| --- | --- | --- |
| Caddy | `caddy` | :80 and :443; Miniflux on loopback; the ACME CA |
| Miniflux | `miniflux` | PostgreSQL's socket; public addresses on 80 and 443 |
| PostgreSQL | `postgres` | nothing |

- **Feeds from public addresses alone.** A feed is a URL anyone may
  give, so a fetch could be aimed at the machine or its network (SSRF).
  Miniflux refuses private addresses itself, and beneath it fence lets
  its user reach public addresses alone, on 80 and 443. Images served
  over plain HTTP it fetches the same way, by its media proxy.
- **Its own schema.** Its tables are in the schema `miniflux` of the
  `postgres` database, owned by the role of its name, which logs in by
  peer authentication over the socket; pg-init makes them before each
  start ([rootfs/usr/share/werewolf-postgres/miniflux.sql](rootfs/usr/share/werewolf-postgres/miniflux.sql)).
  Its migrations run before it serves.
- **Behind Caddy.** Miniflux listens on loopback alone, sets secure
  cookies, and takes the client's address from Caddy's header and no
  one else's.
- **Built here.** Wolfi does not ship Miniflux: melange builds it from
  the release's commit with Wolfi's Go
  ([melange/miniflux.yaml](melange/miniflux.yaml)).
- PostgreSQL's `allow: [jit]` turns MDWE off for the whole machine, a
  weakness this form names.

## Drawbacks

- Feeds on your own network (an intranet's) cannot be read: that is the
  SSRF the form refuses.
- No mail: Miniflux sends none.
- Until Wolfi takes the recipe, every release is werewolf's to rebuild.

## Checked

`make check-miniflux` boots it with its test config ([test/config](test/config)),
base URL `https://localhost`, for which Caddy's own CA signs: Miniflux
answers its health check through Caddy over HTTPS, plain HTTP is sent to
HTTPS, the API takes the administrator's password, and a feed on a
loopback address is refused and not kept, with fence's lines for its user
public alone. `make check-shellfree-miniflux` boots it as it ships, with
no config: no posture failure but those named, PostgreSQL and Caddy up,
and Miniflux parked, saying it has no administrator's password, before it
migrates or serves anything.
