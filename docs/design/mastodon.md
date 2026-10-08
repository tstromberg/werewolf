# Mastodon

Proposed, 2026-10-08. The first form of [forms-catalog.md](forms-catalog.md)'s
tier 4, and the one that needs all of tier 3.

## Summary

A Mastodon server that a bug in Mastodon, its media libraries or its
language runtimes cannot turn into a foothold: each part is its own user
on its own leash, the parser of strangers' media has no network and no
database, the kernel refuses requests to private addresses, nothing
generates code at runtime, and security releases reach the machine within
a day. Strict where an attacker reaches; as fast and as ordinary to run as
any Mastodon, for its admin and its users.

## Background

Mastodon 4.7 is a Rails application (Puma for the web, Sidekiq for jobs),
a Node streaming server, PostgreSQL, Valkey and nginx. It takes ActivityPub
traffic, HTTP signatures, link previews and media from every server it
federates with, all day, and ships security releases several times a
year. Wolfi has its runtimes (`ruby-4.0`, `nodejs-24`, `libvips`,
`ffmpeg`, `postgresql-17`, `valkey-9.1`) but not Mastodon, so it is a
melange recipe ([forms.md](../forms.md#packages-wolfi-does-not-ship)),
built in Wolfi's environment, gems and assets included, and offered to
Wolfi.

## Goals

- A remote code execution in any one part reads and writes only what that
  part already holds, starts nothing new, and is gone at the next reboot.
- No request, however a bug forges it, reaches a private, loopback,
  link-local or cloud-metadata address.
- Media from strangers is parsed by a process that cannot send a packet
  or open the database.
- A Mastodon security release runs on machines within a day of release.
- It serves as fast as a stock install on the same machine, and the admin
  does nothing a stock install would not ask of them.
- `make check-mastodon` attacks each of the above.

## Non-Goals

- Search (Elasticsearch, OpenSearch): a JVM and a second store. Mastodon
  works without it; a form of your own adds it.
- Object storage: media stays on `/data`; S3 is a form of your own, on
  `minio` or a cloud's.
- Defending direct messages from a compromised web process: it must read
  them to serve them. Roles narrow who else can.

## Detailed design

### Parts, users and what each may do

| Part | User | Listens | Reaches | Runs |
| --- | --- | --- | --- | --- |
| nginx | `nginx` | tcp/80 (TLS in front: `caddy`, or the cloud's) | web, streaming on loopback | nothing |
| web (Puma) | `mastodon` | 127.0.0.1:3000 | PostgreSQL, Valkey sockets; tcp/443 public | nothing |
| streaming (Node 24) | `mastodon-stream` | 127.0.0.1:4000 | PostgreSQL (read-only role), Valkey | nothing |
| jobs (Sidekiq) | `mastodon-jobs` | nothing | PostgreSQL, Valkey; tcp/443 public, tcp/587 | `media` only |
| media (ffmpeg, ffprobe) | `mastodon-jobs`, narrower leash | nothing | nothing | nothing |
| PostgreSQL, Valkey | `postgres`, `valkey` | sockets | nothing | nothing |

Uploaded and fetched media live in `/data/svc/mastodon/system`, written by
web and jobs through a shared group, served by nginx with `sendfile`.

### The base work it needs (tier 3, and two of tier 5's)

1. **Bundles.** `forms/mastodon/form.yaml` takes `with: [postgresql,
   valkey, nginx]`; the build puts their parts before Mastodon's own,
   so packages, accounts, services, policies and pruning merge, and
   Mastodon's files win. Duplicate uids or names fail the build.
2. **A `ruby` runtime form** on `app`, Ruby 4.0 and Bundler, as `node` and
   `python` are; Mastodon's recipe vendors its gems at build.
3. **A narrower leash for a program a service runs.** `run PROGRAM with
   POLICY` in a service file: the child gets its own pledge, write paths,
   no network and its own memory and CPU ceilings, applied by a small
   launcher before exec. ffmpeg and ffprobe run so.
4. **Public-only egress.** `connect USER tcp/443 public` in a `.net`
   file: fence adds refusals for that user's traffic to 10/8, 172.16/12,
   192.168/16, 100.64/10, 127/8, 169.254/16 and their IPv6 kin before the
   allowance, by policy routing on destination and uid. Mastodon's own
   address filter stays; this one has no bugs Mastodon can reach.
5. **First-run.** Before Puma serves, `tootctl` makes the owner from the
   config, and `db:prepare` brings the schema up; a `before` step, as
   `gitea-init` does.
6. **Timed services** (`every 1d` in a service file) for media and
   preview-card cleanup, instead of cron.
7. **`cpu`** beside `memory`, so a federation flood cannot starve nginx.

### Defaults

- **Accounts:** registrations by approval; the owner from the config; 2FA
  required for owner, admins and moderators; secure mode
  (`AUTHORIZED_FETCH=true`); no Sidekiq web UI; secrets made once on
  `/data`, 0600, unless the config brings them.
- **No runtime code generation:** Node with `--jitless`. Ruby's YJIT stays
  on only if it keeps W^X (no page writable and executable at once); the
  check measures both, and the doc records the cost.
- **Performance:** Puma workers from the CPUs, threads 5, `MAX_THREADS`
  matched to the PostgreSQL pool; Sidekiq concurrency sized to the pool;
  libvips for images (faster and smaller than ImageMagick, and not
  ImageMagick's history); assets precompiled at build; bootsnap's cache in
  `/run`; nginx `sendfile`, HTTP/2 in front; jemalloc as Mastodon ships.
- **Rate limits:** Mastodon's rack-attack as shipped, and nginx
  `limit_req` on sign-in, sign-up and the API's write endpoints.
- **Retention:** remote media 7 days, preview cards 14, as most admins
  set them.

### Updates

The recipe pins a release and its sha256. melange's `update:` follows
Mastodon's releases; CI rebuilds and publishes, and machines update
themselves. Security releases are the clock: within a day, measured.

## Drawbacks

- Six users and a launcher are more moving parts than one container.
- Without YJIT, if it cannot keep W^X, the web serves fewer requests a
  core; the measurement decides.
- A Mastodon not in Wolfi is werewolf's to rebuild on every release until
  Wolfi takes the recipe.

## Alternatives Considered

### One user for all of Mastodon
Simpler, and how most installs run. A bug in the media path would then
hold the database, the network and every secret.

### Mastodon's own container image
Debian, a shell, ImageMagick, and the whole of Mastodon as one user.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| RCE in media parsing | ffmpeg in a narrower leash: no network, no sockets, one temp directory; libvips, not ImageMagick |
| SSRF through link previews or fetches | fence refuses private and metadata destinations for those users, below Mastodon's own filter |
| RCE in web or jobs | its own user, Landlock, pledge without `exec` (web), read-only root, no shell; reboot heals |
| Takeover of the first account | owner from the config before the site serves; approval for the rest |
| Stale Mastodon | a release reaches machines within a day |

## Reliability Considerations

- PostgreSQL and media on `/data` survive a power cut (`persist`).
- Each part restarts alone; a crashing streaming server leaves the web up.
- Federation floods hit Sidekiq's concurrency and `cpu`, not nginx.
