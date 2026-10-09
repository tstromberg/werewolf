# Mastodon

Proposed, 2026-10-08; its base work is built (below), the form not yet.
The first form of [forms-catalog.md](forms-catalog.md)'s tier 4.

## Summary

A Mastodon that a bug in Mastodon, its media libraries or its runtimes
cannot turn into a foothold, yet as fast and as easy to run as any.

## Background

Mastodon 4.7 is a Rails application (Puma, Sidekiq), a Node streaming
server, PostgreSQL, Valkey and nginx. It parses what every server it
federates with sends, and ships several security releases a year. Wolfi
has its runtimes but not Mastodon, so it is a melange recipe, pinned by
sha256 and followed by melange's `update:`
([docs/forms.md](../forms.md#packages-wolfi-does-not-ship)).

## Goals

- Code an attacker runs in one part reaches only what that part holds,
  starts nothing, and is gone at the next reboot.
- No request, however forged, reaches a private or metadata address.
- Strangers' media is parsed by a process with no network or database.
- A security release runs on machines within a day of its release.
- `make check-mastodon` attacks each of the above.

## Non-Goals

- Search (a JVM and a second store) and object storage, which Mastodon
  works without; and keeping direct messages from a compromised web
  process, which must read them to serve them.

## Detailed design

| Part | User | Listens | Reaches | Runs |
| --- | --- | --- | --- | --- |
| nginx | `nginx` | tcp/80 (TLS in front: `caddy`, or the cloud's) | web, streaming on loopback | nothing |
| web (Puma) | `mastodon` | 127.0.0.1:3000 | PostgreSQL, Valkey sockets; tcp/443 public | nothing |
| streaming (Node 24) | `mastodon-stream` | 127.0.0.1:4000 | PostgreSQL (read-only role), Valkey | nothing |
| jobs (Sidekiq) | `mastodon-jobs` | nothing | PostgreSQL, Valkey; tcp/443 public, tcp/587 | `media` only |
| media (ffmpeg, ffprobe) | `mastodon-jobs`, narrower leash | nothing | nothing | nothing |
| PostgreSQL, Valkey | `postgres`, `valkey` | sockets | nothing | nothing |

**Base work.** Built: the `ruby` form (Ruby 4.0) and bundles, so the
form is `base: ruby` with `[postgresql, valkey, nginx]`
([docs/forms.md](../forms.md#bundles-one-form-taking-several)); and
`connect USER tcp/443 public`, which fence keeps off private, loopback,
link-local and metadata addresses ([cmd/fence](../../cmd/fence/README.md)).
Built for it:

1. **A narrower leash for a child**: `narrow` lines give ffmpeg and
   ffprobe their own pledge, paths and memory, and no network, run by
   their links ([narrow.md](narrow.md)).
2. **First run**: a `before` step, as `gitea-init` is, runs `db:prepare`
   and makes the owner from the config with `tootctl` before Puma serves
   ([cpu-and-first-run.md](cpu-and-first-run.md)).
3. **Timed jobs** for media and preview-card cleanup: the `cron` form,
   taken `with` ([forms/cron](../../forms/cron/README.md)).
4. **`cpu`** beside `memory`, so a federation flood cannot starve nginx.
5. **`/bin/sh -c`**, which Terrapin, Paperclip's runner, starts ffmpeg
   through: the `sh-shim` form ([cmd/sh-shim](../../cmd/sh-shim/README.md)).

**Defaults.**

- Registrations by approval; 2FA for owner, admins and moderators;
  secure mode (`AUTHORIZED_FETCH`); no Sidekiq web UI; secrets made once
  on `/data`, 0600, unless the config brings them.
- No `allow: jit`, so MDWE holds: Node runs `--jitless`, Ruby without
  YJIT; whether YJIT is worth `jit` is measured and recorded here.
- Puma workers from the CPUs, `MAX_THREADS` and Sidekiq's concurrency
  matched to the database pool; libvips, not ImageMagick; assets
  precompiled at build; jemalloc, as Mastodon ships. Media in
  `/data/svc/mastodon/system`, shared by group, served with `sendfile`.
- rack-attack as shipped, and nginx `limit_req` on sign-in, sign-up and
  the API's writes. Remote media kept 7 days, preview cards 14.

## Drawbacks

- Six users and a launcher are more moving parts than one container.
- Without YJIT or V8's JIT, the web serves fewer requests a core.
- Until Wolfi takes the recipe, every release is werewolf's to rebuild.

## Alternatives Considered

- **One user for all of Mastodon**, as most installs run: a bug in the
  media path would hold the database, the network and every secret.
- **Mastodon's own container image**: Debian, a shell, ImageMagick, and
  all of Mastodon as one user.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| RCE in media parsing | ffmpeg on a narrower leash: no network, no sockets, one temp directory; libvips, not ImageMagick |
| SSRF through previews or fetches | fence's `public`, below Mastodon's own filter |
| RCE in web or jobs | own user, Landlock, no `exec` (web), read-only root, no shell; reboot heals |
| Takeover of the first account | the owner from the config before the site serves |

## Reliability Considerations

- PostgreSQL and media on `/data` survive a power cut.
- Each part restarts alone; a crashing streaming server leaves the web up.
