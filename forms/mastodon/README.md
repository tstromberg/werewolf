# Mastodon

The `mastodon` form is Mastodon 4.7 on `ruby`, with `postgresql`,
`valkey`, `nginx`, `cron` and `sh-shim` beside it, each part on a leash
of its own ([design/mastodon.md](../../docs/design/mastodon.md)).

| | |
| --- | --- |
| Listens | tcp/80, nginx; TLS ends in front of it (a load balancer, or a proxy of your own), which says so in `X-Forwarded-Proto`. Puma :3000 and the streaming server :4000 on loopback only |
| Sends | HTTPS and HTTP, federation and previews, and mail by submission (tcp/587), to public addresses only; DNS to the machine's resolver |
| Runs | the web, Puma, as `mastodon`; the streaming server, Node with no JIT, as `mastodon-stream`; the jobs, Sidekiq, as `mastodon-jobs`; cleanup, supercronic, as `mastodon-cron`; nginx, PostgreSQL and Valkey as their own |
| Keeps | in `/data/svc/mastodon`: the secrets (`env`, made once) and the media (`system/`); the database in PostgreSQL's, the queue in Valkey's |
| Config | `mastodon/owner-password`; settings `domain`, `owner` and `owner-email`, all required |

```sh
printf '%s' 'a long password for the owner' >config/mastodon/owner-password
build/host/howl pack --with mastodon -o config.tar --config config \
	--domain social.example.com --owner alice --owner-email alice@example.com
```

## Before it serves

The web's `before` lines run as `mastodon`, under its leash, at each
start. `secrets.rb` makes the secrets once, `SECRET_KEY_BASE`, the
encryption keys and a VAPID pair, into `/data/svc/mastodon/env`, 0640,
with the domain; Mastodon reads it as `.env.production`, a link in the
image. A start whose config names another domain is refused: the domain
is the server's identity on the network. `rails db:prepare` makes the
schema or migrates it. `owner.rb` grants the streaming server's role its
reads and, if the owner is missing, makes it from the config, confirmed
and approved, with the config's password, never printed. No one meets a
setup page.

## How the parts are held

- **One user each**, so a bug in one part holds only that part's files.
  The web's directories are `share group` (02771, with a default ACL):
  the jobs' and cron's users have its group and write the media and
  read the secrets there; nginx reads the media by name.
- **The database by role.** Each logs in by peer authentication as its
  user. `mastodon` owns the database; the jobs' and cron's roles are its
  members; `mastodon-stream` may only read. Valkey's socket is its
  group's, which Mastodon's four services join (`group valkey`).
- **Media parsed narrowed.** Paperclip runs `file`, `ffprobe` and
  `ffmpeg` through `/bin/sh`, which is `sh-shim`; each is the service's
  narrow link ([design/narrow.md](../../docs/design/narrow.md)): no
  network, its own pledge, the upload's directory alone.
- **Public addresses only.** fence keeps federation, previews and remote
  media off private, loopback, link-local and metadata addresses
  (`connect ... public`), below Mastodon's own filter.
- **No shell, no JIT where it can be helped.** Node runs `--jitless`,
  Ruby without YJIT. PostgreSQL's `allow: [jit]` turns MDWE off for the
  whole machine, a weakness this form names.

## Drawbacks

- In a DEV build `/bin/sh` is busybox's, which no leash lets run, so
  uploads and media processing fail there (cmd/sh-shim).
- No search and no object storage (design/mastodon.md's Non-Goals).

## Checked

`make check-mastodon` boots it with its test config
([test/config](test/config)): Mastodon answers `/health` through nginx,
for its domain, as behind TLS; the instance is the config's; the owner
exists; the streaming server answers; the secrets are 0640 and the
directory 02771. `make check-shellfree-mastodon` boots it as it ships,
with no config: no posture failure but those named; the streaming server
leashed and listening; the web parked, saying it has no owner, before it
makes or serves anything; nothing else down.
