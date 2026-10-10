# Bugsink

The `bugsink` form is error tracking: [Bugsink](https://www.bugsink.com)
2, which takes the events of Sentry's SDKs, with Caddy in front serving
HTTPS for your domain with a certificate from Let's Encrypt, each part
on a leash of its own ([design/startup.md](../../docs/design/startup.md)).

| | |
| --- | --- |
| Listens | tcp/80 and tcp/443, Caddy's; Bugsink on loopback alone |
| Sends | alert webhooks, to public addresses on 443; Caddy's ACME requests |
| Runs as | `_oci-bugsink` in Bugsink's own image, and `caddy`, each leashed |
| Keeps | its SQLite database in `/data/svc/bugsink` |
| Config | `bugsink/secret-key`; `bugsink/admin`, `EMAIL:PASSWORD`; `bugsink/base-url`, the URL its links and DSNs use; setting `domain` (required), Caddy's site |

## Run your own

You need a domain name you can point at the machine.

```sh
mkdir -p config/bugsink
openssl rand -hex 32 >config/bugsink/secret-key                  # keep it
printf '%s' alice@example.com:"$(openssl rand -base64 18)" >config/bugsink/admin
printf '%s' https://errors.example.com >config/bugsink/base-url
howl create errors --with bugsink --on gcp --allow-from 0.0.0.0/0 \
	--config config --domain errors.example.com
```

Point `errors.example.com` at the address howl prints, sign in as
`alice@example.com` with the password in `admin`, make a team and a
project, and give its DSN to your application's Sentry SDK. The name is
given twice, as Caddy's domain and in Bugsink's `base-url`, since a
service in an image takes files, not settings.

## Defaults

- **Claimed before it serves.** The secret key, the administrator and
  the URL come from the config, and Bugsink parks without any of them,
  naming the file: no key is generated, and no visitor claims a fresh
  machine. The administrator is made once; change its password in
  Bugsink.
- **Nobody signs up.** An administrator adds users and teams; signing up
  is a 404, and Django's admin is off.
- **Events by key alone.** A project takes only events carrying its own
  key, as its DSN gives it; others are refused with 403.
- **Behind Caddy.** Bugsink listens on loopback, sets secure cookies, and
  takes the client's address from the `X-Real-IP` Caddy sets, replacing
  any a client sent.
- **Quiet.** Nothing sent home (`PHONEHOME=false`), no version shown, and
  no mail unless you add `EMAIL_*` lines; fence lets it reach public
  addresses on 443 alone, for webhooks to Slack, Mattermost or Discord,
  which Bugsink itself refuses to send to private addresses.
- **Bugsink's own image**, its 2.x release pinned by digest at each
  build, run in a tree of its own ([oci.md](../../docs/design/oci.md)).
  Its command is `monofy`, Bugsink's supervisor, which runs gunicorn and
  snappea, the task runner that digests events, as the image does; leash
  runs the image's checks, migrations and administrator first, and lets
  the service run only the image's `python3.12`.

## How the parts are held

| Part | Runs as | Reaches |
| --- | --- | --- |
| Caddy | `caddy` | :80 and :443; Bugsink on loopback; the ACME CA |
| Bugsink | `_oci-bugsink` | public addresses on 443; a resolver |

gunicorn hands events to snappea through a queue in the service's
`/tmp`, which is `/run/svc/bugsink`: events taken but not yet digested
are lost on a reboot, as in Bugsink's own image.

## Drawbacks

- Its image is Debian's Python, with its userland: leash lets nothing
  but `python3.12` run, but posture sees an interpreter, a weakness this
  form names.
- SQLite: one machine, as Bugsink recommends below a few million events
  a day.
- No mail: invitations and alerts by mail need `EMAIL_HOST` and its
  friends, and a `connect` line for the relay's port.

## Checked

`make check-bugsink` boots it with its test config ([test/config](test/config)),
domain `localhost`, for which Caddy's own CA signs: Bugsink answers its
readiness check through Caddy over HTTPS, gunicorn and snappea as
`_oci-bugsink` with no capability; plain HTTP is sent to HTTPS; a stranger is sent to the login
page, and signing up and Django's admin are 404s; a wrong password gets
no session and the administrator's gets a secure one; the administrator
makes a team and a project; an event with a forged key is refused and
not kept, while one with the project's key is stored and digested into
its issues; the database is on `/data`; and fence holds it to 443.
`make check-shellfree-bugsink` boots it as it ships, with no config:
Bugsink parks, saying it has no secret key, and Caddy, saying it has no
domain.
