# A startup's machines: the top ten uses

Built, 2026-10-10. Each of the ten uses has a form, and so do team
chat and the company's own container images.

## Summary

The ten things a young company stands a VM or a rented machine up for,
beside its laptops and its SaaS: its product, its data, and the tools
its engineers would otherwise pay for per seat. Each gets a form, with
defaults no visitor can claim.

## Background

[forms-catalog.md](forms-catalog.md) chose forms for a machine serving
strangers; [self-hosting.md](self-hosting.md) for a household. A startup
is neither: a few engineers and many machines, each run by whoever
deployed it last. A forgotten admin page or an open registry is how
they are broken into; per-seat pricing is why they self-host at all.

A form need not wait for Wolfi. melange builds a package from a pinned
source (forms/miniflux), and `image:` runs a project's own OCI image,
pinned by digest, in a tree of its own ([oci.md](oci.md); forms/grafana).

## Goals

- Each use has a form or a bundle, passing `make check-NAME` and
  `check-shellfree-NAME`, its check ending in the attack its defaults
  refuse.
- One form of each shares a machine: no two take the same port.

## Non-Goals

- CI runners and Kubernetes nodes, which run anyone's code.
- Mail to customers: mox serves a company's own mail; bulk sending is
  a provider's.

## Detailed design

| Use | Forms | State |
| --- | --- | --- |
| The product: app, TLS, balancing | runtime forms, `caddy`, `nginx`, `haproxy` | built |
| Its database | `postgresql`, `mariadb-local`, `mariadb-tcp` | built |
| Cache, queues, jobs | `valkey`, `nats`, `cron` | built |
| Files and uploads | `minio` | built |
| Secrets and internal TLS | `openbao`, `step-ca` | built |
| Reaching private machines | `tailscale`, `bastion` | built; `wireguard` waits on its forwarding rules |
| Monitoring and status | `prometheus`, `loki`, `gatus`, `grafana` | built; grafana in self-hosting.md |
| Code | `gitea` | built |
| Single sign-on | `authelia` | built |
| Errors and analytics | `bugsink`, `umami` | built |
| Team chat | `mattermost` | built |
| The company's images | `zot` | built |

| Form | Built by | Defaults; its check's attack |
| --- | --- | --- |
| `authelia` with `caddy` | melange | users and every secret from the config, none generated; default policy deny; two factors (TOTP, WebAuthn); regulation bans repeated failures; a login with the password alone |
| `bugsink` with `caddy` | image | admin from the config, sign-up off; events taken by DSN alone; SQLite in its `/data`; the admin pages without a login |
| `umami` with `postgresql`, `caddy` | image | admin from the config, its default `admin`/`umami` refused; the tracker script and collector public, the rest behind a login; a stats query without one |
| `mattermost` with `postgresql`, `caddy` | image | admin from the config; open sign-up and plugin uploads off (a plugin is code); a plugin upload |
| `zot` with `caddy` | melange | users from the config as bcrypt htpasswd lines; no anonymous pull or push; a push without credentials |

**Each behind Caddy**: HTTPS at the machine's domain, a certificate from
Let's Encrypt, the application on loopback. `authelia` also guards the
others: Caddy's `forward_auth` sends a request it does not recognise
to Authelia's portal first, so an internal tool needs no login of its
own.

**Images are pinned and overridden.** An image's entrypoint is often a
shell script; the form runs the program itself (`exec:`), as grafana
does, and an image that needs its script fails the build.

## Drawbacks

- Images bring their own userland: Ubuntu's in Mattermost's, Python's
  in Bugsink's. leash holds each as `_oci-NAME`, but posture sees more
  programs, each a weakness its form names.
- A melange recipe is werewolf's to rebuild each release until Wolfi
  takes it.

## Alternatives Considered

**Keycloak** is what larger companies run for sign-on; [academic.md](academic.md)
carries it. Authelia is one Go program whose users fit a file in the
config, which suits a dozen engineers.
**GlitchTip and Sentry** speak the same SDKs as Bugsink but need Redis,
Celery workers and, for Sentry, Kafka and ClickHouse.
**Plausible** needs ClickHouse beside PostgreSQL; Umami needs neither.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| A first visitor claims the tool | its admin from the config, made before the port opens |
| A plugin or an image is code | plugins off by default; images pinned by digest and run under a leash |
| A collector takes anyone's events | Bugsink and Umami take what their DSN or site id names, behind Caddy's request limits |
| An internal tool is reached from the internet | `authelia` in front; or served to a tailnet alone |

## Reliability Considerations

- Error tracking and analytics take bursts of writes: each has its own
  `memory`, and a full queue refuses events rather than stopping.
- Sign-on is in every login's path: Authelia keeps its sessions in its
  own SQLite, so a reboot of another machine signs no one out.
