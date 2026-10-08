# A catalog of forms: the top 25 uses of a locked-down VM

Proposed, 2026-10-07. Follows [service-forms.md](service-forms.md), whose
order 1 and 2 are built, and whose `prune` and `answering` work this
plan builds on.

## Summary

Twenty-five things people stand a Linux VM up for, each as a form that is
one Wolfi package (or one vendored application on a runtime form) run by
leash as its own user, with the most secure defaults that leave the thing
usable, and a check that tries the attack those defaults are for. Half
are run *for people* (a Mastodon, a Minecraft server, a password manager);
half *for machines* (DNS, NTP, metrics). The first half needs two things
the base lacks, bundles and a Ruby runtime, so they come first.

## Background

A werewolf form is an apko config plus files, built into a verified
read-only image, its service leashed: own user, Landlock to its own
directories and declared ports, a seccomp pledge, a cgroup, fence's
network policy, posture at every boot ([forms.md](../forms.md)). Nine
service forms exist. The rest of what people run is applications for
other people, which is where the self-hosting demand is and where a
machine that cannot be taken over matters most: a fediverse server
federates with strangers all day; a game server takes packets from
whoever finds the port.

What Wolfi ships decides the cheap half: a closure with no shell or
interpreter is a form in an afternoon. Checked on 2026-10-07: cloudflared,
sftpgo, oauth2-proxy, chrony, nats-server, mosquitto, minio, zot, gitea,
prometheus, loki, gatus, ollama, nsd, coredns, meilisearch, clickhouse and
memcached are clean; haproxy, unbound, grafana, mattermost and teleport
bring bash for a script nobody runs (`prune`); mariadb and postfix bring
perl; Mastodon, Vaultwarden, Immich, Miniflux, Matrix and Syncthing are not
in Wolfi at all, and come as vendored applications on a runtime form, as
WordPress's SQLite plugin does.

## Goals

- Every form here boots under `make check` with its own `forms/FORM/test/checks`
  that includes the attack its defaults refuse, a `forms/FORM/test/config` that
  gives it what an operator would, and a shell-free boot where its config
  allows one.
- No form waits for its first visitor to claim it, serves a control
  interface on the network, or starts a program it did not declare.
- Each form's own ceiling (memory, connections, pool) sits under its
  leash's, so it refuses work rather than being killed for it.
- Each form lands with the base improvement it exposed, listed in "What
  they teach the base", so the next form is cheaper.

## Non-Goals

- Kubernetes nodes, CI runners, dev boxes: machines whose job is to run
  arbitrary code. `qemu-host` and `prod-ssh` are as far as werewolf goes.
- Nextcloud, Immich, Matrix (Synapse): three or four daemons in two
  languages each, after Mastodon has shown what a bundle costs.
- Packaging what Wolfi lacks for Wolfi. A vendored application is pinned
  by the form, updated by a new image.

## Detailed design

### The 25

| # | Use | Form | On | State |
| --- | --- | --- | --- | --- |
| 1 | website, blog | `nginx`, `wordpress` | `prod`, `php` | built |
| 2 | fediverse server | `mastodon` | `ruby` + bundle | needs bundles, `ruby` |
| 3 | game server | `minecraft` | `jre` | needs `cpu`, large `memory` |
| 4 | team chat | `mattermost` | `prod` + bundle | needs bundles, `prune` |
| 5 | password manager | `vaultwarden` | `prod` | vendored (Rust) |
| 6 | media server | `jellyfin` | `prod` | .NET by design; first-run wizard |
| 7 | files: SFTP, sync | `sftpgo` | `prod` | clean |
| 8 | notes, wiki, docs | a static site on `nginx`; `outline` later | `prod` | built |
| 9 | news, RSS | `miniflux` | `go` + bundle | vendored (Go), postgres |
| 10 | home automation broker | `mosquitto` | `prod` | clean |
| 11 | AI inference | `ollama` | `prod` | clean, no auth of its own |
| 12 | git hosting | `gitea` | `prod` | clean; the first `exec` form |
| 13 | TLS edge, reverse proxy | `caddy` | `prod` | built |
| 14 | SSH bastion | `bastion` | `prod` | built |
| 15 | VPN | `tailscale`; `wireguard` | `prod` | built; `forward`, UDP |
| 16 | ingress with no open port | `cloudflared` | `prod` | clean |
| 17 | login in front of anything | `oauth2-proxy` | `prod` | clean |
| 18 | DNS resolver | `unbound` | `prod` | `prune`, UDP |
| 19 | time | `chrony` | `prod` | `settime` |
| 20 | SQL | `postgresql`; `mariadb` | `prod` | built; `prune`, `mariadb-init` |
| 21 | cache, queue | `valkey` | `prod` | built |
| 22 | object storage, backups | `minio` | `prod` | clean |
| 23 | secrets, PKI | `openbao`, `step-ca` | `prod` | built |
| 24 | metrics, logs, uptime | `prometheus`, `loki`, `gatus` | `prod` | clean |
| 25 | message bus | `nats` | `prod` | clean |

Also fits, cheaply, when someone asks: `nsd`, `coredns`, `dnsmasq`
(needs raw sockets), `zot`, `meilisearch`, `clickhouse`, `memcached`,
`syslog-ng`, `haproxy`, `grafana`, `teleport`, `k3s` (no: busybox).

### Defaults, for every form

As [service-forms.md](service-forms.md) has them: no unclaimed first
boot; a missing secret parks the service with one line; state wants a
disk; no control interface on the network; no `exec` unless the form
names what runs; its own limit under the leash's; modern TLS; security
events on the console; a check with an attack in it. Two more from this
year's forms:

- **Performance is a default too.** Worker counts from the CPUs it has,
  pools sized to its `memory`, the opcode or query cache on, timeouts
  that end idle clients without cutting off uploads, `sendfile` and HTTP/2
  where the daemon offers them. A locked-down machine that is slow gets
  replaced by one that is not.
- **TLS in front, once.** Forms that speak HTTP serve plain HTTP on a
  high port and expect `caddy` (or the cloud's balancer) in front, which
  says so in `X-Forwarded-Proto`. Forms that are the edge (`caddy`,
  `mosquitto`, `minio`, `nats`) take a certificate from the config, or
  from `step-ca`, and never make their own.

### What they teach the base

Each form below names what it needs; gathered here, in the order they
unblock the most:

1. **Bundles.** A chain of bases is linear; Mastodon is a runtime plus
   PostgreSQL plus Valkey plus nginx. A form gains `with:` beside
   `base:`, naming forms whose folders, services, policies and modules
   merge after the chain, in order, each once; apko gets their packages.
   The Makefile's `CHAIN` becomes a list the yaml walks, and a bundle's
   users and ports must not collide, which the build checks. Unblocks 2,
   4, 9, and every "app with a database" a user writes.
2. **A `ruby` runtime form**, as `node` and `python` are: Ruby 3.4 and
   `bundler`, an `app` user, gems vendored into the image at build by the
   host (as the Go and Rust examples compile on the host). Unblocks 2.
3. **`listen udp`** in fence and the checks, and a `dgram` note in
   leash: Landlock cannot bind UDP, so the policy's rules are the whole of
   it. Unblocks 15, 18, 19, and syslog.
4. **Capabilities a service keeps.** leash grants `CAP_NET_BIND_SERVICE`
   alone. `capability time` (chrony), `capability net-raw` (dnsmasq's DHCP)
   name one more, each an allowance the form must also carry, so a service
   file alone cannot take it. Unblocks 19.
5. **A clock for every machine.** werewolf syncs no clock: TLS, update
   signatures and OpenBao's leases trust the RTC. `prod` gets a small
   Zig SNTP client, run by init before fence as `_clock` with
   `CAP_SYS_TIME`, stepping once at boot and slewing every hour, servers
   from the config or the cloud's. Chrony's form is then the *server*.
6. **`cpu` beside `memory`** in service files: `cpu.max` or `cpu.weight`
   in the service's cgroup, so a Minecraft server on the same machine as
   its map site cannot starve it. Unblocks 3.
7. **`prune` of a tree** (`usr/src/wordpress/.git`, 58 MB), with the
   updater's `Root.remove` deleting a directory. Shrinks 1 and 4.
8. **`exec` with a `run` list, the discipline**: gitea runs `git`, git
   runs hooks through `sh`. The form names `git` and nothing else, hooks
   are off in gitea's config, and the check plants a hook and sees it
   refused. Unblocks 12 and documents the pattern.
9. **`render json` into a list**, for Prometheus's `file_sd` (a list of
   target groups): `render json FILE as list` wraps the object. Unblocks
   24's targets as settings.
10. **A first-run step through the daemon's own API**: Jellyfin and
    Mattermost have no CLI to make the first admin, only a wizard the
    first visitor completes. A `before` program (Zig, `first-run`) posts
    the config's values to the API on loopback before the port opens to
    the network. Unblocks 4 and 6, and any app with a wizard.
11. **Newlines in config files.** OpenBao's and WordPress's password files
    must have no trailing newline, which `echo` adds. `config NAME PATH
    oneline` strips it, as `secret` already does.
12. **A stand-in for what cannot be redistributed**: Minecraft's jar is
    Mojang's. `forms/minecraft/test/config` uses `$MINECRAFT_JAR` when given and
    a stand-in jar (the `jre` form's server) otherwise, saying which; CI
    runs the stand-in, a release runs both.

### The forms

Each: what runs and as whom; what it listens on and sends; where its
state lives; the defaults; the attack its check tries; what it teaches.

#### mastodon (2)

Ruby 3.4 on the `ruby` form, `with: [postgresql, valkey, nginx]`. Four
services: `web` (Puma, :3000 on loopback), `streaming` (Node 22, :4000
on loopback), `sidekiq`, and nginx on :80 in front, with `caddy` or the
balancer for TLS. Assets precompiled at image build on the host; media on
`/data/svc/mastodon`, the database in `postgresql`, queues in `valkey`.

- Sends tcp/443 and DNS (federation, link previews, media fetches) and
  tcp/587 (mail). Nothing else leaves.
- `LOCAL_DOMAIN` a required setting; `SECRET_KEY_BASE`, `OTP_SECRET`, the
  VAPID pair and the Active Record encryption keys made once on `/data`
  unless the config brings them. The first admin (`tootctl accounts
  create --role Owner`) from the config before Puma serves: no open
  registration to claim it.
- Registrations closed (`approval` mode), `AUTHORIZED_FETCH=true` (secure
  mode: signed fetches only), no Elasticsearch, `MAX_THREADS` and
  `WEB_CONCURRENCY` from the CPUs, `SIDEKIQ_CONCURRENCY` sized to the
  database pool, nginx rate limits on `/api/v1/accounts` and the login,
  media served by nginx with `sendfile`, 7-day media retention of remote
  media (`tootctl media remove` as a timed service).
- Attack: register an account unapproved; fetch a status without a
  signature; a sidekiq job that reaches tcp/80 (refused by fence).
- Teaches: bundles, the `ruby` form, timed services (a `every` line, as
  the demo's scan has), image size (ImageMagick vs libvips).

#### minecraft (3)

Java 21 on `jre`, the server jar as the application (`--app`, or a form
of your own with the jar). Paper or vanilla, the operator's choice and
EULA.

- Listens tcp/25565; sends tcp/443 and DNS (Mojang's session servers,
  which `online-mode=true` needs). No UDP: `enable-query=false`,
  `enable-rcon=false`.
- `server.properties` in the image, the world in `/data/svc/app` (leash's
  working directory): `white-list=true`, `enforce-whitelist=true`,
  `online-mode=true`, `spawn-protection`, `max-players`, `view-distance`
  10, `simulation-distance` 8, `network-compression-threshold` 256;
  `whitelist.json` and `ops.json` from the config.
- JVM: `-Xms`=`-Xmx` at 75% of `memory`, G1 with Aikar's flags,
  `-XX:+AlwaysPreTouch`, `-Djava.io.tmpdir=/run/svc/app`. `memory 4096`,
  `cpu` weighted below the site beside it.
- Attack: a status ping answers; a join not on the whitelist is refused;
  :25575 (RCON) and udp/25565 (query) take nothing; a plugin that writes
  outside `/data/svc/app` fails.
- Teaches: `cpu`, the stand-in jar, worlds surviving a power cut (a timed
  `save-all` is not possible without RCON: the form keeps autosave and
  the check cuts power as `persist` does).

#### mattermost (4)

Go, `with: [postgresql]`. Listens :8065 behind `caddy`.

- Sends tcp/443 (push notifications, link previews) and tcp/587; DNS.
- `EnableOpenServer=false`, `EnableUserCreation` on invitation only, the
  first admin made by `mattermost user create --system-admin` from the
  config before it serves; plugins off (`PluginSettings.Enable=false`,
  uploads off: a plugin is code); `EnableDeveloper=false`; files on
  `/data/svc/mattermost`, 50 MB each; `SqlSettings.MaxOpenConns` under
  the database's.
- `prune` of the bash its package brings.
- Attack: sign up on the open form; upload a plugin; the API without a
  session.
- Teaches: `first-run` through the API (Mattermost's CLI needs the
  database, which is there; Jellyfin's does not).

#### vaultwarden (5)

Rust, vendored and built on the host (as the Rust example is), SQLite
on `/data`. Listens :80 behind `caddy`; `DOMAIN` an `https` URL, required.

- `SIGNUPS_ALLOWED=false`, `INVITATIONS_ALLOWED=true`, `ADMIN_TOKEN` an
  argon2 hash from the config (the admin page is off without one),
  `SHOW_PASSWORD_HINT=false`, `WEBSOCKET_ENABLED` on, `ROCKET_WORKERS`
  from the CPUs; mail by SMTP as WordPress sends it. Sends tcp/587, DNS,
  and tcp/443 only if a form enables icon fetching (`ICON_SERVICE`),
  which is off: icons are a request to every site a user saves.
- Attack: sign up; `/admin` without the token; an icon fetch leaving the
  machine (refused by fence).
- Teaches: a vendored Rust application's pin and update; `config ...
  oneline`.

#### jellyfin (6)

.NET 10, by design, as `jre` is Java. Listens :8096 behind `caddy`; media
read-only from `/data/svc/jellyfin/media`, its database beside it.

- No DLNA (udp/1900), no auto-discovery (udp/7359), no remote metadata
  until a form adds `connect jellyfin tcp/443`; hardware transcoding is a
  device, which no form carries: `ffmpeg` on CPU, limited by `cpu`.
- The startup wizard claims the server for its first visitor:
  `first-run` completes it from the config (admin, password, library
  paths) on loopback before the port opens.
- Attack: `/Startup/User` after first run; a path outside the library.
- Teaches: `first-run`; `programs-no-interpreters` has `dotnet` in it
  already, as the ASP.NET example found.

#### sftpgo (7)

Go. Listens tcp/2022 (SFTP; 22 is the bastion's), nothing else: the web
admin and REST API are off, users come from the config as a JSON import
(`sftpgo initprovider --loaddata`), keys only, each user chrooted to
`/data/svc/sftpgo/USER`.

- Attack: a password login; a path above the home; the web admin port.
- Teaches: nothing new; the first form after `prune` and the loopback
  rule with no base work at all. Three hours.

#### miniflux (9)

Go, vendored, `with: [postgresql]`. Listens :8080 behind `caddy`.

- `CREATE_ADMIN` from the config before it serves; `DISABLE_LOCAL_AUTH`
  off; polling frequency 60 min; sends tcp/443 and DNS to fetch feeds,
  and that is the one form whose *purpose* is to fetch from anywhere.
- Attack: registration (there is none); a feed URL on loopback (SSRF:
  refused by the application, and checked).
- Teaches: how much a fetching application needs: `connect tcp/443` is
  "any HTTPS server", which fence cannot narrow by destination
  ([fence.md](fence.md), Not covered). A destination allowlist in fence
  is the improvement, if it comes.

#### mosquitto (10)

C. Listens tcp/8883 (MQTT over TLS, certificate from the config or
`step-ca`) and tcp/9001 (WebSockets, TLS) if a form says; `1883` plain a
line away, for a LAN.

- `allow_anonymous false`, a password file from the config, ACLs from the
  config (`acl_file`), `persistence` on `/data/svc/mosquitto`,
  `max_connections` and `message_size_limit` set, `max_queued_messages`.
- Attack: anonymous connect; a wildcard subscribe the ACL denies.
- Teaches: nothing new.

#### ollama (11)

Go. Listens :11434 on every address, which is Ollama's API with no
authentication: the form says so, and `oauth2-proxy` or `tailscale` in
front is the way to serve it beyond the machine.

- Models in `/data/svc/ollama`, pulled from `registry.ollama.ai`
  (`connect ollama tcp/443` and DNS), `OLLAMA_ORIGINS` narrow,
  `OLLAMA_KEEP_ALIVE`, `memory` large and `cpu` honest; no GPU until a
  device allowance exists.
- Attack: `/api/pull` of a model from another registry (the API takes a
  name, the registry is fixed); `/api/push`.
- Teaches: a device allowance's shape, when it comes.

#### gitea (12)

Go. Listens tcp/3000 (web, behind `caddy`) and tcp/22 (its own SSH
server, Go; no sshd); `exec` with `run /usr/bin/git`.

- `INSTALL_LOCK=true` (no web installer), `DISABLE_REGISTRATION=true`, the
  admin from the config before it serves (`gitea admin user create`),
  `DISABLE_GIT_HOOKS=true` (a hook is a shell script: RCE for a repo
  admin), `DISABLE_WEBHOOKS` off but `ALLOWED_HOST_LIST` empty, LFS on
  `/data`, SQLite by default (`with: [postgresql]` for more), migrations
  from tcp/443 only if the form adds it.
- Attack: the installer; registration; a hook pushed and expected to run
  (refused: off, and `sh` is not there); a webhook to loopback.
- Teaches: the `exec` discipline; git's helpers (`git-core/*`) as `run`
  entries, and whether Landlock's per-file exec grants make that one
  line.

#### cloudflared (16)

Go. Listens on nothing. Sends udp/7844 (QUIC) and tcp/443 to Cloudflare,
and reaches the services it fronts on the machine or the network.

- The tunnel token from the config; ingress rules in the image
  (`config.yml`), `--no-autoupdate`, metrics on loopback only,
  `--protocol quic` with `http2` fallback.
- Attack: no port to attack; the check is that nothing listens and the
  tunnel registers (console line), offline otherwise.
- Teaches: `connect udp` works today; the first UDP-only client.

#### oauth2-proxy (17)

Go. Listens :4180 behind `caddy`, or :80 itself; upstream on loopback.

- OIDC provider, client id and secret from the config, cookie secret
  made once on `/data`, `--cookie-secure`, `--cookie-samesite=lax`,
  `--cookie-refresh`, `--skip-provider-button`, `--reverse-proxy`, allowed
  emails or groups as settings; sends tcp/443 and DNS to the provider.
- Attack: the upstream without a session (302); a forged cookie.
- Teaches: nothing new; pairs with ollama, loki, prometheus.

#### unbound (18), chrony (19), wireguard (15), mariadb (20)

As [service-forms.md](service-forms.md) has them, with: unbound's
`bash-binsh` pruned; chrony as a server with `capability time`, NTS to
upstream (`server time.cloudflare.com nts`), `allow` the LAN, `cmdport
0`, and the base's own clock (5) for every other form; wireguard last.

#### minio (22)

Go. Listens tcp/9000 (S3 API, TLS from the config or `step-ca`); the
console on :9001 only if a form says, else off.

- Root credentials from the config; a single drive at
  `/data/svc/minio`; `MINIO_BROWSER=off`; no anonymous policies; sends
  nothing (no KMS, no notifications) until a form adds them. It is the
  backup target for `restic` and `rclone` from the other machines.
- Attack: anonymous `ListBuckets`; the console port.
- Teaches: large `/data` throughput: `noatime` and the data filesystem's
  options are the base's to tune.

#### prometheus, loki, gatus (24)

Go, three services in one `observability` form, or three forms; one
form, since they are always together.

- Prometheus :9090 and Loki :3100 on loopback behind `oauth2-proxy` or on
  the LAN; `--web.enable-admin-api` off, remote-write receiver off, Loki
  `auth_enabled` on with one tenant, retention set; targets from
  settings through `file_sd` (9); gatus :8080 with its endpoints in the
  image's config and alerts' webhooks as settings.
- Attack: the admin API; a push to Loki without the tenant header.
- Teaches: `render json ... as list`; `node_exporter` is not in Wolfi, so
  a werewolf machine exports its own posture and boot times instead,
  which `status-page` already has the makings of.

#### nats (25)

Go. Listens tcp/4222 (TLS from the config), monitoring :8222 on loopback.

- Accounts and users as nkeys from the config, JetStream on
  `/data/svc/nats`, `max_payload` and `max_connections` set,
  `--no_advertise`; clustering adds tcp/6222 in a form of your own.
- Attack: connect without credentials; publish to another account's
  subject.
- Teaches: nothing new.

### Order

| | Forms | Waits on |
| --- | --- | --- |
| 1 | `sftpgo`, `cloudflared`, `oauth2-proxy`, `mosquitto`, `nats`, `minio`, `gatus` | nothing; one each. Built 2026-10-08 |
| 2 | `vaultwarden`, `ollama`, `gitea` | vendoring (5), `exec` discipline (8). Built 2026-10-08 |
| 3 | bundles (1), `ruby` (2), `cpu` (6), `first-run` (10) | the base work |
| 4 | `mastodon`, `minecraft`, `mattermost`, `miniflux`, `jellyfin` | 3 |
| 5 | `listen udp` (3), capabilities (4), the clock (5) | the base work |
| 6 | `unbound`, `chrony`, `prometheus`/`loki`, `mariadb`, `wireguard` | 5 |

Tier 1 was a day, not a week; each form there is `caddy`'s size. What
it taught, beyond the list above: a check that speaks the daemon's own
protocol wants the daemon's client, so form.yaml's `dev` names packages
for DEV=1 builds alone (`mosquitto-clients`, `nats`, `mc`); a daemon that
would reach the Internet and exit when refused (cloudflared) is checked
with no way out (form.yaml's `check: offline`); the shared HTTP check takes any status
line, since an S3 store says 403 and a login wall says 302; a service may
take 30 s to stop (cloudflared with no network), which the `reaped`
check now allows; `sftpgo` confirms Go's ssh takes a post-quantum-only
key exchange; nats resolves `include` against its config directory, so a
link in the image points at leash's copy; MinIO needs `netlink` to list
the host's addresses.

Tier 2 taught three more. An application Wolfi lacks is a melange
recipe in Wolfi's style (`forms/NAME/melange/`), built in Wolfi's
environment, unpacked over the image, and linked to the form's Wolfi
libraries so the updater keeps those current; the recipe is also the
pull request that retires it. On macOS melange runs in QEMU from
werewolf's own Alpine kernel. An
application that writes hooks as shell scripts (Gitea) gets a tiny Zig
program in their place (`gitea-hook`), named in git's `core.hooksPath`,
so the `exec` it needs is git, the hook and itself, and no shell. And a
daemon that calls its own API (Gitea's SSH server) needs `connect` to its
own port on loopback, which fence never lets in from outside. Tier 3 is
the real work and should start next.

### Testing

As the nine built forms are tested: `forms/FORM/test/config` writes what an
operator would (keys, a certificate, an admin's password), `make
check-FORM` boots it twice and runs `test/checks` plus `forms/FORM/test/checks`,
and the forms that boot without config boot shell-free too. Each form's
checks end with its attack. A bundle is checked as one machine. CI's
`forms` group grows by a boot a form, five minutes each here, under
`make -j`; arm64 keeps the `native` half for what a container can carry.
Vendored applications pin a version and a sha256 in the form, fetched by
the build host, never the machine; the lock's digest changes with them,
so CI rebuilds.

## Drawbacks

- Twenty-five forms is twenty-five service files to keep right as Wolfi
  moves. `make check` catches a form that breaks; nothing catches one that
  quietly loosens (a new default in the package). Posture and each
  form's attack check are the answer, and they cost a boot each.
- Vendored applications are code werewolf does not build from Wolfi:
  their updates are a new image, and their supply chain is the form's
  pin. The Go and Rust examples already took that position.
- Bundles make a form a graph. The build must refuse collisions (users,
  ports, service names), and `make list-forms` must show the merge.

## Alternatives Considered

### Containers on a host form
Run each application as an OCI image under a werewolf host. Every
container brings its own userland, shell and updater, which is what the
forms exist to remove; the leash does for one process tree what a
container does, with less.

### Only infrastructure forms
Leave applications to users' own forms on the runtime forms. The runtime
forms are there, but the defaults above (no unclaimed first boot, hooks
off, signups closed, secure mode) are what people get wrong, and a form
that has them is the point.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| An application fetches from anywhere (Mastodon, Miniflux, Ollama) | `connect tcp/443` alone; fence names ports, not hosts: a destination allowlist in fence is the open improvement |
| A first-run step that fails leaves a wizard open | the port opens only after `before` steps succeed; a failed one parks the service |
| A vendored application's upstream is compromised | pinned version and sha256 in the form; the build host checks; the image is signed |
| A bundle lets one service reach another's socket | each keeps its own user and directories; sharing is by group, declared, as `php` and `nginx` share one |
| Interpreters by design (Ruby, Java, .NET) | `programs-no-interpreters` fails on those forms and says so; the leash, not the absence of an interpreter, is the control |

## Reliability Considerations

- Every form's own limit sits under its leash's `memory`, and bundles
  sum theirs under the machine's: the build warns when they exceed it.
- State on `/data` survives a power cut (`persist` checks it for
  PostgreSQL; Minecraft's and Mastodon's media get the same boot).
- A form whose upstream service is away (the OIDC provider, Mojang's
  session servers, a mail relay) degrades to refusing logins or mail,
  never to crashing: each check cuts the network for one request.
