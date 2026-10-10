# Forms

A form says what a werewolf machine is for. Each form is a directory,
`forms/<name>/`, that holds:

- `form.yaml`: the Wolfi packages and accounts apko installs, and what
  apko cannot say, from the form it is built on to its network policy and
  the posture checks it fails, and why;
- `rootfs/`: the files it lays over its packages;
- where it needs them, its own programs (`cmd/`), checks (`test/`), melange
  recipes (`melange/`) and a `README.md`.

A form gets the parts of the form it is built on, and of that form's base,
and adds its own. [forms/README.md](../forms/README.md) lists every file
and key, and `make list-forms` shows the chains.
[design/forms.md](design/forms.md) explains why there are so few forms.

## The forms

| Form | Built on | Is |
| --- | --- | --- |
| `minimal` | | boots anywhere, from the initramfs, its own disk or a slot bite installed; a static address; updates itself from a slot; listens on nothing |
| `prod` | `minimal` | the production base: DHCP, the cloud's metadata, `/data` on a disk, in LUKS2 when the config brings `data.key` ([data.md](data.md)); no shell, nothing listening. Build yours on this, or on a runtime form below |
| `app` | `prod` | where an application is laid; its service's `app` user gets a hashed uid; no runtime, service or listener |
| `nginx` | `prod` | serving a site from the image on :80 |
| `php` | `nginx` | with php-fpm running the site's `.php` files |
| `node`, `python`, `ruby`, `jre` | `app` | a runtime, for the service and application a form on it brings |
| `node-app`, `python-app`, `ruby-app` | `node`, `python`, `ruby` | a service for the application `--app` lays, on :8080; none shipped |
| `postgresql` | `prod` | PostgreSQL 17 on a UNIX socket ([postgresql.md](../forms/postgresql/README.md)) |
| `demo` | `postgresql` | nginx and the status page ([demo.md](../forms/demo/README.md)) |
| `prod-ssh` | `prod`, with `sshd` | sshd, for people who log in with a security key |
| `bastion` | `prod` | forwarding-only SSH, with explicit destinations ([bastion.md](../forms/bastion/README.md)) |
| `tailscale` | `prod` | userspace subnet routing ([tailscale.md](../forms/tailscale/README.md)) |
| `caddy` | `prod` | a web server that gets its own certificates ([caddy.md](../forms/caddy/README.md)) |
| `valkey` | `prod` | Valkey 9.1 on a UNIX socket, for the application beside it ([valkey.md](../forms/valkey/README.md)) |
| `openbao` | `prod` | OpenBao, unsealed by a key from the config and set up by itself ([openbao.md](../forms/openbao/README.md)) |
| `step-ca` | `prod` | an internal certificate authority, ACME for the names the config allows ([step-ca.md](../forms/step-ca/README.md)) |
| `wordpress` | `php` | WordPress on SQLite, installed from the config before it serves ([wordpress.md](../forms/wordpress/README.md)) |
| `gatus` | `prod` | a status page watching a service ([gatus.md](../forms/gatus/README.md)) |
| `sftpgo` | `prod` | SFTP for the users the config names, nothing else ([sftpgo.md](../forms/sftpgo/README.md)) |
| `cloudflared` | `prod` | a Cloudflare Tunnel: hostnames served with no open port ([cloudflared.md](../forms/cloudflared/README.md)) |
| `oauth2-proxy` | `prod` | a login in front of anything, by an OIDC provider ([oauth2-proxy.md](../forms/oauth2-proxy/README.md)) |
| `mosquitto` | `prod` | an MQTT broker over TLS, users and ACLs from the config ([mosquitto.md](../forms/mosquitto/README.md)) |
| `nats` | `prod` | a NATS server over TLS, with JetStream on `/data` ([nats.md](../forms/nats/README.md)) |
| `minio` | `prod` | S3 object storage from `/data` ([minio.md](../forms/minio/README.md)) |
| `ollama` | `prod` | models served on the CPU, behind a login of your choosing ([ollama.md](../forms/ollama/README.md)) |
| `gitea` | `prod` | git hosting over its own SSH and the web, nothing run from a repository ([gitea.md](../forms/gitea/README.md)) |
| `vaultwarden` | `prod` | a Bitwarden-compatible password manager server, built here from a pinned release ([vaultwarden.md](../forms/vaultwarden/README.md)) |
| `sshd`, `qemu-host` | `minimal` | sshd with a shell, by security key, and its service, for any form to take `with`; and a host for virtual machines |
| `mastodon` | `ruby`, with `postgresql`, `valkey`, `caddy`, `cron`, `sh-shim` | Mastodon 4.7, each part on a leash and a user of its own, media parsed narrowed, fetches to public addresses only ([mastodon.md](../forms/mastodon/README.md)) |
| `mox` | `prod` | a domain's mail: SMTP, IMAP, submission, webmail and its own certificates, as its own user, never root, built here with one patch ([mox.md](../forms/mox/README.md)) |
| `haproxy` | `prod` | HAProxy 3.4 balancing HTTP over the backends its settings name, HTTPS with a certificate from the config, nothing to control it by but its configuration ([haproxy.md](../forms/haproxy/README.md)) |
| `miniflux` | `prod`, with `postgresql`, `caddy` | a feed reader fetching from public addresses alone, its administrator from the config, built here ([miniflux.md](../forms/miniflux/README.md)) |
| `cron` | `prod` | supercronic, running a form's jobs on a schedule through sh-shim, leashed, for any form to take `with` ([cron.md](../forms/cron/README.md)) |
| `sh-shim` | `minimal` | `/bin/sh` as one program and its words, for any form to take `with` whose programs run `sh -c` ([sh-shim](../cmd/sh-shim/README.md)) |
| `playground` | `prod`, with `sshd` | `howl run`'s form on every engine: Lima manages it, and it takes key files, Lima's and `~/.ssh`'s, beside security keys |

Every form boots the same way. stage0 opens the form's `root.erofs`
read-only, through dm-verity, and hands over to init
([design/verified-boot.md](design/verified-boot.md)). CI publishes
`minimal`, `prod` and `prod-ssh` as signed releases
([releases.md](releases.md)).

Any form also builds with `DEV=1`, which adds busybox and the debug shell
on the console, so you can find out why something does not work. What
ships is built without it.

## The runtime forms

`prod` has no `app` user or group, and neither has its descendant `app`,
which adds only where an application is laid: no packages, service or
listening port. The `node`, `python`, `ruby` and `jre` forms, and the Go,
Rust and ASP.NET Core examples, build on it, and a service's `user app`
gets the account from the build: uid and gid its name's hash, home
`/var/empty` and shell `/sbin/nologin` (forms/README.md). PHP and nginx
keep separate service accounts, because they run separate services in
the same VM.

`nginx`, `php`, `node`, `python`, `ruby` and `jre` are each `prod` plus
one runtime from Wolfi, as Chainguard's images are, and no application.
`nginx` and `php` serve the site laid in their html root. The others start
nothing until a form on them brings a service. `node-app`, `python-app` and
`ruby-app` bring one for the application laid in `/usr/lib/app`, and ship
no application: until yours is there, the service stays down and says why
on the console.

| Form | Runs | As | On | Yours goes in |
| --- | --- | --- | --- | --- |
| `nginx` | nginx (`etc/sv/nginx`) | `nginx` | :80 | `/usr/share/nginx/html`, and `etc/nginx/nginx.conf` |
| `php` | nginx, and php-fpm (`etc/sv/php-fpm`) on a socket only nginx may use | `nginx`, `php` | :80 | `/usr/share/nginx/html` |
| `node-app` | `node /usr/lib/app/server.js` (`etc/sv/app`) | `app` | :8080 | `/usr/lib/app` |
| `python-app` | `python3 /usr/lib/app/main.py` (`etc/sv/app`) | `app` | :8080 | `/usr/lib/app` |
| `ruby-app` | `ruby /usr/lib/app/main.rb` (`etc/sv/app`) | `app` | :8080 | `/usr/lib/app` |
| `jre` | your jar, as your service file says ([below](#ship-it)) | `app` | yours | `/usr/lib/app`, and `etc/sv/app/service` |

`node-example`, `python-example` and `ruby-example` are those `-app` forms
with a sample application, and `jre-example` is `jre` serving a page with
the JDK's own web server. Each is a tutorial
([examples/README.md](../examples/README.md)).

Every one of those programs runs on a leash ([programs.md](programs.md)).
It runs as its own user, with no capability except binding a port below
1024 where it serves one. It may bind its own port and no other, read the
image, and write only `/run/svc/NAME` and `/data/svc/NAME`. The machine
around it is `prod`'s: the root is read-only and verified, there is no
shell or package manager, nothing the form did not declare leaves the
machine, and posture reports all this at every boot.

An interpreter is the point of these forms. So posture's
`programs-no-interpreters` check fails on `php`, `node`, `python`, `ruby`
and `jre`, and every form on them, by design, as `kernel-no-hypervisor`
does on `qemu-host`. Each of these forms says so in its form.yaml, with its
excuse:

```yaml
weaknesses:
  programs-no-interpreters: php-fpm runs the application, which is what this form is for
```

`nginx` declares no weaknesses. `make check` fails a machine on any posture
failure its form does not excuse, and on any excused failure that passes.

## Files a form leaves out

Sometimes a package declares a dependency that nothing on the machine runs.
Wolfi's `valkey-9.1` brings bash, because the `posix-libc-utils` package it
names ships `ldd` as a bash script. apk installs whatever a package
declares, so form.yaml's `prune` names the files to leave out, by their
paths in the image:

```yaml
prune:
  - usr/bin/bash
```

The build makes the root without these files, and the image records them
in `/usr/share/werewolf/prune`. The updater removes them from every slot it
builds, so a slot built on the machine holds what the build's slot held.
apk's database and a release's manifest still list the package as
installed; posture reports what the image holds. Use `prune` for a file a
dependency drags in, never to trim a package the form uses.

## Bundles: one form taking several

A form is built on one other form. But a machine that runs an application
with its database is several forms side by side. So a form may take other
forms `with` it, and gets their parts too: their packages and accounts,
services, policies, modules and pruning.

```yaml
# forms/mastodon/form.yaml
base: ruby
with: [postgresql, valkey, nginx]
```

The build puts each member's forms that the form's own chain lacks before
the form itself, in order. So the form's own files win where two forms lay
the same path. The build merges their apko configs in the same order. Two
users or groups with the same name or id fail the build. `make list-forms`
and `howl pack` follow the same chain.

## Packages Wolfi does not ship

When Wolfi does not package a form's application, the form keeps a melange
recipe for it in `forms/<name>/melange/`, written in Wolfi's style. For
example, `vaultwarden` has `forms/vaultwarden/melange/vaultwarden.yaml`.
howl's build runs melange in Wolfi's environment, which checks each source
by sha256 ([melange.zig](../cmd/howl/melange.zig)). It unpacks the packages
over the image, and fails if they link a library that is not one of the
form's packages. That way Wolfi's fixes to those libraries reach the
machine through its updater. `build/vendor` keeps the packages until the
recipe, or under QEMU the kernel, changes. While you write a recipe,
`howl build-apk RECIPE` builds it alone and reports what each package links. On macOS melange runs in QEMU,
booted from werewolf's own Alpine kernel, with half the host's CPUs and
8 GiB (`MELANGE_CPU` and `MELANGE_MEMORY` change them); on Linux it runs in
bubblewrap. A recipe Wolfi would accept doubles as the pull request to
wolfi-dev/os that retires it. A recipe Wolfi will not take stays with its
form.

## Private configuration files

Use `config NAME PATH` in a service file to give that service one file:

```text
config users /run/config/nats/users.conf
```

For service `nats`, this creates `/run/svc/nats/users`, owned by the
service's user, with mode `0600`. Point the program's configuration at that
copy. The service cannot read the rest of `/run/config`. NAME matches
`[a-z][a-z0-9-]*`, as a setting's name does, because `howl pack` takes it
as `--NAME FILE`. Name the file in the tar NAME too, such as
`admin-password` from `/run/config/FORM/admin-password`, or name it by its
format where the format has a usual name (`tls.crt`, `users.json`). Never
use `_` in the name.

Sources must be beneath `/run/config`, and destinations are plain names,
not paths. A service may name up to 32 files, each at most 64 KiB. A
missing or unreadable file keeps the service down, unless the line ends in
`optional`. Then a missing file leaves no copy, and the service runs
without it (for example, a mail relay's password on a machine that sends
no mail). Contents are copied unchanged, never logged, and refreshed on
each start, before any `before` command. Leash reads them as root, but
writes the copies only after it drops privileges and enters Landlock. It
replaces existing destination links rather than following them.

Put credentials in the boot config, not the image; see
[cloud.md](cloud.md). These runtime copies disappear at reboot. For a value
needed in an environment variable, use `secret NAME PATH` instead, ending
in `optional` if the service runs without it. howl takes each as a file
flag named for its variable: `secret SMTP_PASSWORD PATH` is
`--smtp-password FILE`.

## Settings

*Settings* are values that differ per machine but are not secret, such as
a router's routes or an application's database URL. A service file
declares each one with a type, and says where the values go:

```text
config  settings /run/config/tailscale/settings.json
setting routes cidr... as advertiseRoutes
render  json config.json from /etc/tailscale/config.json
```

The `config settings` line names the file in the boot config that gives
the values. That file may be missing.

```json
{"routes": ["10.20.0.0/24"]}
```

`setting NAME TYPE[...] [required] [as KEY]` declares one, up to 32 in a
service. NAME, `[a-z][a-z0-9-]*` and at most 32 bytes, is its key in
settings.json and the flag `--NAME` of `howl pack`. KEY names it in the
output: the directive, JSON key or variable. Without `as`, KEY is NAME, or
for `env` NAME in upper case with `-` as `_` (`database-url` is
`DATABASE_URL`).

| Type | Accepts | For example |
| --- | --- | --- |
| `ip` | a literal IPv4 or IPv6 address, without a zone | `10.0.0.1` |
| `cidr` | a network with no host bits set, never `/0` | `10.20.0.0/24` |
| `addrport` | a literal address and port | `10.20.0.10:22`, `[fd00::1]:22` |
| `hostport` | a hostname or literal address, and port | `db.internal:5432` |
| `hostname` | RFC 1123, at most 253 bytes, no trailing dot | `bao.example.com` |
| `port` | a JSON number from 1 to 65535 | `8200` |
| `url` | `http` or `https`, no user or password, at most 2 KiB | `https://bao.example.com:8200` |
| `int` | a signed 64-bit JSON number | `4` |
| `bool` | JSON `true` or `false` | `true` |
| `string` | UTF-8 without control characters, at most 1 KiB | `Engineering` |

A list (`TYPE...`) holds up to 32 values; an `int` or `bool` cannot be one.

At each start, leash copies the file into the service's directory and runs
`service-config` as the service. service-config checks every value against
its declared type and writes `/run/svc/SERVICE/FILE`, from the service's
one `render FORMAT FILE` line, in one of three formats:

- `env`: `KEY=VALUE` lines, a list joined by commas, which leash adds to
  the service's environment. It refuses a list of `string` or `url`, whose
  values may hold a comma, and `PATH`, `LD_*`, or a key that is also an
  `env` or `secret` line;
- `json`: one JSON object. `from PATH` merges it into a file from the
  image, which leash lets service-config read without a `read` line, and a
  key with dots, such as `authority.policy.x509.allow.dns`, fills a key
  the daemon nests;
- `conf`: `KEY VALUE...` lines, a list joined by spaces, a `bool` as `yes`
  or `no`. It refuses `string` and `url`, since a space or `#` would end
  the value. Where the daemon includes the file decides whether a setting
  overrides the image's value.

A form whose service file declares a refused pair does not build. A
setting that is not given, or an empty list, is left out, so the default
in the daemon's own configuration holds. `required` keeps the service down
instead. A key in settings.json that the service does not declare, or a
value not of its type, keeps the service down, with one line naming the
setting and why. Settings cannot add a directive: a value only fills a key
the image declared. See [design/settings.md](design/settings.md).

## Your application

For complete, runnable tutorials, each run here and on GCP with howl, see
[the language examples](../examples/README.md):
[PHP](../examples/php/README.md), [Python](../examples/python/README.md),
[Node.js](../examples/nodejs/README.md), [Go](../examples/go/README.md),
[Rust](../examples/rust/README.md) and [ASP.NET Core](../examples/aspnet/README.md).
Each explains declarative configuration, and what automatic updates do,
including their limits for application code.

An application is built into the image, as Chainguard's are with apko. The
machine does not fetch it. A form of your own is built on a runtime form,
names the Wolfi packages it needs, and carries the application's files. So
the code is in the verified, read-only root, and is built, signed, updated
and rolled back with the rest. Nothing writable ever runs. What the
application keeps is data, in its working directory, `/data/svc/app`.

### Without a form: `--app`

When a form already starts the application the right way, as
`python-app`, `node-app` and `ruby-app` do, the application's files are all
a machine needs.
`--app DIR` lays a directory where the form keeps its application
(form.yaml's `app`): `/usr/lib/app` for the forms on `app`, and nginx's
html root for `nginx` and `php`.

```sh
build/host/howl create web --with python-app --app ./myapp     # ./myapp/main.py, on :8080
build/host/howl build --with python-app --app ./myapp          # the release files, for elsewhere
```

DIR is what the application's own toolchain made (`go build`, `dotnet
publish`, `mvn package`, a checkout). It may hold only regular files and
directories. Executable bits are kept, and it may hold no setuid files and
no links.
werewolf prints DIR's sha256, over every path, executable bit and byte, so
the same DIR makes the same image. An image with an application builds
apart from the form's own image, and a new application means a new
machine: `howl delete`, then `create`. [apps-by-hand.md](apps-by-hand.md)
does all of this with `make disk` and `tar`, to show the mechanism underneath.

What the application needs from each machine, such as a database's address
or a greeting, is a setting. Its form declares it, so a form of your own
declares it. `python-example` takes `--greeting TEXT` and hands it
to the application as `GREETING` (`render env`, [Settings](#settings)). A
secret is a file, given with `config` and read from `/run/svc/app`.

### A Python web server

`helloworld` is a Flask application, served by gunicorn on :8080, that
counts its visitors on `/data`. It takes two files.

The form names the form it is built on, and the packages it adds, by their
Wolfi names:

```yaml
# forms/helloworld/form.yaml
base: python
packages: [py3.13-flask, py3.13-gunicorn]
```

The application goes in `/usr/lib/app`, form.yaml's `app`:

```python
# forms/helloworld/rootfs/usr/lib/app/helloworld.py
import fcntl

from flask import Flask, jsonify

app = Flask(__name__)


@app.get("/")
def index():
    # The working directory is /data/svc/app. Two workers may count at
    # once: the lock keeps every visit.
    with open("visits", "a+") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        f.seek(0)
        n = int(f.read() or 0) + 1
        f.seek(0)
        f.truncate()
        f.write(str(n))
    return f"Hello from werewolf! You are visitor {n}.\n"


@app.get("/health")
def health():
    return jsonify(status="ok")
```

It starts differently from `python-app`'s `main.py`, so it builds on
`python` and says its own service, which the build writes as the service
file leash reads to start it ([cmd/leash/leash.zig](../cmd/leash/leash.zig)
lists every directive; a value is one line, a list one line each):

```yaml
# forms/helloworld/form.yaml
base: python
packages: [py3.13-flask, py3.13-gunicorn]
services:
  app:
    exec: /usr/bin/python3 -m gunicorn --bind 0.0.0.0:8080 --workers 2 --worker-tmp-dir /run/svc/app --no-control-socket --pythonpath /usr/lib/app --access-logfile - helloworld:app
    user: app
    pledge: stdio rpath wpath proc inet listen
    listen: [tcp/8080]
    env: [PYTHONDONTWRITEBYTECODE=1, PYTHONUNBUFFERED=1]
```

- `--worker-tmp-dir` is needed because the root is read-only, and the app
  user may write only its own directories, not `/tmp`.
- `--no-control-socket` is needed because runit already supervises
  gunicorn, and the control socket would go in the app user's home,
  `/var/empty`.
- `-m gunicorn` is needed because leash lets the service run only the
  program it names, `python3`.

Build it and boot it under QEMU, with a disk for `/data`:

```sh
build/host/howl create hello --with helloworld --on qemu
```

howl forwards the form's port from one on this host's loopback, 8080 if it
is free, and prints it. `howl console hello` shows the boot, posture's
line, and gunicorn's log. From another terminal:

```sh
$ curl http://127.0.0.1:8080/
Hello from werewolf! You are visitor 1.
$ curl http://127.0.0.1:8080/health
{"status":"ok"}
```

Run the same `howl create` again. The count goes on: under QEMU a second
create stops the machine and boots it again, keeping its `/data`,
`build/machines/hello/data.img`. `howl delete hello` removes the machine
and its `/data`.

To change the application, change its files and run the create again,
which rebuilds the image. A machine never changes in place.

### What the leash holds

The application can do what its service file and the form's `net` allow,
and nothing else. The kernel enforces each limit; nothing depends on the
program's cooperation:

| It tries | Without a line for it | The line |
| --- | --- | --- |
| to make a system call | refused as if the kernel had no such call (seccomp) | `pledge PROMISE...`: what classes of call it may make (`stdio rpath inet listen`), the OpenBSD-pledge words werewolf maps to calls ([design/pledge.md](design/pledge.md)) |
| to listen on another port | the bind fails (Landlock) | `listen tcp/PORT` in the service, and `listen tcp/PORT` in the form's `net` for fence |
| to reach another machine: a database, an API | the connect fails (Landlock), and fence drops the packet | `connect tcp/PORT` in the service, and `connect app tcp/PORT` in the form's `net` |
| to write outside `/data/svc/app` and `/run/svc/app` | refused; the root is read-only anyway | `write PATH` |
| to run another program: a shell, `curl` | refused (`pledge exec`, then Landlock); there is no shell in the image anyway | `run PROGRAM` |
| through a program it runs on a stranger's file (ffmpeg), taken over, to do all the service may | it may: the program holds the service's leash | `narrow PROGRAM pledge\|read\|write\|memory ...`, run by its link `/etc/sv/NAME/narrow/PROGRAM`: fewer promises, no network, fewer files ([design/narrow.md](design/narrow.md)) |
| to read a secret | it has none | `secret NAME PATH`: a variable read from a file in the config |
| to exhaust the machine's memory | capped where the service sets a cap | `memory MiB`: its cgroup's `memory.max`, a ceiling on resident memory (not address space), so it suits an interpreter, the JVM and V8 alike |
| to leave a process running after it is stopped | killed with the service | nothing to add: each leashed service is a cgroup, and its `finish` writes `cgroup.kill` on stop, restart and shutdown, so its whole tree, a detached backdoor included, goes with it |

Every service file states a `pledge`. A service whose file has none is
parked at boot, so a service always says what it does. `memfd`, `ipc`
(System V shared memory) and `watch` (inotify) are separate promises, off
unless a service asks for them. So an application that does not name them
cannot make an anonymous executable file, squat another service's IPC key,
or watch the machine's file activity.

The promises, which lib/seal.zig maps to system calls on both
architectures:

| Promise | Allows |
| --- | --- |
| `stdio` | what a program does with what it holds: reading and writing descriptors and sockets, memory, time, signals, waiting, polling, pipes, its own ids, `ioctl`, `prctl` |
| `rpath` | opening, reading and looking at files and directories |
| `wpath` | changing them without opening: creating, removing, renaming, linking, modes, owners, times, syncing |
| `watch` | inotify and fanotify, which Landlock does not mediate |
| `inet`, `unix`, `netlink`, `packet` | a socket of that family; `unix` makes socket pairs too |
| `connect`, `listen` | connecting a socket; binding, listening and accepting |
| `proc` | creating, waiting for and signalling processes and threads; sessions; scheduling |
| `exec` | running another program, one a `run` line names |
| `setuid`, `setgid`, `setgroups`, `caps`, `chroot` | changing user ids, group ids, groups, capabilities, the root directory |
| `mount`, `umount`, `namespace` | mounting (the new mount API and `pivot_root` too); unmounting; `unshare` and `setns` |
| `seccomp`, `landlock` | confining itself further |
| `memfd`, `ipc`, `mlock` | anonymous memory files; System V IPC; locking memory |
| `sendfile`, `splice` | `sendfile`, as nginx uses; `splice` and `tee`, which nothing here needs |
| `aio` | the old asynchronous I/O (`io_submit`), as nginx uses; never io_uring |
| `settime`, `hostname`, `syslog`, `reboot` | setting the clock; the host and domain names; reading the kernel's log; rebooting |

No promise brings `ptrace`, eBPF, perf, modules, `kexec`, io_uring,
`userfaultfd`, the kernel keyring, file handles or another process's
memory.

A service's `listen` and `connect` are its network policy, for leash and
for fence alike (`listen: [tcp/8080]`; `connect: [tcp/443 udp/53 tcp/53]`,
with `public` or `loopback` as a net line takes them). To serve on :8000
instead, change gunicorn's `--bind` and the service's `listen` to 8000.

### Ship it

| | |
| --- | --- |
| `howl build --with helloworld` | `dist/helloworld-ARCH-disk.qcow2`, a disk that boots it under UEFI, for a provider that takes one (`--format raw\|vhd\|vmdk`); `howl create NAME --with helloworld --on gcp\|aws\|azure` makes a cloud machine of it |
| `make FORM=helloworld bite-me` | run on a Debian, Ubuntu, Fedora or Rocky VM: installs it beside the distro ([bite.md](bite.md)) |
| `make FORM=helloworld image` | the kernel and initramfs, for QEMU, Firecracker or any host that boots them directly |

It updates itself, as every form does. The updater follows Wolfi's packages,
builds a new slot with your files carried forward, boots it once, and keeps
it only if it commits ([updater.md](updater.md)). posture runs at every
boot and reports what holds. On a Python machine, `programs-no-interpreters`
is the one check it fails. `python`'s form.yaml excuses it, but only for
`python` itself, because excuses are not inherited. So a form of your own
that `make check` boots names the weaknesses it has, as `python-example`
does.

A Node, Ruby or Java application works the same way, on `node`, `ruby` or
`jre`, with a service file of its own. A Java application is a jar and
this:

```
exec    /usr/bin/java -XX:-UsePerfData -Djava.io.tmpdir=/run/svc/app -jar /usr/lib/app/app.jar
user    app
pledge  stdio rpath wpath proc inet listen unix
listen  tcp/8080
```

The JVM's pledge is wider than a Python or Node server's. It keeps its own
temporary files (`wpath`, with `java.io.tmpdir` in its `/run`, since the
service may not write `/tmp`). It spawns its compiler and GC threads
(`proc`), and opens its own `AF_UNIX` socket at startup (`unix`). It still
runs with no `exec`, `memfd`, `ipc` or `watch`. So an interpreted exploit
gets no shell, no anonymous executable memory, and no reach to another
service's IPC or file activity.

## Forms from the command line

To try something, you need not write a form. howl's `build`, `run`,
`create` and `pack` take flags that write one, and `howl form ... -o DIR`
keeps it, so DIR builds what the flags built
([design/adhoc.md](design/adhoc.md)):

```sh
build/host/howl run --with python-app --app ./api --package py3.13-flask
build/host/howl create shop --with caddy,valkey,postgresql --domain shop.example.com
build/host/howl run --oci web=cgr.dev/chainguard/nginx --web.listen tcp/8080 --web.write /var/lib/nginx/tmp
build/host/howl form --with caddy,valkey -o forms/shop/
```

| Flag | Writes |
| --- | --- |
| `--with FORM,...` | nothing, for one form alone: it runs as it is. One form with more flags becomes `base:`; several are taken `with` on `prod` (for `run`, on `playground`) |
| `--package PKG,...` | form.yaml's `packages` |
| `--oci NAME=REF` | an OCI image, baked in at `/oci/NAME` and run as `_oci-NAME` |
| `--NAME.KEY 'LINE'` | one line of image NAME's service file, as it stands in the file: `listen`, `connect`, `write`, `read`, `run`, `env`, `secret`, `exec`, `dir`, `memory`, `nofile`, `pledge`, `before` or `requires` |
| `--link A:B` | `connect` from image A to image B's ports on loopback |
| `--net`, `--prune`, `--modules`, `--programs` `LINE` | one more line in that list of form.yaml |
| `--KEY.SUB VALUE` | one scalar in form.yaml's map KEY: `--sshd.max-auth-tries 3` |

List flags repeat or take commas. `-n` prints the form and stops.
`create NAME` writes `build/adhoc/NAME`, and `run` writes
`build/adhoc/run`; the form is named after its directory. Its first
comment is the command line. It restates its chain's `weaknesses`, since
a form's are never inherited; to add one, keep the form and edit it.

An image is pinned: a tag is resolved once with `crane` and printed as
the `REF@sha256:...` to use next time. `crane export` pulls the image and
`howl _unpack` lays it out. It refuses the whole image at a name with `..`
or an empty part, a path through a link, a hard link to anything but a
file already laid out, a whiteout, or more than 500,000 entries, 8 GiB,
4,096 bytes in a name or 255 in a part of one. A leading `/` is dropped,
device nodes and FIFOs are left out, and only the execute bit of a mode
is kept, with no extended attribute, so nothing is setuid or carries a
file capability. The entrypoint, looked up on the image's `PATH` inside
the tree, must be an ELF program: a `#!` script would need a shell (say
`--NAME.exec '/PROGRAM ARGS'` instead). The image's `ExposedPorts` and
`Volumes` grant nothing. Until you give a `listen` or `write` line, howl
refuses, and prints the lines to choose from,
`--web.listen 'tcp/8080 loopback'` (for linked images only) first.

The service runs inside the image, as `_oci-NAME` whatever its `User`
says, with the image's entrypoint, working directory (else `/data`) and
environment (plus `PATH` and `HOME=/data` if it sets none). Unless you say
otherwise, its pledge is `stdio rpath wpath inet unix connect listen proc`
and its memory 512 MiB. The image is its root, read-only. Its `/tmp`,
`/run` and `/data` are its own directories, and each `write PATH` is
`/data/svc/NAME/PATH`, mounted `noexec`. It also gets its own `/proc`
(`hidepid=invisible`), the machine's CPU list, `/dev/null`, `zero`,
`full`, `random` and `urandom`, and the machine's `/etc/resolv.conf`;
`/etc/hosts`, written at build, names `localhost` and NAME. Its
account's uid and gid are its user's hash (`compose.defaultId`), the id
the build gives any service user no form declares. A
`--link` to a form's service is not built yet: give the image a `connect`
line and the form a `loopback` port.

## webshell-example: a contained vulnerability

`webshell-example` is a form that ships the worst thing a web application
can do. Its page takes a string from an unauthenticated request, runs it
as a command through `/bin/sh`, as an application's `sh -c` would, and
shows the output. That is remote code execution by design, the bug behind
a large share of real breaches. The form shows what an attacker gets for
it on werewolf: nothing worth having.

```sh
build/host/howl run --with webshell-example --on qemu
```

This boots the form as it ships, with no shell: its `/bin/sh` is
[sh-shim](../cmd/sh-shim/README.md). It forwards its port from this
host's `http://127.0.0.1:8080` (or the free port it prints). Open it,
or `curl` it, and try to escape. The page keeps the last 100 attempts, each with its source
address, User-Agent, exit code and output, so a failed break-in is on the
screen:

```sh
$ curl --data-urlencode 'cmd=cat /etc/shadow && echo LEAK' 127.0.0.1:8080 >/dev/null
$ curl --data-urlencode "cmd=/usr/bin/python3 -c \"open('/pwned','w')\"" 127.0.0.1:8080 >/dev/null
$ curl -s 127.0.0.1:8080/attempts.json | python3 -m json.tool
# cat ... && echo LEAK    -> sh-shim: refused: unquoted & is shell syntax   (no shell ships)
# python3 open('/pwned')  -> OSError: Read-only file system    (dm-verity root)
```

Each layer is a different wall. The shell is sh-shim, which runs one
program and refuses `&&`, pipes and `$`. The Landlock floor does not
include `/etc/shadow`, so reading a secret is denied. The root is read-only, so a write fails. The form declares no
`connect`, so fence drops any packet going out. Even full Python, through
the one interpreter that runs, cannot read a secret, change the system,
persist, or call home, and a reboot returns the machine to the signed
image.

The execution is real, though, and the leash bounds it, not an empty image.
The form ships coreutils and net-tools, and the service's `run` line names
`id`, `uname`, `hostname`, `cat`, `ls`, `head`, `tail`, `wc`, `echo`,
`date`, `env`, `pwd` and a couple more.

```sh
$ curl -s --data-urlencode 'cmd=id' 127.0.0.1:8080             # uid=527139628(app) gid=527139628(app) ...
$ curl -s --data-urlencode 'cmd=cat /etc/passwd' 127.0.0.1:8080  # root:x:0:0:... app:x:527139628:527139628:...
$ curl -s --data-urlencode 'cmd=cat /etc/shadow' 127.0.0.1:8080
# cat: /etc/shadow: Permission denied                          (cat runs; the read is denied)
$ curl -s --data-urlencode 'cmd=dd if=/dev/zero of=/pwned' 127.0.0.1:8080
# dd runs, but: dd: failed to open '/pwned': Read-only file system
$ curl -s --data-urlencode 'cmd=ifconfig' 127.0.0.1:8080
# sh-shim: ifconfig: permission denied                        (a separate binary, exec not allowed)
```

So remote code execution runs here, and two different walls hold it.

For a program that runs, the leash's read and write floor decides what it
may touch. `cat /etc/passwd` prints the public account list, but
`cat /etc/shadow`, with the same allowed `cat`, is denied the file. `dd`
cannot write to the read-only root.

Landlock's exec allowlist decides which programs run at all. But it works
per file, not per command name, and **Wolfi's coreutils is one multi-call
binary**: `/usr/bin/coreutils`, with `cat`, `dd`, `id`, `chroot`, `base64`
and the rest as symlinks to it. So naming `id` on the `run` line allows
every coreutils applet, `dd` and `chroot` included. They run, and gain
nothing, because the floor, the dropped capabilities (`chroot` has no
`CAP_SYS_CHROOT`) and the empty network still bind them. net-tools ships
each program as its own file, so `ifconfig` and `route`, which the `run`
line does not name, are refused at exec. The lesson is that `run`
allowlists *files*. A multi-call binary is all-or-nothing, and the real
containment is the floor, the capabilities and the network policy around
whatever runs, not the list of names.

A program the app runs on what a stranger sends can be held tighter than
the app. `cat` also runs narrowed, by its link `/etc/sv/app/narrow/cat`
([design/narrow.md](design/narrow.md)): it reads the image, but neither
the account list nor the app's own files, which plain `cat` reads.

```sh
$ curl -s --data-urlencode 'cmd=/etc/sv/app/narrow/cat /etc/passwd' 127.0.0.1:8080
# leash: {"event":"narrow","service":"app","program":"/usr/bin/cat",...}
# ...: /etc/passwd: Permission denied                           (cat runs; the read is denied)
```

At boot, the application attacks itself with that battery of commands, and
logs as JSON on the console that none escaped. It then runs the
allowlisted commands and logs that each one ran, and narrowed `cat`, that
it held. `make check` boots it with no shell and checks all three: every
attack contained, every allowed command run, and the narrowing held
(`check-shellfree-webshell-example`,
[forms/webshell-example/test/console](../forms/webshell-example/test/console)).
So the claim is tested, not just made.

To put it where anyone can attack it, on a real VM on the Internet:

```sh
build/host/howl create webshell --with webshell-example --on gcp --allow-from 0.0.0.0/0
build/host/howl delete webshell --on gcp   # when you are done
```

This is the same machine, built as a release disk and run on Google
Compute Engine, at the address create prints, with a firewall rule that
opens only its :8080, to anyone. It needs `gcloud`, logged in, with a
project ([examples/README.md](../examples/README.md#prepare-gcp-once)). The
VM costs money until you delete it.
