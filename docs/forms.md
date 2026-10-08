# Forms

A form is what a werewolf machine is for, and a directory,
`forms/<name>/`: `apko.yaml`, the Wolfi packages and accounts apko
installs; `form.yaml`, what apko cannot say, from the form it is built on
to its network policy and the posture checks it fails, and why;
`rootfs/`, the files it lays over its packages; and, where it needs them,
its own programs (`cmd/`), checks (`test/`), melange recipes (`melange/`)
and a `README.md`. A form gets the parts of the form it is built on,
and of that form's base, and adds its own. [forms/README.md](../forms/README.md)
lists every file and key; `make list-forms` shows the chains;
[design/forms.md](design/forms.md) is why there are so few.

## The forms

| Form | Built on | Is |
| --- | --- | --- |
| `minimal` | | boots anywhere, from the initramfs, its own disk or a slot bite installed; a static address; listens on nothing |
| `prod` | `minimal` | the production base: DHCP, the cloud's metadata, updates itself, `/data` on a disk, in LUKS2 when the config brings `data.key` ([data.md](data.md)); no shell, nothing listening. Build yours on this, or on a runtime form below |
| `app` | `prod` | the unprivileged `app` user and group (204); no runtime, service or listener |
| `nginx` | `prod` | serving a site from the image on :80 |
| `php` | `nginx` | with php-fpm running the site's `.php` files |
| `node`, `python`, `ruby`, `jre` | `app` | running an application on :8080 |
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
| `lima` | `prod`, with `sshd` | the Lima test vehicle (`make lima`), which takes Lima's own key file |

Every form boots the same way: stage0 opens its `root.erofs` read-only,
through dm-verity, and hands over to init
([design/verified-boot.md](design/verified-boot.md)). CI publishes
`minimal`, `prod` and `prod-ssh` as signed releases
([releases.md](releases.md)).

Any form builds with `DEV=1` too: busybox and the debug shell on the
console, for finding out why something does not work. What ships is built
without it.

## The runtime forms

`prod` has no `app` user or group. Its descendant `app` adds that account
with uid/gid 204, home `/var/empty` and shell `/sbin/nologin`. It adds no
packages, service or listening port. The `node`, `python` and `jre` forms,
and the Go, Rust and ASP.NET Core examples, inherit it. PHP and nginx keep distinct
service accounts because they run separate services in the same VM.

`nginx`, `php`, `node`, `python` and `jre` are `prod` and one runtime from
Wolfi, as Chainguard's images are, each with a site or application of its
own that answers until yours replaces it:

| Form | Runs | As | On | Yours goes in |
| --- | --- | --- | --- | --- |
| `nginx` | nginx (`etc/sv/nginx`) | `nginx` | :80 | `/usr/share/nginx/html`, and `etc/nginx/nginx.conf` |
| `php` | nginx, and php-fpm (`etc/sv/php-fpm`) on a socket only nginx may use | `nginx`, `php` | :80 | `/usr/share/nginx/html` |
| `node` | `node /usr/lib/app/server.js` (`etc/sv/app`) | `app` | :8080 | `/usr/lib/app` |
| `python` | `python3 /usr/lib/app/main.py` (`etc/sv/app`) | `app` | :8080 | `/usr/lib/app` |
| `jre` | the JDK's web server (`etc/sv/app`) | `app` | :8080 | `/usr/lib/app`, and `etc/sv/app/service` |

Every one of those programs runs on a leash ([programs.md](programs.md)):
as its own user, with no capability but binding a port below 1024 where it
serves one, able to bind its port and no other, to read the image, and to
write only `/run/svc/NAME` and `/data/svc/NAME`. The machine around it is
`prod`'s: the root read-only and verified, no shell or package manager,
nothing leaving the machine that the form did not declare, and posture
saying so at every boot.

An interpreter is the point of these forms, so posture's
`programs-no-interpreters` fails on `php`, `node`, `python` and `jre` by
design, as `kernel-no-hypervisor` does on `qemu-host`, and each says so in
its form.yaml, with its excuse:

```yaml
weaknesses:
  programs-no-interpreters: php-fpm runs the application, which is what this form is for
```

`nginx` carries none. `make check` fails a machine on any posture
failure its form does not excuse, and on any excused one that passes.

## Files a form leaves out

A package sometimes declares a dependency nothing on the machine runs:
Wolfi's `valkey-9.1` brings bash, because `posix-libc-utils`, which it
names, ships `ldd` as a bash script. apk installs what a package declares,
so form.yaml's `prune` names the files to leave out, as each is in the
image:

```yaml
prune:
  - usr/bin/bash
```

The build makes the root without them, the image records them in
`/usr/share/werewolf/prune`, and the updater removes them from every slot
it builds, so a slot built on the machine holds what the build's did.
The package stays installed as far as apk's database and a release's
manifest know; posture reports what the image holds. It is for a file a
dependency drags in, never for trimming a package the form uses.

## Bundles: one form taking several

A form is built on one other. A machine that runs an application with
its database is several forms side by side, so a form may take others
`with` it, whose parts it gets too: their packages and accounts,
services, policies, modules and pruning.

```yaml
# forms/mastodon/form.yaml
base: ruby
with: [postgresql, valkey, nginx]
```

The build puts each member's forms that the form's own chain lacks
before the form itself, in order, so the form's own files win where two
lay the same path, and merges their apko configs in the same order. Two
users or groups of one name or id fail the build. `make list-forms` and
`howl pack` follow the same chain.

## Packages Wolfi does not ship

A form whose application Wolfi does not package keeps a melange recipe
for it, in Wolfi's own style, in `forms/<name>/melange/`: `vaultwarden`
has `forms/vaultwarden/melange/vaultwarden.yaml`. The build runs melange
in Wolfi's environment,
checks each source by sha256, unpacks the packages over the image, and
fails if a library they link is not one of the form's packages, so
Wolfi's fixes to those reach the machine through its updater. While
writing a recipe, `howl build-apk RECIPE` builds it alone and says
what each package links. On macOS melange runs in QEMU, booted from
werewolf's own Alpine kernel; on Linux, in bubblewrap. A recipe Wolfi
would take is also the pull request to wolfi-dev/os that retires it; one
it will not stays with its form.

## Private configuration files

Use `config NAME PATH` in a service file to give that service one file:

```text
config users /run/config/nats/users.conf
```

For service `nats`, this creates `/run/svc/nats/users`, owned by its
user with mode `0600`. Point the program's configuration at that copy.
The service cannot read the rest of `/run/config`. NAME is
`[a-z][a-z0-9-]*`, as a setting's is, since `howl pack` takes it as
`--NAME FILE`. Name the file in the tar NAME too, `admin-password` from
`/run/config/FORM/admin-password`, or by its format where that has a
name of its own (`tls.crt`, `users.json`); never with `_`.

Sources must be beneath `/run/config`; destinations are plain names, not
paths. A service may name up to 32 files, each at most 64 KiB. Missing or
unreadable files keep it down, unless the line ends in `optional`: then a
missing file leaves no copy, and the service runs without it (a mail
relay's password, where the machine sends no mail). Contents are copied
unchanged, never logged, and refreshed on each start, before any `before`
command. Leash reads them
as root but writes the copies only after dropping privileges and entering
Landlock. Existing destination links are replaced, not followed.

Put credentials in the boot config, not the image; see
[cloud.md](cloud.md). These runtime copies disappear at reboot.
For a value needed in an environment variable, use `secret NAME PATH`
instead.

## Settings

Values that differ per machine but are not secret, such as a router's
routes or an application's database URL, are *settings*. A service
file declares each one with a type, and says where they go:

```text
config  settings /run/config/tailscale/settings.json
setting routes cidr... as advertiseRoutes
render  json config.json from /etc/tailscale/config.json
```

The `config settings` line names the file in the boot config that gives
the values, and may name one that is missing:

```json
{"routes": ["10.20.0.0/24"]}
```

At each start, leash copies it into the service's directory and runs
`service-config` as the service, which checks every value against its
declared type and writes `/run/svc/SERVICE/FILE`: `KEY=VALUE` lines
(`env`, which leash adds to the service's environment), one JSON object
(`json`, with `from PATH` merging into a file from the image; a key with
dots, `authority.policy.x509.allow.dns`, fills a key the daemon nests), or
`KEY VALUE...` lines (`conf`). A list (`TYPE...`) holds up to 32 values.
The types are `ip`, `cidr`, `addrport`, `hostport`, `hostname`, `port`,
`url`, `int`, `bool` and `string`.

A setting not given, or an empty list, is left out, so the default in the
daemon's own configuration holds; `required` keeps the service down
instead. A key settings.json does not declare, or a value not of its type,
keeps the service down, with one line naming the setting and why. Settings
cannot add a directive: a value only fills a key the image declared. See
[design/settings.md](design/settings.md).

## Your application

For complete runnable tutorials with an image-building Makefile and
`deploy-qemu` / `deploy-gcp` targets, see [the language examples](../examples/README.md):
[PHP](../examples/php/README.md), [Python](../examples/python/README.md),
[Node.js](../examples/nodejs/README.md), [Go](../examples/go/README.md),
[Rust](../examples/rust/README.md) and [ASP.NET Core](../examples/aspnet/README.md).
Each explains declarative configuration
and what automatic updates do, including their limits for application code.

An application is built into the image, as Chainguard's are with apko,
not fetched by the machine: a form of your own is built on a runtime form,
names the Wolfi packages it needs, and carries the application's files. So
the code is in the verified, read-only root, built, signed, updated and
rolled back with the rest, and nothing writable ever runs. What the
application keeps is data, in `/data/svc/app`, its working directory.

### Without a form: `--app`

Where a runtime form already starts the application as it should be
started, its files are all a machine needs. `--app DIR` lays a directory
where the form keeps its application (form.yaml's `app`: `/usr/lib/app`
for `python`, `node` and `jre`; nginx's html root for `nginx` and `php`):

```sh
build/host/howl create web --with python --app ./myapp     # ./myapp/main.py, on :8080
build/host/howl build --with python --app ./myapp          # the release files, for elsewhere
```

DIR is what the application's own toolchain made (`go build`, `dotnet
publish`, `mvn package`, a checkout): regular files and directories, an
executable bit kept, nothing setuid, no links. werewolf prints its sha256,
over every path, executable bit and byte, so the same DIR makes the same
image. An image with an application builds apart from the form's own, and
a new application is a new machine: `howl delete`, then `create`.
[apps-by-hand.md](apps-by-hand.md) does all of it with `make` and `tar`,
to show the mechanism underneath.

What the application needs from each machine, a database's address or a
greeting, is a setting its form declares, and a form of your own declares
it: `examples/python`'s form takes `--greeting TEXT` and hands it to the
application as `GREETING` (`render env`, [Settings](#settings)). A secret
is a file, given with `config` and read from `/run/svc/app`.

### A Python web server

`helloworld`: a Flask application, served by gunicorn on :8080, counting its
visitors on `/data`. Three files.

The form names what it is built on, and the packages it adds by their
Wolfi names:

```yaml
# forms/helloworld/form.yaml
base: python
```

```yaml
# forms/helloworld/apko.yaml
contents:
  packages:
    - py3.13-flask
    - py3.13-gunicorn
```

The application goes where the `python` form looks for one:

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

It starts differently from the `python` form's `main.py`, so it brings its
own service file, which leash reads to start it
([cmd/leash/leash.zig](../cmd/leash/leash.zig) lists every directive):

```
# forms/helloworld/rootfs/etc/sv/app/service
exec    /usr/bin/python3 -m gunicorn --bind 0.0.0.0:8080 --workers 2 --worker-tmp-dir /run/svc/app --no-control-socket --pythonpath /usr/lib/app --access-logfile - helloworld:app
user    app
pledge  stdio rpath wpath proc inet listen
listen  tcp/8080
env     PYTHONDONTWRITEBYTECODE=1
env     PYTHONUNBUFFERED=1
```

`--worker-tmp-dir`, because the root is read-only and the app user may
write only its own directories, not `/tmp`. `--no-control-socket`, because
runit supervises gunicorn already, and its control socket would go in the
app user's home, `/var/empty`. `-m gunicorn`, because leash lets the
service run the program it names, `python3`, and no other.

Build it and boot it under QEMU, with a disk for `/data`:

```sh
make FORM=helloworld run
```

The console shows the boot, posture's line, and gunicorn's log. `make run`
forwards the form's port to 8080 on this host's loopback, so from another
terminal:

```sh
$ curl http://127.0.0.1:8080/
Hello from werewolf! You are visitor 1.
$ curl http://127.0.0.1:8080/health
{"status":"ok"}
```

Quit with `Ctrl-a x` and `make FORM=helloworld run` again: the count goes on,
since `/data` is `build/<arch>/data.img`, which outlives the machine.
Delete it to start over.

To change the application, change its files and run `make FORM=helloworld run`
again: the image is rebuilt. A machine never changes in place.

### What the leash holds

The application can do what its service file and the form's `net` say,
and nothing else. The kernel enforces each limit; nothing asks the program:

| It tries | Without a line for it | The line |
| --- | --- | --- |
| to make a system call | refused as if the kernel had no such call (seccomp) | `pledge PROMISE...`: what classes of call it may make (`stdio rpath inet listen`), the OpenBSD-pledge words werewolf maps to calls ([design/pledge.md](design/pledge.md)) |
| to listen on another port | the bind fails (Landlock) | `listen tcp/PORT` in the service, and `listen tcp/PORT` in the form's `net` for fence |
| to reach another machine: a database, an API | the connect fails (Landlock), and fence drops the packet | `connect tcp/PORT` in the service, and `connect app tcp/PORT` in the form's `net` |
| to write outside `/data/svc/app` and `/run/svc/app` | refused; the root is read-only besides | `write PATH` |
| to run another program: a shell, `curl` | refused (`pledge exec`, then Landlock); there is no shell in the image anyway | `run PROGRAM` |
| to read a secret | it has none | `secret NAME PATH`: a variable read from a file in the config |
| to exhaust the machine's memory | capped where the service sets one | `memory MiB`: its cgroup `memory.max`, a ceiling on resident memory (not address space), so it fits an interpreter, the JVM and V8 alike |
| to leave a process running after it is stopped | killed with the service | nothing to add: each leashed service is a cgroup, and its `finish` writes `cgroup.kill` on stop, restart and shutdown, so its whole tree -- a detached backdoor included -- goes with it |

Every service file states a `pledge`; a form built without one is parked at
boot, so a service always says what it does. `memfd`, `ipc` (System V
shared memory) and `watch` (inotify) are promises of their own, off unless
a service asks, so an application that does not name them cannot make an
anonymous executable file, squat another service's IPC key, or watch the
machine's file activity.

A form's `net` adds to its chain's, so `helloworld` needs one only to
allow more than `python`'s does. To serve on :8000 instead, change
gunicorn's `--bind` and the service's `listen` to 8000, and add:

```yaml
# forms/helloworld/form.yaml
base: python
net:
  - listen tcp/8000
```

### Ship it

| | |
| --- | --- |
| `make FORM=helloworld disk` | a disk image that boots it under UEFI, for a provider that takes one |
| `make FORM=helloworld bite-me` | run on a Debian, Ubuntu, Fedora or Rocky VM: installs it beside the distro ([bite.md](bite.md)) |
| `make FORM=helloworld image` | the kernel and initramfs, for QEMU, Firecracker or any host that boots them directly |

It updates itself, as `prod` does: the updater follows Wolfi's packages,
builds a new slot with your files carried forward, boots it once, and
keeps it only if it commits ([updater.md](updater.md)). posture runs at
every boot and says what holds; `programs-no-interpreters` is the one it
fails on a Python machine, and `python`'s form.yaml excuses it, but only
for `python` itself: excuses are not inherited, so a form of your own
that `make check` boots names the weaknesses it has, as `example-python`
does.

A Node or Java application is the same on `node` or `jre`. A Node one is
`server.js` in `/usr/lib/app`, or a service file of its own. A Java one is
a jar and a service file:

```
exec    /usr/bin/java -XX:-UsePerfData -Djava.io.tmpdir=/run/svc/app -jar /usr/lib/app/app.jar
user    app
pledge  stdio rpath wpath proc inet listen unix
listen  tcp/8080
```

The JVM's pledge is wider than a Python or Node server's: it keeps its own
temporary files (`wpath`, and `java.io.tmpdir` in its `/run`, since `/tmp`
is not the service's to write), spawns its compiler and GC threads
(`proc`), and opens an `AF_UNIX` socket of its own at startup (`unix`). It
still runs with no `exec`, `memfd`, `ipc` or `watch`, so an interpreted
exploit has no shell, no anonymous executable memory, and no reach to
another service's IPC or file activity.

## webshell-example: a contained vulnerability

`webshell-example` is a form that ships the worst thing a web application
can do: a page that takes a string from an unauthenticated request and
runs it as a command, by a shell or by a straight fork/exec, and shows the
output. That is remote code execution by design -- the bug behind a large
share of real breaches. It is there to show what an attacker gets for it
on werewolf: nothing worth having.

```sh
make webshell-demo
```

boots it as it ships, with no shell, and forwards its port to this host's
`http://127.0.0.1:8080`. Open it, or `curl` it, and try to escape. The
page keeps the last 100 attempts, each with its source address,
User-Agent, exit code and output, so a failed break-in is on the screen:

```sh
$ curl --data-urlencode 'cmd=cat /etc/shadow' --data 'shell=1' 127.0.0.1:8080 >/dev/null
$ curl --data-urlencode "cmd=/usr/bin/python3 -c \"open('/pwned','w')\"" 127.0.0.1:8080 >/dev/null
$ curl -s 127.0.0.1:8080/attempts.json | python3 -m json.tool
# cat /etc/shadow         -> not found: ... '/bin/sh'          (no shell ships)
# python3 open('/pwned')  -> OSError: Read-only file system    (dm-verity root)
```

Every layer shows a different wall: a shell command finds no `/bin/sh`;
the Landlock floor has no `/etc/shadow`, so a secret read is denied; the
root is read-only, so a write fails; and the form declares no `connect`,
so fence drops any packet out. Even full Python through the one
interpreter that runs cannot read a secret, change the system, persist, or
call home, and a reboot returns the machine to the signed image.

The execution is real, though, and bounded by the leash, not by an empty
image. The form ships coreutils and net-tools, and the service's `run`
line names `id`, `uname`, `hostname`, `cat`, `ls`, `head`, `tail`, `wc`,
`echo`, `date`, `env`, `pwd` and a couple more.

```sh
$ curl -s --data-urlencode 'cmd=id' 127.0.0.1:8080             # uid=204(app) gid=204(app) ...
$ curl -s --data-urlencode 'cmd=cat /etc/passwd' 127.0.0.1:8080  # root:x:0:0:... app:x:204:204:...
$ curl -s --data-urlencode 'cmd=cat /etc/shadow' 127.0.0.1:8080
# refused: [Errno 13] Permission denied: '/etc/shadow'         (cat runs; the read is denied)
$ curl -s --data-urlencode 'cmd=dd if=/dev/zero of=/pwned' 127.0.0.1:8080
# dd runs, but: dd: failed to open '/pwned': Read-only file system
$ curl -s --data-urlencode 'cmd=ifconfig' 127.0.0.1:8080
# refused: ... 'ifconfig'                                      (a separate binary, exec not allowed)
```

So remote code execution runs here, and two different walls hold it. For a
program that runs, the leash's read and write floor decides what it may
touch: `cat /etc/passwd` prints the public account list, but
`cat /etc/shadow` -- the same allowed `cat` -- is denied the file, and
`dd` cannot write the read-only root. For which programs run at all,
Landlock's exec allowlist decides -- but at the granularity of the file,
not the command name, and **Wolfi's coreutils is one multi-call binary**
(`/usr/bin/coreutils`, with `cat`, `dd`, `id`, `chroot`, `base64` and the
rest as symlinks to it). So naming `id` on the `run` line allows every
coreutils applet, `dd` and `chroot` included; they run, and gain nothing,
because the floor, the dropped capabilities (`chroot` has no
`CAP_SYS_CHROOT`) and the empty network still bind them. net-tools ships
each program as its own file, so `ifconfig` and `route`, which the `run`
line does not name, are refused at the exec. The lesson the form teaches is
that `run` whitelists *files*: a multi-call binary is all-or-nothing, and
the real containment is the floor and the capability and network policy
around whatever runs, not the list of names.

At boot the application attacks itself with that battery and logs, as JSON
on the console, that none escaped; it then runs the three allowlisted
commands and logs that each ran. `make check` boots it with no shell and
asserts both -- every attack contained, every allowed command executed
(`check-shellfree-webshell-example`,
[forms/webshell-example/test/console](../forms/webshell-example/test/console)) -- so
the claim is tested, not just made.

To put it where anyone can attack it, on a real VM on the Internet:

```sh
make webshell-gcp          # import the disk, boot a GCP VM, print its http://ADDR:8080
make webshell-gcp-delete   # when you are done
```

It is the same machine as the demo, built as a release disk and run on
Google Compute Engine (test/gcp), with a firewall rule opening only
:8080 to it. Needs `gcloud`, logged in, with a project; the VM costs until
you delete it.
