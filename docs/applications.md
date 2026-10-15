# Your application

An application is built into the image, as Chainguard's are with apko; the
machine does not fetch it. A form of your own is built on a runtime form
([forms.md](forms.md)), names the Wolfi packages it needs, and carries the
application's files, so the code is in the verified, read-only root, built,
signed, updated and rolled back with the rest. What it keeps is data, in
its working directory, `/data/svc/app`. The [tutorials](../examples/README.md)
run PHP, Python, Node.js, Go, Rust and ASP.NET Core here and on GCP.

## Without a form: `--app`

When a form already starts the application the right way, as the `-app`
forms do, its files are all a machine needs. `--app DIR` lays a directory
where the form keeps its application (form.yaml's `app`): `/usr/lib/app` for
the forms on `app`, nginx's html root for `nginx` and `php`.

```sh
build/host/howl create web --with python-app --app ./myapp     # ./myapp/main.py, on :8080
build/host/howl build --with python-app --app ./myapp          # the release files, for elsewhere
```

DIR is what the application's own toolchain made: regular files and
directories, no links, no setuid files. werewolf prints DIR's sha256 over
every path, mode and byte, so the same DIR makes the same image; a new
application means a new machine, `howl delete` then `create`.
[apps-by-hand.md](apps-by-hand.md) does the same with `make disk` and `tar`.
What the application needs from each machine, such as a database's address,
is a setting its form declares ([forms.md](forms.md#settings)):
`python-example` takes `--greeting TEXT` and hands it over as `GREETING`.

## A Python web server

`helloworld` is a Flask application, served by gunicorn on :8080, that
counts its visitors on `/data`. It takes two files, the application in
`/usr/lib/app`:

```python
# forms/helloworld/rootfs/usr/lib/app/helloworld.py
import fcntl
from flask import Flask

app = Flask(__name__)

@app.get("/")
def index():
    # Two workers may count at once in /data/svc/app: the lock keeps every visit.
    with open("visits", "a+") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        f.seek(0)
        n = int(f.read() or 0) + 1
        f.seek(0)
        f.truncate()
        f.write(str(n))
    return f"Hello from werewolf! You are visitor {n}.\n"
```

It starts differently from `python-app`'s `main.py`, so it builds on
`python` and says its own service, which the build writes as the service
file leash reads ([cmd/leash/leash.zig](../cmd/leash/leash.zig) lists
every directive):

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

`--worker-tmp-dir`, because the app user may write only its own directories,
not `/tmp`; `--no-control-socket`, because runit supervises gunicorn
already, and the socket would go in the app user's home, `/var/empty`;
`-m gunicorn`, because leash lets the service run only the program it
names, `python3`.

```sh
build/host/howl create hello --with helloworld --on qemu
```

howl forwards the form's port from this host's loopback, 8080 if it is free,
and prints it; `howl console hello` shows the boot and gunicorn's log, and
`curl http://127.0.0.1:8080/` answers `Hello from werewolf! You are visitor
1.` A second `create` boots the machine again on its disk, so the count goes
on; `howl delete hello` removes both. To change the application, change its
files and create again: a machine never changes in place.

## What the leash holds

The application can do what its service file and the form's `net` allow,
and nothing else. The kernel enforces each limit:

| It tries | Without a line for it | The line |
| --- | --- | --- |
| to make a system call | refused as if the kernel had no such call (seccomp) | `pledge PROMISE...`: the classes of call it may make, OpenBSD's pledge words mapped to calls ([design/pledge.md](design/pledge.md)) |
| to listen on another port | the bind fails (Landlock) | `listen tcp/PORT` in the service, and in the form's `net` for fence |
| to reach another machine | the connect fails (Landlock), and fence drops the packet | `connect tcp/PORT` in the service, and `connect app tcp/PORT` in the form's `net` |
| to write outside `/data/svc/app` and `/run/svc/app` | refused; the root is read-only anyway | `write PATH` |
| to run another program: a shell, `curl` | refused (`pledge exec`, then Landlock); there is no shell anyway | `run PROGRAM` |
| through a program it runs on a stranger's file (ffmpeg), taken over, to do all the service may | it may: the program holds the service's leash | `narrow PROGRAM pledge\|read\|write ...`, run by its link `/etc/sv/NAME/narrow/PROGRAM` ([design/narrow.md](design/narrow.md)) |
| to read a secret | it has none | `secret NAME PATH`: a variable read from a file in the config |
| to exhaust the machine's memory | capped where the service sets a cap | `memory MiB`: its cgroup's `memory.max`, resident memory, so it suits an interpreter, the JVM and V8 alike |
| to leave a process running after it is stopped | killed with the service | nothing: each service is a cgroup, and its `finish` writes `cgroup.kill` on stop, restart and shutdown, a detached backdoor included |

Every service file states a `pledge`; a service with none is parked at
boot. `stdio rpath wpath proc inet listen` covers a server; `memfd`, `ipc`
and `watch` are off unless asked for, so an application that does not name
them cannot make an anonymous executable file, squat another service's IPC
key, or watch the machine's files. No promise brings `ptrace`, eBPF, perf,
modules, io_uring or another process's memory. [lib/seal.zig](../lib/seal.zig)
maps each promise to its calls. A service's `listen` and `connect` are its
network policy for leash and fence alike.

## Ship it

`howl build --with helloworld` writes `dist/helloworld-ARCH-disk.qcow2`, a
UEFI boot disk (`--format raw|vhd|vmdk`); `howl create NAME --with helloworld
--on gcp|aws|azure` makes a cloud machine of it.

It updates itself unless `updates: off` leaves the updater out and records
the `updates-enabled` weakness: the updater follows Wolfi's packages, builds
a new slot with your files carried forward, boots it once, and keeps it only
if it commits ([updater.md](updater.md)). For later changes to the
application, set `updates.from` to an HTTPS apk repository before creation;
`howl apply FILE` signs and publishes `local-NAME`, which the updater
composes into the other slot ([design/manifest.md](design/manifest.md)).
A form of your own that `make check` boots names its weaknesses, as
`python-example` does, since excuses are not inherited.

A Node, Ruby or Java application works the same way, with a service file of
its own: `jre-app`'s runs `java -jar /usr/lib/app/app.jar` with
`java.io.tmpdir` in its `/run`, and a wider pledge (`wpath` for those files,
`proc` for the JVM's threads, `unix` for its startup socket), still with no
`exec`, `memfd`, `ipc` or `watch`.

## Forms from the command line

To try something, you need not write a form. howl's `build`, `run`, `create` and `pack`
take a manifest, `-f FILE`, and flags that are its keys, and write a form from them
([design/adhoc.md](design/adhoc.md), [design/manifest.md](design/manifest.md)):

```sh
build/host/howl run --with python-app --app ./api --packages py3.13-flask
build/host/howl create shop --with caddy,valkey,postgresql --domain shop.example.com
build/host/howl run --services.web.image cgr.dev/chainguard/nginx --services.web.listen tcp/8080 --services.web.write /var/lib/nginx/tmp
```

| Flag | Writes |
| --- | --- |
| `-f FILE` | the manifest, as written; the flags layer over it |
| `--with FORM,...` | nothing, for one form alone. One form with more flags becomes `base:`; several are taken `with` on `prod` (for `run`, on `playground`) |
| `--packages PKG,...` | form.yaml's `packages` |
| `--KEY LINE` | one more line in a list key: `--net 'connect bastion tcp/5432'`, `--prune usr/bin/bash` |
| `--KEY.SUB VALUE` | one value in a map key: `--sshd.max-auth-tries 3`, `--updates.every 1h`; `--updates off` alone |
| `--services.NAME.KEY LINE` | a service's line, as it stands in form.yaml; `image REF` makes it an OCI image's, `link NAME` reaches another service's loopback port |
| `--users.NAME.keys LINE`, `--users.NAME.admin` | a person, and that their keys are root's too |

A key's shape decides ([lib/form.zig](../lib/form.zig) `keys`): a list takes
a line a flag; a map's value set twice is refused; `accounts`, `paths`,
`bastion` and `weaknesses` hold structure a line cannot, so keep the form
(`howl form ... -o DIR`) and edit it. `-n` prints the form and stops.

An `image` is pinned to the digest `crane` resolves, baked in at `/oci/NAME`
and run inside it as `_oci-NAME`, with its entrypoint (an ELF program, never
a `#!` script), its own `/tmp`, `/run`, `/data` and `/proc`, and a pledge of
`stdio rpath wpath inet unix connect listen proc` unless you say otherwise.
Until you give a `listen` or `write` line, howl refuses and prints the lines
to choose from. The unpack's rules are in [design/oci.md](design/oci.md).
