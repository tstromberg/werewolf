# Forms

A form says what a werewolf machine is for. Each is a directory, `forms/<name>/`:
`form.yaml` (the Wolfi packages and accounts apko installs, and what apko cannot say:
the form it is built on, its services, its network policy, the posture checks it fails
and why), `rootfs/` (files laid over the packages) and, where needed, `cmd/`, `test/`,
distro-specific `melange/` and a README. A form gets the parts of the form it is built
on, and its ancestors. [forms/README.md](../forms/README.md) lists every file and key;
[design/forms.md](design/forms.md) explains composition; `make list-forms` lists chains.

[forms-catalog.md](forms-catalog.md) lists every form. Each boots the same way: stage0
opens its `root.erofs` read-only through dm-verity and hands over to init
([design/verified-boot.md](design/verified-boot.md)). `DEV=1` adds busybox and a console
shell to any form. Howl's `--dev` also layers in root SSH using a local Ed25519 key
managed under `$XDG_DATA_HOME/howl/keys/dev/`; `howl ssh root@NAME` selects that key for
the VM. These are local debugging conveniences, and what ships is built without them.
Native test authors can reuse that channel with [`howl test
--iterate`](design/local-test-iteration.md).

## The runtime forms

Forms declare supported data operations with `imports: [init]` (the default),
`imports: [init, sync]`, or `imports: []`. The declaration is part of the signed
deployment definition; the form supplies its confined importer. Plex supports
initial media loading and non-deleting file sync. Database forms retain their
initialization-specific behavior. See [data import and sync](design/data-import.md).

`nginx`, `php`, `node`, `python`, `ruby` and `jre` are each `prod` plus one runtime from
Wolfi, as Chainguard's images are, and no application. `nginx` and `php` serve the site
laid in their html root; the others start nothing until a form on them brings a service.
The `-app` forms bring one for the application laid in `/usr/lib/app`, and ship none:
until yours is there, the service stays down and says why on the console. The `-example`
forms add a sample application, each a tutorial
([examples/README.md](../examples/README.md)).

| Form | Runs | As | On | Yours goes in |
| --- | --- | --- | --- | --- |
| `nginx` | nginx (`etc/sv/nginx`) | `nginx` | :80 | `/usr/share/nginx/html`, and `etc/nginx/nginx.conf` |
| `php` | nginx, and php-fpm (`etc/sv/php-fpm`) on a socket only nginx may use | `nginx`, `php` | :80 | `/usr/share/nginx/html` |
| `node-app` | `node /usr/lib/app/server.js` (`etc/sv/app`) | `app` | :8080 | `/usr/lib/app` |
| `python-app` | `python3 /usr/lib/app/main.py` (`etc/sv/app`) | `app` | :8080 | `/usr/lib/app` |
| `ruby-app` | `ruby /usr/lib/app/main.rb` (`etc/sv/app`) | `app` | :8080 | `/usr/lib/app` |
| `jre-app` | `java -jar /usr/lib/app/app.jar` (`etc/sv/app`), its heap 640 MiB | `app` | :8080 | `/usr/lib/app` |
| `jre` | your jar, as your service file says | `app` | yours | `/usr/lib/app`, and `etc/sv/app/service` |

A service's `user app` gets its account from the build (uid and gid its name's hash,
home `/var/empty`, shell `/sbin/nologin`). Each of these programs runs on a leash
([programs.md](programs.md)): as its own user, binding its own port and no other,
reading the image, writing only `/run/svc/NAME` and `/data/svc/NAME`, with no
capability.

An interpreter is the point of these forms, so posture's `programs-no-interpreters`
fails on them by design, as `kernel-no-hypervisor` does on `qemu-host`. Each says so in
its form.yaml, with its excuse:

```yaml
weaknesses:
  programs-no-interpreters: php-fpm runs the application, which is what this form is for
```

Excuses are never inherited. `make check` fails a machine on any failure its form does
not excuse, and on any excused failure that passes.

## Files a form leaves out

A package may declare a dependency nothing on the machine runs: Wolfi's `valkey-9.1`
brings bash, because `posix-libc-utils` ships `ldd` as a bash script. `prune:
[usr/bin/bash]` names such files by their path in the image. The build makes the root
without them and records them in `/usr/share/werewolf/prune`, so the updater removes
them from every slot it builds. Use `prune` for a file a dependency drags in, never to
trim a package the form uses.

## Bundles: one form taking several

A form is built on one other form, but a machine that runs an application with its
database is several side by side. A form may take other forms `with` it, and gets their
parts too: packages, accounts, services, policies and pruning.

```yaml
# forms/mastodon/form.yaml
base: ruby
with: [postgresql, valkey, nginx]
```

The build puts each member's forms that the form's own chain lacks before the form
itself, in order, so the form's own files win where two lay the same path. Two users or
groups with the same name or id fail the build.

## Packages Wolfi does not ship

Third-party software comes from a signed feed by package name: `../packages` builds what
Wolfi lacks or ships unfit, rarely what it ships (named `-werewolf`), and
`../packages/lang` also holds the runtimes Werewolf patches. `minimal` lists both feeds;
a name either covers comes from it or the build fails. Built-in forms declare
published dependencies in `packages`; their builds need no package source checkout.
Image locks pin the resolved APK versions and checksums for each architecture.
Recipes for Werewolf's own software or private development packages stay beside
their source in `melange/*.yaml`, as in `forms/vuln-demo`. Melange builds those in
QEMU or bubblewrap, overlays the packages and checks shared-library dependencies.
See [package dependencies](../CONTRIBUTING.md#package-dependencies).

## Private configuration files

`config NAME PATH` in a service file gives that service one file:

```text
config users /run/config/nats/users.conf
```

For service `nats`, leash copies it to `/run/svc/nats/users`, the service's, mode
`0600`, at every start; point the program's configuration there. The service cannot read
the rest of `/run/config`. NAME matches `[a-z][a-z0-9-]*`, as `howl pack` takes it as
`--NAME FILE`; name the file in the tar NAME too, or by its format where one is usual
(`tls.crt`). A service may name up to 32 files of at most 64 KiB. A missing file keeps
the service down, unless the line ends in `optional`. Contents are copied unchanged and
never logged.

Credentials go in the boot config, not the image ([cloud.md](cloud.md)). For a value
needed in an environment variable, `secret NAME PATH` reads one line into NAME; howl
takes it as `--smtp-password FILE` for `SMTP_PASSWORD`.

## People

A form that runs sshd takes root's keys from the boot config (`--root-keys`). A manifest
can also name accounts, with security keys, and make some admins, whose keys log in as
root too:

```yaml
users:
  tom:
    keys: [sk-ssh-ed25519@openssh.com AAAAGnNr... tom@yubikey]
    admin: true
```

`users: {alice: {}}` is an account without keys; an admin must have keys. prod-ssh and
playground include `ssh-su` for root reauthentication using a forwarded agent. It
installs the SSH client and keeps the existing listener. Production requires FIDO
presence and verification. See [su](../forms/ssh-su/README.md) for client setup and the
explicit software-key policy for local VMs. People are never in the image: howl packs
them into the boot config, init makes each an account (uid mapped from its name into
`[65536, 2^30)`, NoCloud's kept in 500-60000; home on `/data`) and writes its keys where
sshd looks; `net` grants them all as `:people`. Names and IDs stay reserved in
`/data/.werewolf/identities` after removal; cloud metadata locks absent people and
reapplies active keys as they change. Services have distinct users; components of one
application may share one with `shared-user: true` on each, which shares files,
processes and network policy while Landlock, seccomp and limits stay per service.

When `users` is absent, `howl run` and `howl create` default to adding the current
local user with the public keys in `~/.ssh` accepted by the form's SSH policy.
`--add-current-user=auto|yes|no` controls this: `auto` respects any explicit
`users`, including an empty map or config file; `yes` adds the current user
alongside other accounts, preserving an existing declaration for that name;
`no` disables the addition. This does not grant `admin`. Lima keeps its NoCloud
user, and developer SSH remains root-only. `howl pack --on TARGET` applies the
same default; without a target, pack requires `--add-current-user=yes`.

## Settings

*Settings* are values that differ per machine but are not secret: a router's routes, a
database URL. A service file declares each with a type and says where the values go
([design/settings.md](design/settings.md)):

```text
config  settings /run/config/tailscale/settings.json
setting routes cidr... as advertiseRoutes
render  json config.json from /etc/tailscale/config.json
```

`config settings` names the file in the boot config, `{"routes": ["10.20.0.0/24"]}`,
which may be missing. `setting NAME TYPE[...] [required] [as KEY]` declares one, up to
32 a service: NAME is its key in the JSON and `howl pack`'s `--NAME`; KEY names it in
the output, by default NAME (for `env`, upper case with `_`). A list (`TYPE...`) holds
up to 32 values.

| Type | Accepts |
| --- | --- |
| `ip`, `cidr`, `addrport`, `hostport` | a literal address; a network with no host bits; address and port; hostname or address and port |
| `hostname`, `port`, `url` | RFC 1123, at most 253 bytes; 1 to 65535; `http` or `https` without credentials, at most 2 KiB |
| `int`, `bool`, `string` | a signed 64-bit number; `true` or `false`; UTF-8 without control characters, at most 1 KiB |

At each start leash runs `service-config` as the service, which checks every value
against its type and writes `/run/svc/SERVICE/FILE` in the `render FORMAT FILE` format:
`env` (`KEY=VALUE` lines leash adds to the environment; no lists of `string` or `url`,
no `PATH` or `LD_*`), `json` (one object, `from PATH` merged into a file from the image,
dotted keys nested) or `conf` (`KEY VALUE...` lines; no `string` or `url`). A refused
pair does not build. A setting not given is left out, so the daemon's default holds;
`required` keeps the service down instead, as does an undeclared key or a value of the
wrong type, with one line naming it.

See [applications.md](applications.md) for building and shipping applications.
