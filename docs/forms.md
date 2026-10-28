# Forms

A form says what a werewolf machine is for. Each is a directory, `forms/<name>/`:
`form.yaml` (the Wolfi packages and accounts apko installs, and what apko cannot say:
the form it is built on, its services, its network policy, the posture checks it
fails and why), `rootfs/` (laid over the packages) and, where needed, `cmd/`,
`test/`, `melange/` and a README. It gets the parts of the form it is built on and
its ancestors. [forms/README.md](../forms/README.md) lists every file and key;
[design/implemented/forms.md](design/implemented/forms.md) explains composition;
`make list-forms` lists chains.

[Variants](variants.md) add compatible features inline. For example, `howl run
--with postgresql --variant vector --ssh` selects pgvector and operator SSH. Every
form offers implicit `ssh`; selected combinations keep separate update channels.

[forms-catalog.md](forms-catalog.md) lists every form. Each boots the same way:
stage0 opens its `root.erofs` read-only through dm-verity and hands over to init
([design/implemented/verified-boot.md](design/implemented/verified-boot.md)). For
local test iteration only, howl's `--dev=ssh` adds root SSH with a local key
(`$XDG_DATA_HOME/howl/keys/dev/`) that `howl ssh root@NAME` selects and
[local iteration](design/implemented/local-test-iteration.md) reuses. Published
images have no developer SSH; login forms or the `ssh` variant give operator access.

## The runtime forms

Data transfer operates on `/data`, or exactly one `/data/svc/NAME`, using
`howl export` and `howl import`. Forms no longer declare seed or sync import modes.
Normal initialization uses an existing restored service directory directly. See
[data storage](data.md) and the [import design](design/pending/data-import.md).

`nginx`, `php`, `node`, `python`, `ruby` and `jre` are each `prod` plus one runtime
from Wolfi, as Chainguard's images are, and no application. `nginx` and `php` serve
the site laid in their html root; the others start nothing until a form on them
brings a service. The `-app` forms bring one for the application laid in
`/usr/lib/app`, and ship none: until yours is there, the service stays down and says
why on the console. The `-example` forms add a sample application, a tutorial each
([examples](../examples/README.md)).

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
home `/var/empty`, shell `/sbin/nologin`), and each of these programs runs on a leash
([programs.md](programs.md)) as that user: binding its own port and no other, reading
the image, writing only `/run/svc/NAME` and `/data/svc/NAME`, with no capability.

An interpreter is the point of these forms, so posture's `programs-no-interpreters`
fails on them by design, as `kernel-no-hypervisor` does on `qemu-host`. Each says so
in its form.yaml, with its excuse:

```yaml
weaknesses:
  programs-no-interpreters: php-fpm runs the application, which is what this form is for
```

Excuses are never inherited. `make check` fails a machine on any failure its form
does not excuse, and on any excused failure that passes.

## Files a form leaves out

A package may declare a dependency nothing on the machine runs: Wolfi's `valkey-9.1`
brings bash, because `posix-libc-utils` ships `ldd` as a bash script. `prune:
[usr/bin/bash]` names such files by path in the image; the build leaves them out of
the root and lists them in `/usr/share/werewolf/prune`, so the updater removes them
from every slot it builds. Prune what a dependency drags in, never a package the form
uses.

## Bundles: one form taking several

A form is built on one other form, but a machine that runs an application with its
database is several side by side. A form may take other forms `with` it, and gets
their parts too: packages, accounts, services, policies and pruning.

```yaml
# forms/mastodon/form.yaml
base: ruby
with: [postgresql, valkey, nginx]
```

The build puts each member's forms that the form's own chain lacks before the form
itself, in order, so the form's own files win where two lay the same path. Two users
or groups with the same name or id fail the build.

## Packages Wolfi does not ship

Third-party software comes from a signed feed by package name: `../packages` builds
what Wolfi lacks or ships unfit, rarely what it ships (named `-werewolf`), and
`../packages/lang` holds the runtimes Werewolf patches. `minimal` lists both feeds; a
name either covers comes from it, or the build fails. Built-in forms name published
dependencies in `packages` and build with no package source checkout; image locks pin
each architecture's resolved versions and checksums. Recipes for Werewolf's own
software or private development packages stay beside their source in
`melange/*.yaml`, as in `forms/vuln-demo`; melange builds them in QEMU or bubblewrap,
overlays the packages and checks shared-library dependencies. See
[CONTRIBUTING.md](../CONTRIBUTING.md#package-dependencies).

## Private configuration files

`config NAME PATH` in a service file gives that service one file:

```text
config users /run/config/nats/users.conf
```

For service `nats`, leash copies it to the service's `/run/svc/nats/users`, mode
`0600`, at every start; point the program's configuration there. The service cannot
read the rest of `/run/config`. NAME matches `[a-z][a-z0-9-]*`, as `howl pack` takes
it as `--NAME FILE`; name the file in the tar NAME too, or by its usual format
(`tls.crt`). A service may name up to 32 files of at most 64 KiB; a missing one keeps
it down unless the line ends in `optional`. Contents are copied unchanged and never
logged. Credentials go in the boot config, not the image ([cloud.md](cloud.md)). For
a value needed in an environment variable, `secret NAME PATH` reads one line into
NAME; howl takes it as `--smtp-password FILE` for `SMTP_PASSWORD`.

## People

People come from boot configuration or cloud metadata. See [people and SSH
accounts](people.md) for keys, admin grants, account lifecycle and Howl defaults.

## Settings

*Settings* are values that differ per machine but are not secret: a router's routes,
a database URL. A service file declares each with a type and says where the values go
([design/implemented/settings.md](design/implemented/settings.md)):

```text
config  settings /run/config/tailscale/settings.json
setting routes cidr... as advertiseRoutes
render  json config.json from /etc/tailscale/config.json
```

`config settings` names the boot config's file, `{"routes": ["10.20.0.0/24"]}`, which
may be missing. `setting NAME TYPE[...] [required] [as KEY]` declares one of up to 32
a service: NAME is its JSON key and `howl pack`'s `--NAME`, KEY its name in the
output (NAME by default; for `env`, upper case with `_`); a list, `TYPE...`, holds up
to 32.

| Type | Accepts |
| --- | --- |
| `ip`, `cidr`, `addrport`, `hostport` | a literal address; a network with no host bits; address and port; hostname or address and port |
| `hostname`, `port`, `url` | RFC 1123, at most 253 bytes; 1 to 65535; `http` or `https` without credentials, at most 2 KiB |
| `int`, `bool`, `string` | a signed 64-bit number; `true` or `false`; UTF-8 without control characters, at most 1 KiB |

At each start leash runs `service-config` as the service; it checks every value
against its type and writes `/run/svc/SERVICE/FILE` as `render FORMAT FILE` says:
`env` (`KEY=VALUE` lines leash adds to the environment; no lists of `string` or
`url`, no `PATH` or `LD_*`), `json` (one object, `from PATH` merged into a file from
the image, dotted keys nested) or `conf` (`KEY VALUE...` lines; no `string` or
`url`). A refused pair does not build. A setting not given is left out, so the
daemon's default holds; `required` keeps the service down instead, as an undeclared
key or a mistyped value does, with one line naming it.

See [applications.md](applications.md) for building and shipping applications.
