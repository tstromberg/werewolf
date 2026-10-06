# PostgreSQL

The `postgresql` form is `prod` with PostgreSQL 17, for the machine's own
services. `demo` is built on it: its page and scan keep what they find
there ([demo.md](demo.md)).

| | |
| --- | --- |
| Listens | a UNIX socket in `/run/svc/postgres`, and nothing else: `listen_addresses` is empty and the form declares no port, so fence would refuse one anyway |
| Data | `/data/svc/postgres/data`, made by `initdb` on the first start |
| Runs as | `postgres` (uid 70), leashed ([programs.md](programs.md)): it reads the image and writes only its own directories |
| Logs in | by peer authentication: a local role is its system user's name, and TCP logins are refused |
| Updates | within PostgreSQL 17, with the rest of the image; the major version is the package's name, since a new one needs `pg_upgrade` |

## Starting without a shell

`initdb` runs the server it is setting up through `popen(3)` and
`system(3)`, which glibc runs as `/bin/sh -c`, and werewolf has no
`/bin/sh`. Its commands are all of one shape, a program and its arguments
with a redirection or two:

```
"/usr/libexec/postgresql17/postgres" --check -c max_connections=100 < "/dev/null" > "/dev/null" 2>&1
```

So `pg-init` (`cmd/pg-init/pg-init.zig`), which leash runs before the server,
preloads `popen-shim.so` (`cmd/popen-shim/popen-shim.zig`) into `initdb`. Its
`popen`, `pclose` and `system` take that shape and nothing else: an
absolute program and plain or double-quoted words, then `<FILE`, `>FILE`
and `2>&1`. They run the program directly. Anything more (a pipe, `;`, `$`,
a glob, a single quote) is not run, and the command is printed on stderr,
so `initdb` fails where it can be seen. The servers `initdb` starts to
set the cluster up keep the library, since one of them runs `locale -a` to
import the system's locales; there are none to import, so that command
reads as empty. The server leash starts afterwards never has it. Nothing
on the machine is a shell, and posture's check that there is none still
passes.

## The image's SQL

Before each start, while the server is still down, pg-init applies every
`/usr/share/werewolf-postgres/*.sql`, in name order, to the `postgres`
database as the superuser, through the server in single-user mode. A form
brings its roles, schemas and grants this way, written so that applying
them again changes nothing (`CREATE ... IF NOT EXISTS`, and `DO` blocks
for roles); the first error keeps the server down, with the reason on the
console. A statement ends at a semicolon before an empty line.

The demo's (`forms/demo/usr/share/werewolf-postgres/status.sql`) makes
the roles `status` and `grype` and a schema `status` with two tables:
each boot's posture report, and each scan's summary, as `jsonb`. The
`status` role owns them; `grype` may add scans and nothing more.

## Size

Wolfi's PostgreSQL brings LLVM, for its query compiler, and ICU's data:
about 200 MB of the 300 MB it adds unpacked. The demo's `root.erofs` grows
from 28 MB to 96 MB. On a slot, which the demo boots from, that is disk,
not memory.
