# PostgreSQL - Hardened VM

A database for the other services on this machine:
[PostgreSQL](https://www.postgresql.org) 18, on a UNIX socket. The form's manifest is
[form.yaml](form.yaml).

[Images, test status and download
instructions](https://dist.werewolf-linux.org/boot/v1/postgresql/index.html).

## Security Posture

The server runs as its own user, and nothing else does. There is no shell. Landlock and
seccomp hold it to its socket and to `/data/svc/postgres`. The root is read-only.

- No TCP. `listen_addresses` is empty. A local role is the system user's name, and a TCP
  login is refused.
- `initdb` uses the static sh-shim: one declared program and its arguments, with only
  `/dev/null` redirections. Setup needs no preload.
- The cluster is mode 0700. If it was made and then lost, the next start refuses to
  create an empty one over it.
- PostgreSQL compiles costly queries to machine code with LLVM. `jit` stays on, which is
  its default.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
howl create postgresql --with postgresql
```

Nothing answers on the network. A form takes this one `with` and brings its own
database. Statements are in [PostgreSQL's SQL
reference](https://www.postgresql.org/docs/18/sql.html).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
howl create postgresql --with postgresql --on gcp --allow-from me
```

`--allow-from` opens no port: there is no listener. Keep the database on the same
machine as the service that queries it.

### Importing data

The host cannot reach this server. `--import` attaches a directory of SQL. `pg-init`
applies it once, in the `postgres` database, while it makes the cluster.
[example/shop.sql](example/shop.sql) is a two-row shop. `CREATE DATABASE` is not
available in that backend.

```sh
howl create postgresql --with postgresql --import ./dump
```

A form can still carry `rootfs/usr/share/werewolf-postgres/NAME.sql`. That SQL runs on
every start.

### Known Quirks

- Debian's PostgreSQL listens on port 5432. This one does not.
- A dump's roles must be system users on this machine. Peer authentication has no
  passwords.
- The image's SQL files run on every start. An `INSERT` needs a conflict target, or the
  rows multiply. `--import` runs once.
- This form owns `/bin/sh` as sh-shim, including DEV builds. The console debugger uses
  `/bin/ash`. A form replacing the PostgreSQL service must keep its explicit initdb,
  sh-shim and locale run paths.

## Size

PostgreSQL brings LLVM and ICU. The demo's image grows by about 70 MB for them.
