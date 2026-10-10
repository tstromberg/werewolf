# PostgreSQL - Hardened VM

A database for the other services on this machine: [PostgreSQL](https://www.postgresql.org) 17, on a UNIX socket. The form's manifest is [form.yaml](form.yaml).

## Security Posture

The server runs as its own user, and nothing else does. There is no shell. Landlock and seccomp hold it to its socket and to `/data/svc/postgres`. The root is read-only.

- No TCP. `listen_addresses` is empty. A local role is the system user's name, and a TCP login is refused.
- `initdb` would run a shell. `pg-init` runs those commands itself, and only when they are one program and its arguments.
- The cluster is mode 0700. If it was made and then lost, the next start refuses to create an empty one over it.
- PostgreSQL compiles costly queries to machine code with LLVM. `jit` stays on, which is its default.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
howl create postgresql --with postgresql
```

Nothing answers on the network. A form takes this one `with` and brings its own database. Statements are in [PostgreSQL's SQL reference](https://www.postgresql.org/docs/17/sql.html).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
howl create postgresql --with postgresql --on gcp --allow-from me
```

`--allow-from` opens no port: there is no listener. Keep the database on the same machine as the service that queries it.

### Migrating data in

The host cannot reach this server. `--import` attaches a directory of SQL. `pg-init` applies it once, in the `postgres` database, while it makes the cluster. [example/shop.sql](example/shop.sql) is a two-row shop. `CREATE DATABASE` is not available in that backend.

```sh
howl create postgresql --with postgresql --import ./dump
```

A form can still carry `rootfs/usr/share/werewolf-postgres/NAME.sql`. That SQL runs on every start.

### Known Quirks

- Debian's PostgreSQL listens on port 5432. This one does not.
- A dump's roles must be system users on this machine. Peer authentication has no passwords.
- The image's SQL files run on every start. An `INSERT` needs a conflict target, or the rows multiply. `--import` runs once.
- Stay on 17. A new major version is a new form: the data needs `pg_upgrade`.

## Size

PostgreSQL brings LLVM and ICU. The demo's image grows by about 70 MB for them.
