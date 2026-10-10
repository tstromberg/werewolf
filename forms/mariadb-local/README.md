# MariaDB local - Hardened VM

A database for the other services on this machine: [MariaDB](https://mariadb.org) 12.3, the long-term release, on a UNIX socket. The form's manifest is [form.yaml](form.yaml). The same server on a reachable port is [mariadb-tcp](../mariadb-tcp/README.md).

## Security Posture

The server runs as its own user, and nothing else does. There is no shell and no perl. Landlock and seccomp hold it to its socket and to `/data/svc/mariadb`. The root is read-only.

- No TCP. The socket is the only way in, and MariaDB takes the peer as the user.
- No passwords. An account is `unix_socket`.
- A query cannot read or write a file on the machine. `local-infile` is off, and the file privilege points at an empty directory.
- The data directory is mode 0700. If it was made and then lost, the next start refuses to create an empty one over it.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
howl create mariadb-local --with mariadb-local
```

Nothing answers on the network. A form takes this one `with` and brings its own database, as [wordpress-mariadb](../wordpress-mariadb/README.md) does. Statements are in [MariaDB's SQL reference](https://mariadb.com/kb/en/sql-statements/).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
howl create mariadb-local --with mariadb-local --on gcp --allow-from me
```

`--allow-from` opens no port: there is no listener. Keep the database on the same machine as the service that queries it.

### Migrating data in

The host cannot reach this server. `--import` attaches a directory of SQL. mariadb-init applies it once, while it makes the data directory, and reads it from the disk. [example/shop.sql](example/shop.sql) is a two-row shop. The account is the system user `app`.

```sh
howl create mariadb-local --with mariadb-local --import ./dump
```

A form can still carry `rootfs/usr/share/werewolf-mariadb/NAME.sql`. That SQL runs on every start.

### Known Quirks

- Debian's MariaDB listens on port 3306 and has a password for root. This one does neither. [mariadb-tcp](../mariadb-tcp/README.md) listens on 3306 and still has no root password.
- A dump's `IDENTIFIED BY` does not work here until the account is `unix_socket` and names a system user on this machine.
- The image's SQL files run on every start. An `INSERT` needs a key and `INSERT IGNORE`, or the rows multiply. `--import` runs once.
- There is no replication. `mariadb-upgrade` is not run. Stay on 12.3. A new major version is a new form.
