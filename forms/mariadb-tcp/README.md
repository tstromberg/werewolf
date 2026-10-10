# MariaDB TCP - Hardened VM

[MariaDB](https://mariadb.org) 12.3 on TCP port 3306: [mariadb-local](../mariadb-local/README.md) with a reachable listener. The form's manifest is [form.yaml](form.yaml).

## Security Posture

The server runs as its own user. There is no shell and no perl. Landlock and seccomp hold it to its socket, to port 3306, and to `/data/svc/mariadb`. The root is read-only.

- The socket remains. A local account is still `unix_socket`.
- Port 3306 is open. A client on the network cannot use `unix_socket`. It needs an account with a password, in the SQL a form carries.
- A query cannot read or write a file on the machine. `local-infile` is off, and the file privilege points at an empty directory.
- The data directory is mode 0700. If it was made and then lost, the next start refuses to create an empty one over it.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
howl create mariadb-tcp --with mariadb-tcp
```

The server answers on port 3306 of ADDRESS, and on its socket. Statements are in [MariaDB's SQL reference](https://mariadb.com/kb/en/sql-statements/).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
howl create mariadb-tcp --with mariadb-tcp --on gcp --allow-from me
```

`--allow-from me` admits your address to port 3306.

### Migrating data in

`--import` applies a directory of SQL once, while the data directory is first made. The accounts in it need passwords. `unix_socket` does not cross the network.

```sh
howl create mariadb-tcp --with mariadb-tcp --import ./dump
```

Once an account exists, a client can load more.

```sh
mysql --host ADDRESS --port 3306 -u app -p <dump.sql
```

A form can still carry `rootfs/usr/share/werewolf-mariadb/NAME.sql`, applied before each start. [mariadb-local's shop.sql](../mariadb-local/example/shop.sql) is a socket account, so it belongs on that form.

### Known Quirks

- Debian's root has a password and listens on 3306. This one listens on 3306 and has no such account until the SQL creates one.
- The image's SQL files run on every start. An `INSERT` needs a key and `INSERT IGNORE`, or the rows multiply. `--import` runs once.
- There is no replication. `mariadb-upgrade` is not run. Stay on 12.3. A new major version is a new form.

### Network Exposure

tcp/3306
