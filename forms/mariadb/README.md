# MariaDB

The `mariadb` form is MariaDB 12.3, the long-term release, for the
machine's own services: on a UNIX socket alone, its data in
`/data/svc/mariadb`, made on the first start without a shell, on one
leash ([design/service-forms.md](../../docs/design/service-forms.md)).
A form takes it `with`, as `wordpress-mariadb` does, and brings its own
database and role.

## Use it from a form

```yaml
with: [mariadb]
```

and in the form's `rootfs/usr/share/werewolf-mariadb/NAME.sql`:

```sql
CREATE DATABASE IF NOT EXISTS app CHARACTER SET utf8mb4;

CREATE USER IF NOT EXISTS 'app'@'localhost' IDENTIFIED VIA unix_socket;

GRANT ALL PRIVILEGES ON app.* TO 'app'@'localhost';
```

The service running as the system user `app` connects to
`/run/svc/mariadb/mariadb.sock` (its `connect` line names it) as `app`,
with no password: MariaDB knows it by the socket's peer (unix_socket).
The SQL is applied before every start, so each statement must change
nothing the second time.

## How it is held

- **mariadb-init first.** [cmd/mariadb-init](cmd/mariadb-init/mariadb-init.zig)
  runs before the server, on its leash. On the first start it does
  `mariadb-install-db`'s work, a shell script here left out: it feeds
  MariaDB's system tables, help and sys schema to `mariadbd --bootstrap`,
  in `data.new`, renamed to `data` when whole. A data directory that was
  made and is gone is not made again empty: it refuses, saying so. Before
  every start it applies the forms' SQL, in name order, the same way,
  after loading the grant tables bootstrap mode leaves out.
- **A socket alone.** `skip-networking`: no TCP port, and the form
  declares none.
- **No files for clients.** `local-infile` off, and `secure-file-priv`
  an empty directory none may write: no client reads or writes the
  machine's files, root's FILE privilege included.
- **Its own user, administering.** The account `mariadb`, the service's
  system user, by unix_socket; `root` only as the system's root, by the
  same.
- **Its own files.** Data and its temporary files on `/data`, the data
  directory 0700 and what MariaDB makes in it 0750 and 0640 (`UMASK`);
  its socket and pid in `/run/svc/mariadb`.
- **No shell, no perl.** Its scripts' interpreters are pruned;
  `mariadbd-safe`, `mytop` and the cluster's tools cannot run.
- **The long-term release.** 12.3 is supported until 2029. A rolled-back
  slot still reads `/data`: minor releases keep the format. Wolfi's 11.8
  builds stopped in 2025, six releases behind upstream's, so the form
  took 12.3; a new major is a new form.

## Drawbacks

- One machine: no replication, no backups off it.
- Open: MariaDB advises `mariadb-upgrade` after an update, which this
  form does not run.

## Checked

`make check-mariadb` boots it: root answers on the socket as itself,
nothing listens on 3306, `local_infile` is 0, `secure_file_priv` is
`/var/empty/`, an `INTO OUTFILE` and a `LOAD_FILE` of `/etc/passwd`
fail even for root, and the data is on `/data`, 0700, MariaDB's.
`make check-shellfree-mariadb` boots it as it ships: on the blank disk
mariadb-init makes the data, and the server starts on its socket alone.
