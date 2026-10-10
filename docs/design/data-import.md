# Data import

Built, 2026-10-10.

## Summary

`howl create --import DIR` attaches a read-only disk. The form streams it
into the database once, while it first makes its data. The console says
each step. The form's import stanza is that command.

## Background

The traffic is inward ([TEMPLATE.md](../../forms/TEMPLATE.md)). Most forms
have no sshd. `/data` is the only writable place ([data.md](../data.md));
init formats it blank. The config tar is too small ([cloud.md](../cloud.md)).
Image SQL runs every start and must be idempotent. A dump is not.

## Goals

- `--import DIR` on `mariadb-local` imports once. A second boot does not.
- Each step is one console line. Failure leaves the server down and the
  database unmade.
- The README states the command, not `make`. That block is not the example
  fence ([examples.md](examples.md)).

## Non-Goals

Copying data out. A dump format howl understands. The image, the config tar,
or user-data as the channel. One importer for every database.

## Detailed design

`--import DIR` builds an ext4 image labelled `werewolf-import` and attaches
it read-only. It is not a tar: init takes the first ustar disk as the config
([cli.md](cli.md)). init mounts one such disk at `/run/werewolf/import`,
`ro,nosuid,nodev,noexec,nosymfollow`. The directory always exists, so a
service may read it. Two disks with the label, or a mount that fails: init
mounts neither and writes `import-failed` in that directory.

```
werewolf: import: /dev/vdc on /run/werewolf/import
```

MariaDB is the case. The service gains one read. `mariadb-tcp` restates
the service, so it names the same read.

```
read: /etc/mariadb /run/werewolf/import
```

`mariadb-init` streams `/run/werewolf/import/*.sql` into `mariadbd
--bootstrap` against `data.new`, after the system tables and before the
rename. It does not copy the dump onto `/data`. A symlink is refused. If
`import-failed` is there, it makes no database.

```
mariadb-init: making the data in /data/svc/mariadb/data
mariadb-init: imported /run/werewolf/import/shop.sql
```

Failure removes `data.new`, sets no mark, and leaves the server down.
The dump is still on the disk. The next boot reads it again.

```
mariadb-init: /usr/bin/mariadbd --bootstrap failed; see above
mariadb-init: import kept on /run/werewolf/import
```

Success renames `data.new` to `data`, syncs, and writes the mark. A later
boot that finds the data keeps it and does not import. Image SQL still runs.

A different dump is `howl delete`, then `create`. `--import` on a machine
that already exists is refused. `--on gcp` refuses `--import`: it cannot
attach the disk. PostgreSQL streams the same way. Valkey copies one
snapshot into its data directory, because the file has to land there. The
form writes that itself.

## Drawbacks

The dump stays attached until `howl delete`. Each form writes its own few
lines.

## Alternatives Considered

`--app` puts one dump in every machine from that image. The config tar is
too small. Copying the dump to `/data` first keeps a second copy until the
import commits, so the data disk must hold the dump and the database. The
import disk is already attached on the next boot.

## Security Considerations

The dump stays out of the image and the config tar. The volume is
read-only, `nosuid,nodev,noexec,nosymfollow`. Only the service may read
the mount. A symlink on it is refused.

## Reliability Considerations

`data` appears only after the import succeeds. The mark is written after
the rename. A crash leaves `data.new`, which the next start deletes, and
the disk is read again. A short read does not commit. Two labelled disks
make no empty database.
