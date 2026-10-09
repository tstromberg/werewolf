# pg-init

## Summary

pg-init is PostgreSQL's `before` step. It makes the cluster on the first
start and applies the image's SQL before every start. The server starts
only if both succeed.

## Background

The `postgresql` form (and `demo`, built on it) runs PostgreSQL 17 as the
`postgres` user, for local clients over a UNIX socket. The server needs a
cluster before it will start, and a form's roles, schemas and grants must be
in it. Distros do this with a shell script; werewolf has no shell. leash runs
each `before` program as the service's user, under the service's Landlock
rules (forms/postgresql/rootfs/etc/sv/postgres/service), and parks the
service if one fails.

## Goals

- The cluster is made exactly once, and is whole or absent.
- If a cluster was made and is now gone, pg-init says so and does not make
  an empty one.
- The image's SQL is applied before the server takes a connection.
- Nothing from outside the image decides what runs.

## Non-Goals

- Upgrading between major versions. A new major is a new form, since its
  data needs `pg_upgrade`.
- Backups, replication, or SQL from a config disk.

## Detailed design

1. **First start of this boot**: pg-init creates
   `/run/svc/postgres/pg-init-started`. `/run` is empty at each boot.
2. **A cluster exists** (`/data/svc/postgres/data/PG_VERSION`): it is kept.
   If `cluster-made` beside it is missing, pg-init writes it. On the first
   start of a boot it removes the server's `postmaster.pid`, because after a
   power cut that pid may belong to another process.
3. **No cluster, but `cluster-made` exists**: the data was lost. pg-init says
   so and fails, so the server stays down.
4. **No cluster, and never one**: pg-init removes any `data.new` that an
   interrupted start left. `initdb` makes the cluster in `data.new` (UTF-8,
   no locale, local logins by peer, TCP logins rejected) with
   `popen-shim.so` preloaded, since `initdb` starts a server through
   `popen(3)` and `system(3)`, which need a shell. pg-init then renames
   `data.new` to `data`, syncs the directory, and writes and syncs
   `cluster-made`.
5. **The SQL**: every `/usr/share/werewolf-postgres/*.sql`, in name order, up
   to 1 MiB each, is fed to `postgres --single` in the `postgres` database
   with `exit_on_error`. Single-user mode runs before the real server is up.
   With `-j` a statement ends at a semicolon before an empty line, so a `DO`
   block may contain semicolons. The first error keeps the server down.
6. **Logging**: one console line per step: `pg-init: keeping the cluster
   in ...`, `making`, `removed the lock`, `applied N SQL files`, or why not.

## Drawbacks

- The SQL runs before every start, so it must be idempotent (`IF NOT
  EXISTS`, `DO` blocks for roles).
- A lost cluster keeps the server down until someone removes `cluster-made`.

## Alternatives Considered

### Run initdb in place
`initdb` writes `PG_VERSION` first. If it was stopped partway (a power cut,
a shutdown, or `sv restart`, after which leash-reap kills what is left), the
half-made cluster looked complete, and the server failed on every boot.

### Judge the lock by the clock
Comparing the lock's start time with the boot time trusts the real-time
clock across boots. The mark in `/run` needs no clock.

### A shell script, as distros ship
There is no shell, and the steps are few.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| SQL or arguments from outside | Only the image's files and fixed arguments are used. |
| Excess privilege | It runs as `postgres` under the server's Landlock rules: no more than the server has. |
| A shell for initdb | `popen-shim.so`, preloaded only into initdb, runs only commands of one known shape. |
| Two servers on one data directory | Only a lock from an earlier boot is removed; the server judges one from this boot. |
| Data silently replaced | `cluster-made` stops a lost cluster from being remade. |

## Reliability Considerations

- **Crash-safe creation**: the cluster is whole or absent, and its mark
  reaches disk after it.
- **Power cuts**: the next boot removes the stale lock, and PostgreSQL
  replays its WAL.
- **Tested**: `check-persist` makes the cluster, keeps it across a reboot,
  and starts after a power cut that left the lock behind.
