# pg-init

## Summary

PostgreSQL's `before` step: it makes the cluster once, on the first start,
and applies the image's SQL before every start. The server starts only if
both succeed.

## Background

The `postgresql` form (and `demo`, built on it) runs PostgreSQL 17 as the
`postgres` user, leashed, for local clients over a UNIX socket. A cluster
must exist before the server will start, and a form's roles, schemas and
grants must be in it. A distro does both with a shell script; werewolf has
no shell. leash runs each `before` program as the service's user, under its
Landlock rules, and parks the service if one fails.

## Goals

- A cluster made exactly once, whole or not at all.
- A cluster that was made and is now gone is said, not remade empty.
- The image's SQL in place before the server takes a connection.
- Nothing from outside the image decides what runs.

## Non-Goals

- Upgrading between major versions: a new major is a new form, as its data
  needs `pg_upgrade`.
- Backups, replication, or SQL from a config disk.

## Detailed design

1. **First start this boot**: it leaves `/run/svc/postgres/pg-init-started`,
   in `/run`, which each boot begins empty.
2. **A cluster** (`/data/svc/postgres/data/PG_VERSION`) is kept. If
   `cluster-made` beside it is missing, it is written. On the first start
   of a boot, the server's `postmaster.pid` is removed: a power cut leaves
   it naming a pid this boot may have given to something else.
3. **No cluster, but `cluster-made`**: the data was lost. It says so, and
   the server stays down.
4. **No cluster, never one**: any `data.new` a stopped start left is
   removed. `initdb` makes the cluster in `data.new` (UTF-8, no locale,
   local logins by peer, TCP logins rejected), with `popen-shim.so`
   preloaded, since `initdb` starts its server through `popen` and
   `system`. Then `data.new` is renamed to `data`, the directory synced,
   and `cluster-made` written and synced.
5. **The SQL**: every `/usr/share/werewolf-postgres/*.sql`, in name order,
   up to 1 MiB each, fed to `postgres --single` with `exit_on_error`. A
   statement ends at a semicolon before an empty line (`-j`), so a `DO`
   block may hold its own. The first error keeps the server down.
6. **One line each** on the console: `pg-init: keeping the cluster in ...`,
   `making`, `removed the lock`, `applied N SQL files`, or why not.

## Drawbacks

- The SQL runs before every start, so it must be written to change nothing
  the second time (`IF NOT EXISTS`, `DO` blocks for roles).
- A cluster lost from a disk that once had one keeps the server down until
  someone removes `cluster-made`.

## Alternatives Considered

### Run initdb in place
`initdb` writes `PG_VERSION` before anything else. Stopped partway (a power
cut, a shutdown, or `sv restart`, after which leash-reap kills what is left),
it left a cluster that read as made, on which the server failed every boot.

### Judge the lock by the clock
Comparing the lock's start time with this boot's start trusted the real-time
clock to agree across boots. The mark in `/run` needs no clock.

### A shell script, as distros ship
There is no shell, and the steps are few.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| SQL or arguments from outside | Only the image's files and fixed arguments. |
| Its own privilege | The `postgres` user and the server's Landlock rules: no more than the server has. |
| A shell for initdb | `popen-shim.so`, for initdb alone, runs only commands of its one shape. |
| Two servers on one data directory | Only a lock from an earlier boot is removed; one from this boot, the server judges itself. |
| Data silently replaced | `cluster-made`: a lost cluster is not remade. |

## Reliability Considerations

- **Crash-safe making**: a cluster is whole or absent, and its mark follows
  it on disk.
- **Power cuts**: the next boot removes the dead lock, and PostgreSQL
  replays its WAL.
- **Tested**: `check-persist` makes the cluster, keeps it across a reboot,
  and starts after a power cut with the lock left behind.
