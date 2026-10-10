# cron

The `cron` form is `prod` with [supercronic](https://github.com/aptible/supercronic),
a cron for one service's jobs. A form takes it beside its base, `with:
[cron]`, or builds on it, `base: cron`, to run programs on a schedule.

| | |
| --- | --- |
| Runs | supercronic, leashed as the `supercronic` user, on `/etc/cron/crontab` |
| Jobs | none as shipped. Each runs as `sh-shim -c COMMAND` ([sh-shim](../../cmd/sh-shim/README.md)), as the same user, under the same leash |
| Listens, sends | nothing |
| Limits | 64 MiB and a quarter share of contended CPUs, for supercronic and its jobs together |
| Logs | a JSON line per event on the console: each job's start, its output, line by line, and how it ended |

Schedules are crontab(5) lines, with an optional seconds field first, in
UTC. A job never overlaps its own last run. The user is not `cron`
because Wolfi's base layout has that account already (uid 16).

## Security Posture

The service runs as its own user. Landlock and seccomp hold it to the files and ports its manifest names. The root is read-only. An update replaces the image, and `/data` is what survives.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
howl create cron --with cron
```

This command runs the form alone, which has no jobs. A form takes it beside its own and lays a crontab over `etc/cron/crontab`, as below.

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
howl create cron --with cron --on gcp --allow-from me
```

`--allow-from` opens no port: there is no listener.

### Migrating data in

This machine starts empty. The jobs are in the create command or `--config`. There is no database to import.


## Inheriting it

There is no shell, so supercronic runs each job through sh-shim, the
crontab's `SHELL`: one program and its words, quoted as sh would quote
them. A pipe, a redirection, a variable or a `;` is refused, and the job
fails in the log rather than running mangled.

A form with jobs lays two files over this form's; a later form's rootfs
files win ([forms/README.md](../README.md)):

- `etc/cron/crontab`: its jobs, below the `SHELL=/usr/lib/werewolf/sh-shim`
  line it keeps. Variables on lines of their own reach every job.
- `etc/sv/cron/service`: the leash. `run` names every program a job
  starts but sh-shim, which the sh-shim form's `allow: [sh]` lets every
  leashed service run; `pledge`, `write`, `connect` and `memory` add
  what the jobs do. `user` stays `supercronic`, or names another user of
  the form's own.

A sketch for [Mastodon](../../docs/design/mastodon.md), whose jobs clean
up remote media and preview cards with `tootctl`:

```yaml
# forms/mastodon/form.yaml
base: ruby
with: [postgresql, valkey, nginx, cron]
```

```
# forms/mastodon/rootfs/etc/cron/crontab
SHELL=/usr/lib/werewolf/sh-shim
RAILS_ENV=production
15 3 * * * /usr/bin/ruby /usr/lib/app/bin/tootctl media remove --days 7
45 3 * * * /usr/bin/ruby /usr/lib/app/bin/tootctl preview_cards remove --days 14
```

```yaml
# forms/mastodon/form.yaml
services:
  cron:
    exec: /usr/bin/supercronic -json -no-reap /etc/cron/crontab
    user: supercronic
    pledge: stdio rpath wpath proc exec unix connect
    run: /usr/bin/ruby
    read: /etc/cron
    write: /data/svc/mastodon/system
    connect: [/run/svc/postgres/.s.PGSQL.5432]
    memory: 768
    cpu: 25
```

tootctl reaches PostgreSQL as its peer, the `supercronic` role, and
removes media the `mastodon` group may write; it can execute nothing.

## Security

- **The leash is the boundary.** supercronic and every job share one
  user, one Landlock domain, one pledge and one cgroup. A job executes
  only what `run` names, writes only the service's own directories and
  its `write` paths, reaches only what `connect` and the form's `net`
  allow, and dies with the service (leash-reap). sh-shim is an adapter,
  not a control: it starts nothing Landlock would not let a job start.
- **No shell.** Nothing on the machine can read a command as sh would;
  sh-shim runs one program or refuses.
- **Schedules are the image's.** The crontab is in the verified,
  read-only root. A job cannot add a job or change one, since supercronic
  reads nothing writable.
- **Output cannot forge the console.** supercronic logs a job's output as
  JSON strings, control characters escaped.
- **Not per job.** Jobs that need different powers go in a second service,
  with its own crontab, user and leash.
- **No weaknesses** as shipped: no shell, and supercronic is a static Go
  program, not an interpreter.

## Checked

`make check-cron` runs [forms/cron/test/checks](test/checks):
supercronic runs as its user, with no capability and its pledge's
filter; a job runs, through sh-shim, which only the sh allowance lets it
run; and the kernel refused none of supercronic's or sh-shim's calls.
The shipped crontab has no job, so leash starts a second supercronic
from this service file, only its crontab and one `run` program changed:
a job each second leaves a file owned by `supercronic`, and one naming a
program no `run` line names is refused by Landlock.
`make check-shellfree-cron` boots the form as it ships: no posture
failure, and supercronic takes sh-shim as its shell, quietly.
