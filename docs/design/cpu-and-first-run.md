# cpu, and a first run

Built, 2026-10-09: `cpu` (lib/service.zig, cmd/leash; demo's scan uses it);
the first run is a pattern for the forms that need it. Two base features
[forms-catalog.md](forms-catalog.md) lists for mastodon, minecraft,
jellyfin and mattermost.

## Summary

A service file's `cpu WEIGHT` gives the service a share of the CPUs when
they are contended, so one busy service cannot starve the others. A form
whose daemon is configured through its own API does that in its `before`
program, with the daemon bound to loopback, so no visitor meets a setup
wizard.

## Background

leash puts each service in its own cgroup with `memory.max` and
`pids.max` ([cmd/leash](../../cmd/leash/README.md)); init delegates the
memory and pids controllers under `/run/cgroup/svc`. Nothing limits CPU:
a Sidekiq queue flooded by federation, a Minecraft tick loop or a
Jellyfin transcode can take every CPU from nginx, sshd and the updater.

Some daemons are set up only through their API once they run: Mattermost
and Jellyfin open a wizard that whoever reaches the port first completes.
gitea-init avoids that for Gitea, whose CLI works with the server down;
Mastodon's `db:prepare` and `tootctl` do too.

## Goals

- `cpu WEIGHT` in a service file, checked at build and set by leash.
- A form configures an API-only daemon before its port is reachable.
- No new privilege, and nothing new in leash for the first run.

## Non-Goals

- A hard CPU cap (`cpu.max`): it idles CPUs a quiet machine could lend.
- CPU affinity or real-time scheduling.
- A generic first-run program: each daemon's API differs.

## Detailed design

**cpu.** `cpu WEIGHT`, 1 to 10000, sets the service's `cpu.weight`; a
service without the line keeps the kernel's 100. Weight only matters when
CPUs are contended: `cpu 25` gets a quarter of an equal share, and an
idle machine still lends it every CPU. init delegates `+cpu` under
`/run/cgroup/svc`, written apart from `+memory +pids` so a kernel without
the controller loses nothing. If leash cannot write `cpu.weight` it logs
`uncapped` and starts the service: a share is fairness, not containment,
unlike `memory`, whose failure parks the service.

**First run.** The form's `before` program, as the service's user and
under its leash:

1. starts the daemon bound to 127.0.0.1 on its declared port, through the
   daemon's own setting (an environment variable or a flag);
2. waits for its API, applies the configuration from `/run/config`, and
   records in `/data/svc/NAME` that setup is done;
3. stops it, and exits 0; leash then starts the daemon as declared.

Landlock grants a port, not an address, so the loopback bind needs no
new rule, and fence's ingress refusal never sees loopback traffic. The
daemon is in the service's `run` list, as gitea-hook's targets are. A
failed setup exits non-zero, and leash parks the service: the port never
opens with the wizard waiting.

## Drawbacks

- Weights are relative: a form must set them against its other services.
- Each first-run program knows its daemon's API, and breaks when it changes.

## Alternatives Considered

- **cpu.max.** A hard cap protects as well under load, but wastes idle
  CPUs and needs a period and quota a form author would have to tune.
- **A gate in fence** that opens a port when leash says so. It needs
  `CAP_NET_ADMIN` after boot, which fence drops for good.
- **A `first-run` directive in leash.** The before program already runs at
  the right moment with the right rights; a directive adds code and no power.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| A service raises its own weight | the cgroup is joined as root before the drop; the service cannot write it |
| A visitor completes the wizard | the daemon listens on loopback until setup ends |
| A setup secret leaks into a log | read from `/run/config`, never an argument or the log |

## Reliability Considerations

`cpu.weight` is set before the service starts, so it holds from the first
instruction. A first-run program records completion on `/data`, so a
restart does not repeat setup, and logs each step as JSON.
