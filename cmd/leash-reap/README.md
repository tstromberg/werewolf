# leash-reap

## Summary

leash-reap is a leashed service's `./finish`. When runsv stops the service,
leash-reap kills everything left in the service's cgroup, logs how many
processes there were, and waits for them to die before runsv starts the
service again.

## Background

leash puts each service in its own cgroup, `/run/cgroup/svc/NAME`, and joins
it as root, so the service cannot leave. cmd/init mounts cgroup2 at
`/run/cgroup`, not under `/sys`, which fence's Landlock domain keeps
read-only, and delegates `memory` and `pids` to `/run/cgroup/svc`.
runsv supervises only the process it started. A service that forks, calls
`setsid` and execs leaves a daemon that reparents to PID 1 and outlives the
service. The daemon is still confined, but it is alive, and plain runit
would never reap it. runsv runs `./finish` as root, in the service's
directory, after the service ends: on `sv down`, a crash, a restart or
shutdown. It passes the exit status as arguments, which leash-reap ignores.

## Goals

- No process a service started outlives it.
- When one did, the console says so.
- The service restarts into an empty cgroup, with its ports free.

## Non-Goals

- Stopping the service. runsv still sends it TERM first.
- werewolf's own programs. They are not leashed and have no cgroup.

## Detailed design

- **The service name** is the basename of the directory runsv runs it in.
  It must be 1 to 64 letters, digits, `-` or `_`, so the path is always a
  leaf of `/run/cgroup/svc`.
- **Leftovers** are read from `cgroup.procs`. If there are none, it exits.
  Otherwise it writes `1` to `cgroup.kill`, which kills every process in
  the cgroup at once, including any that are mid-fork.
- **The wait** polls `cgroup.events` every 10 ms for `populated 0`, for up
  to five seconds.
- **One JSON line** goes to the console, in the same form as leash's:
  `leash-reap: {"event":"reaped","service":"nginx","left":2,"what":"killed"}`.
  `what` instead says when the kill failed, when `cgroup.events` could not
  be read, or when processes were still there after five seconds.
- **No cgroup2:** if `cgroup.procs` cannot be read, it does nothing.

## Drawbacks

- It cannot tell a worker that is still stopping from a child left behind
  on purpose. It counts and kills both.
- The five-second wait can delay a restart, or stage 3.

## Alternatives Considered

### runsv's TERM alone
runsv signals only the process it started, so a detached child survives
every stop until reboot.

### Kill by process group or session
A child that calls `setsid` leaves both. It cannot leave its cgroup.

### Return right after the kill
The kernel delivers the signal at once, but the processes die later. If
runsv restarts the service at that moment, ports are still held and the
start fails.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| A daemon left behind as a backdoor | Killed with the cgroup, and logged on the console. |
| A crafted directory name reaching another file | Only plain names are accepted, so the path is always a leaf of `/run/cgroup/svc`. |
| It runs as root | It trusts no argument, reads only its service's cgroup files, and writes only `cgroup.kill`. It runs under the seal and fence's Landlock domain. |

## Reliability Considerations

- **Bounded:** after five seconds it logs that processes remain and exits,
  so runsv never hangs on it.
- **No cgroup2, no harm:** without the cgroup files it does nothing.
- **Tested:** `make check`'s `cgrouped` requires every leashed service to
  be in its own cgroup, and the console shows a line for any service that
  left processes behind.
