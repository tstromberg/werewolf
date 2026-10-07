# leash-reap

## Summary

A leashed service's `./finish`: when runsv stops the service, it kills
everything left in the service's cgroup, says how many there were, and
waits for them to be gone before runsv starts the service again.

## Background

leash puts each service in its own cgroup, `/run/cgroup/svc/NAME`, joined
as root so the service cannot leave it. runsv supervises only the process
it started. A service that forks, `setsid`s and execs leaves a daemon that
reparents to PID 1 and outlives it, confined but alive: a backdoor a bare
runit would never reap. runsv runs `./finish` after the service ends, on
`sv down`, a crash, a restart or shutdown, as root, in the service's
directory.

## Goals

- Nothing a service started outlives it.
- Something that did is said, where an operator will see it.
- The service starts again into an empty cgroup, its ports free.

## Non-Goals

- Stopping the service: runsv sends it TERM first, as always.
- Werewolf's own programs, which are not leashed and have no cgroup.

## Detailed design

- **The service** is the basename of the directory runsv runs it in. It
  must be 1 to 64 letters, digits, `-` and `_`, so the path is only ever a
  leaf of `/run/cgroup/svc`.
- **What is left** is read from `cgroup.procs`: if nothing, it is done. If
  something, it writes `1` to `cgroup.kill`, which signals every process in
  the cgroup at once, forks in flight included.
- **Then it waits**, polling `cgroup.events` every 10 ms for `populated 0`,
  up to five seconds.
- **One line** on the console, as leash writes its own:
  `leash-reap: {"event":"reaped","service":"nginx","left":2,"what":"killed"}`,
  or that the processes could not be killed, or were not all gone in time.

## Drawbacks

- It cannot tell a worker still stopping from a child left on purpose:
  both are counted as left, and both are killed.
- Five seconds of waiting can delay a restart, or stage 3.

## Alternatives Considered

### runsv's TERM alone
runsv signals the one process it started, so a detached child survives
every stop until the machine reboots.

### Kill by process group or session
A child that calls `setsid` leaves both; the cgroup it cannot leave.

### Return at once after the kill
The kernel signals at once but the processes die after; runsv restarting
the service at that moment meets ports still held, and fails until they go.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| A daemon left behind as a backdoor | Killed with the cgroup, and counted on the console. |
| A crafted directory name reaching another file | Only a plain name, so only a leaf of `/run/cgroup/svc`. |
| Its own privilege | Root, but it trusts no argument, reads only its service's cgroup files, and writes one. It runs under the seal and fence's Landlock domain. |

## Reliability Considerations

- **Bounded:** at most five seconds, then it says the tree was not all gone
  and returns, so runsv is never stuck on it.
- **No cgroup2, no harm:** without the files, it does nothing.
- **Tested:** `make check`'s `cgrouped` requires every leashed service in
  its own cgroup, and the console shows a line for any service that left
  something behind.
