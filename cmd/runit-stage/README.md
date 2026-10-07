# runit-stage

## Summary

runit's three stages, one program under three names (`/etc/runit/1`, `2`
and `3`): nothing, run the services, and stop them with `/data` put down
before the power goes.

## Background

runit, PID 1 after werewolf's `/init`, runs `/etc/runit/1` once, then `2`
until it is told to stop, then `3`, then kills what is left and powers off
or reboots. A distro's stages are shell scripts; werewolf has no shell.
Stage 1's work (mounts, modules, fence, the seal) is `/init`'s, done before
runit starts.

## Goals

- Services on a console that waits, so none loses its output.
- A stop that leaves ext4 and LUKS clean: services down, `/data` unmounted
  and closed, the victim's filesystem read-only with its journal written.
- A stop bounded in time, and fast when services stop at once.
- A new slot that cannot run its services falls back to the old one.

## Non-Goals

- Service dependencies or ordering: every service is stopped at once.
- Stopping what runit did not start: runit kills it after stage 3.

## Detailed design

- **Stage 1** returns at once.
- **Stage 2** opens `/dev/console` blocking for stdout and stderr (runit's
  own is non-blocking, so a service writing faster than the serial port got
  EAGAIN and lost lines), then becomes `runsvdir -P /etc/sv`. If it cannot,
  it says why and exits 111, which runit answers by running stage 2 again.
  Exiting otherwise would run stage 3, whose kill ends stage0's deadman,
  and power off: an uncommitted slot would stay off rather than reboot
  into the last slot that worked.
- **Stage 3**: every `/etc/sv/*` is told `d` (TERM, then CONT) at once
  through runsv's control pipe, opened non-blocking, so a missing runsv is
  skipped. Each `supervise/stat` is read every 10 ms until it says `down`
  (sv waits 420 ms between looks). After 30 s, the rest get `k` (KILL) and
  six more seconds, long enough for leash-reap's five, then it goes on,
  naming each. Every runsv is told `x`. Then `sync`, and the mount broker's
  `shutdown`: `/data` unmounted (read-only if still held) and its LUKS
  mapping removed, the victim read-only.
- **One line each**: `werewolf: stopping services`, any service killed, and
  `werewolf: down in 0.011s (services 0.011s, filesystems 0.000s)`.

## Drawbacks

- Services are not ordered: a client and its database stop together.
- A service that ignores TERM holds a stop for 30 s.

## Alternatives Considered

### runit's own scripts, or `sv -w 30 force-stop`
A shell, and `sv`'s 420 ms poll on every stop, which an update's reboot
waits on.

### Stopping services one by one
Each service's wait would add to the next; together the stop costs the
slowest one.

### Exit 1 when runsvdir will not start
That was this program's first form: runit took it as stage 2 over, ran
stage 3, and powered the machine off.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| A service that will not stop | KILL after 30 s; runit kills everything left after stage 3. |
| A service hiding a child | leash-reap kills its cgroup as its `./finish`; stage 3 waits for it. |
| Unmounting from inside fence's domain | Not this program's: it asks the mount broker, which stays outside. |
| Its own privilege | Root, as runit's child, in fence's domain and under the seal; it reads only runsv's files and writes one byte to each control pipe. |

## Reliability Considerations

- **Bounded**: 36 s at most for the services, then the broker's own
  bounded shutdown.
- **Falls back**: a stage 2 that cannot start retries, and the deadman
  reboots an uncommitted slot into the old one.
- **Tested**: every `make check` boot ends in stage 3, and its next boot
  (`-again`) finds `/data` as the last one left it.
