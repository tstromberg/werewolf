# runit-stage

## Summary

runit-stage is runit's three stages, one program under three names
(`/etc/runit/1`, `2` and `3`). Stage 1 does nothing, stage 2 runs the
services, and stage 3 stops them and unmounts `/data` before the power goes.

## Background

runit is PID 1 after werewolf's `/init`. It runs `/etc/runit/1` once, then
`2` until told to stop, then `3`, then kills what is left, syncs, and powers
off or reboots. A distro's stages are shell scripts; werewolf has no shell.
Stage 1's work (mounts, modules, fence, the seal) is done by `/init` before
runit starts. Without stage 3, a stop is a power cut, and ext4 loses its last
few seconds of writes.

## Goals

- Give services a blocking console, so none loses output.
- Leave ext4 and LUKS clean on a stop: services down, `/data` unmounted and
  closed, the victim's filesystem read-only with its journal written.
- Bound the stop in time, and make it fast when services stop at once.
- If a new slot cannot run its services, fall back to the old slot.

## Non-Goals

- Service dependencies or ordering. Every service is stopped at once.
- Stopping what runit did not start. runit kills it after stage 3.

## Detailed design

- **Stage 1** returns at once.
- **Stage 2** opens `/dev/console` blocking for stdout and stderr, then execs
  `runsvdir -P /etc/sv`. runit's own console is non-blocking, so a service
  writing faster than the serial port got EAGAIN and lost lines. If the exec
  fails, it logs why and exits 111, which makes runit run stage 2 again. Any
  other exit would run stage 3, which kills stage0's deadman and powers off,
  so an uncommitted slot would stay off instead of rebooting into the last
  slot that worked.
- **Stage 3** sends `d` (TERM, then CONT) to every `/etc/sv/*` at once
  through runsv's control pipe. The pipe is opened non-blocking, so a
  missing runsv is skipped. It reads each `supervise/stat` every 10 ms until
  it says `down` (sv waits 420 ms between checks). After 30 s, services still
  up get `k` (KILL) and 6 s more, enough for leash-reap's 5 s; then it moves
  on, naming each. Every runsv gets `x`. Then `sync`, and the mount broker's
  `shutdown`: it unmounts `/data` (or remounts it read-only if held), removes
  its LUKS mapping, and remounts the victim read-only. If the broker fails,
  stage 3 logs it and the journal repairs the filesystems on next boot.
- **Logging**: `werewolf: stopping services`, each service killed, and
  `werewolf: down in 0.011s (services 0.011s, filesystems 0.000s)`.

## Drawbacks

- Services are not ordered: a client and its database stop together.
- A service that ignores TERM holds a stop for 30 s.

## Alternatives Considered

### runit's own scripts, or `sv -w 30 force-stop`
They need a shell, and `sv` polls every 420 ms on every stop, which an
update's reboot waits on.

### Stopping services one by one
Each wait would add to the next. Stopped together, the stop costs only the
slowest service.

### Exit 1 when runsvdir will not start
That was the first design. runit treated it as stage 2 finished, ran
stage 3, and powered the machine off.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| A service that will not stop | KILL after 30 s; runit kills everything left after stage 3. |
| A service hiding a child | leash-reap, its `./finish`, kills its cgroup; stage 3 waits for it. |
| Unmounting from inside fence's domain | Not done here: it asks the mount broker, which runs outside. |
| Its own privilege | Root, as runit's child, in fence's domain and sealed; it reads runsv's files and writes one byte to each control pipe. |

## Reliability Considerations

- **Bounded**: at most 36 s for the services, then the broker's own bounded
  shutdown.
- **Falls back**: a stage 2 that cannot start retries, and the deadman
  reboots an uncommitted slot into the old one.
- **Tested**: unit tests for `stageOf` and `isDown`; every `make check` boot
  ends in stage 3, and its next boot (`-again`) finds `/data` as the last one
  left it.
