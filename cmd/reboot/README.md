# reboot

## Summary

`reboot` and `poweroff` stop the machine cleanly, then restart it or turn it
off. They are one program under two names, like OpenBSD's `reboot` and `halt`.

## Background

runit is PID 1. To stop the machine it runs stage 3 (`/etc/runit/3`, see
cmd/runit-stage), which stops the services and unmounts `/data`, then restarts
or powers off. `runit-init 6` and `runit-init 0` ask runit to do this. The
image has no Busybox or util-linux, which supply `reboot` on most distros.

## Goals

- Provide the names operators and programs expect, `reboot` and `poweroff`,
  with runit's clean stop behind both.
- Nothing else: no delays, no forcing, no wall messages.

## Non-Goals

- An unclean stop (`reboot -f`). Stage 3 is the only way down, so `/data` is
  always unmounted first.
- Halting without powering off. A VM has no use for it.

## Detailed design

- **The name decides.** `reboot` means level 6, `poweroff` level 0. Any other
  name, or any argument, prints usage and exits 2.
- **It sets runit's reboot flag**, `/etc/runit/reboot`, as `runit-init` does:
  mode 0100 to restart, mode 0 to power off.
- **It then sends SIGTERM to stage 2**, the `runsvdir` whose parent is PID 1,
  found by scanning `/proc/*/stat`. runsvdir exits at once and runit runs
  stage 3, then calls `reboot(2)` as the flag says. Through `runit-init`,
  runit signals stage 2 itself and, unless it has already exited, sleeps a
  full second before it checks again. Under Lima that second was paid in six
  reboots of eight.
- **If the flag cannot be set, or stage 2 cannot be found or signalled**, it
  execs `runit-init LEVEL`, which writes runit's stop files and signals PID 1.
- **On failure** it prints `reboot: runit-init: ERROR` and exits 1.
- **Callers**: an operator on the debug shell or over ssh; slot-update after
  it stages an update; power-button, as `poweroff`, after a press.

## Drawbacks

- The fallback depends on runit's `runit-init`.
- Only root succeeds. Writing the flag and signalling runsvdir need root, and
  `runit-init` refuses anyone else.

## Alternatives Considered

### Always ask runit-init
An earlier version did. It cost a second on most reboots, which matters for
update reboots.

### Write all of runit's stop files here
That would copy runit's private protocol for signalling PID 1. The program
writes only the reboot flag and leaves the rest to `runit-init`.

### Default to reboot for any other name
An early version did. A stray `halt` link restarted the machine. Now an
unknown name does nothing.

### Busybox or util-linux
Both are multi-call binaries of many tools, against the rule of one small
program per job.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| Someone else stopping the machine | Only root can write the flag or signal runsvdir. |
| A name that does something unexpected | Only `reboot` and `poweroff` work; others are refused. |
| A stop that skips unmounting `/data` | Always through runit's stage 3; no force flag. |

## Reliability Considerations

- **Always clean**: stage 3 stops services and unmounts or remounts `/data`
  read-only before the kernel is told.
- **Fallback**: if the fast path fails, `runit-init` still stops the machine.
- **Tested**: unit tests for `levelFor` and `isStageTwo`; `check-updater`
  reboots with it after an update, and every `make check` boot powers off
  through `poweroff`, run by power-button.
