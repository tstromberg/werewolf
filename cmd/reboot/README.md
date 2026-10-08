# reboot

## Summary

`reboot` and `poweroff`: one program under two names that stops the machine
cleanly, then restarts it or turns it off, as OpenBSD's `reboot` and `halt`
are one.

## Background

runit, PID 1, stops the machine when asked: it runs stage 3
(`/etc/runit/3`, cmd/runit-stage), which stops the services and puts
`/data` down, then restarts or powers off. Its `runit-init 6` and
`runit-init 0` do the asking. Busybox and util-linux, whose `reboot` would
do it on a distro, are not in the image.

## Goals

- The names an operator and a program expect, `reboot` and `poweroff`, with
  runit's clean stop behind both.
- Nothing else: no delays, no forcing, no wall messages.

## Non-Goals

- An unclean stop (`reboot -f`): stage 3 is the only way down, so `/data`
  is always put down first.
- Halting without powering off: a VM has no use for it.

## Detailed design

- **The name decides**: `reboot` asks for level 6, `poweroff` for level 0.
  Any other name, or any argument, prints usage and exits 2.
- **It sets runit's reboot flag**, `/etc/runit/reboot`, as `runit-init`
  does: owner-executable to restart, not to power off.
- **Then it ends stage 2**, `runsvdir`, PID 1's child (from `/proc`), with
  SIGTERM. runsvdir exits at once, and runit goes to stage 3, which stops
  the services and puts `/data` down, then calls `reboot(2)` as the flag
  says. Asked through `runit-init` instead, runit signals stage 2 itself
  and, unless it has already exited, sleeps a whole second before it looks
  again: measured under Lima, that second was in six reboots of eight.
- **Where stage 2 cannot be found or signalled**, it becomes `runit-init
  LEVEL`, which leaves runit's stop files and signals PID 1, as before.
- **On failure**, one line, `reboot: runit-init: ERROR`, and exit 1.
- **Callers**: an operator on the debug shell or over ssh;
  slot-update, after staging an update; power-button, as `poweroff`, after a
  press.

## Drawbacks

- It runs `runit-init`, and so depends on runit's package for one small
  step.
- Only root succeeds: `runit-init` must write files root owns and signal
  PID 1. Anyone else gets runit-init's refusal.

## Alternatives Considered

### Write runit's stop files here
That is three system calls, but runit's own tool would no longer be the
thing that speaks runit's private protocol. Keeping it means one program
start, not a second copy of how runit stops.

### Default to reboot for any other name
That was this program's first form. A stray link, `halt`, say, restarted
the machine. Now an unknown name does nothing.

### Busybox or util-linux
Either is a multi-call binary of many tools, against shell-free's rule of
one small program per job.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| Someone else stopping the machine | Only root can; anyone else is refused by runit-init. |
| A name that does what it does not say | Only `reboot` and `poweroff`; anything else is refused. |
| A stop that skips putting `/data` down | Always through runit's stage 3; no force flag. |

## Reliability Considerations

- **Always clean**: stage 3 stops services and unmounts or remounts `/data`
  read-only before the kernel is told.
- **Tested**: `levelFor`'s names; `check-updater` reboots with it after an
  update, and every `make check` boot powers off through `poweroff`, which
  power-button runs.
