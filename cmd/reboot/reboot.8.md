# reboot(8)

<!-- date: October 25, 2026 -->
<!-- os: Werewolf -->

## NAME

reboot, poweroff — restart or power off the machine cleanly

## SYNOPSIS

**reboot**

**poweroff**

## DESCRIPTION

The **reboot** utility requests an orderly restart. The **poweroff** utility requests
an orderly poweroff. Both require root and accept no arguments.

The invoked name selects the operation. The utility sets runit's reboot flag and
signals its stage 2 supervisor. If this fails, it invokes `runit-init 6` or
`runit-init 0`, respectively. Stage 3 stops services and unmounts or remounts
persistent storage read-only before the kernel restarts or powers off. There is no
force option or halt-without-poweroff mode.

## FILES

- `/etc/runit/reboot`

  Runit's reboot flag.

- `/etc/runit/3`

  Shutdown stage.

## EXIT STATUS

An invalid name or any argument produces status 2. Failure to execute the fallback
produces status 1. Successful submission does not wait for shutdown to finish.

## SEE ALSO

power-button(8), runit-stage(8), slot-update(8)
