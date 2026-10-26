# power-button(8)

<!-- date: October 25, 2026 -->
<!-- os: Werewolf -->

## NAME

power-button — request clean shutdown on a virtual power-button press

## SYNOPSIS

**power-button**

## DESCRIPTION

The **power-button** service listens for power-key input events from ACPI or GPIO
devices. A press requests runit's orderly poweroff: services stop and persistent
storage is unmounted before the machine powers off. Cloud stop requests and hypervisor
power-down operations use this path when they deliver a virtual button event.

An unprivileged _power child reads input events. A root monitor without capabilities
receives only a one-byte decision; its system call filter restricts the flag writes
and signal used for shutdown. The service does not provide a command socket or
arbitrary command execution.

## FILES

- `/dev/input`

  Power-button event devices.

## SEE ALSO

reboot(8), runit-stage(8)
