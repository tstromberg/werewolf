# power-button

## Summary

power-button turns the hypervisor's power-button press into a clean
poweroff: services stop, `/data` is unmounted, then the machine turns off.

## Background

A cloud's "stop", QEMU's `system_powerdown` and `limactl stop` press a virtual
power button rather than cutting the power. Most distros hand the press to
acpid or systemd-logind. werewolf has neither, and no shell. Without a
listener the press is ignored, and the hypervisor cuts the power after a
timeout, possibly mid-write.

## Goals

- A press always ends in an orderly poweroff.
- Handle both ways the press arrives, each an input event: ACPI's power
  button (x86, and arm64 with ACPI), and a GPIO line (arm64 with a device
  tree: QEMU's `virt`, Apple's VZ), which werewolf's kernel turns into a
  key with its built-in `gpio-keys` driver.
- Parse input as an unprivileged user; confine the shutdown monitor.

## Non-Goals

- Other keys, lids, or sleep. A server has none.
- Devices plugged in after start. A VM's power button exists at boot.

## Detailed design

runsv starts it as `/etc/sv/power-button/run`, with no arguments.

1. **Input devices**: it opens every `/dev/input/event*`, up to 32, once, so
   the kernel queues events between reads.
2. **Nothing to watch**: it logs why and runs `sv down .`, so runsv does not
   restart it.
3. **Separate**: fork `_power` (uid 71), chroot it to `/var/empty`, clear
   capabilities, and install a syscall allowlist. Only this child reads events.
4. **Wait**: the child polls the preopened descriptors. A press is EV_KEY,
   KEY_POWER, value 1. It sends `P` on its private pipe, then exits. A closed
   monitor end also wakes the reader, so it cannot outlive the monitor.
5. **Poweroff**: the root parent has no capabilities and cannot open files,
   execute programs or reboot directly. Its filter permits setting the two
   preopened runit flags to their fixed modes and sending SIGCONT to PID 1.
   Runit stops services and runs stage 3 before powering off.
6. **Vanished devices**: the child closes each after draining it. When none
   remains it sends `D`; the parent parks only its own service through the
   control pipe opened before confinement. A broken or malformed pipe exits
   with failure so runsv restarts both roles.

## Drawbacks

- Any input device with a power key powers the machine off, keyboards
  included. That is what the key means.
- Devices added later are not watched until the next boot.

## Alternatives Considered

### acpid or systemd-logind
Each brings scripts, a shell or a bus, for one key.

### Reading the GPIO line here
Before werewolf built its own kernel, Alpine's had no gpio-keys, and
power-button requested the line itself. That took a hundred lines and a
GPIO chip open to ioctls in fence's rules; the kernel's driver takes neither.

### Only devices that report a power key
That needs an ioctl on input devices, which fence's Landlock rules refuse,
and keyboards report one anyway.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| A compromised event reader | Its own user, empty chroot, no capabilities and a syscall allowlist; only a fixed shutdown request reaches the monitor. |
| A compromised monitor | No capabilities, opens or execs; its filter pins the flag descriptors, modes, PID and signal. |
| Parsed input | Fixed-size kernel events. |
| A forged press | Creating an input device (uinput) needs root and device ioctls, which fence refuses; root could power off anyway. |

## Reliability Considerations

- **No spin**: a vanished device is closed, not polled forever.
- **Logs its decisions**: what it watches, which device was pressed, and why
  it parked.
- **Tested**: a unit test for `isPowerPress`; every
  `make check` boot ends with `system_powerdown`, and the machine must power
  off cleanly within 60 s.
