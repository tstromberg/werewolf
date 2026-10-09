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
- Handle both ways the press arrives: an input event (ACPI, on x86 and on
  arm64 with ACPI), and a GPIO line (arm64 with a device tree: QEMU's `virt`,
  Apple's VZ).
- Hold no privilege while waiting.

## Non-Goals

- Other keys, lids, or sleep. A server has none.
- Devices plugged in after start. A VM's power button exists at boot.

## Detailed design

runsv starts it as `/etc/sv/power-button/run`, with no arguments.

1. **Input devices**: it opens every `/dev/input/event*`, up to 32, once, so
   the kernel queues events between reads.
2. **GPIO line**: on a device tree, the power button is wired to a GPIO line
   through a `gpio-keys` node, whose driver Alpine's `linux-virt` does not
   build. So power-button reads the line itself. The `gpio-keys` entry with
   `linux,code` KEY_POWER (116) names the controller by phandle, the line,
   and its polarity. The controller is the `gpiochip` whose `of_node` has
   that phandle (a PL061, `gpio-pl061` in `minimal.modules`). It requests
   the line as input, for rising edges, inverted if active low.
3. **Nothing to watch**: it logs why and runs `sv down .`, so runsv does not
   restart it.
4. **Drop**: it logs what it watches, then calls `sandbox.keepOnly(0)`: no
   capabilities, an empty bounding set, securebits locked. Powering off
   needs only root's uid.
5. **Wait**: it `poll`s every descriptor. An input event is 24 bytes; a
   press is EV_KEY, KEY_POWER, value 1. A GPIO event is a rising edge.
6. **Press**: it logs where the press came from and execs
   `/usr/bin/poweroff`, which tells runit to run stage 3 and power off.
7. **Vanished device** (hang-up or error): it logs it, closes it, and leaves
   it out of `poll`. If none is left, it parks as in step 3.

## Drawbacks

- Any input device with a power key powers the machine off, keyboards
  included. That is what the key means.
- Devices added later are not watched until the next boot.

## Alternatives Considered

### acpid or systemd-logind
Each brings scripts, a shell or a bus, for one key. Neither reads a GPIO
power key without the gpio-keys driver.

### Building gpio-keys into the kernel
werewolf runs Alpine's signed kernel unchanged. Reading the line here takes
about fifty lines.

### Only devices that report a power key
That needs an ioctl on input devices, which fence's Landlock rules refuse,
and keyboards report one anyway.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| A long-lived root daemon | No capabilities after setup, empty bounding set, securebits locked; sealed and in fence's domain. |
| Parsed input | Fixed-size kernel events; device-tree properties are length-checked. |
| GPIO lines | One input-only line; fence allows the request only on a PL061. |
| A forged press | Creating an input device (uinput) needs root and device ioctls, which fence refuses; root could power off anyway. |

## Reliability Considerations

- **No spin**: a vanished device is closed, not polled forever.
- **Logs its decisions**: what it watches, which device was pressed, and why
  it parked.
- **Tested**: unit tests for `parseGpios` and `isPowerPress`; every
  `make check` boot ends with `system_powerdown`, and the machine must power
  off cleanly within 60 s.
