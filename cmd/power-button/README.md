# power-button

## Summary

Turns the hypervisor's power-button press into a clean poweroff: services
stopped, `/data` put down, then the machine off.

## Background

A cloud's "stop", QEMU's `system_powerdown` and `limactl stop` press a
virtual power button rather than cutting the power. A distro hands that to
acpid or systemd-logind; werewolf has neither, and no shell. Without a
listener the press is ignored, and the hypervisor cuts the power after its
timeout, mid-write.

## Goals

- A press always ends in an orderly poweroff.
- Both ways the press arrives: an input device (ACPI, on x86 and on arm64
  with ACPI), and a GPIO line (arm64 with a device tree: QEMU's `virt`,
  Apple's VZ).
- No privilege held while it waits.

## Non-Goals

- Other keys, lids, or sleep: a server has none.
- Devices plugged in after it starts: a VM's power button is there at boot.

## Detailed design

1. **Input devices**: every `/dev/input/event*`, up to 32, opened once, so
   the kernel queues events between reads.
2. **The GPIO line**: the device tree's `gpio-keys` entry with
   `linux,code` KEY_POWER (116) names the controller by phandle, the line,
   and its polarity. The controller is the `gpiochip` whose `of_node`
   carries that phandle (a PL061, `gpio-pl061` in `minimal.modules`). The
   line is requested input-only, for its rising edge, inverted if active
   low. fence allows that request on a PL061 alone.
3. **Nothing to watch**: it parks itself (`sv down`), with the reason.
4. **Drop**: one line says what it watches. Then `sandbox.keepOnly(0)`:
   no capability, an empty bounding set, securebits locked. Powering off
   needs only root's uid.
5. **Wait**: `poll` on every descriptor. An input event is 24 bytes; a
   press is EV_KEY, KEY_POWER, value 1. A GPIO event is a rising edge.
6. **A press**: one line naming where it came from, then it becomes
   `/usr/bin/poweroff`, which tells runit to run stage 3 and power off.
7. **A device that goes away** (hang-up, error): closed and said, and left
   out of `poll`. If none is left, it parks.

## Drawbacks

- Any input device with a power key powers the machine off, a keyboard's
  included: that is what the key means.
- Devices added later are not watched until the next boot.

## Alternatives Considered

### acpid, or systemd-logind
Each brings scripts, a shell or a bus, for one key. And neither reads a
GPIO power key without the gpio-keys driver, which Alpine's `linux-virt`
does not build.

### Building gpio-keys into the kernel
werewolf runs Alpine's signed kernel unchanged. Reading the line is fifty
lines here.

### Only devices that report a power key
That means an ioctl on input devices, which fence's Landlock rules refuse,
and keyboards report one anyway.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| A long-lived root daemon | No capability after setup, bounding set empty, securebits locked; under the seal and in fence's domain. |
| Input it parses | Fixed-size events from the kernel; device-tree properties checked by length. |
| GPIO lines | One line, input-only; fence allows the request only on the PL061. |
| A forged press | Making an input device (uinput) takes root and device ioctls, which fence refuses; root could power off anyway. |

## Reliability Considerations

- **No spin**: a vanished device is dropped, not polled forever.
- **Says what it does**: what it watches, which device was pressed, and why
  it parked.
- **Tested**: every `make check` boot ends with `system_powerdown`, and the
  machine must power off within 60 s, cleanly.
