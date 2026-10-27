# Secured local deployment

**Status:** Implemented
[2026-10-12](https://github.com/werewolf-linux/werewolf/commit/b65fd379)
## Summary
Deploy Lima, Linux QEMU and x86_64 FreeBSD bhyve guests with enrolled Secure Boot,
IPE and the TPM floor ([independent updates](independent-updates.md)). The local host
and its stored VM state are trusted; guest root and guest disks are not. A `--build`
machine boots an image signed with the user's keys and takes changes by reinstalling,
unless its builder serves a channel. Status: built.
## Background
Lima on macOS uses QEMU, like Linux. A download follows werewolf's public channel
([publication design](published-secure-boot.md)); this covers `--build`.
## Goals
- Keep signing keys outside the guest and keep no TPM credential anywhere.
- Refuse startup when required firmware, enrollment or the TPM is missing.
- Keep A/B updates, commit and operator rollback where a channel is served.
- Exercise real arm64 Lima boots, tampering and interrupted updates.
## Non-Goals

- Defend against a host administrator replacing the entire VM and virtual TPM.
- Give guests firmware signing or TPM hierarchy credentials.
- Silently migrate existing VZ disks or replace their enrolled trust.

## Detailed design

### Provider

Use `vmType: qemu`, enrolled firmware and Lima's persistent `tpm: true`. Keep the TPM
state in the instance's private `swtpm` directory across restarts and expose only the
emulated guest device: neither state nor control sockets are mounts. Linux QEMU uses
a private host supervisor for persistent swtpm (`howl _tpm`, cmd/howl/swtpm.zig);
QEMU receives the control socket, the guest only the device. Missing enrolled backing
state fails, and shutdown must finish before state removal.

FreeBSD bhyve uses its own enrolled CODE/VARS firmware pair and a persistent swtpm
command socket. Its supervisor restarts the emulator on guest reboot to reset PCRs
while retaining NV state. TAP on an existing bridge is the default for locally built
and unprotected guests. The chosen mode and bridge stay with the protected machine.
Downloads use the existing signed x86 QEMU UEFI image channel, including its
authenticated update channel and rollback floor. Those images sign a fixed SLIRP
network into their kernel command line, so howl selects SLIRP automatically and
refuses incompatible TAP/static flags. A TAP image must be built for that network.
The VMM runs in Capsicum mode; the outbound SLIRP helper runs as `nobody` outside
Capsicum, so an exploit in that helper could access host resources available to that
account. howl warns about this boundary. ARM64 bhyve does not support this protected
profile. Automatic local IPE kernel/stub builds still require Linux or macOS;
FreeBSD's normal launch uses published images.

### Invocation and prerequisites

`howl run --build` selects this profile on an arm64 Mac or native Linux. Without
overrides, howl creates a private host IPE identity and caches matching builds: a
kernel whose IPE trusts its certificate (`tools/test-kernel`) and the pinned EFI stub
(`boot/stub-source`). A cache identity binds architecture, public signer, sources and
builder bytes, and a checksummed completion record rejects altered or incomplete
artifacts. All three IPE overrides must be supplied together; `UKI_STUB` can override
the stub. Mac builds use the Melange QEMU runner, which boots Alpine's `linux-virt`
only as a build guest; private keys stay on the Mac. `--build` seals a bundle as CI
seals werewolf's, signed with keys in `$XDG_DATA_HOME/howl`; the machine enrolls it
as it would a download, so the image holds nothing of one machine. `--dev=ssh`
requires `--disable=secureboot,tpm,ipe`, the legacy deployment path.

### Enrollment

Firmware enrolls the bundle's boot certificate as PK, KEK and db, and the VM gets a
TPM nothing has touched. Its first boot makes the TPM its own: stage0 defines the
channel's counter at the release's index, disables clear and sets owner and lockout
passwords nothing keeps, each step checked first so a cut completes on the next boot.
The host keeps no recovery credential; a machine whose TPM state is lost is
reinstalled.

### Updates and changes

The image follows a channel only if the builder serves one: `IPE_UPDATES=URL` names
it, `IPE_UPDATES_CA` a PEM file of a private CA the root also trusts, and
`IMAGE_INDEX=N` the release's index (default 1). The builder makes each later release
with the same keys and a higher index, exports it ([prebuilt
images](prebuilt-images.md)) and serves `ARCH/latest.json` and `ARCH/BUILD/` under
that URL; the machine's updater installs it as a download's would. Without a channel,
changes mean reinstalling: `howl run`'s machine is reinstalled when its inputs
change, and a named machine keeps the image it was made with while howl says how to
delete and create it again.

### Startup and existing machines

Create the Lima instance, then start the guest, and report readiness only after the
required guest checks succeed. Restart preserves disk, firmware variables and TPM
state; unchanged runs reuse live guests. An existing machine without this profile
needs explicit recreation: configuration changes cannot make an older image
enforcing.

## Drawbacks

- Requires QEMU, swtpm and an IPE kernel matching the signer.
- A privately signed image takes changes by reinstalling unless its builder runs a
  channel.
- First-use kernel compilation needs native build dependencies and outlasts a VM
  boot.

## Alternatives Considered

- VZ does not provide the required enrolled Linux Secure Boot path.
- Host-held TPM credentials and per-transition permits (protocol v2) keep the host in
  every update and give whoever holds them the power to reset retirement.
- A floor raised at commit would retire the predecessor and defeat A/B recovery.

## Security Considerations

Host keys and private state must never appear in roots, config disks or guest mounts.
Reject missing and foreign TPMs, wrong keys, setup-mode firmware and unsigned or
retired images. Firmware must trust only UKIs that enforce the floor.

## Reliability Considerations

`make check-independent-updates` (Lima on macOS, `PROVIDER=qemu` on Linux) covers
creation, updates from a served channel, rollback, failed trials, tampering, a power
cut at the floor's increment and the refusal of a restored retired release
([testing-secure-boot.md](../../testing-secure-boot.md)). Killing VM and simulator
does not prove TPM power-loss atomicity.
