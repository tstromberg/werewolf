# Live hypervisor tests

These opt-in checks use disposable VMs on Linux/KVM or FreeBSD hosts.
See [live tests](testing-live.md) for cloud and updater checks.

The protected checks use the Zig
[isolation helper](../test/check-hypervisor-isolation.zig) for host containment,
posture and raw-packet probes. Both passed again on galadriel and bilbo on
2026-10-27 after the helper migration. Local evidence is under
`build/readme-audit/live-firecracker/` and `build/readme-audit/live-bhyve/`.

## Firecracker

On a Linux/KVM host, `make check-firecracker-protected` builds a private playground
guest using Firecracker's default IPE mode. It checks the limitation warning, active
and locked IPE, guest reboot, stop/start, refusal of changed kernels, initrds and
boot arguments, missing host trust, explicit protection downgrades, and delete. It
needs Firecracker 1.17+, bubblewrap, enabled user namespaces, prlimit, timeout,
mtools, erofs-utils, passwordless sudo/doas and the source-build tools, with TUN, NAT
and conntrack modules available for the running host kernel. It also inspects the
VMM's actual namespaces, read-only mounts, capabilities, seccomp and resource limits,
floods both log pipes past their storage limit, and verifies continued SSH/DNS
access. With the disposable VM stopped, it injects raw IPv4 packets at its tap to
prove host filtering of metadata, spoofed sources, tap-to-tap traffic and host
services independently of the guest's own fence. x86_64 boots the original bzImage to
retain kernel address randomization; extracting its ELF bypasses it. The first run
builds the local IPE kernel. Logs stay under `build/check/fc-protected-PID`; failures
stop the guest and retain its artifacts. Boot files are pinned on the host; this mode
takes image changes through host rebuilds.

On 2026-10-26, galadriel passed the legacy signed A/B test with IPE and dm-verity:
A→B and commit, rollback to A that survived another reboot, automatic recovery after
an unhealthy candidate's full 600-second timeout, and failed-image retry refusal. A
separate default-mode check proved that signed B stages but host pins retain A on a
fresh reboot. This is an expected limitation, not an automatic upgrade pass for the
default mode; security updates still require host rebuilds. Both disposable machines
were removed. Evidence is under
`build/ab-validation-20261026/firecracker-v2/provider-ab-firecracker/` and
`build/ab-validation-20261026/firecracker-pinned-v2/provider-ab-firecracker/` (local,
not checked in). See [provider A/B
tests](design/implemented/provider-ab-tests.md#firecracker-and-bhyve).

`make check-firecracker` boots the `sshd` form as a Firecracker microVM on
`FIRECRACKER_HOST` (default `galadriel`), a Linux host with KVM, Firecracker, mtools,
erofs-utils and passwordless `doas`. The tree, built for x86_64 here, is copied over
with a howl, a form tool and a verity tool cross-compiled for the host, so it needs
no toolchain; the host resolves a lock the copy does not match with `go install`'s
apko, at the version tools/install-deps pins. The form is sshd relaxed to take a key
file the host holds, and the ad-hoc generator declares the
`network-ssh-security-keys` weakness that costs. The machine must hand over to runit
with its root verified, posture must fail exactly what the form and
test/posture-known allow, ssh must reach it through its tap with the host's key, and
delete must remove the machine. `FIRECRACKER_KEEP=1` leaves it for a look.

## bhyve

On x86_64 FreeBSD, `gmake check-bhyve-protected` exercises the normal published-image
launch with Secure Boot, TPM and IPE enabled. It checks the VMM's actual Capsicum
state, guest posture, locked IPE, data persistence through three reboots and
stop/start, protection-downgrade refusal and delete. It requires bhyve-firmware,
swtpm, virt-firmware, libslirp and passwordless doas/sudo. Failures stop the
disposable guest and retain evidence under `build/check/bhyve-protected-PID`.

Passed 2026-10-26 on bilbo, FreeBSD 15.1-RELEASE-p5 amd64: all 224 howl unit tests
and the protected lifecycle check. A separate one-byte UKI tamper was rejected by
firmware with `Access denied` before stage0. The guest's automatic signed-channel
check reported `current`; this run did not exercise a complete A/B upgrade. Evidence
is in `build/bhyve-validation/bilbo-20261026/` (local, not checked in). Host ACPI/TPM
diagnostics now go to `bhyve.log` so they cannot interrupt serial readiness lines.

The separate 2026-10-26 signed A/B run on bilbo also passed with `AB_MODE=secure
AB_TPM=1`: A→B and commit, operator rollback to A, another reboot, an unhealthy
candidate that remained uncommitted for the full 600 seconds, automatic recovery to
A, and refusal to retry the failed image. Every boot verified the expected signed
root, Secure Boot, IPE, dm-verity and TPM admission. The protected supervisor kept
the same TPM state across reboots; cleanup removed the VM and TPM. Evidence is under
`build/ab-validation-20261026/bhyve/provider-ab-bhyve/` (local, not checked in). See
[provider A/B tests](design/implemented/provider-ab-tests.md#firecracker-and-bhyve)
for fixture preparation and commands.

The published x86 image uses the QEMU channel's signed SLIRP network; howl selects
SLIRP automatically. A bridged TAP guest needs an image built for TAP. The outbound
SLIRP helper drops to `nobody` but runs outside Capsicum, and howl warns that a
helper exploit could reach host resources available to that account. TAP avoids that
helper. The VMM itself remains in Capsicum. Neither mode adds host signing keys or
TPM control sockets to the guest. Automatic local IPE prerequisite builds are still
Linux/macOS-only.

Status, 2026-10-18: ARM64 on smaug is experimental, not qualified for unattended
deployment. Normal howl launches pass signed A/B recovery with the private runtime,
but a sustained TAP transfer test panicked in virtio TX. Secure Boot and TPM were
off. Earlier bilbo x86_64 results do not qualify ARM64, or vice versa.

`make check-bhyve-lifecycle ARGS='HOST ARCH DISK.zst KEY [tap|slirp] [SECONDS]'`
tests a fresh copy of a prebuilt playground disk through howl's create/reconfigure,
supervisor, stop and delete paths. KEY and KEY.pub are a disposable SSH identity. The
host needs passwordless doas, firmware and zstd; the builder needs Zig, zstd and
e2fsck. ARM64 needs legacy virtio PCI (kernel 7.2.11-r6 or later). TAP requires an
existing bridge; `BHYVE_BRIDGE` selects it. `BHYVE_TEST_IP` and `BHYVE_TEST_GW`
select a static test subnet instead of DHCP. The test does not create a bridge or
change host addressing, routes or firewall rules. Defaults are TAP and 180 seconds;
SLIRP remains an explicit option.

It checks the source disk, repeated 64 MiB SSH transfers, three guest reboots,
persistent checksums, stop/start and offline ext4 integrity after journal recovery.
Successful runs delete their remote directory; failed runs stop the VM and retain
their disk. Logs, phase records and snapshots are in
`build/bhyve-validation/wwlife-*`. Never share a writable disk between test VMs. A
successful lifecycle run does not certify Secure Boot, updates or long-term
timekeeping; the initial guest clock must be within 300 seconds of the builder's
clock.

Use `make check-ab-bhyve ARCH=aarch64 BHYVE_HOST=smaug AB_MODE=plain` for signed
updates, rollback and unhealthy-slot recovery (see [secure
tests](testing-secure-boot.md)). This test requires IPE and a correct guest clock; it
does not bypass TLS validation. The direct A/B harness defaults to SLIRP, unlike
normal howl. To test direct TAP, supply an existing `BHYVE_TAP=tapN`,
`BHYVE_TEST_IP=192.0.2.2/30` and `BHYVE_TEST_GW=192.0.2.1`; the caller owns its TAP,
bridge and cleanup. The fixture serves signed updates on guest loopback, so an
isolated bridge suffices. `BHYVE_BINARY=/absolute/remote/path/bhyve` tests a separate
host executable without replacing system bhyve. `BHYVE_ARM64_FIRMWARE` selects an
absolute remote path to a separate ARM64 firmware image. These overrides also work
with normal unprotected `howl create` launches on the FreeBSD host; they do not
change the ARM64 Secure Boot refusal. FreeBSD 15.1's ARM RTC identification bug can
leave the guest in 1970; upstream [corrected the ID register
offsets](https://github.com/freebsd/freebsd-src/commit/a554906ea44c26925730a25263e64890d48d2b36).
That fix restores the clock, but does not establish automatic update recovery. ARM64
U-Boot 2024.07's EFI file protocol refuses renames: the loader cannot consume the
`+1` boot attempt, so the deadman can reboot into the unhealthy slot again. Signed
upgrades and explicit rollback passing are not sufficient; require the unhealthy-slot
recovery phase to pass before relying on unattended updates. On smaug, a separate
U-Boot 2025.07 build with the FreeBSD bhyve board support and `CONFIG_FAT_RENAME=y`,
paired with the RTC-fixed bhyve and TAP, passed the full plain A/B test through both
direct and normal howl launches: signed upgrade, explicit and persistent rollback,
automatic 600-second unhealthy-slot recovery, and failed-image retry refusal. This
validates the workaround, not the installed firmware or Secure Boot. Provenance and
A/B/soak evidence are in
`build/bhyve-validation/results-smaug-normal-runtime-20261018.json` (local, not
checked in).

For repeatable private builds and normal-launch testing, see the [pinned ARM64
runtime recipe](../tools/bhyve-arm64/README.md). The longer normal-launch soak on
smaug found a separate blocker: after 286 verified 64 MiB transfers, virtio TX
reported `id 255 is not a head!`, then a soft-lockup panic about 12 minutes into the
half-hour test, before its reboot, stop/start and filesystem checks. No root cause or
workaround is known.
