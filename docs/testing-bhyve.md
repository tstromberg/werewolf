# Live bhyve tests

## bhyve

Status, 2026-10-18: ARM64 on smaug is experimental, not qualified for unattended
deployment. Normal howl launches pass signed A/B recovery with the private runtime, but
a sustained TAP transfer test panicked in virtio TX. Secure Boot and TPM were off.
Earlier bilbo x86_64 results do not qualify ARM64, or vice versa.

`test/check-bhyve-lifecycle HOST ARCH DISK.zst KEY [tap|slirp] [SECONDS]` tests a fresh
copy of a prebuilt playground disk through howl's create/reconfigure, supervisor, stop
and delete paths. KEY and KEY.pub are a disposable SSH identity. The host needs
passwordless doas, firmware, zstd, and Python 3 for TAP; the builder needs Zig, zstd and
e2fsck. ARM64 needs legacy virtio PCI (kernel 7.2.11-r6 or later). TAP requires an
existing bridge; `BHYVE_BRIDGE` selects it. `BHYVE_TEST_IP` and `BHYVE_TEST_GW` select a
static test subnet instead of DHCP. The test does not create a bridge or change host
addressing, routes or firewall rules. Defaults are TAP and 180 seconds; SLIRP remains an
explicit option.

It checks the source disk, repeated 64 MiB SSH transfers, three guest reboots,
persistent checksums, stop/start and offline ext4 integrity after journal recovery.
Successful runs delete their remote directory; failed runs stop the VM and retain their
disk. Logs, phase records and snapshots are in `build/bhyve-validation/wwlife-*`. Never
share a writable disk between test VMs. A successful lifecycle run does not certify
Secure Boot, updates or long-term timekeeping; the initial guest clock must be within
300 seconds of the builder's clock.

Use `make check-ab-bhyve ARCH=aarch64 BHYVE_HOST=smaug AB_MODE=plain` for signed
updates, rollback and unhealthy-slot recovery (see [secure
tests](testing-secure-boot.md)). This test requires IPE and a correct guest clock; it
does not bypass TLS validation. The direct A/B harness defaults to SLIRP, unlike normal
howl. To test direct TAP, supply an existing `BHYVE_TAP=tapN`,
`BHYVE_TEST_IP=192.0.2.2/30` and `BHYVE_TEST_GW=192.0.2.1`; the caller owns its TAP,
bridge and cleanup. The fixture serves signed updates on guest loopback, so an isolated
bridge suffices. `BHYVE_BINARY=/absolute/remote/path/bhyve` tests a separate host
executable without replacing system bhyve. `BHYVE_ARM64_FIRMWARE` selects an absolute
remote path to a separate ARM64 firmware image. These overrides also work with normal
unprotected `howl create` launches on the FreeBSD host; they do not change the ARM64
Secure Boot refusal. FreeBSD 15.1's ARM RTC identification bug can leave the guest in
1970; upstream [corrected the ID register
offsets](https://github.com/freebsd/freebsd-src/commit/a554906ea44c26925730a25263e64890d48d2b36).
That fix restores the clock, but does not establish automatic update recovery. ARM64
U-Boot 2024.07's EFI file protocol refuses renames: the loader cannot consume the `+1`
boot attempt, so the deadman can reboot into the unhealthy slot again. Signed upgrades
and explicit rollback passing are not sufficient; require the unhealthy-slot recovery
phase to pass before relying on unattended updates. On smaug, a separate U-Boot 2025.07
build with the FreeBSD bhyve board support and `CONFIG_FAT_RENAME=y`, paired with the
RTC-fixed bhyve and TAP, passed the full plain A/B test through both direct and normal
howl launches: signed upgrade, explicit and persistent rollback, automatic 600-second
unhealthy-slot recovery, and failed-image retry refusal. This validates the workaround,
not the installed firmware or Secure Boot. System binaries were unchanged. Build
provenance and the latest A/B/soak evidence are in
`build/bhyve-validation/results-smaug-normal-runtime-20261018.json` (local artifacts,
not checked in).

For repeatable private builds and normal-launch testing, see the [pinned ARM64 runtime
recipe](../tools/bhyve-arm64/README.md). The longer normal-launch soak on smaug found a
separate blocker: after 286 verified 64 MiB transfers, virtio TX reported `id 255 is not
a head!`, followed by a soft-lockup panic around 12 minutes into the requested half-hour
test. It did not reach the planned reboot, stop/start or post-soak filesystem checks.
The failed VM was stopped, its disk retained, and test TAPs/bridge removed. Firmware
recovery success does not establish sustained network reliability. No root cause or
workaround for this TX failure has been established.
