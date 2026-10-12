# Verified boot

Proposed, 2026-10-06. Built: phase 1, lockdown and sysctls (cmd/stage0,
cmd/init); 2, a read-only root; 3, its dm-verity hash tree (lib/verity.zig)
and signed releases ([docs/releases.md](../releases.md)); and phase 5's
first slice, a signed UKI on a local disk (make check-secureboot). Phase 4,
our own kernel with IPE, is opt-in ([ipe.md](ipe.md)); enrolled images have
signed slot updates ([prebuilt-images.md](prebuilt-images.md)). Phase 5's
Secure Boot passed on AWS and GCP; Azure firmware acceptance remains unreliable.
Posture holds gaps as `boot-` checks (docs/posture.md); IPE builds enforce
module signatures. Bite firmware remains a deployment gap; TPM integration is opt-in.

## Summary

A werewolf machine should run only code we built and signed, even for
root, and a reboot should restore what we signed. ChromeOS does this with
its own firmware; we use dm-verity, IPE, and Secure Boot where we can.

## Background

What is built stops new binaries during a boot
([docs/security.md](../security.md)): writable mounts are `noexec`, fence's
Landlock runs programs only from `/usr` and `/oci` and forbids mounting,
root included, and lockdown, MDWE and one-way sysctls hold. Two gaps
remain. Landlock binds only fence's descendants, not the mount broker,
DHCP's renewal, the deadman or the kernel's helpers. And only the host, on
direct boot, checks the kernel and stage0, which holds the root hash. On
the original unsigned disk or a bitten machine (GRUB is the distro's),
root can have the mount broker mount them and replace them.

## Goals

- Phase 4: the kernel refuses any exec, executable mmap or module not from
  this release's root image, for every process.
- Phase 5: firmware boots only our signed kernel, stage0 and command line.

## Non-Goals

- The host; kernel exploits; exploits in memory; and scripts, which IPE
  does not judge (most forms carry none, [shell-free.md](shell-free.md)).

## Detailed design

**The root (built).** stage0 opens `root.erofs` through dm-verity and
mounts it read-only at `/`, with no overlay: what is written to an overlay
can run, and IPE judges a file by its filesystem's device, so through one
nothing would. `make check-verity` proves a changed image does not boot.

**Phase 4: our kernel.** Alpine's `linux-virt` lacks IPE, so CI builds it
from Alpine's config, at Alpine's version so CVE reports still match, with
`SECURITY_IPE` (in `CONFIG_LSM`), `IPE_PROP_DM_VERITY`, `DM_VERITY`,
`SYSTEM_TRUSTED_KEYS` (the image certificate), `MODULE_SIG_FORCE` and
`LOCK_DOWN_KERNEL_FORCE_INTEGRITY`, without `KEXEC` or a developer key.

**Phase 4: the policy.** Each release carries one, `DEFAULT action=DENY`
and `op=EXECUTE dmverity_roothash=sha256:ROOTHASH action=ALLOW`, signed by
CI with the image key as PKCS#7. It names a root hash, not any signed
root, so only this release runs. Stage0 loads and activates it before
forking the deadman, then removes `CAP_MAC_ADMIN` from all capability
sets. Init refuses handover if `/usr/share/werewolf/ipe` requires IPE and
the policy is not enforcing. The deadman must exec and map nothing.

**IPE, tested** on 2026-10-06 with Alpine's 6.18.55 config and these
options. With no policy, a busybox copy in `/tmp` ran. With a signed
policy, busybox ran from the named dm-verity image and was refused, with
an audit record, from an unnamed verified image, from `/tmp` and through
`ld.so`.

**Phase 5: Secure Boot (built).** New QEMU machines enroll a host-held
key and boot signed systemd-boot and UKIs. Signed release disks carry
`boot.crt`; cloud uploads verify both PEs against it before enrollment.
AWS receives UEFI data and a persistent boot entry, GCP receives PK/KEK/db,
and Azure uses a specialized gallery version with custom UEFI keys and
Trusted Launch. Stage0 requires SecureBoot on and SetupMode off.

**Native slot identity.** The UKI seals root UUID, directory and ESP identity.
Stage0 resolves only canonical slot UKI paths from StubImageIdentifier, then
protects the resolved `/proc/cmdline`. Unsigned loader options cannot alter
root, slot or IPE enforcement. Both stock Alpine and IPE kernels are supported.
The native UKI carries only stage0 and uses counted `uki` entries for A/B recovery.
`make check-secureboot` verifies the actual release disk and manifest on both
architectures; the continuous update test covers eight rejected boot cases.

**Updates under Secure Boot.** A machine that boots a signed UKI cannot
build its own next slot: nothing on it may hold the boot key. Enrolled IPE
images fetch the UKI and exact root as one signed bundle, retaining proof
before arming ([prebuilt-images.md](prebuilt-images.md)). A UKI packaged
inside a locally recomposed root cannot preserve its sealed root hash.
`make IPE=1 check-updater-uki` proves firmware delivery, verified slot b and commit.

**Open.** KMS custody, Lima arm64 integration and provider TPM provisioning.
Opt-in [protected pair retirement](tpm-ab-retirement.md) rejects retired releases
and preserves A/B rollback through actual QEMU x86_64 power cuts. The module
key makes kernel builds differ, and CI requires two to match.

## Drawbacks

- Our own kernel is a build to run and keep current with Alpine's, and
  bitten machines never get a checked kernel or stage0.
- A release whose policy is missing or wrong runs nothing and falls back.

## Alternatives Considered

- **The BPF LSM**: its protection against root would be ours to get right.
- **IMA, or fs-verity with IPE**: a signature per file, not one root hash.
- **Signed root hashes** (`dmverity_signature=TRUE`): one policy for every
  release, but every root we ever signed would run.

## Security Considerations

- No policy may trust `boot_verified` once the root is mounted: the
  initramfs stays writable and its files count as verified.
- `CAP_MAC_ADMIN` must leave the bounding set, as init already does, or
  root can switch IPE off. `ipe.enforce=0` on the command line is as safe
  as the line: fixed on direct boot and in a UKI, open on a bitten machine.

## Reliability Considerations

- A changed block fails to read; a bad root, policy or boot falls back to
  the slot that last worked. A manifest never expires, so it needs no clock.
