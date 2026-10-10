# Verified boot

Proposed, 2026-10-06. Built: phase 1, lockdown and sysctls (cmd/stage0,
cmd/init); 2, a read-only root; 3, its dm-verity hash tree (lib/verity.zig)
and signed releases ([docs/releases.md](../releases.md)); and phase 5's
first slice, a signed UKI on a local disk (make check-secureboot). Not
built: 4, our own kernel with IPE; the rest of 5, Secure Boot in the
clouds. Posture holds each unbuilt phase open, as the `boot-` checks
(docs/posture.md): Secure Boot on, module signatures enforced by the
kernel's build, rollback refused by a TPM counter, each failing today
and excused by every image (test/posture-known).

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
werewolf's own disk (systemd-boot is unsigned) or a bitten machine (GRUB is
the distro's), root can have the mount broker mount them and replace them.

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
`SECURITY_IPE` (in `CONFIG_LSM`), `IPE_PROP_DM_VERITY`, `DM_VERITY=y`,
`SYSTEM_TRUSTED_KEYS` (the image certificate), `MODULE_SIG_FORCE` and
`LOCK_DOWN_KERNEL_FORCE_INTEGRITY`, without `KEXEC` or a developer key.

**Phase 4: the policy.** Each release carries one, `DEFAULT action=DENY`
and `op=EXECUTE dmverity_roothash=sha256:ROOTHASH action=ALLOW`, signed by
CI with the image key as PKCS#7. It names a root hash, not any signed
root, so only this release runs. stage0 writes it to `ipe/new_policy`, as
it cannot live in the root it names. init activates it before the seal
drops `CAP_MAC_ADMIN`, with no securityfs file left open. If the root
carries `/usr/share/werewolf/enforce` and no policy is active, init exits
and the slot falls back. The deadman must then exec and map nothing.

**IPE, tested** on 2026-10-06 with Alpine's 6.18.55 config and these
options. With no policy, a busybox copy in `/tmp` ran. With a signed
policy, busybox ran from the named dm-verity image and was refused, with
an audit record, from an unnamed verified image, from `/tmp` and through
`ld.so`.

**Phase 5: Secure Boot**, where a provider takes our keys: AWS
(`register-image --uefi-data`), GCP (an image's signature database) and
Azure (a Trusted Launch key vault). Each slot is a signed UKI of kernel,
stage0 and a fixed command line, so the address comes by DHCP; the boot
key is RSA-2048, as firmware needs. Until the loader is signed for a
cloud, `howl create` takes what it gives beside it — GCP a vTPM with
integrity monitoring, AWS a NitroTPM (`test/cloud` checks both).

**Phase 5, first slice (built): a signed UKI on a local disk.**
`tools/uki` assembles one PE from systemd's stub and the slot's kernel,
stage0, root and command line; `osslsigncode` signs it, and `make
check-secureboot` (docs/testing.md) boots it under firmware with only
that key and proves a one-byte change refused.

**Updates under Secure Boot.** A machine that boots a signed UKI cannot
build its own next slot: nothing on it may hold the boot key. So where
Secure Boot is on, CI signs each release's UKI, the manifest lists it
with its hash, and the updater fetches and lays it where the firmware
boots it, serial in line for a TPM to check.

**Open.** Key custody in a KMS. Rollback: root on a bitten machine can
install an older signed release; TPM counters would stop it. The module
key makes kernel builds differ, and CI requires two to match. A slot
built on the machine cannot carry a signed policy. Phase 5 may sign
systemd-boot.

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
