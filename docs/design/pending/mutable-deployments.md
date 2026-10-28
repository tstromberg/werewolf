# Mutable deployments

**Status:** Pending as of 2026-10-27

Proposed, 2026-10-27. Commands and kernel support below are not implemented.

## Summary

`howl run --mutable` independently installs signed Werewolf and Wolfi APKs.
Selection changes locally; running deployments stay verified and read-only with A/B.

## Background

Today [protected updates](../implemented/prebuilt-images.md) authorize an exact root
and UKI. Our [composer](../implemented/custom-updates.md) consumes `NAME-form` APKs
but cannot sign roots. APK signatures cover archives, not subsequent changes to
extracted files.

## Goals

- Install `curl` and `samba-form` from existing signed feeds without a build service.
- Preserve Secure Boot, execution integrity, confinement and failed-trial fallback.
- Prove independent installation, update, removal and tamper rejection in VM tests.

## Non-Goals

- Change the default immutable mode, allow unsigned APKs or live root mutation.
- Run arbitrary package scripts or promise every package works under confinement.
- Introduce private signing keys on nodes or roll back application data.

## Detailed design

**Interface.** `howl run --mutable --packages curl --with samba` seeds a world;
`howl create NAME --mutable` persists one. Guest `update add curl samba-form`,
`update del curl` and `update status` manage the next deployment through the
authenticated admin channel. Changes stage until reboot; automatic upgrades keep
the existing update schedule. Plain packages start no service or widen any grant.
`samba-form` declares its dependencies, accounts, confinement and TCP/445 listener;
missing config credentials block commit. Operators manage external firewalls.

**Identity and storage.** Provisioning chooses a separate mutable boot certificate,
channel and TPM profile. Immutable machines refuse it; mode changes reprovision.
Base A/B holds signed kernel, verifier, composer, launcher and their dependencies.
A package disk holds retained APKs, indexes, locks and deployment A/B; `/data` holds
state and secrets. Partitions may share a disk. Ordinary APKs cannot replace the
verifier, trust keys or enforcement programs; base dependencies are solver pins.
Locks bind base, world, APK digests, repositories and format; rollback keeps all.

**Staging.** Reuse the fetcher and [offline
installer](../implemented/updater-installer.md). Resolve the full world with existing
Werewolf repository precedence and pinned keys and proofs. Reject conflicts,
incompatible formats and package downgrades; removal retains version floors.
Scripts/triggers never execute during installation. Forms declare setup and confined
helpers; strip setuid bits and file capabilities. Admins change worlds; auto-updates
preserve them. The broker checks locks/versions. Provision TPM NV records binding
active, fallback, pending locks and version floors; only verifier/broker may change
them. Today's base counter cannot bind local locks.

**Boot verification.** Before networking or workloads, the signed base checks the
selected lock against TPM state and authenticates every retained APK and index.
Confined base workers reconstruct paths, metadata, symlinks and policy exactly.
Only verified archives enter construction; no candidate code executes. Build EROFS
and its verity tree, open that exact device through dm-verity, then authorize its
root hash. Reconstruct every boot; never trust a cached image or updater's hash.
Verity checks subsequent reads, including scripts/config; `/data` stays noexec.

**IPE.** [Upstream](https://docs.kernel.org/admin-guide/LSM/ipe.html)
requires signed runtime policies. Prototype a mutable-kernel-only, one-shot boot
interface: initial PID 1 with CAP_MAC_ADMIN supplies the verified deployment hash;
the kernel installs only fixed default-deny rules for base and deployment roots.
It atomically closes admission, removes any initramfs allowance and prohibits later
policy changes. PID 1 drops capabilities; children never inherit admission.
This needs new kernel work; bypass/replacement tests gate shipping mutable mode.

## Drawbacks

Boot reconstruction costs space/time; the verifier, composer and IPE interface add
trusted code. Packages requiring scripts or protected base overrides cannot work.

## Alternatives Considered

- Remote signed compositions: retain today's trust model but require a build service.
- Signed package images or per-file fs-verity: avoid boot reconstruction but require
  republishing Wolfi content and separately authenticating layout and composition.
- Verify only at install, or trust a local hash: modified files survive reboot.
- Writable overlays or disabling IPE: lose the requested execution boundary.

## Security Considerations

Trust approved package publishers, not arbitrary signatures. Signed forms may
change service policy only within base-enforced limits; scripts/JIT retain existing
limits. Disk edits cannot authorize a new lock; TPM records prevent replay of retired
deployments. Update floors/locks atomically. Exclude disk erasure, compromised
publishers and host disk/TPM restoration; mirrors can withhold unseen releases.

## Reliability Considerations

Retain active/fallback APKs, base and lock; collect nothing before retirement.
Journal trial authorization and commit through crash-consistent TPM transitions;
health failure restores the retained tuple. Data migrations need separate recovery.
Gate on both architectures: curl HTTPS, Samba authenticated sharing, add/remove,
offline reboot, base upgrades, bad signatures, metadata/symlink tampering, stale
locks, reinstall downgrades, policy replacement, full disk and cuts at each durable
step. Immutable boot/update tests must still pass without entering mutable paths.
