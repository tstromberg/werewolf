# IPE

Implemented as an opt-in build, 2026-10-11. Production release builds still
use Alpine's kernel. This is phase 4 of [verified boot](verified-boot.md).

## Summary

IPE permits native code only from the selected dm-verity root, globally,
including processes outside Fence. A signed policy names that root's hash.
The machine cannot disable or replace the policy after stage0 activates it.

## Background

Mount flags and Landlock already restrict service execution. IPE also
checks executable mappings, including those made by a dynamic loader,
and reaches the mount broker, DHCP renewal and kernel helpers.

## Goals

- Allow native executables and libraries from one immutable root image.
- Refuse other volumes, writable files, and policy administration.
- Fail boot before handing over if the policy is missing or invalid.
- Keep the signing key on the builder, outside every guest artifact.

## Non-Goals

- Per-service binary declarations: Leash and Landlock still enforce them.
- Interpreted input, JIT code, kernel exploits, or executable code already mapped.
- Secure Boot and TPM rollback protection: separate boot-chain work.

## Detailed design

`boot/build-kernel` builds on native Linux, starting from the matching
Alpine configuration. `boot/kernel-source` pins the upstream version and
SHA-256; the script refuses a different Alpine version. Both architectures
keep their drivers and compressed modules. IPE, module signature enforcement
and forced lockdown are enabled; kexec and extra IPE signer keyrings are off.
The supplied certificate is trusted for policies and its key signs modules.
There is no generated developer module key. Keep this identity stable when
comparing independent builds; the private key is absent from the output tar.

The bootstrap policy permits execution and modules from initramfs only.
Stage0 loads modules, opens the verified root, then loads `ipe.p7b` from
initramfs. The kernel verifies its PKCS#7 signature. Stage0 checks the
deployed policy against the mounted root hash, activates it, and forces
enforcing mode. The final policy has no initramfs exception:

```text
policy_name=werewolf policy_version=1.0.0
DEFAULT action=DENY
op=EXECUTE dmverity_roothash=sha256:ROOT_HASH action=ALLOW
```

Stage0 drops CAP_MAC_ADMIN from its bounding, effective, permitted and
inheritable sets before forking the deadman. No policy file stays open.
The deadman uses only existing code and raw syscalls. Init checks the
active, enforcing policy before continuing. Posture checks enforcement
and PID 1's capability boundary; IPE images remove the stock exceptions.

Builds use separate paths, `build/ARCH/ipe/FORM-ipe`, and the root carries
`/usr/share/werewolf/ipe`. The builder checks the custom kernel config and
certificate. The private signing key is read only by host OpenSSL.

On Linux, supply a stable certificate and private key, then run:

```sh
export WEREWOLF_IPE_KEY=/path/to/policy.key
export WEREWOLF_IPE_CRT=/path/to/policy.crt
make ipe-kernel
make IPE=1 FORM=minimal image
make IPE=1 check-ipe
```

On macOS, build the kernel in a Linux VM and copy its `rootfs.tar` back.
`IPE_KERNEL` selects that archive. The remaining build and QEMU checks run
on the host. Howl also accepts `--ipe-kernel`, `--ipe-key`, `--ipe-cert`
for `build` and `_build`; all three are required together.

**Updates are held.** The package updater rebuilds EROFS locally, changing
the root hash without obtaining its signed policy. On an IPE machine it
returns `IpeSignedImageRequired` before modifying a slot. Completing
automatic updates requires a prebuilt signed-image delivery path, including
custom application images. There is no fallback to unsigned local rebuilds.
Installing or arming another slot and rebooting into a pending update are
also held; the current slot can still commit normally.
Production releases do not enable IPE until that delivery path is built.

## Drawbacks

- Maintaining and testing a custom kernel on both architectures.
- Signing each distinct root, including an application's custom image.
- Native code already in the trusted image remains available to IPE.
- The strict root policy refuses anonymous executable memory; JIT forms are unsupported.

## Alternatives Considered

- Trusting any signed verity volume simplifies updates but authorizes older roots.
- Per-file fs-verity signatures need a different filesystem and image pipeline.

## Security Considerations

IPE authenticates runtime code under the current kernel. A mutable kernel,
stage0 or command line still needs Secure Boot protection. The policy version
is constant for a boot-selected root, and supplies no persistent rollback
counter. No claim of script or JIT integrity is made.

## Reliability Considerations

`make IPE=1 check-ipe` boots the actual image, then runs an independent
kernel probe without seccomp, Landlock or noexec mounts. It tests trusted
exec, mmap and mprotect, an executable tmpfs, another verified volume, a trusted loader
mapping untrusted ELF, and lost policy-administration capability. Missing,
tampered, untrusted-signer and correctly signed wrong-root policies must stop stage0.
Anonymous executable mmap and mprotect are refused. CI runs
the same suite on x86_64 and aarch64 with disposable keys.
