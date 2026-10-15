# Boot enrollment and protected rollback

## Summary

New local QEMU machines boot signed UKIs with enrolled firmware keys.
Protected boot state must reject retired releases while preserving A/B recovery.

## Background

Signed slot bundles already preserve kernel, stage0, root and command line.
The firmware update test initially used Secure Boot off. Under Secure Boot,
systemd-stub ignores unsigned loader options when its embedded command line
exists. Slot identity therefore cannot depend on an entry's `options` line.

## Goals

- Generate and retain a private boot signer on the host for local machines.
- Enroll PK, KEK and db before boot; refuse unsigned and tampered loaders.
- Boot and commit both slots through UKIs with Secure Boot enforced.
- Retire obsolete releases without disabling the retained A/B fallback.
- Test root's attempts to lower, undefine or reset that state.

## Non-Goals

- Protect against an administrator who controls the hypervisor or TPM state.
- Claim TPM protection from a writable disk marker or an unprovisioned TPM.
- Enable a cloud flag before its firmware trusts the actual boot chain.

## Detailed design

### Signed native boot identity

A native UKI embeds the root filesystem UUID, root directory, ESP serial and
`werewolf.native=1`. It omits the mutable slot selector. Stage0 reads the
stub's current image path as a routing hint, accepting only the two canonical
slot UKI paths. The signed verity parameters still authenticate the selected
external root; a forged hint cannot authorize another root or command line.

Stage0 supplies the resolved, validated command line to later programs through
a read-only bind on `/proc/cmdline`. No unsigned loader options are imported.
Existing direct boots and native tests retain their explicit slot handling.
Native mode refuses ambiguous selectors, unexpected EFI paths and missing state.

### Host enrollment

The host keeps its boot key at mode 0600 beside private machine state. It signs
systemd-boot and the UKI before constructing the disk. New local QEMU machines use
Secure Boot firmware and per-machine enrolled variable storage. Existing disks retain
their enrollment; missing keys or variables fail closed. `WEREWOLF_BOOT_KEY` and
`WEREWOLF_BOOT_CRT` select a channel-compatible signer. Firmware discovery and
enrollment use local packages, or the existing Linux build VM on macOS. Plain firmware
is not a silent fallback for new machines. Cloud builds retain private per-machine disk
outputs; a build lock protects shared intermediates.

The QEMU command attaches firmware code read-only and variable state separately.
On x86, SMM isolates authenticated variable writes. Arm enrollment flash is
read-only because legacy AAVMF has no privilege boundary protecting it from
guest root. Slot selection persists in BLS files, without writable key storage.
Arm key rotation therefore requires an explicit host enrollment operation.
Host variable services are an alternative with compatible newer firmware.
Lima's QEMU backend can test this enrollment through explicit debug arguments.
Its VZ backend cannot enroll keys. Firecracker has no UEFI and refuses EFI entries;
a host-verified direct launch would require a separate trust design.

### Protected rollback

TPM policy must keep the current and retained last-known-good releases bootable. A
healthy commit preserves its predecessor; retire releases when replacing that fallback.
Signed boot identity must match protected authorization before handover. The [exact-pair
retirement protocol](tpm-ab-retirement.md) replaces the serial prototype. Its opt-in
guest checks, provisioning and actual QEMU x86_64 power cuts are verified.

Guest root must not replace the protected anchor, clear the TPM, or provision
a replacement index with weaker permissions. Hierarchy credentials remain on
the host. NV writes need authenticated transitions preserving the retained fallback;
an ordinary owner-writable index or guest-held password is insufficient.
Unprovisioned devices fail mandatory boot and cannot pass protected-rollback posture.

### Clouds

AWS AMIs can carry enrolled UEFI data. GCP images accept signature databases. Those
paths must bind the certificate to the signed disk and enable enforcement on the
instance. Azure uses a specialized TrustedLaunchSupported gallery definition and a
version with NoSignatureTemplate plus our PK/KEK/db, then enables Trusted Launch.
Uploads verify the actual loader and UKI against their certificate first. Azure requests
explicitly use JSON and read back the exact enrollment before launch. Tests distinguish
argument construction from live firmware acceptance. Azure firmware inconsistently
reports SetupMode=1; reliable deployment remains blocked.

## Drawbacks

- Firmware packages and enrollment tools differ between host platforms.
- Losing the host key prevents signing future images for that enrollment.
- Retirement is irreversible; it must not invalidate the retained fallback.

## Alternatives Considered

- Unsigned BLS options are ignored under Secure Boot and cannot bind slots.
- A disk serial floor is useful replay filtering but can be rewritten by root.
- A TPM presence check says nothing about who can reset its NV state.
- Guest-held signing or hierarchy keys would give root the authority being denied.

## Security Considerations

EFI path variables are routing hints, never executable-code authority.
Authenticating the UKI, verifying the exact root and enforcing IPE remain
necessary independently of rollback protection. TPM policy tests must cover
actual device commands and hierarchy reset paths, not just serial comparisons.

## Reliability Considerations

Initial tests use disposable keys, cloned variables and local TPM state. They prove A/B
updates, tamper, unsigned image, wrong signer and loader-option override rejection. QEMU
x86_64 TPM-gated boots refuse retired releases, missing TPMs and unmeasured UKIs. Power
cuts preserve B; commit and operator rollback retain both members. Lima arm64 and Linux
QEMU are verified. Cloud enrollment follows the proposed [TPM bootstrap
design](cloud-tpm-enrollment.md). References:
[systemd-stub](https://github.com/systemd/systemd/blob/main/man/systemd-stub.xml), [QEMU
variables](https://www.qemu.org/docs/master/devel/uefi-vars.html), [GCP
enrollment](https://docs.cloud.google.com/compute/shielded-vm/docs/creating-shielded-images).
