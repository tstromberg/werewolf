# Boot enrollment and protected rollback
## Summary

New local QEMU machines boot signed UKIs with enrolled firmware keys. Protected boot
state must reject retired releases while preserving A/B recovery.
## Background

Signed slot bundles already preserve kernel, stage0, root and command line. The
firmware update test initially used Secure Boot off. Under Secure Boot, systemd-stub
ignores unsigned loader options when its embedded command line exists. Slot identity
therefore cannot depend on an entry's `options` line.
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
`werewolf.native=1`. It omits the mutable slot selector. Stage0 reads the stub's
current image path as a routing hint, accepting only the two canonical slot UKI
paths. The signed verity parameters still authenticate the selected external root; a
forged hint cannot authorize another root or command line.

Stage0 supplies the resolved, validated command line to later programs through a
read-only bind on `/proc/cmdline`. No unsigned loader options are imported. Existing
direct boots and native tests retain their explicit slot handling. Native mode
refuses ambiguous selectors, unexpected EFI paths and missing state.

### Host enrollment

The host keeps its boot key at mode 0600 beside private machine state. It signs
systemd-boot and the UKI before constructing the disk. New local QEMU machines use
Secure Boot firmware and per-machine enrolled variable storage. Existing disks retain
their enrollment; missing keys or variables fail closed. `WEREWOLF_BOOT_KEY` and
`WEREWOLF_BOOT_CRT` select a channel-compatible signer. Firmware discovery and
enrollment use local packages, or the existing Linux build VM on macOS. Plain
firmware is not a silent fallback for new machines. Cloud builds retain private
per-machine disk outputs; a build lock protects shared intermediates.

The QEMU command attaches firmware code read-only and variable state separately. On
x86, SMM isolates authenticated variable writes. Arm enrollment flash is read-only
because legacy AAVMF has no privilege boundary protecting it from guest root. Slot
selection persists in BLS files, without writable key storage. Arm key rotation
therefore requires an explicit host enrollment operation. Host variable services are
an alternative with compatible newer firmware. Lima's QEMU backend can test this
enrollment through explicit debug arguments. Its VZ backend cannot enroll keys.
Firecracker has no UEFI and refuses EFI entries; a host-verified direct launch would
require a separate trust design.

### Protected rollback

The current and retained last-known-good releases must both stay bootable, so
releases retire only when that fallback is replaced. The [TPM
floor](independent-updates.md) replaces the serial prototype: one counter per
channel, which the signed UKI's `werewolf.index` must reach, raised to the running
index before a slot is overwritten.

Guest root must not lower the counter, clear the TPM, or define a replacement with
weaker attributes. The first boot defines the counter, disables clear and sets owner
and lockout passwords that nothing keeps, so no one holds hierarchy credentials;
anyone holding the device may only increment it. A TPM in any other state fails
mandatory boot and cannot pass protected-rollback posture.

### Clouds

AWS AMIs can carry enrolled UEFI data. GCP images accept signature databases. Those
paths bind the image's boot certificate, as the whole PK, KEK and db, to the signed
disk and enable enforcement and a vTPM on the instance. Azure uses a specialized
TrustedLaunchSupported gallery definition; a version that brought its own PK booted
in setup mode, so the version keeps Microsoft's PK via the Microsoft UEFI CA
template, adds the image's certificate to db, and revokes Microsoft's UEFI CAs in
dbx. Uploads verify the loader and UKI against their certificate first, and requests
use JSON and read the enrollment back. On every provider, stage0 refuses handover
unless the EFI db less dbx is exactly the image's signer, so no second signer can
boot another loader.

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

EFI path variables are routing hints, never executable-code authority. Authenticating
the UKI, verifying the exact root and enforcing IPE remain necessary independently of
rollback protection. TPM floor tests must cover actual device commands and hierarchy
reset paths, not just serial comparisons.

## Reliability Considerations

Initial tests use disposable keys, cloned variables and local TPM state. They prove
A/B updates, tamper, unsigned image, wrong signer and loader-option override
rejection. `test/check-tpm-floor.zig` attacks the counter on swtpm;
`test/check-independent-updates.zig` boots guests through updates, operator rollback,
a power cut at the floor's increment and a restored retired release, which stage0
refuses. Clouds enroll the same way ([testing-live.md](../testing-live.md)).
References:
[systemd-stub](https://github.com/systemd/systemd/blob/main/man/systemd-stub.xml),
[QEMU variables](https://www.qemu.org/docs/master/devel/uefi-vars.html), [GCP
enrollment](https://docs.cloud.google.com/compute/shielded-vm/docs/creating-shielded-images).
