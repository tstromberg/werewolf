# Secured local deployment

## Summary

Deploy Lima and Linux QEMU guests with enrolled Secure Boot, IPE and exact-pair TPM retirement.
The local host and its stored TPM state are trusted; guest root and guest disks are not.
Status: arm64 Lima and x86_64 Linux QEMU verified, including managed security inputs.

## Background

The guest protocol and QEMU x86_64 lifecycle pass; normal Lima uses VZ.
The secured profile combines host enrollment, signing and permit issuance.

## Goals

- Keep signing, recovery credentials and simulator state outside the guest.
- Refuse startup when required firmware, measured boot or enrollment is missing.
- Preserve both authorized A/B releases across commit and operator rollback.
- Retire only the inactive release before replacement; preserve the running release.
- Exercise real arm64 Lima boots, tampering and interrupted updates.

## Non-Goals

- Defend against a host administrator replacing the entire VM and virtual TPM.
- Give guests firmware signing or TPM hierarchy credentials.
- Silently migrate existing VZ disks or replace their enrolled trust.

## Detailed design

### Provider

Use `vmType: qemu`, enrolled firmware and Lima's persistent `tpm: true` support.
Keep the TPM state in the instance's private `swtpm` directory across restarts.
Expose only its emulated guest device; neither state nor control sockets are mounts.
Linux QEMU uses the same authorities, with a private host supervisor for persistent swtpm.
QEMU receives its control socket; the guest receives only the emulated TPM device.
Missing enrolled backing state fails; shutdown must finish before authority removal.
Use a TPM-enabled EFI stub and compare predicted PCR 11 against actual boots.
The default Alpine stub disables measurement and cannot serve this profile.
Build the measured stub from `boot/stub-source` with `tools/build-tpm-stub` on Linux.

### Invocation and prerequisites

`howl run --on lima --secure` selects this profile on an arm64 Mac.
`howl run --on qemu --secure` selects it on native Linux.
Without overrides, howl creates a private host IPE identity and caches matching builds.
Cache identities bind architecture, Alpine base, public signer, sources and builder bytes.
Checksummed completion records reject altered or incomplete cached artifacts.
All three IPE overrides must be supplied together; `UKI_STUB` can override the measured stub.
The Mac uses a trusted Linux build helper and sends only its public IPE certificate.
A separate temporary module signer stays in the builder and is deleted after compilation.
Host authorities and public release objects persist beneath the machine directory.
`--dev` is refused; ordinary Lima remains available without this opt-in profile.

### Enrollment

Create a unique machine nonce and signed factory pair for the initial release.
Store its signed journal outside the slots before constructing the boot disk.
Provision a fresh simulator before the first guest boot, using native host TPM commands.
Persist random owner and lockout credentials privately before changing authority.
Disable clear, define the exact v2 NV policy and initialize/read back its anchor.
Existing enrollment cannot be overwritten. Interrupted provisioning fails closed;
retain recovery credentials and report the partial state rather than reset silently.

### Images and permits

Use a consistent host-held signer across a machine's authorized release images.
All update roots must contain the same TPM verification key as their predecessor.
The image manifest, embedded UKI identity and host PCR mapping must agree.
Boot, IPE and update signing identities must match their enrolled authorities.
Generate a unique boot signer; ignore shared legacy boot-signing environment overrides.
The host signs a transition only after authenticating the old record and candidate,
checking retained membership, validating release/PCR mappings and serializing issuance.
Deliver only public signed permits; guest code authenticates them against the TPM.
Permit delivery and release publication must survive host-service restart.
Guest root can request updates or cause denial of service; it cannot grant authority.
Only the current published candidate can receive a new transition signature.
Historical registrations cannot reauthorize retired roots; completed transitions may resume.
Publication refuses older heads. Signature checks and a lock serialize bounded issuance.
The local TLS certificate and update port are declared in the verified root.
Hourly host refreshes rebuild only when pinned inputs or the builder change.

### Startup and existing machines

Create the Lima instance, provision its own simulator state, then start the guest.
Report readiness only after the required guest checks succeed.
Restart preserves disk, firmware variables, hierarchy credentials and TPM state.
An existing machine without this profile requires explicit recreation or migration;
configuration changes cannot turn an older non-enforcing image into an enforcing one.

## Drawbacks

- Requires QEMU, swtpm, a measured stub and an IPE kernel matching the signer.
- Host permit issuance adds persistent state and an availability dependency.
- First-use kernel compilation requires native build dependencies and takes longer than VM boot.

## Alternatives Considered

- VZ does not provide the required enrolled Linux Secure Boot path.
- Guest-held hierarchy credentials allow reset and defeat protected retirement.
- Unmeasured stubs allow software construction of future PCR values from zero.
- Commit-time floors invalidate the predecessor and defeat A/B recovery.

## Security Considerations

Firmware must trust only UKIs that require mandatory TPM checks.
Host keys and private state must never appear in roots, config disks or guest mounts.
Reject unknown anchors, missing TPMs, wrong keys and unsigned or retired images.
Avoid advertising full protection when only a subset of the profile is enabled.

## Reliability Considerations

Test creation, restart, healthy update, rollback, failed trials and retirement cuts.
Check explicit rejection of retired releases, missing TPMs and unmeasured UKIs.
Validate provisioning against independent TPM tools and retain only public evidence.
The CLI regression covers updates, rollback, restart, failed trials, tampering and NV cuts.
VM/simulator process kills do not prove physical TPM power-loss atomicity.
