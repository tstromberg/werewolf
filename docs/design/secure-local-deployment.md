# Secured local deployment

## Summary

Deploy Lima QEMU guests with enrolled Secure Boot, IPE and exact-pair TPM retirement.
The Mac and its stored TPM state are trusted; guest root and guest disks are not.
Status: arm64 Lima integration implemented; lifecycle and issuer checks pass.

## Background

The guest protocol and QEMU x86_64 lifecycle pass, but normal Lima uses VZ.
Host enrollment and permit issuance are currently separate test operations.

## Goals

- Keep signing, recovery credentials and simulator state outside the guest.
- Refuse startup when required firmware, measured boot or enrollment is missing.
- Preserve both authorized A/B releases across commit and operator rollback.
- Retire only the inactive release before replacement; preserve the running release.
- Exercise real arm64 Lima boots, tampering and interrupted updates.

## Non-Goals

- Defend against a Mac administrator replacing the entire VM and virtual TPM.
- Give guests firmware signing or TPM hierarchy credentials.
- Silently migrate existing VZ disks or replace their enrolled trust.

## Detailed design

### Provider

Use `vmType: qemu`, enrolled firmware and Lima's persistent `tpm: true` support.
Keep the TPM state in the instance's private `swtpm` directory across restarts.
Expose only its emulated guest device; neither state nor control sockets are mounts.
Use a TPM-enabled EFI stub and compare predicted PCR 11 against an actual arm64 boot.
The default Alpine stub disables measurement and cannot serve this profile.
Build the measured stub from `boot/stub-source` with `tools/build-tpm-stub` on Linux.

### Invocation and prerequisites

`howl run --on lima --secure` selects this profile on an arm64 Mac.
Supply `WEREWOLF_IPE_KERNEL`, `WEREWOLF_IPE_KEY`, `WEREWOLF_IPE_CRT` and `UKI_STUB`.
The kernel archive must match the policy signer; first-use kernel caching is separate.
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
- First-use kernel creation or retrieval may take longer than the VM boot itself.

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
The Lima regression covers A/B/C updates, rollback, restart, failed trials and tampering.
VM/simulator process kills do not prove physical TPM power-loss atomicity.
