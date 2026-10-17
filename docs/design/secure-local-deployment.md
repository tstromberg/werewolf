# Secured local deployment

## Summary

Deploy Lima and Linux QEMU guests with enrolled Secure Boot, IPE and exact-pair TPM
retirement. The local host and its stored TPM state are trusted; guest root and guest
disks are not. Status: Lima lifecycle passed with Melange-built inputs and native Mac
firmware enrollment.

## Background

The QEMU lifecycle passes; Lima uses QEMU. Both combine enrollment and permit issuance.

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

Use `vmType: qemu`, enrolled firmware and Lima's persistent `tpm: true`. Keep the TPM
state in the instance's private `swtpm` directory across restarts and expose only the
emulated guest device: neither state nor control sockets are mounts. Linux QEMU uses the
same authorities, with a private host supervisor for persistent swtpm; QEMU receives the
control socket, the guest only the device. Missing enrolled backing state fails, and
shutdown must finish before authority removal. Use a TPM-enabled EFI stub and compare
predicted PCR 11 against actual boots: the default Alpine stub disables measurement, so
build the measured one from `boot/stub-source` with `tools/build-tpm-stub` on Linux.

### Invocation and prerequisites

`howl run --build` selects this profile on an arm64 Mac or native Linux. Published
downloads remain gated in [the publication design](published-secure-boot.md). Without
overrides, howl creates a private host IPE identity and caches matching builds: a
kernel whose IPE trusts its certificate (`tools/test-kernel`) and the measured stub. A
cache identity binds architecture, public signer, sources and builder bytes, and a
checksummed completion record rejects altered or incomplete artifacts. All three IPE
overrides must be supplied together; `UKI_STUB` can override the measured stub. Mac
builds use the Melange QEMU runner, which boots Alpine's `linux-virt` only as a build
guest: an isolated Linux guest supplies native Kbuild and EFI/TPM tools, private keys
stay on the Mac, and firmware and enrollment dependencies are hash-pinned. `--build`
seals a bundle as CI seals werewolf's, signed with keys in `$XDG_DATA_HOME/howl`; the
machine enrolls it as it would a download, so the image holds nothing of one machine.
`--dev` requires `--disable=secureboot,tpm,ipe`, the legacy deployment path.

### Enrollment

Create a unique machine nonce and signed factory pair for the initial release.
Store its signed journal outside the slots before constructing the boot disk.
Provision a fresh simulator before the first guest boot, using native host TPM commands.
Persist random owner and lockout credentials privately before changing authority.
Disable clear, define the exact v2 NV policy and initialize/read back its anchor.
Existing enrollment cannot be overwritten. Interrupted provisioning fails closed;
retain recovery credentials and report the partial state rather than reset silently.

### Images and permits

A host listener is shared across checkouts/providers; its TLS identity and registry
live in `$XDG_DATA_HOME/howl/permit-service/PORT`. Legacy identities retain certificates
and VM enrollment during adoption. New local channels are scoped by checkout.
Use one host-held signer across a machine's authorized release images. New roots select
the enrolled firmware PK; legacy roots retain their embedded TPM verification key. The
image manifest, embedded UKI identity and host PCR mapping must agree, and boot, IPE and
update signing identities must match their enrolled authorities. A bundle is signed with
the caller's boot credentials, or the user's managed signer. The host signs a transition
only after authenticating the old record and candidate, checking retained membership and
release/PCR mappings, under a lock that serializes issuance; only the current published
candidate can receive one, historical registrations cannot reauthorize retired roots,
completed transitions may resume, and publication refuses older heads. Only public
signed permits are delivered, which guest code authenticates against the TPM; delivery
and publication survive host-service restart. Guest root can request updates or cause
denial of service, never grant authority. The root declares the permit host and port;
[signed config](machine-transport.md) supplies its public TLS CA. A rerun rebuilds only
when pinned inputs or the builder change, and offers the result as an update.

### Startup and existing machines

Create the Lima instance, provision its own simulator state, then start the guest, and
report readiness only after the required guest checks succeed. Restart preserves disk,
firmware variables, hierarchy credentials and TPM state; unchanged runs reuse live
guests. An existing machine without this profile needs explicit recreation or
migration: configuration changes cannot make an older image enforcing.

## Drawbacks

- Requires QEMU, swtpm, a measured stub and an IPE kernel matching the signer.
- Host permit issuance adds persistent state and an availability dependency.
- First-use kernel compilation needs native build dependencies and outlasts a VM boot.

## Alternatives Considered

- VZ does not provide the required enrolled Linux Secure Boot path.
- Guest-held hierarchy credentials allow reset and defeat protected retirement.
- Unmeasured stubs allow software construction of future PCR values from zero.
- Commit-time floors invalidate the predecessor and defeat A/B recovery.

## Security Considerations

New profiles use PK for TPM authority, matching KEK and pinned db; old roots keep
embedded keys. Host keys and private state must never appear in roots, config disks or
guest mounts. Reject unknown anchors, missing TPMs, wrong keys and unsigned or retired
images. Firmware must trust only UKIs that require mandatory TPM checks.

## Reliability Considerations

The CLI regression covers creation, restart, updates, rollback, failed trials,
tampering, retirement and NV cuts, and the rejection of retired releases, missing TPMs
and unmeasured UKIs; provisioning is validated against independent TPM tools, keeping
only public evidence. Killing VM and simulator does not prove TPM power-loss atomicity.
