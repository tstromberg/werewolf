# Published protected boot images

## Summary

`howl run` downloads the latest authenticated protected image and deploys it through
Lima on macOS or QEMU on Linux; `--build` builds from source with the caller's signing
credentials, managed locally if absent. Secure deployment is the default; incomplete
providers and missing protection fail closed. Clouds take `--build` images only:
werewolf publishes no cloud images yet. Status: built.

## Background

The [download design](protected-downloads.md) covers dedicated trust, cache floors and
publication evidence, the [boot bundle design](boot-images.md) admission and
enrollment, and [independent updates](independent-updates.md) the TPM floor and how a
machine follows its channel. The shared release flow also publishes explicit
legacy-boot images without this protected profile; its manifests stay separate.

## Goals

Boot downloaded images without a kernel compile, local image composition or publisher
private key. Keep A/B updates, operator rollback and failed-trial fallback, with each
machine updating itself from werewolf's public channel. Authenticate published code
with pinned keys; refuse mismatched keys, profiles and TPM state without changing
trust. Publish only artifacts tested as users run them.

## Non-Goals

Protecting against a host administrator who restores VM and virtual TPM together;
falling back to VZ, an unprotected image or a source build when a download fails;
building custom applications without `--build`; publishing cloud images.

## Detailed design

### Two invocation modes

Without `--build`, resolve a published form, authenticate its latest manifest with a
pinned public key, download the exact signed disk and boot certificate, and verify every
size and hash before enrollment; persist the authenticated serial and build floor, and
reject replay, serial reuse and another architecture. An application, local form or
changed image declaration requires `--build`, never silent composition. `--build` honors
`WEREWOLF_BOOT_KEY`/`WEREWOLF_BOOT_CRT` and the complete IPE override tuple, or makes a
private local identity once and keeps it; credential loss, mismatch or partial state
requires inspection, not implicit rotation. A `--build` image follows a channel only if
its builder serves one ([secure local deployment](secure-local-deployment.md)).

### Published code trust

A dedicated protected-image boot certificate, separate from the legacy release
certificate, signs the published loader and UKIs, and howl pins its identity; a legacy
signature must not authorize a kernel that omits mandatory IPE or TPM checks. The IPE
kernel has a stable public policy authority, and every protected root requires Secure
Boot, IPE, a verified root and the TPM floor (`/usr/share/werewolf/tpm/protocol` is
`3`). Vendor signatures authenticate code and the update manifest, artifact hashes bind
the whole slot, and the signed UKI's `werewolf.channel` and `werewolf.index` name the
release.

### Firmware and TPM

Firmware on every provider admits the image's own boot certificate and no other signer;
stage0 requires Secure Boot on, setup mode off, and that the EFI `db` less `dbx` is
exactly that certificate before workloads. AWS and GCP enroll it as the whole PK, KEK
and db. Azure keeps Microsoft's PK, since a custom PK leaves its firmware in setup mode,
and revokes Microsoft's UEFI CAs in `dbx` so only the image's signer remains. The
VM's TPM starts empty and its first boot makes it the machine's own. No machine key,
nonce or credential exists on the host, so nothing a host keeps can authorize a release.

### Update channel and retirement

A published image follows the channel `SOURCE/FORM/PROVIDER` of
`release/protected/trust.json`'s source, `https://dist.werewolf-linux.org/boot/v1`. The
root pins that channel and the image key; configuration cannot authorize code or lower
the floor. The machine's updater fetches the head as `_update`, requires the running
channel and a later index, and has the mount broker raise the floor to the running
release's index before overwriting the inactive slot. Commit, failed-trial fallback and
operator rollback touch no TPM state.

### Publication gates

Playground is published too, so the default command has a disk. CI compiles pinned IPE
kernels and stubs, cached by source, architecture and public signer bytes; builds twice
with the same stable keys and metadata and compares the signed artifacts exactly; keeps
PEM secrets in private temporary files, verified against their certificate first; fixes
PE signing time; tests firmware authentication, a missing TPM, tampering and the
complete A/B lifecycle on the artifacts; and uploads immutable objects before signed
heads. `build/host/release form-images` plans each release's index, one past the last
published, and `release publish-protected` refuses one that does not advance. Missing
keys refuse; nothing unsigned is published.

## Drawbacks

Production needs a dedicated signing identity and protected CI secrets. Every machine
of a channel trusts one boot certificate, which running VMs cannot rotate.

## Alternatives Considered

Sharing a publisher private key with clients or guests defeats code authentication.
Baking a unique machine key into each root requires a source build for every consumer.
A machine-owner PK with host-held TPM credentials (protocol v2) needs a signer at every
update. Reusing legacy boot trust authorizes older signed kernels without mandatory
enforcement, and dropping the floor makes retired code bootable again.

## Security Considerations

Firmware enrollment, signed code identity and the TPM floor must agree before workload
handover; key sourcing changes need tests for setup mode, foreign PKs and key
substitution. Mutable config, a mirror or a compromised guest must not choose a new
signer or boot retired history.

## Reliability Considerations

Test a fresh Mac and cache with no Ubuntu helper, missing-state refusal, several
machines, interrupted downloads, publication ordering, and the update lifecycle with
power cuts in `test/check-independent-updates.zig`.
