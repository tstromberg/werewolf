# Published protected boot images

## Summary

`howl run` downloads the latest authenticated protected image and deploys it through
Lima on macOS; `--build` builds from source with the caller's signing credentials,
managed locally if absent. Secure deployment is the default; incomplete providers and
missing protection fail closed. Status: importer, dedicated trust, cached downloader
and candidate CI implemented; default wiring remains gated.

## Background

New roots take machine authority from firmware and TLS trust from signed config; source
builds use per-machine channels, imported bundles a declared local one. The [download
design](protected-downloads.md) covers dedicated trust, cache floors and publication
evidence, the [boot bundle design](boot-images.md) shared artifact enrollment and a
multiplexed host issuer. The legacy release workflow signs disks without an IPE policy
or protected release retirement, so it does not publish this profile.

## Goals

Boot downloaded images without a kernel compile, local image composition or publisher
private key, through Lima on macOS (its QEMU backend gives enrolled firmware and a
persistent TPM). Preserve exact-pair A/B updates, operator rollback, failed-trial
fallback and interrupted retirement. Authenticate published code apart from the user's
machine enrollment and recovery authority; refuse mismatched keys, profiles and missing
TPM state without changing trust. Publish only artifacts tested as users run them.

## Non-Goals

Protecting against a Mac administrator who restores VM and virtual TPM together;
falling back to VZ, an unprotected image or a source build when a download fails;
building custom applications without `--build` or a published application channel;
exporting private host signing or TPM credentials to the workload or builder.

## Detailed design

### Two invocation modes

Without `--build`, resolve a published form, authenticate its latest manifest with a
pinned public key, download the exact signed disk and boot certificate, and verify every
size and hash before enrollment; persist the authenticated serial and build floor, and
reject replay, serial reuse and another architecture. An application, local form or
changed image declaration requires `--build`, never silent composition. `--build` honors
`WEREWOLF_BOOT_KEY`/`WEREWOLF_BOOT_CRT` and the complete IPE override tuple, or makes a
private local identity once and keeps it; credential loss, mismatch or partial state
requires inspection, not implicit rotation or re-enrollment.

### Published code trust

A dedicated protected-image boot certificate, separate from the legacy release
certificate, signs the published loader and UKIs, and howl pins its identity; a legacy
signature must not authorize a kernel that omits mandatory IPE or TPM checks. The IPE
kernel has a stable public policy authority and a pinned measured EFI stub, and every
protected root requires Secure Boot, IPE, a verified root and protocol-v2 TPM
authorization. Vendor signatures authenticate code and the update manifest, artifact
hashes bind the whole slot, and the signed UKI supplies the shared release identity.

### Machine authority outside the published root

The explicit `2-firmware` enrollment mode leaves embedded-key roots unchanged and reads
the single authenticated firmware Platform Key as its TPM permit authority: howl
installs a unique machine owner certificate as PK/KEK, which administer firmware, and
the code certificate in db, which authorizes execution. Firmware must start outside
setup mode with exactly that trust; stage0 reads bounded EFI signature-list data before
workloads and refuses ambiguous or missing keys. Host-side provisioning defines the NV
policy for that public machine key and signs its factory record; the nonce, journal and
reset credentials stay machine-specific, and boot still requires a nonzero PCR, an
authenticated journal, a protected hierarchy and the exact pair.

### Update transport and retirement

The published root pins its vendor image channel and manifest key independently of the
machine permit key; image fetching is separate from the host permit endpoint, and
configuration cannot authorize code or reset NV. Permit requests carry the machine
nonce, candidate identity, protected predecessor and retained PCR; the local authority
authenticates vendor manifests and release/PCR mappings before signing a transition,
and the [signed transport declaration](machine-transport.md) binds TLS trust to the
nonce. Several Lima guests share a host listener or declare isolated ones; immutable
host/port declarations bound the endpoint, which signed config cannot widen. Commit
retains both releases, replacement retires only the inactive one, once, and rollback
and unhealthy-trial fallback reuse that authorization without lowering the floor.

### Publication gates

Playground is published too, so the default command has a disk. CI compiles pinned IPE
kernels and measured stubs, cached by source, architecture and public signer bytes;
builds twice with the same stable keys and metadata and compares the signed artifacts
exactly; keeps PEM secrets in private temporary files, verified against their
certificate first; fixes PE signing time; tests firmware authentication, a missing TPM,
wrong enrollment, tampering and the complete A/B lifecycle on the artifacts; and uploads
immutable objects before signed heads. Missing keys refuse; nothing unsigned is
published. Only after these gates pass does the consumer take the profile as default.

## Drawbacks

Portable machine enrollment adds a firmware trust parser and a second signing authority
to audit; production needs a dedicated signing identity and protected CI secrets; host
permit publication stays an availability dependency.

## Alternatives Considered

Sharing a publisher private key with clients or guests defeats code authentication.
Baking a unique machine key into each root requires a source build for every consumer.
Reusing legacy boot trust authorizes older signed kernels without mandatory
enforcement, and dropping TPM retirement makes retired code bootable again.

## Security Considerations

Firmware enrollment, measured code identity and NV authorization must agree before
workload handover; key sourcing changes need tests for setup mode, foreign and duplicate
PKs, legacy db entries and key substitution. Mutable config, a mirror or a compromised
guest must not choose a new signer or authorize retired history.

## Reliability Considerations

Test a fresh Mac and cache with no Ubuntu helper, retained-authority restart,
missing-state refusal, several Lima guests, publisher restart, interrupted downloads,
publication ordering, and the real VM/TPM cut tests and A/B matrix in both modes.
