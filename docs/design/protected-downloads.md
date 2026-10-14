# Protected image downloads and publication

## Summary

Protected downloads authenticate vendor code before enrolling a machine.
Dedicated boot and image certificates are embedded in howl; mirrors cannot select trust.
Default `howl run` downloads the signed profile; `--build` retains caller-owned signing.
GHA publication first targets x86_64 QEMU playground after exact-bundle lifecycle tests.

## Background

The [portable bundle](boot-images.md) already separates vendor code from machine owner keys.
Legacy releases use different trust and cannot satisfy this protected profile.

## Goals

- Download bounded, authenticated disks without compiling or obtaining vendor private keys.
- Reject older heads, serial reuse and incompatible form, architecture or provider.
- Cache verified immutable objects and make repeated admission require no network or disk hashing.
- Keep failed downloads from advancing the release floor or modifying a VM.
- Publish only the exact artifacts that passed complete protected lifecycle tests.

## Non-Goals

- Protect against the Mac administrator rewriting the entire host cache and VM/TPM state.
- Treat successful artifact admission as proof that a provider passed runtime boot tests.
- Expose a public head before all publication gates have evidence.

## Detailed design

### Dedicated production trust

`release/protected/boot.crt` authorizes only protected loaders and UKIs.
`release/protected/image.crt` authorizes IPE policies, modules and signed image/boot heads.
These are separate identities and neither may reuse a legacy release key.
`release/protected/trust.json` fixes the HTTPS mirror and declared host permit port.
Compiled public certificates establish trust.
`release/create-protected-trust PRIVATE PUBLIC` refuses partial state or replacement of committed trust.
Default custody is `config/release-signing/protected/`: private files 0600, directory 0700, ignored by Git.
Keep an offline backup before putting these keys into production.
The release environment needs `WEREWOLF_PROTECTED_BOOT_KEY` and `WEREWOLF_PROTECTED_IMAGE_KEY`.
Both secrets are configured in werewolf-linux/werewolf's main-only release environment.
`release/with-protected-keys` checks both committed public certificates before starting a child.
It materializes private host paths, suppresses malformed-secret diagnostics and removes temporary keys.
Melange compile staging receives only public inputs; private module/policy signing stays on the host.

### Mirror layout

The mirror is separate from the local update/permit channel; namespaces bind each provider's gateway.

```text
boot/v1/FORM/PROVIDER/ARCH/latest/boot.json[.sig]
boot/v1/FORM/PROVIDER/ARCH/objects/DESCRIPTOR/disk.img.zst
boot/v1/FORM/PROVIDER/ARCH/objects/DESCRIPTOR/{vmlinuz,root.erofs,stage0.zst,cmdline,uki.efi}
boot/v1/FORM/PROVIDER/ARCH/objects/DESCRIPTOR/latest.json[.sig]
boot/v1/FORM/PROVIDER/ARCH/objects/DESCRIPTOR/disk.qcow2
boot/v1/FORM/PROVIDER/ARCH/objects/DESCRIPTOR/downloads.json[.sig]
boot/v1/FORM/PROVIDER/ARCH/objects/DESCRIPTOR/{gates.json,boot.crt,image.crt}
```

`DESCRIPTOR` is the SHA-256 of the signed boot JSON bytes.
Objects precede heads; torn JSON/signature pairs refuse without changing the floor or cached bundle.

### Admission and caching

`howl _boot-image head DIR BOOT_CERT IMAGE_CERT CHANNEL ARCH FORM PROVIDER` authenticates
bounded metadata, checks the boot certificate hash and requires the exact requested identity.
The downloader uses this native gate before fetching any artifact selected by the descriptor.
HTTPS redirects cannot downgrade to HTTP or inject credentials.
Requests identify Werewolf; stock macOS uses system curl for TLS 1.3. Streams enforce signed sizes/hashes.
Native complete-bundle verification then checks the independent image signature, PE signature,
embedded kernel/initrd, measured identity and predicted PCR before cache promotion.

A private lock serializes downloads for one channel/public-trust identity across mirrors.
Hash-addressed objects share slot bytes; temporary partial downloads are removed on failure or interruption.
A verified receipt binds the validator, all artifact sizes and file identity/change timestamps.
Unchanged receipts skip rehashing and native artifact verification for five minutes.
Metadata signatures still authenticate cached admission; changing validator or cached bytes forces verification.

The persistent floor binds serial, build and descriptor hash and advances only after full admission.
Equal serials must identify the same complete descriptor, including the disk and PCR.
Older and future heads, corrupt floors and a missing retained floor fail closed.
The cache floor does not retire a TPM release or replace a machine's original bootstrap bundle.
An existing enrollment must retain its owner/TPM state and accept a candidate through its issuer.

### CI and publication

`.github/workflows/protected-images.yml` runs unit, admission, download, custody and export regression tests.
Relevant main pushes, an hourly schedule and manual dispatch produce two independent
x86_64 QEMU copies with dedicated environment secrets; both include playground, prod and prod-ssh.
Admission resolves a shared package snapshot for the images, kernel base, bootloader and both Melange builders.
Both copies consume those exact versions; the deduplication key binds source, package bytes and public trust.
Only a fully published GitHub release and verified R2 mirror mark inputs successful; failures retry.
Manual dispatch accepts `force` to publish again with the same inputs. No compiled kernel cache crosses copies.
Each job shares prerequisites between forms but the two copies do not restore compiled kernels.
The comparison covers complete signed disks and slots. Public candidates omit `boot.json.sig`.
The QEMU gate authorizes three playground candidates and tests them on hosted Linux with KVM, OVMF and swtpm.
The harness also supports Lima; evidence cannot cross providers or architectures. Only tested bundles publish.

`release/prepare-protected` authenticates the candidate with committed trust, requires an exact
artifact/provider/architecture evidence record and runs complete native admission before copying.
All fourteen evidence checks must be boolean true, including A/B upgrade, operator rollback,
unhealthy fallback, retirement cuts, tampering, independent owner isolation and fresh downloads.
It prepares immutable objects, signed heads and an upload plan in a new directory atomically.
`release/publish-protected` checks the store's authenticated floor and uploads objects before heads.
An atomic signed-head receipt preserves the newest accepted release across interrupted head writes.
Signed configuration accompanies the exact code; resumed machines retain their original bootstrap.

`release/export-protected` preserves original signatures and verifies standalone qcow2/raw disk equivalence.
Its signed manifest binds asset hashes, lifecycle evidence, source commit and GHA run; uploads reverify it.
GitHub assets have form/provider/architecture prefixes; identical R2 objects retain canonical filenames.
All GitHub assets are attested. A draft becomes public only after fresh R2 downloads match every asset.
The `publishing-health` workflow tracks main-branch check, package and image failures in one issue per workflow,
updates that issue on retries and closes it after recovery. Pull-request runs cannot create these issues.

## Security Considerations

Vendor signatures authorize code; machine keys authorize TPM transitions. They remain separate.
Advancing a cache head must never implicitly delete a VM, reset TPM state or replace owner keys.
Production trust changes require a deliberate rotation design; missing keys never rotate automatically.
## Reliability Considerations

Tests exercise real native signature admission before mocked artifact transport.
Additional stream tests cover exact, truncated, oversized and encoded responses.
Publication tests reject missing, false, nonboolean and foreign-artifact lifecycle evidence.
Unit tests alone cannot authorize publication; exact-bundle runtime evidence remains mandatory.
