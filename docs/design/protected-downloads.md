# Protected image downloads and publication

## Summary

Protected downloads authenticate vendor code before enrolling a machine.
Dedicated boot and image certificates are embedded in howl; mirrors cannot select trust.
Default `howl run` downloads the signed profile; `--build` retains caller-owned signing.
Publication requires actual downloaded-image lifecycle evidence before any public head is uploaded.

## Background

The [portable bundle](boot-images.md) already separates vendor code from machine owner keys.
Existing production releases use different trust and do not supply the complete protected profile.
This path never accepts those legacy releases as protected images.

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
The compiled public certificates, rather than certificates downloaded beside an image, establish trust.

`release/create-protected-trust PRIVATE PUBLIC` creates an identity once, refusing partial state
or replacement of committed trust. Default custody here is `config/release-signing/protected/`.
Private files have mode 0600; the directory has mode 0700 and is ignored by Git.
Keep a separate offline backup before putting these keys into production.
The release environment needs `WEREWOLF_PROTECTED_BOOT_KEY` and `WEREWOLF_PROTECTED_IMAGE_KEY`.
Both secrets are configured in werewolf-linux/werewolf's main-only release environment.
`release/with-protected-keys` checks both committed public certificates before starting a child.
It materializes private host paths, suppresses malformed-secret diagnostics and removes temporary keys.
Melange compile staging receives only public inputs; private module/policy signing stays on the host.

### Mirror layout

The external mirror is independent of the image's declared local HTTPS update/permit channel.
Provider-specific namespaces bind Lima's gateway or Linux QEMU's gateway into the signed profile.

```text
boot/v1/FORM/PROVIDER/ARCH/latest/boot.json[.sig]
boot/v1/FORM/PROVIDER/ARCH/objects/DESCRIPTOR/disk.img.zst
boot/v1/FORM/PROVIDER/ARCH/objects/DESCRIPTOR/{vmlinuz,root.erofs,stage0.zst,cmdline,uki.efi}
boot/v1/FORM/PROVIDER/ARCH/objects/DESCRIPTOR/latest.json[.sig]
```

`DESCRIPTOR` is the SHA-256 of the signed boot JSON bytes.
Objects must be uploaded before the latest signature, then the latest JSON.
A torn JSON/signature pair refuses without changing the accepted floor or cached bundle.

### Admission and caching

`howl _boot-image head DIR BOOT_CERT IMAGE_CERT CHANNEL ARCH FORM PROVIDER` authenticates
bounded metadata, checks the boot certificate hash and requires the exact requested identity.
The downloader uses this native gate before fetching any artifact selected by the descriptor.
HTTPS redirects cannot downgrade to HTTP or inject credentials.
Requests identify Werewolf explicitly; missing publication and access denial have separate errors.
Every streamed artifact enforces its exact signed size and SHA-256, including absent content lengths.
Native complete-bundle verification then checks the independent image signature, PE signature,
embedded kernel/initrd, measured identity and predicted PCR before cache promotion.

A private lock serializes downloads for one channel/public-trust identity across mirrors.
Objects are addressed by hash and linked into complete bundles without duplicating slot bytes.
Partial downloads live in temporary directories and are removed on ordinary failure or interruption.
A verified receipt binds the validator, all artifact sizes and file identity/change timestamps.
Unchanged receipts skip rehashing and native artifact verification for five minutes.
Metadata signatures still authenticate cached admission; changing validator or cached bytes forces verification.

The persistent floor binds serial, build and descriptor hash and advances only after full admission.
Equal serials must identify the same complete descriptor, including the disk and PCR.
Older and future heads, corrupt floors and a missing retained floor fail closed.
The cache floor does not retire a TPM release or replace a machine's original bootstrap bundle.
An existing enrollment must retain its owner/TPM state and accept a candidate through its issuer.

### CI and publication

`.github/workflows/protected-images.yml` runs native admission, download and custody regression tests.
Manual candidate builds on main require dedicated environment secrets and produce two independent
copies for x86_64 QEMU, arm64 QEMU and arm64 Lima; all include playground, prod and prod-ssh.
Each job shares prerequisites between forms but the two copies do not restore compiled kernels.
The comparison covers complete signed disks and slots. Public candidates omit `boot.json.sig`.
The trusted Lima gate privately authorizes three candidates and tests exact production artifacts.
It requires a dedicated arm64 Mac runner with QEMU, Lima and persistent TPM tooling.

`release/prepare-protected` authenticates the candidate with committed trust, requires an exact
artifact/provider/architecture evidence record and runs complete native admission before copying.
All fourteen evidence checks must be boolean true, including A/B upgrade, operator rollback,
unhealthy fallback, retirement cuts, tampering, independent owner isolation and fresh downloads.
It prepares immutable objects, signed heads and an upload plan in a new directory atomically.
`release/publish-protected` checks the store's authenticated floor and uploads objects before heads.
An atomic signed-head receipt preserves the newest accepted release across interrupted head writes.
Signed configuration accompanies the exact code; resumed machines retain their original bootstrap.

## Security Considerations

Vendor signatures authorize code; machine keys authorize TPM transitions. They remain separate.
Advancing a cache head must never implicitly delete a VM, reset TPM state or replace owner keys.
Production trust changes require a deliberate rotation design; missing keys never rotate automatically.

## Reliability Considerations

Tests exercise real native signature admission before mocked artifact transport.
Additional stream tests cover exact, truncated, oversized and encoded responses.
Publication tests reject missing, false, nonboolean and foreign-artifact lifecycle evidence.
Unit tests alone cannot authorize publication; exact-bundle runtime evidence remains mandatory.
