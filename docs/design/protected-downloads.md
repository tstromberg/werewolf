# Protected image downloads and publication

## Summary

Protected downloads authenticate vendor code before enrolling a machine, with dedicated
boot and image certificates embedded in howl, so a mirror cannot select trust. `howl
run` downloads the signed profile by default; `--build` keeps caller-owned signing.

## Background

[Bundles](boot-images.md) separate vendor code from owner keys; legacy trust cannot.

## Goals

- Download bounded, authenticated disks without compiling or holding vendor keys;
  reject older heads, serial reuse and incompatible form, architecture or provider.
- Cache verified immutable objects, so repeated admission needs no network or hashing;
  keep failed downloads from advancing the floor or modifying a VM.
- Publish only the exact artifacts that passed complete protected lifecycle tests.

## Non-Goals

- Protect against the Mac administrator rewriting the host cache and VM/TPM state.
- Treat artifact admission as proof that a provider passed runtime boot tests, or
  expose a public head before all publication gates have evidence.

## Detailed design

### Dedicated production trust

`release/protected/boot.crt` authorizes protected loaders and UKIs alone;
`release/protected/image.crt` IPE policies and signed image and boot heads.
Neither may reuse a legacy release key. `release/protected/trust.json` fixes the HTTPS
mirror and the declared host permit port. `release/create-protected-trust PRIVATE
PUBLIC` refuses partial state or replacing committed trust; custody is the Git-ignored
`config/release-signing/protected/` (0600, directory 0700), backed up offline.
`WEREWOLF_PROTECTED_BOOT_KEY` and `WEREWOLF_PROTECTED_IMAGE_KEY` live in the main-only
release environment; `release/with-protected-keys` checks both committed certificates
before starting a child and removes the temporary keys after. Melange compile staging
gets public inputs only; module and policy signing stays on the host.

### Mirror layout

Apart from the local update and permit channel, with a namespace per provider gateway:

```text
boot/v1/FORM/PROVIDER/ARCH/latest/boot.json[.sig]
boot/v1/FORM/PROVIDER/ARCH/objects/DESCRIPTOR/disk.{img.zst,qcow2}
boot/v1/FORM/PROVIDER/ARCH/objects/DESCRIPTOR/{vmlinuz,root.erofs,stage0.zst,cmdline,uki.efi}
boot/v1/FORM/PROVIDER/ARCH/objects/DESCRIPTOR/{latest,downloads}.json[.sig]
boot/v1/FORM/PROVIDER/ARCH/objects/DESCRIPTOR/{gates.json,boot.crt,image.crt}
```

`DESCRIPTOR` is the SHA-256 of the signed boot JSON. Objects precede heads; a torn pair
refuses without changing the floor or cached bundle.

### Admission and caching

`howl _boot-image head DIR BOOT_CERT IMAGE_CERT CHANNEL ARCH FORM PROVIDER`
authenticates bounded metadata, checks the boot certificate hash and requires the exact
requested identity before any artifact the descriptor names is fetched. A redirect
cannot downgrade to HTTP or inject credentials; requests identify Werewolf (on macOS,
system curl for TLS 1.3). Streams enforce signed sizes and hashes, and admission checks
image and PE signatures, kernel, initrd, measured identity and PCR before promotion.

A private lock serializes downloads for one channel and trust identity across mirrors;
hash-addressed objects share slot bytes, and a partial download is removed on failure.
A verified receipt binds the validator, artifact sizes and the files' identity and
change times: unchanged, it skips rehashing and native verification for five minutes,
metadata signatures still checked; a changed validator or byte forces verification.

The persistent floor binds serial, build and descriptor hash and advances only after
full admission; equal serials must name the same descriptor, disk and PCR included, and
older or future heads, a corrupt floor or a missing retained floor fail closed. The
floor retires no TPM release and replaces no bootstrap bundle: an enrollment keeps its
owner and TPM state and accepts a candidate through its issuer.

### CI and publication

`.github/workflows/form-images.yml` runs the unit, admission, download, custody and
export tests, then builds every form for each provider of each architecture, in two
independent copies with dedicated environment secrets. A shard resolves one package
snapshot (forms, kernel, bootloader, the stub's Melange builder) for both copies; jobs
share prerequisites between forms, never compiled output between copies, and the
comparison covers complete signed disks and slots. A target is skipped only when its
digest of source, package bytes, tools and trust matches a passed signed catalog row,
unless `force`d. Public candidates omit `boot.json.sig`. Each gate job authorizes three
playground candidates and tests them where they boot: hosted Linux with KVM, OVMF and
swtpm for QEMU/x86_64, self-hosted runners for arm64 QEMU and Lima. Evidence never
crosses providers or architectures; only tested bundles publish. Pull requests run the
QEMU lifecycle with disposable trust (`protected-images.yml`).

`release/prepare-protected` requires committed trust, evidence for the exact artifact,
provider and architecture, and native admission: all fourteen evidence checks must be
boolean true (A/B upgrade, operator rollback, unhealthy fallback, retirement cuts,
tampering, owner isolation, fresh downloads), and lays out immutable objects, signed
heads and an upload plan in a new directory, atomically. `release/publish-protected`
checks the store's authenticated floor and uploads objects before heads, a signed-head
receipt keeping the newest accepted release across an interrupted write. Signed
configuration accompanies the exact code; a resumed machine keeps its bootstrap.

`release/export-protected` keeps the original signatures, verifies that the standalone
qcow2 and raw disk match, and signs a manifest binding asset hashes, lifecycle evidence,
source commit and GHA run, which uploads reverify. GitHub assets carry form, provider
and architecture prefixes and are attested; R2 keeps canonical names; a draft goes
public only after fresh R2 downloads match every asset. The `publishing-health` workflow
tracks main-branch check, package and image failures in one issue per workflow, updated
on retries and closed on recovery; never from a PR.

## Security Considerations

Vendor signatures authorize code and machine keys TPM transitions, never the other.
Advancing a cache head never deletes a VM, resets TPM state or replaces owner keys;
changing production trust takes a deliberate rotation design, never a missing key.

## Reliability Considerations

Tests exercise native admission before mocked transport, with exact, truncated,
oversized and encoded streams; publication tests reject missing, false, nonboolean
and foreign evidence. Unit tests never authorize publication alone.
