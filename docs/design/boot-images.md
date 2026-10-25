# Portable protected boot bundles

## Summary

One vendor-signed boot bundle installs any number of unrelated local machines: howl
admits it under pinned public certificates, unpacks its disk, enrolls the image's own
boot certificate in fresh firmware, and boots it with a TPM nobody has touched. Nothing
is compiled or signed for a machine. Producer, admission and downloader are built.

## Background

The bundle is what [protected downloads](protected-downloads.md) fetch and what
`--build` makes with the user's keys. Its machine follows its channel by itself
([independent updates](independent-updates.md)); the [publication
design](published-secure-boot.md) keeps the release gates.

## Goals

- Share identical signed code across machines with distinct firmware variables and TPMs.
- Admit only complete IPE boot profiles whose signed UKI names the manifest's release.
- Keep A/B updates, operator rollback and failed-trial recovery, and import without
  compiling or vendor signing, reusing kernel and stub caches.

## Non-Goals

- Trust a certificate an unauthenticated download supplies.
- Keep any per-machine key, credential or registration on the host.
- Protect against a host administrator restoring the entire VM and TPM together.

## Detailed design

### Artifact and admission

`boot.json` uses the closed `werewolf-boot/2` schema and an RSA/SHA-256 signature. It
binds the form, the complete signed slot manifest (`werewolf-image/2`, with its channel
identity and release index), compressed disk hash/size, raw disk size, the boot
certificate's DER hash and the form's deployment definition. The slot files and signed
image head accompany `disk.img.zst`. The consumer takes its boot and image certificates
from an explicit trusted caller; no certificate inside the bundle establishes trust.

Authenticate the boot descriptor before parsing it, and the image head separately; the
two manifests must be identical. Require IPE and a signed UKI; refuse unknown fields and
weak profiles. Check every slot hash and the compressed disk hash before enrollment;
verify the UKI's PE signature, that its `.linux` and `.initrd` sections are the signed
kernel and stage0, and that its signed command line is a secure native boot naming the
manifest's `werewolf.channel` and `werewolf.index`.

Compressed disks are at most 2 GiB; raw disks between 512 MiB and 16 GiB. Sparse
decompression bounds the decoder's memory and writes nothing beyond the declared raw
size; truncation, excess output and decoder errors remove the partial output. Require
the canonical GPT layout, exact installed UKI, authenticated loader and protected boot
entry; refuse unsigned loader options, alternate executables and command-line editing.

### Machine enrollment

Fresh firmware variables enroll the image's boot certificate as PK, KEK and db alone;
the VM gets a fresh TPM. Its first boot makes the TPM its own: stage0 defines the
channel's floor counter at the release index and seals the hierarchies with passwords
nothing keeps. The host holds the disk, firmware variables and TPM state, but no key or
credential of the machine. A restart keeps all three; a newer download never replaces an
existing machine's enrollment.

### Internal APIs

`howl _boot-image seal CONFIG` authenticates producer output and signs the portable
descriptor; `howl _boot-image verify DIR BOOT_CERT IMAGE_CERT CHANNEL [ARCH]` checks a
bundle against explicit pins; `head DIR BOOT_CERT IMAGE_CERT CHANNEL ARCH FORM` admits
the descriptor alone; `download FORM PROVIDER` fetches the latest bundle. They serve the
downloader, `release/` and the regression runners. The [download
design](protected-downloads.md) specifies vendor pins, cached admission and CI gates.

## Drawbacks

- Admission depends on native PE, compressed-disk and filesystem tools.
- Every machine of a channel trusts the same boot certificate, so rotating it takes a
  reinstall.

## Alternatives Considered

- Giving consumers vendor private keys defeats publication trust separation.
- Per-machine code builds prevent sharing immutable signed boot artifacts.
- A machine-owner PK with host-held TPM credentials keeps a signer at every update.

## Security Considerations

Machine state stays outside signed code, and imported code cannot select its own vendor
trust. TLS authenticates transport and vendor signatures code; the TPM floor decides
which releases may boot. No reset credential exists to leak into a config tar or guest.

## Reliability Considerations

Offline tests cover foreign and altered signatures, signed weak profiles, unknown
fields, release identity mismatches and size bounds (`cmd/howl/boot-image.zig`'s tests).
The lifecycle, with updates, rollback, power cuts and retired replay, is
`test/check-independent-updates.zig`
([testing-secure-boot.md](../testing-secure-boot.md)).
