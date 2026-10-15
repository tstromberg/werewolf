# Portable protected boot bundles

## Summary

One vendor-signed boot bundle initializes independently enrolled local machines:
consumers hold public vendor certificates and their own owner keys, and unpack and
enroll the image without compiling or signing vendor code. Producer, import and the
authenticated downloader exist; default deployment remains gated.

## Background

Source builds gave each machine its own image channel and listener port. Firmware
owner authority and signed TLS transport keep machine keys and CAs out of roots; a
fixed declared listener and a shared authenticated artifact complete that separation.
The [publication design](published-secure-boot.md) keeps the production release gates.

## Goals

- Share identical signed code across machines with distinct owner keys, nonces and TPMs.
- Admit only complete measured IPE boot profiles under explicitly supplied vendor pins.
- Preserve exact-pair A/B retirement, operator rollback and failed-trial recovery, and
  import without compiling or vendor signing, reusing kernel and stub caches.

## Non-Goals

- Trust a certificate an unauthenticated download supplies, or replace machine
  enrollment with a shared vendor TPM permit signer.
- Enable production downloads before artifact and lifecycle validation passes.
- Protect against a Mac administrator restoring the entire VM and TPM together.

## Detailed design

### Artifact and admission

`boot.json` uses the closed `werewolf-boot/1` schema and an RSA/SHA-256 signature. It
binds the form, complete signed slot manifest, compressed disk hash/size, raw disk size,
vendor boot certificate DER hash, permit host/port and predicted PCR 11. The slot files
and signed image head accompany `disk.img.zst`. The consumer takes its boot and image
certificates from an explicit trusted caller; no certificate inside the bundle may
establish trust.

Authenticate the boot descriptor before parsing it, and the image head separately; the
two must agree on channel, architecture, serial and artifacts. Require IPE, a signed UKI
and measured boot context; refuse unknown profile fields and weak profiles. Check every
slot hash and the compressed disk hash before enrollment; verify the UKI's PE
signature, embedded kernel and initrd hashes, TPM command line and release identity;
compute PCR 11 from the UKI sections and compare it with the authenticated prediction.

Compressed disks are at most 2 GiB; raw disks between 512 MiB and 16 GiB. Sparse
decompression bounds the decoder's memory and writes nothing beyond the declared raw
size; truncation, excess output and decoder errors remove the partial output. Require
the canonical GPT layout, exact installed UKI, authenticated loader and protected boot
entry; refuse unsigned loader options, alternate executables and command-line editing.

### Machine enrollment

Generate a unique machine permit signer and certify it as the firmware PK/KEK owner;
enroll only the pinned vendor code certificate in db. Sign a fresh factory journal for
the authenticated release and measured PCR, insert it into the mutable `/boot/state`
of the private disk copy (signed code is unchanged), and read it back before
provisioning the TPM. Owner/lockout credentials and simulator state stay private on
the host. A failed build or import keeps partial authority for inspection, never
silently rotating it.

An imported profile holds public image and boot certificates and no vendor private key.
A restart authenticates the original bundle and keeps the disk and TPM authorization; a
source refresh can neither rebuild the profile nor substitute a signing authority. A
candidate is accepted under the original vendor pins and declared transport, and the
issuer enforces head ordering, rejecting older or conflicting vendor heads.

### Shared host service

Imported machines use the bundle's fixed declared gateway and permit port. The host
keeps one private TLS identity for that listener, refusing partial replacement, and
each machine signs a transport declaration binding that public CA to its own nonce.
Registrations live in a private host registry of at most 64 machines. A permit
request selects its issuer by exact machine nonce, with separate keys, records and
locks, so a foreign key or journal cannot authorize another machine's TPM. Public
channel routes expose only validated image heads and immutable slot objects. Stopping
one machine unregisters it alone. Accepting a vendor candidate changes publication and
permits, not firmware or TPM enrollment.

### Internal APIs

`howl _boot-image seal CONFIG` authenticates producer output and signs the portable
descriptor; `howl _boot-image verify DIR BOOT_CERT IMAGE_CERT CHANNEL` checks a bundle
against explicit pins; `howl _enroll-image NAME DIR BOOT_CERT IMAGE_CERT CHANNEL
CONFIG_TAR PROVIDER` imports or resumes it; `howl _accept-image NAME DIR` accepts a
candidate under the machine's existing pins. They serve the download consumer and the
regression runner; plain `howl run` remains gated. The [download
design](protected-downloads.md) specifies vendor pins, cached admission and CI gates.

## Drawbacks

- The shared host service must be up to authorize a transition, and admission
  depends on native PE, compressed-disk and filesystem tools.

## Alternatives Considered

- Giving consumers vendor private keys defeats publication trust separation.
- Per-machine code builds prevent sharing immutable signed boot artifacts.
- Re-enrolling after an update loses protected retirement and the A/B authorization.

## Security Considerations

Machine state stays outside signed code, and imported code cannot select its own vendor
trust. TLS authenticates transport, vendor signatures code, TPM permits the exact pair.
Reset credentials never enter the config tar, artifact or workload guest.

## Reliability Considerations

Offline tests cover foreign and altered signatures, signed weak profiles, unknown fields
and size bounds (`test/boot-images`). `make check-shared-boot` (Lima) checks identical
code with independent enrollments, vendor keys withheld, shared-service routing, signed
A/B updates, operator rollback, older-head refusal, and that unregistering one machine
keeps the other's permit issuer: six protected A/B/A boots passed across two machines,
as did the stable-module-trust kernel, which kept serving HTTPS after a deletion
(`build/ipe-check/secure-lima/shared-vendor-repro-kernel-verified/`). Interrupted
retirement and unhealthy fallback remain mandatory publication gates.
