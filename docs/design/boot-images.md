# Portable protected boot bundles

## Summary

One vendor-signed boot bundle can initialize independently enrolled local machines.
Consumers have public vendor certificates and their own machine owner keys.
They unpack and enroll the image without compiling or signing vendor code.
Status: producer/import and authenticated downloader implemented; default deployment remains gated.

## Background

Source builds previously gave each machine a different image channel and listener port.
Firmware-derived owner authority and signed TLS transport remove machine keys and CAs from roots.
A fixed declared listener and a shared authenticated artifact complete that separation.
The [publication design](published-secure-boot.md) retains the production release gates.

## Goals

- Share identical signed code across machines with distinct owner keys, nonces and TPM state.
- Admit only complete measured IPE boot profiles under explicitly supplied vendor trust pins.
- Preserve exact-pair A/B retirement, operator rollback and failed-trial recovery.
- Reuse kernel/stub caches and perform no compilation or vendor signing during import.

## Non-Goals

- Trust a signing certificate supplied by an unauthenticated downloaded image.
- Replace machine enrollment with a shared vendor TPM permit signer.
- Enable production downloads before artifact and lifecycle validation passes.
- Protect against a Mac administrator restoring the entire VM and TPM together.

## Detailed design

### Artifact and admission

`boot.json` uses the closed `werewolf-boot/1` schema and an RSA/SHA-256 signature.
It binds the form, complete signed slot manifest, compressed disk hash/size, raw disk size,
vendor boot certificate DER hash, permit host/port and predicted PCR 11.
The slot files and signed image head accompany `disk.img.zst`.
The consumer receives its boot and image certificates from an explicit trusted caller.
No certificate inside the bundle may establish new trust.

Authenticate the boot descriptor before parsing it; authenticate the image head separately.
Require the two image declarations to agree, including channel, architecture, serial and artifacts.
Require IPE, a signed UKI and measured boot context; refuse unknown profile fields and weak profiles.
Check every slot hash and the compressed disk hash before enrollment.
Verify the UKI's PE signature, embedded kernel/initrd hashes, TPM command line and release identity.
Compute PCR 11 independently from the UKI sections and compare it with the authenticated prediction.

Compressed disks are at most 2 GiB; raw disks are bounded between 512 MiB and 16 GiB.
Sparse decompression limits the decoder's memory and writes no bytes beyond the declared raw size.
Truncation, excess output and decoder errors remove the partial output.
Require the canonical GPT layout, exact installed UKI, authenticated loader and protected boot entry.
Unsigned loader options, alternate executables and interactive command-line editing are refused.

### Machine enrollment

Generate a unique machine permit signer and certify it as the firmware PK/KEK owner.
Enroll only the pinned vendor code certificate in db.
Sign a fresh factory journal for the authenticated release and measured PCR.
Insert it into the mutable `/boot/state` directory of the private disk copy; signed code is unchanged.
Read the journal back before provisioning the machine's TPM.
Keep original owner/lockout credentials and simulator backing state privately on the host.
Build and import failures preserve partial authority for inspection; they never silently rotate it.

Imported profiles contain public image/boot certificates and no vendor private signing keys.
Restart authenticates the original bundle and retains the existing disk and TPM authorization.
Source refresh cannot rebuild an imported profile or substitute another signing authority.
An authenticated candidate can be accepted using the original vendor pins and declared transport.
The existing issuer enforces head ordering and rejects older or conflicting vendor heads.

### Shared host service

New imported machines use the bundle's fixed declared gateway and permit port.
The host persists one private TLS identity for that listener, refusing partial identity replacement.
Each machine signs a transport declaration binding that public CA to its own authenticated nonce.
Machine registrations live in a private host registry; the listener supports at most 64 machines.
Permit requests select the issuer by the exact machine nonce, with separate keys, records and locks.
Foreign keys or journals cannot authorize another machine's TPM.
Public channel routes expose only validated image heads and immutable slot objects.
Stopping one machine unregisters it; the service remains available to other registered machines.
Vendor candidate acceptance changes publication and permits, not firmware or TPM enrollment.

### Internal APIs

`howl _boot-image seal CONFIG` authenticates producer output and signs the portable descriptor.
`howl _boot-image verify DIR BOOT_CERT IMAGE_CERT CHANNEL` checks a bundle against explicit pins.
`howl _enroll-image NAME DIR BOOT_CERT IMAGE_CERT CHANNEL CONFIG_TAR PROVIDER` imports or resumes it.
`howl _accept-image NAME DIR` accepts a candidate under that machine's existing pins.
These APIs support the download consumer and regression runner; plain `howl run` remains gated.
The [download design](protected-downloads.md) specifies dedicated vendor pins, cached admission and CI gates.

## Drawbacks

- Shared host service availability is needed to authorize new transitions.
- Artifact admission depends on native PE, compressed-disk and filesystem tools.

## Alternatives Considered

- Giving consumers vendor private keys defeats publication trust separation.
- Per-machine code builds prevent sharing immutable signed boot artifacts.
- Re-enrolling after an update loses protected retirement and the original A/B authorization.

## Security Considerations

Machine-specific state remains outside signed code; imported code cannot select its own vendor trust.
Transport authenticates TLS, vendor signatures authenticate code and TPM permits authorize the exact pair.
Reset credentials never enter the config tar, artifact or workload guest.

## Reliability Considerations

Offline tests cover foreign/altered signatures, signed weak profiles, unknown fields and size bounds.
The real Lima runner checks identical code with independent enrollments, unavailable vendor keys,
shared-service routing, signed A/B updates, operator rollback and older-head refusal.
Six protected A/B/A boots passed across two machines; consumer compilation and vendor signing were forbidden.
The revised stable-module-trust kernel also passed six protected boots and continued HTTPS service after deletion.
Public evidence: `build/ipe-check/secure-lima/shared-vendor-repro-kernel-verified/`.
Separate HTTPS tests verify that unregistering one machine preserves the other's permit issuer.
Interrupted retirement and unhealthy fallback remain mandatory downloaded-image publication gates.
