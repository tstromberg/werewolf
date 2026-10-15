# Signed prebuilt IPE updates

## Summary

Enrolled IPE machines download complete, signed slot bundles. They verify
the bundle before writing or arming a slot, preserving the signed root policy.

## Background

The package updater normally composes EROFS on the machine. That changes
the root hash without a host signature for its IPE policy. Machines never
receive the private signing key ([ipe.md](ipe.md)).

## Goals

- Update IPE images, including custom applications, without local composition.
- Authenticate every boot artifact and bind it to one channel and architecture.
- Refuse malformed, replayed or damaged updates before slot writes.
- Prove rejection and a successful reboot/commit in a real VM.

## Non-Goals

- Production publication automation and signing-key provisioning.
- Secure Boot enrollment or TPM-backed rollback prevention.
- Authorizing JIT forms or unsigned local rebuilds.

## Detailed design

Build with the IPE kernel and host-only RSA key/certificate as before. Add
`IPE_UPDATES=https://images.example/shop` and a UTC `IMAGE_SERIAL`, then
run `make IPE=1 FORM=prod APP=/path/to/app prebuilt`. Howl accepts
`--ipe-updates URL --image-serial YYYYMMDDTHHMMSSZ` with its IPE flags.
Development images cannot be exported.

The verified root pins the channel, RSA public key, initial serial and
custom declaration hash in `/usr/share/werewolf/image-update`. Enrollment
and serial participate in build stamps. Each custom application needs its
own channel; neither the machine nor a mirror may choose a different one.

The exporter writes `OUT/prebuilt/ARCH/latest.json` and its detached
`latest.json.sig`. Immutable `ARCH/BUILD/` objects contain `vmlinuz`,
`root.erofs`, `stage0.zst`, `cmdline`, and optional
`uki.efi`. BUILD hashes the canonical artifact names, sizes and SHA-256s.
Upload immutable objects first and the signed head last. Exporting does
not publish remotely. The IPE certificate's RSA key signs the manifest.
With `WEREWOLF_BOOT_KEY` set, export first rebuilds the UKI from this slot.
Without a boot key, a leftover UKI is excluded from the bundle.

The `werewolf-image/1` manifest explicitly requires `ipe: true`. It binds
channel, architecture, serial, root hash, kernel, packages, advisories,
declaration and every artifact's size/hash. RSA/SHA-256 authentication
precedes strict JSON parsing. Unknown fields, incomplete artifact records,
unsafe URLs and malformed command lines fail closed.

The updater bounds the manifest to 1 MiB and each artifact to its signed
size (at most 8 GiB). Its fetcher retains TCP 443/53 restrictions. All
downloads are checked before any slot mutation; installation authenticates
the manifest and hashes the files again. The existing advisory policy
schedules the reboot. A custom declaration change is an operator update.

The root's initial serial and a synced persistent `(serial, build)` floor
refuse older releases, serial reuse with different content and releases
over a day ahead. Equal initial serial requires the running root hash.
The floor is recorded before installation and never silently lowered.

Each parked root retains its signed manifest, signature and command line. Native EFI
receives the authenticated stage0 archive and optional UKI. Installation rechecks the
parked bytes before arming, and automatic reboot rechecks them again. Native updates
remove an obsolete UKI; verification refuses an unselected leftover UKI.

An explicit operator `try` may select an older image, but verifies its
channel, key and all installed artifacts. It does not lower the floor.
Unenrolled IPE machines hold updates with `IpeSignedImageRequired`.

## Drawbacks

- Whole-image downloads consume more bandwidth than package updates.
- Each application channel needs host builds and a protected signer.
- A persisted floor can hold updates after an interrupted installation;
  retrying the same signed release remains possible.

## Alternatives Considered

- An on-machine signer would give compromised root authority to authorize code.
- Signing only EROFS leaves kernel, stage0 and command line outside the bundle.
- Sharing channels between applications loses declaration isolation.

## Security Considerations

The pinned signer authorizes kernels as well as roots. Protect its private
key accordingly. A mirror can withhold releases but cannot forge them.
The floor lives on writable data; it is not a TPM rollback counter.
Mutable firmware/bootloader state still needs Secure Boot protection.
The optional UKI is authenticated as a bundle artifact; firmware must
separately trust its PE signature for Secure Boot enforcement.

## Reliability Considerations

Existing try counts, health commit and fallback remain in use. Objects
precede heads so readers can retry a briefly inconsistent publication.
`make IPE=1 check-image-updater` exercises HTTPS, invalid signatures,
wrong channel/architecture, serial rollback/reuse, missing/false IPE claims,
damaged root bytes and a successful install/reboot/commit with IPE.
Unit tests cover pinned-key authentication, artifact integrity, installed
stage0 variants, stale UKIs and 64-character reboot countdown identities.
CI runs both architectures with disposable signing keys.
`check-image-updater-uki` also tests continuous firmware boot and native
EFI installation on accelerated arm64, checking the delivered UKI digest.
Factory slots retain their signed manifests and command line for authenticated
operator rollback. `check-ab-PROVIDER` proves upgrades, rollback after commit,
another reboot of the retained release, and automatic unhealthy-slot recovery.
