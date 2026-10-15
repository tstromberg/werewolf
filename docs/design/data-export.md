# Exporting a machine's data

Proposed, 2026-10-15. Export is not implemented. It supports operator recovery, migration and inspection, including the [release-testing design](image-release-testing.md); it is not a guest test interface.

## Scope and interface

Add an explicit subcommand, with illustrative syntax:

```sh
howl export NAME --via disk --data-key FILE --output backup.tar
howl export NAME --via ssh --output backup.tar
```

Export produces an archive of persistent application data plus a manifest. It does not export vendor signing keys, machine enrollment/TPM custody, the boot disk or a runnable image. Restoring data into another machine is a separate operation with its own compatibility checks. Begin with complete `/data` export; path selection and application-specific logical dumps can follow.

Require an explicit method initially. Refuse an unavailable method rather than enabling SSH, weakening authentication, stopping a machine unexpectedly or silently falling back to another transport. Identify the machine, data volume and consistency mode before reading. Publish output atomically to a new destination; do not overwrite existing backups.

## Authorization and LUKS

Disk export needs the caller's existing permission to read the machine volume and, when encrypted, a key accepted by its LUKS keyslots. SSH export uses the configured SSH identity, verified host identity and that account's file permissions. Neither method creates a new guest authentication service or grants access that the caller did not already have.

The current [data contract](../data.md) accepts an operator-provided `data.key`, uses it to open LUKS2, then removes its guest config copy. A saved matching key can also unlock a stopped disk copy even if encryption is mandatory. This is intended owner recovery, not a bypass of encryption. A TPM boot credential is not a data-decryption key.

If a future deployment seals its only unlock secret to a TPM and retains no recovery key, disk export must refuse until the owner supplies a supported recovery path. Saving a recovery credential broadens who can decrypt offline; do not add a recovery keyslot implicitly. Key rotation must account for older backups whose keyslots still require an earlier credential.

Initially accept an explicit key file, keeping bytes out of argv, logs, manifests and archives. Later key retention should use an explicitly chosen owner secret store, with volume identity and rotation metadata; never save a plaintext key beside its disk/backup. Wrong or missing keys fail without formatting, modifying keyslots or changing encryption policy.

## Disk method

1. Lock the machine's lifecycle operations and verify it is stopped. Refuse a running VM in the first implementation. Copy the data storage to a private work area with all backing-file dependencies resolved; handle a data partition inside the boot disk without exporting boot/custody material.
2. Use an isolated Linux helper to interpret partitions, LUKS and ext4, including when the host is macOS. Attach only the copy, give the helper no network, and pass the key through a private transient channel. The helper becomes part of the trusted export toolchain and must be pinned and verified.
3. Unlock encrypted copies with the supplied key. Cryptsetup supports key-file authentication and read-only mappings; see its [upstream manual](https://kernel.googlesource.com/pub/scm/utils/cryptsetup/cryptsetup/+/refs/heads/main/man/cryptsetup-open.8.adoc). Encryption can remain enforced on the original throughout.
4. A read-only mount is not by itself a consistency guarantee. Prefer a clean shutdown; if journal/database recovery is required, perform it only on an additional disposable copy and record the operations. Never replay or repair the source volume. Refuse ambiguous layouts or corruption beyond supported recovery.
5. Archive data without following links outside its root or reading devices/FIFOs as ordinary files. Preserve required ownership, modes and supported metadata; reject unsupported semantics instead of silently changing a backup. Keep extraction into the host filesystem out of this command.
6. Write a manifest with source identity, volume ID, capture method, clean/crash state, recovery actions, tool versions and file/archive hashes. Close mappings, detach copies and remove transient key material on success and failure. Do not promise secure erasure of ordinary storage.

Starting with a stopped source avoids inventing a snapshot/guest-quiesce protocol. Provider snapshots and remote disk downloads require separate adapters and consistency guarantees. Until an adapter exists, fail with an actionable unsupported-provider message.

## SSH method

Use only SSH already enabled by the form and the operator's established authentication. Preserve prod-ssh's security-key requirements, host-key verification and account restrictions. Do not create users, relax keys, add tools to the root image or assume every SSH account can read all of `/data`.

A running guest has already unlocked LUKS, so SSH file access does not require sending the disk key. Authorization is the SSH user's authority over plaintext files. This does not imply that the same user could decrypt an offline disk or export files it cannot normally read.

SSH is a transport, not a consistency mechanism. A tar stream of a changing PostgreSQL directory is not a valid database backup. Require a supported quiesce/snapshot operation or an application-native backup procedure before claiming consistency. Do not invent `pg_dump` availability: the standalone PostgreSQL form's client tools are DEV-only, and that form does not enable SSH.

The initial SSH implementation supports only combinations with an existing safe archive/backup mechanism. A quiesced service must be resumed on failure, with the interruption explicit to the operator. Unsupported services refuse rather than emitting a success-shaped inconsistent archive. Logical database dumps and filesystem archives need distinct manifest types and restore instructions.

## Output confidentiality and integrity

Decrypted archives contain plaintext even when the source uses LUKS. Make this explicit in help and output metadata, create files privately (0600, parent 0700), and never attach them to CI artifacts by default. A future encrypted-output mode should use an established format and a separately selected recipient/key. Copying the still-encrypted volume is a different backup product from exporting its files.

Export manifests identify what was observed; they are not vendor attestations about user data. Validate archive names, bounds and destination handling, and keep partial output separate until completion. Tests should publish assertions and bounded redacted evidence, not exported databases, passwords, TLS private keys or Greenbone sessions.

## Use in tests

PostgreSQL can be stopped after restart/update, exported, and checked with a matching database tool on a disposable copy. That establishes persisted rows, not live peer authentication or SQL behavior in the original VM. Those checks still need local-client integration tests.

Greenbone can use normal HTTPS to verify authentication and task persistence without export. Export may help retain a versioned feed cache or obtain its public fixture CA, but restoring that cache into a separately owned VM needs a supported restore path. Never clone another machine's TPM or enrollment state to reuse a test fixture.

## Validation and delivery

First implement local stopped-disk export, then add SSH for explicitly supported service/method pairs. Keep provider snapshots, generic online backup, secret-store integration and restore outside the first increment.

Tests cover encrypted/plain volumes, correct/missing/wrong keys, source byte preservation, clean and crash recovery, malicious archive paths, destination collisions, interrupted cleanup and secret redaction. SSH tests add host-key mismatch, denied file access, retained authentication requirements and failure during quiescing. For each supported database backup mode, restore a disposable copy and verify known records; archive creation alone is not success.

Before implementation, settle the Linux helper boundary, archive metadata contract and supported layouts. The first milestone should demonstrate export and restore verification of one encrypted local VM. Export must remain useful to operators independently of release testing.
