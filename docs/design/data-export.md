# Exporting a machine's data

Proposed, 2026-10-15. Export is not implemented. It supports operator recovery,
migration and inspection, including the [release-testing
design](image-release-testing.md); it is not a guest test interface.

## Scope and interface

Add an explicit subcommand, with illustrative syntax:

```sh
howl export NAME --via disk --data-key FILE --output backup.tar
howl export NAME --via ssh --output backup.tar
```

Export produces an archive of persistent application data plus a manifest: not vendor
signing keys, machine enrollment/TPM custody, the boot disk or a runnable image. Restore
into another machine is a separate operation with its own compatibility checks. Begin
with complete `/data` export; path selection and logical dumps can follow.

Require an explicit method. Refuse an unavailable one rather than enabling SSH,
weakening authentication, stopping a machine unexpectedly or falling back to another
transport. Identify the machine, data volume and consistency mode before reading.
Publish output atomically to a new destination; never overwrite an existing backup.

## Authorization and LUKS

Disk export needs the caller's existing permission to read the machine volume and, when
encrypted, a key its LUKS keyslots accept. SSH export uses the configured SSH identity,
verified host identity and that account's file permissions. Neither creates a guest
authentication service or grants access the caller did not already have.

The [data contract](../data.md) accepts an operator-provided `data.key`, opens LUKS2
with it, then removes its guest config copy. A saved matching key also unlocks a stopped
disk copy even when encryption is mandatory: intended owner recovery, not a bypass. A
TPM boot credential is not a data-decryption key: a deployment that seals its only
unlock secret to a TPM and keeps no recovery key gets no disk export until the owner
supplies a supported recovery path. Never add a recovery keyslot implicitly, since it
broadens who can decrypt offline; rotation must account for older backups' keyslots.

Initially accept an explicit key file, keeping bytes out of argv, logs, manifests and
archives; later key retention uses an explicitly chosen owner secret store with volume
identity and rotation metadata, never a plaintext key beside its disk or backup. A wrong
or missing key fails without formatting, modifying keyslots or changing policy.

## Disk method

1. Lock the machine's lifecycle operations and verify it is stopped; refuse a running VM
   at first. Copy the data storage, backing files resolved, to a private work area; a
   data partition inside the boot disk is taken without boot or custody material.
2. Use an isolated, pinned Linux helper to interpret partitions, LUKS and ext4, on macOS
   too: only the copy attached, no network, the key passed over a private channel.
3. Unlock copies with the supplied key, read-only, as cryptsetup supports
   ([manual](https://kernel.googlesource.com/pub/scm/utils/cryptsetup/cryptsetup/+/refs/heads/main/man/cryptsetup-open.8.adoc));
   encryption stays enforced on the original.
4. A read-only mount is not a consistency guarantee. Prefer a clean shutdown; perform
   any journal or database recovery only on a further disposable copy, and record it.
   Never repair the source. Refuse ambiguous layouts or corruption beyond that.
5. Archive without following links outside the root or reading devices and FIFOs as
   files. Preserve ownership, modes and supported metadata; reject unsupported semantics
   rather than silently changing a backup. Extraction into the host is not this command.
6. Write a manifest: source identity, volume ID, capture method, clean or crash state,
   recovery actions, tool versions and hashes. Close mappings, detach copies and remove
   transient key material on success and failure. Secure erasure is not promised.

A stopped source avoids inventing a snapshot or guest-quiesce protocol. Provider
snapshots and remote disk downloads need separate adapters; until one exists, fail with
an actionable unsupported-provider message.

## SSH method

Use only SSH the form already enables and the operator's established authentication:
prod-ssh's security-key requirement, host-key verification and account restrictions
stay, and export creates no users, relaxes no keys, adds no tools to the root image and
assumes no account can read all of `/data`. A running guest has unlocked LUKS already,
so no disk key is sent: authorization is the SSH user's authority over plaintext files,
which neither lets that user decrypt an offline disk nor export files it cannot read.

SSH is a transport, not a consistency mechanism: a tar stream of a changing PostgreSQL
directory is not a database backup. Require a supported quiesce or snapshot operation,
or an application-native backup, before claiming consistency. Do not assume `pg_dump`:
the standalone PostgreSQL form's client tools are DEV-only, and it enables no SSH. The
first SSH implementation supports only pairs with an existing safe backup mechanism; a
quiesced service is resumed on failure, with the interruption explicit. Unsupported
services refuse rather than emit a success-shaped inconsistent archive. Logical dumps
and filesystem archives need distinct manifest types and restore instructions.

## Output confidentiality and integrity

Decrypted archives hold plaintext even when the source uses LUKS: say so in help and
output metadata, create files privately (0600, parent 0700), and never attach them to
CI artifacts by default. A future encrypted-output mode should use an established format
and a separately chosen recipient key; copying the still-encrypted volume is a different
backup product. Manifests identify what was observed, not vendor attestations about user
data. Validate archive names, bounds and destination handling, and keep partial output
apart until completion. Tests publish assertions and bounded redacted evidence, never
exported databases, passwords, TLS keys or Greenbone sessions.

## Use in tests

PostgreSQL can be stopped after restart or update, exported, and checked with a matching
database tool on a disposable copy: that establishes persisted rows, not live peer
authentication or SQL behavior, which still need local-client integration tests.
Greenbone verifies authentication and task persistence over HTTPS without export, which
may retain a versioned feed cache or its public fixture CA; restoring that cache into
another VM needs a supported restore path. Never clone a machine's TPM or enrollment.

## Validation and delivery

First implement local stopped-disk export, then SSH for explicitly supported service and
method pairs; provider snapshots, generic online backup, secret-store integration and
restore come later. Tests cover encrypted and plain volumes, correct, missing and wrong
keys, source byte preservation, clean and crash recovery, malicious archive paths,
destination collisions, interrupted cleanup and secret redaction; SSH tests add host-key
mismatch, denied file access, retained authentication requirements and failure during
quiescing; each database backup mode restores a disposable copy and verifies known
records. Before implementation, settle the Linux helper boundary, archive metadata
contract and supported layouts; the first milestone is export and verified restore of
one encrypted local VM. Export must stay useful to operators apart from release testing.
