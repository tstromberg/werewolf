# Data export v1 (proposed)

**Status:** Pending as of 2026-10-27

## Summary

Export `/data`, or one service directory, for [import] on another VM.

## Background

Seed imports do not restore backups; [application tests] specify the replacement.

## Goals

- Round-trip all data and a selected service from running and stopped VMs.
- Require no shell or consistency selection; validate each advertised provider.

## Non-Goals

- Live capture, upgrades, cross-architecture moves, incremental/resumable transfer,
  built-in encryption, logical dumps and automatic traffic cutover.

## Detailed design

```sh
howl export source --output ./backup.tar.zst
howl export source --service plex --output ./plex.tar.zst
```

`howl export NAME` creates `NAME-export-TIMESTAMP-RANDOM.tar.zst` by default. Walk
all `/data`: databases, media, preferences, caches, secrets and homes. Signed policy
names every writer and exact exclusions for SSH host keys, updater and
boot/enrollment/TPM state. Record exclusions; unsupported files or uncontrolled
writers fail.

`--service NAME` selects exactly `/data/svc/NAME`, with no dependencies. Require a
known app service; record scope. Plex state is `plex`; media is `plex-media`.

Provider state selects SSH or a stopped-disk copy; SSH timeout is not shutdown.
Announce scope, method and downtime. Missing access/support fails, never enables
listeners/firewalls. Export may interrupt services but never changes VM power.

One SSH connection exports and exits. A guard owns fixed service controls; a separate
reader is confined before scanning and has read/search access only to selected roots.
Neither accepts commands, SQL, paths or URLs. The reader cannot write, execute,
connect externally or control services; the guard has no admin or mount authority.

Lock against updates, imports and lifecycle changes. Save prior states, suppress
restarts, stop clients before databases, and verify clean exit of every selected-root
writer, including other services with write grants. Keep essential services and SSH
outside capture. Timeout aborts; killing is not clean shutdown. Hold writers stopped
through transfer, then restore prior states.

Lock the stopped VM until an immutable copy includes all backing files. A Linux
helper without network/host shares reads only that copy, on macOS too. Require clean
filesystem/application shutdown; refuse damage. Pass the owner recovery key
(`--data-key FILE`) privately to unlock LUKS. Detach and clean scratch; never mount
or repair the source. Verify attached image bytes against trusted verity parameters;
refuse mixed boot slots. Separate data volumes require a recorded verified image.

Use restricted tar: `manifest.json`, regular files/directories under `data/`, then
`complete.json`. Record image, architecture, scope, inventory, exclusions and capture
state. Require the final entry's SHA-256 of all preceding uncompressed tar bytes,
completion entry, full compression frame and terminal success; EOF is insufficient.

Stream [Zstandard] level 1 at source, online or offline: one thread, no dictionary or
SSH compression. Overlap compression, transfer and writing without archive staging.

## Drawbacks

Writers remain stopped for transfer, potentially hours for Plex. Require matching
image/architecture. Compression may not help media; measure time, memory and CPU.

## Alternatives Considered

- Live dumps/snapshots need application-specific coordination; defer.
- Generic SFTP/shell access exposes unnecessary operations; use one fixed verb.
- Dependency expansion makes selection surprising; select an exact service root.

## Security Considerations

Opt-in SSH requires owner grants, pinned host identity and security keys. Native
login accepts [forced command] `export-v1` only; deny shell, PTY, SFTP, forwarding,
agents, password/root login, user rc and environment. Enforce the authenticated
scope. Reject traversal, duplicate names, links, special files and unsupported
metadata. Never extract on the host. Archives are mode 0600, unencrypted and may
hold credentials; document this. A cleanly stopped source is least dangerous.

## Reliability Considerations

Invalidate capture before restarting writers on disconnect, timeout or reader
failure. The independent guard recovers saved states; reboot invalidates capture.
Bound time, memory, headers and expansion. Verify into private scratch; fsync,
publish without replacement, then sync the parent. Preserve valid output if restart
fails; return nonzero and name services. Require [application tests] before delivery.

[import]: data-import.md
[application tests]: data-import-application.md
[Zstandard]: https://facebook.github.io/zstd/
[forced command]: https://man.openbsd.org/sshd_config#ForceCommand
