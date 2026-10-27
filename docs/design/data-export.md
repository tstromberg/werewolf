# Data export v1 (proposed)

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

`--service NAME` selects exactly `/data/svc/NAME`, not dependencies. Require a known
application service, never a path or system service. Print and record the scope. Plex
state is `plex`; media is `plex-media`. Neither alone migrates the whole app.

Provider state selects SSH or a stopped-disk copy; SSH timeout is not shutdown.
Announce scope, method and downtime. Missing access/support fails, never enables
listeners/firewalls. Export may interrupt services but never changes VM power.

One SSH connection exports and exits. A guard owns fixed service controls; a separate
reader has read/search access only to selected roots. Neither accepts commands, SQL,
arbitrary paths or URLs. The reader cannot write, execute, connect externally or
control services; the guard has no general admin or mount-broker access.

Lock against updates, imports and lifecycle changes. Save prior states, suppress
restarts, stop clients before databases, and verify clean exit of every selected-root
writer, including other services with write grants. Keep essential services and SSH
outside capture. Timeout aborts; killing is not clean shutdown. Hold writers stopped
through transfer, then restore prior states.

Lock the stopped VM until an immutable copy includes all backing files. A Linux
helper without network/host shares reads only that copy, on macOS too. Require clean
filesystem/application shutdown; refuse damage. Pass the owner recovery key
(`--data-key FILE`) privately to unlock LUKS. Detach and clean scratch; never mount
or repair the source.

Use restricted tar: `manifest.json`, regular files/directories under `data/`, then
`complete.json`. Record image, architecture, scope, inventory, exclusions and capture
state. The final entry hashes all preceding uncompressed tar bytes with SHA-256.
Require that digest, completion entry, complete compression frame and terminal
capture-success result; EOF alone is insufficient.

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

Opt-in SSH requires owner export grants, pinned host identity and security keys.
Native login accepts only [forced command] `export-v1`. Disable shell, PTY, SFTP,
forwarding, agents, password/root login and user rc/environment. Scope requests
cannot exceed the authenticated grant. Reject links, special files, traversal,
duplicate names and unsupported metadata. Never extract onto host paths. SSH encrypts
transport; the mode-0600 archive is unencrypted and may hold credentials. Explain
this. A cleanly stopped source is least dangerous.

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
