# Data export v1 (proposed)

**Status:** Pending as of 2026-10-27

## Summary

Export `/data`, or one service directory, for [import] on another VM.

## Background

Seed imports do not restore backups; [application tests] specify the replacement.

## Goals

- Round-trip full and service data from running/stopped VMs without shells.

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
names writers and excludes audit logs, SSH keys, updater and boot/enrollment/TPM
state. Record exclusions; unsupported files or uncontrolled writers fail.

`--service NAME` selects exactly `/data/svc/NAME`, with no dependencies. Require a
known app service; record scope. Plex state is `plex`; media is `plex-media`.

Provider state selects SSH or a stopped-disk copy; SSH timeout is not shutdown.
Announce scope, method and downtime. Missing access/support fails, never enables
listeners/firewalls. Export never changes service state or VM power.

One SSH connection invokes the fixed native exporter and exits. The owner stops
application services beforehand, leaving the VM powered on. Require every app
service administratively down and its cgroup empty; v1 conservatively checks all
apps even for one-service export. Missing supervision evidence fails closed.

A reader is confined before scanning and has read/search access only to selected
roots. It cannot write, execute, connect externally or control services. Compression
and PostgreSQL control-file checks run separately without privileges. Require clean
PostgreSQL shutdown. Save supervision records before capture and check them after
copying and compression; any start, including a complete up/down cycle, invalidates
capture. The owner keeps writers down through transfer and resumes them explicitly.

Serialize transfers and hold the host lifecycle lock. A disconnect discards the
incomplete capture and changes no service state. Refuse live writers.

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

## Security Considerations

Opt-in SSH requires owner grants, pinned host identity and security keys. The root
account's native login program accepts [forced command] `export-v1` and explicit
owner stop/start requests for known apps. No root shell, PTY, SFTP, forwarding,
agent access, password login, user rc or environment. Drop to an unprivileged reader
with read/search capability; no SETPCAP is added to SSH. Reject traversal, duplicate
names, links, special files and unsupported metadata. Never extract on the host.
Archives are plaintext, mode 0600 and may hold credentials; offline is safest.

## Reliability Considerations

Require unchanged supervision records and authenticated terminal success, in
addition to a complete archive. Bound time, memory, headers and expansion. Verify
into private scratch; fsync, publish without replacement, then sync the parent.
Delete partial output on failure. Both paths require [application tests].

[import]: data-import.md
[application tests]: data-import-application.md
[Zstandard]: https://facebook.github.io/zstd/
[forced command]: https://man.openbsd.org/sshd_config#ForceCommand
