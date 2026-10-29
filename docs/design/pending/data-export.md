# Data export v1 (proposed)

**Status:** Pending as of 2026-10-28

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
names writers and excludes SSH keys, updater and boot/enrollment/TPM
state. Include logs for evidence; import discards them. Unsupported files fail.

`--service NAME` selects exactly `/data/svc/NAME`, with no dependencies. Require a
known app service; record scope. Plex state is `plex`; media is `plex-media`.

Online export uses opt-in SSH; disk-based export requires a confirmed stopped VM.
Cloud disks use `aws`/`gcloud`/`az`, private snapshots and temporary storage.
GCP uses Cloud Build image export. Missing access fails; add no guest listeners.
SSH failure is not shutdown. Export changes no service or VM power state.

One SSH connection invokes the fixed native exporter and exits, without a shell.
The owner stops application services beforehand, leaving the VM powered on. Require
every app administratively down and its cgroup empty; v1 conservatively checks all
apps even for one-service export. Logs use bounded snapshots; rotation may fail.

A reader is confined before scanning and has read/search access only to selected
roots. It cannot write, execute, connect externally or control services. Compression
and PostgreSQL control-file checks run separately without privileges. Require clean
PostgreSQL shutdown. Save supervision records before capture and check them after
copying and compression; any start, including a complete up/down cycle, invalidates
capture. The owner keeps writers down through transfer and resumes them explicitly.

Serialize transfers and hold the host lifecycle lock. A disconnect discards the
incomplete capture and changes no service state. Refuse live writers.

Copy the stopped VM's raw disk under its lifecycle lock. A Linux
helper without network/host shares reads that copy, on macOS too. Replay its journal
only; require clean metadata/application shutdown and refuse damage. Pass the owner
recovery key (`--data-key FILE`) privately to unlock LUKS. Clean scratch; never mount
or repair the source. Verify attached images against trusted verity parameters;
refuse mixed boot slots. Separate data volumes require a recorded verified image.

Tar: `manifest.json`, `data/` files/directories, `complete.json`. Record image, arch,
scope, inventory, exclusions and capture state. Require SHA-256 over preceding tar
bytes, completion entry, full compression frame and terminal success; never only EOF.

Stream [Zstandard] level 1 at source, online or offline: one thread, no dictionary or
SSH compression. Overlap compression, transfer and writing without archive staging.

## Drawbacks

Writers remain stopped for transfer, potentially hours for Plex. Require matching
image/architecture. Compression may not help media; measure time, memory and CPU.

## Alternatives Considered

- Live dumps/snapshots need application-specific coordination; defer.
- Online storage signalling needs a new privileged controller and protocol; defer.

## Security Considerations

Opt-in SSH requires owner grants, pinned host identity and security keys. The native
login program accepts only fixed transfer and known-service control requests. No
shell, PTY, SFTP, forwarding, agent access, password login, user rc or environment.
Drop to a confined reader with read/search capability and no service control. No
SETPCAP is added to SSH. Reject traversal, duplicates, links, special files and
unsupported metadata. Never extract on the host; add no HTTP or storage listener.
Archives are plaintext, mode 0600 and may hold credentials; offline is safest.

## Reliability Considerations

Require unchanged supervision records and authenticated terminal success, in
addition to a complete archive. Bound time, memory, headers and expansion. Verify
into private scratch; fsync, publish without replacement, then sync the parent.
Delete partial output on failure. Both paths require [application tests].

[import]: data-import.md
[application tests]: data-import-application.md
[Zstandard]: https://facebook.github.io/zstd/
