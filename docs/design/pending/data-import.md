# Data import v1 (proposed)

**Status:** Pending as of 2026-10-28

## Summary

Restore [data export] archives, preserving `/data` layout, optionally one service.

## Background

Replace seed/dump imports, `create --import` and `sync` with one `howl import`.

## Goals

- Restore exported bytes, paths, modes, timestamps and approved ownership.
- Support full and single-service imports; preserve every unselected directory.
- Pass [application tests] for each advertised provider and cross-cloud pair.

## Non-Goals

- Merge/overwrite, raw SQL/media ingestion, data conversion, upgrades,
  cross-architecture moves, running application writers and automatic activation.

## Detailed design

```sh
howl import replacement ./backup.tar.zst --on qemu
howl import replacement ./backup.tar.zst --service plex
```

Default scope is the archive's. `--service NAME` selects only `/data/svc/NAME`,
required in archive and target. A service archive never becomes full.

For a new name, use existing provisioning without starting applications. Require the
recorded image/architecture through normal trusted verification; an archive cannot
supply code or authorize signers. Destination apps must be stopped and match that
image/architecture in every fallback slot and declare the signed boot barrier. Full
import requires empty application data; service import requires only its root empty.
Leave all unselected data untouched; never erase conflicts. Supply deployment
configuration separately; `--with FORM --version SERIAL` selects a trusted release.

**Delivery.** Disk-based import requires a confirmed stopped VM and private transfer
storage. A networkless Linux helper installs it without host shares or guest SSH.
Cloud import uses new names: stage locally, publish a fresh VM on explicit start.
Use `gcloud`/`az` authentication; never swap an existing VM's disk or VMGS.
Create empty Firecracker targets first; document manual `--disk` staging.
Online import uses opt-in SSH with pinned host identity and owner grants; its
fixed native command needs no shell. Hold lifecycle/transfer locks; require every
app down and its cgroup empty. Block service startup until publication is durable.
Never infer shutdown from SSH failure. Remove staging; keep archives out of logs.

An unprivileged decoder stream-decompresses into private staging on the destination
data volume. A separate publisher checks bounded inventory records and staged files
against approved paths, owners and scope. Validate the whole archive, including
unselected entries, before publishing selected data. Require its manifest, completion
digest and one complete Zstandard frame; reject trailing data. Bound decoder window,
headers, entry count and expanded bytes; reject inventory mismatches and duplicates.

Preserve modes/timestamps; selected owners must be approved destination identities.
Reject invalid names/metadata; initialize new identities before publication;
archives cannot create accounts. Regenerate new-machine SSH keys/enrollment; retain
existing authority. Old import receipts are inert, never instructions to replay.

Persist an immutable receipt binding the archive digest, scope and target identity.
Use fixed-size, checksummed progress records; retain the previous durable copy. Stage
files, sync, install without replacement, then publish readiness after every selected
directory is durable. Block boot during a pending receipt. On interruption, the same
invocation may finish that receipt; another digest/scope is refused. Completed import
is not replayed at boot. Never declare partial data ready.

Leave applications stopped; offline targets remain off. The operator fences the
source before starting apps with shared identity. A service import guarantees only
its directory; supply companion data separately. Plex state and media are separate.

## Drawbacks

Import needs temporary storage and a matching image; one service may be insufficient.

## Alternatives Considered

- Auto-detect SQL/media formats: restores ambiguity and application-specific code.
- A separate restore command: duplicates import's new meaning.
- Merge into existing data: complicates rollback; refuse occupied destinations.

## Security Considerations

Treat archives as untrusted: digests detect damage, not intent. Reject traversal,
absolute paths, links, special files and privileged metadata. Pin directory
descriptors; never follow destination links or extract onto host paths. Only selected
roots change; data gains no code trust. Validate archived logs but never stage or
restore them; preserve destination logs. Enforce signed machine-state exclusions.
Use export's SSH limits; privileged code never parses archives. No new listener.

## Reliability Considerations

Delivery or extraction failure leaves applications stopped and source bytes intact.
Require [application tests] for each provider, retries, cleanup and target isolation.

[data export]: data-export.md
[application tests]: data-import-application.md
