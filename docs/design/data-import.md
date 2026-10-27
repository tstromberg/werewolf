# Data import v1 (proposed)

## Summary

Import a [data export] archive into an empty destination, optionally one service.
Export and import use one filesystem format and preserve the `/data` layout.

## Background

Current import handles SQL/media/Valkey seed data. This unimplemented proposal
replaces it. Remove directory/dump import, `create --import`, snapshot-retry syntax
and `sync`. Keep one `howl import`, no `--restore` or legacy-format fallback.

## Goals

- Restore exported bytes, paths, modes, timestamps and approved ownership.
- Support full and single-service imports; preserve every unselected directory.
- Pass [application tests] for each advertised provider and cross-cloud pair.

## Non-Goals

- Merge/overwrite, raw SQL/media ingestion, data conversion, upgrades,
  cross-architecture moves, running-destination import and automatic activation.

## Detailed design

```sh
howl import replacement ./backup.tar.zst --on gcp
howl import replacement ./backup.tar.zst --service plex
```

Default scope is the archive's; a service archive never becomes full.
`--service NAME` selects only `/data/svc/NAME`, required in archive and target image.
Reject paths and system services. Never rename, infer dependencies or widen scope.

For a new name, use existing provisioning without starting applications. Require the
recorded image/architecture through normal trusted verification; an archive cannot
supply code or authorize signers. Existing VMs must be stopped and match that
image/architecture. Full import requires empty application data; service import
requires only its root empty. Leave all unselected data untouched; never erase
conflicts. Supply deployment configuration separately.

**Delivery.** Howl copies the archive into a private transfer disk. Local adapters
attach it directly; cloud adapters upload it through private provider storage and
create an attachable volume. Remote hypervisors receive it over authenticated SSH.
Hold the destination lifecycle lock from inspection through installation.
An isolated Linux helper reads that disk read-only and writes destination storage,
with no network or host shares. The destination stays stopped; no guest SSH is used.
Remove transfer disks and remote staging; keep archives out of user-data and logs.

Stream-decompress to private staging on the destination data volume. Validate the
entire archive, including unselected entries, before publishing selected data.
Require its manifest, completion digest and one complete Zstandard frame; reject
trailing data. Bound decoder window, headers, file count and expanded bytes. Check
selection against manifest inventory; reject mismatches and duplicate entries.

Preserve modes/timestamps; map ownership through approved destination identities.
Refuse unknown owners or unsupported metadata. Initialize new machine identities
before publishing data; an archive cannot create OS accounts. Regenerate new-machine
SSH keys/enrollment; retain existing-machine authority. Old import receipts are
inert, never instructions to replay a source batch.

Persist one receipt binding the archive digest, selected scope and target identity.
Stage files, sync, install without replacement, then publish readiness after every
selected directory is durable. Block boot during a pending receipt. On interruption,
the same invocation may finish that receipt; another digest/scope is refused.
Completed import is not replayed at boot. Never declare partial data ready.

Leave the VM stopped after success. The operator starts it through the normal
lifecycle after stopping/fencing the source where application identity is shared. A
single-service import guarantees only that directory; the operator must supply
compatible companion data. Plex state and media are separate services.

## Drawbacks

Import needs temporary storage and a matching image/architecture. Replacing the old
seed/sync workflow is intentional; update help, form declarations, examples and tests
in the same change. A single service may be insufficient to run an application.

## Alternatives Considered

- Auto-detect SQL/media formats: restores ambiguity and application-specific code.
- A separate restore command: duplicates import's new meaning.
- Merge into existing data: complicates rollback; refuse occupied destinations.

## Security Considerations

Treat archives as untrusted: digests detect damage, not intent. Reject traversal,
absolute paths, links, special files and privileged metadata. Pin directory
descriptors; never follow destination links or extract onto host paths. Only selected
roots change; data gains no code trust. Keep staging private and clean up. Enforce
signed machine-state exclusions, not archive claims.

## Reliability Considerations

Delivery or extraction failure leaves applications stopped and source bytes intact.
Require [application tests] for each provider, retries, cleanup and target isolation.

[data export]: data-export.md
[application tests]: data-import-application.md
