# Data import and export verification (proposed)

## Summary

Test [export]/[import] with real PostgreSQL and Plex data, not merely exit status.

## Background

Replace seed/sync test expectations with archive import; reuse isolation/failure
fixtures. Applications consume restored files and need no export format.

## Goals

- Test both source states and both scopes: running/stopped and full/service.
- Compare every selected file before application startup; verify behavior afterward.
- Prove failed or scoped operations cannot overwrite unrelated data or grant trust.

## Non-Goals

- Live application capture, application upgrades, schema conversion and independent
  Plex identity cloning. Synthetic fixtures do not prove real-account playback.

## Detailed design

**PostgreSQL.** Stop clients and PostgreSQL cleanly. Copy `/data/svc/postgres`: all
databases, roles, WAL and transaction state. [Filesystem backup][pg-backup] requires
the stopped server and complete cluster. Reject external tablespaces/WAL paths and
links. Require matching build, extensions, locale, image and architecture.

Seed databases with transactions, roles, sequences, large objects and extensions.
Export both source states, import into a fresh VM and query known records/invariants.
Check acknowledged writes survive and prior services resume. Repeat with `--service
postgres`: unrelated sentinel directories are absent from export and unchanged at
import. Never initialize over failed import or let image SQL overwrite records.

**Plex.** Copy `/data/svc/plex` state (databases, metadata, artwork, preferences and
watched state) and `/data/svc/plex-media` media, including caches. Stop writers,
scanners, callbacks and transcoding before reading, as [Plex requires][plex-move].
Assert selected files cannot change during capture.

Full round trips preserve library state, artwork, media hashes, paths, modes and
access grants. Test `--service plex` for state only and `--service plex-media` for
media only. Neither claims full migration. Importing one into a stopped VM must leave
the other's sentinel bytes and metadata unchanged.

Preserve Plex identity/preferences and leave the target stopped. Fence the source
before startup; assert no source sign-out or token rewriting. Synthetic fixtures
prove data behavior; real-account playback stays outside credential-free CI.

**Common matrix.** For each app/source state, test full export/full import, service
export/default import and full export/service import. Include extra `/data` paths,
hidden/empty files, nested/empty directories, unusual modes and approved owners.
Compare pre-start paths, bytes, modes, timestamps and owners with capture inventory.
Assert exclusions and regenerated destination credentials.

Test LUKS with correct/missing/wrong keys, archive privacy, invalid service names,
absent selections and image/architecture mismatch. Refuse running targets, occupied
selected roots and unsupported owners; preserve other data. Reject raw directories,
SQL dumps and old seed/sync syntax without guessing formats.

Inject failure during stopping, transfer, decompression, directory publication and
service restart. Disconnect or timeout must invalidate capture before writers resume.
An incomplete import blocks boot; only the same archive/scope can finish its receipt.
A complete import never replays after reboot. Preserve valid export if restart fails,
but require nonzero status identifying the affected services.

Run the real CLI on protected local VMs, each supported provider and cross-cloud
pair. Verify fresh boot trust, Secure Boot, IPE, confinement, no shell and refusal to
execute imported code. Benchmark time, CPU and memory on database and media data.

## Drawbacks

The full matrix needs VM time and storage. Vendor Plex account tests need separate
credentials and cannot be replaced by synthetic fixtures.

## Alternatives Considered

- Archive-listing assertions miss wrong bytes, ownership and application behavior.
- Unit tests alone miss service ordering, provider delivery and boot races.
- Reusing seed/sync success tests would preserve the semantics being removed.

## Security Considerations

Use public fixtures and bounded diagnostics; never publish exported real databases,
Plex tokens or SSH/LUKS secrets as CI artifacts. Exercise traversal, duplicate names,
links, devices, corrupt manifests, expansion limits and trailing compressed frames.
Verify denied keys, host-key mismatch, forbidden commands and scope containment.

## Reliability Considerations

Gate CI delivery on a proposed `make check-data-transfer` running this matrix. Test
disk-full, collisions, lifecycle/update races, reboot and guard recovery. Failed
captures leave no complete artifact. Check offline source bytes and online records
remain intact; report capture and service-resumption failures separately.

[export]: data-export.md
[import]: data-import.md
[pg-backup]: https://www.postgresql.org/docs/18/backup-file.html
[plex-move]:
  https://support.plex.tv/articles/201370363-move-an-install-to-another-system/
