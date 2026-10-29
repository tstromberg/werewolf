# Data import and export verification (proposed)

**Status:** Pending as of 2026-10-28

## Summary

Test [export]/[import] with real PostgreSQL and Plex data, not merely exit status.

## Background

Replace seed/sync tests with archive import and isolation/failure fixtures.

## Goals

- Test both VM states at source and destination, with full and service scopes.
- Compare every selected file before application startup; verify behavior afterward.
- Prove failed or scoped operations cannot overwrite unrelated data or grant trust.

## Non-Goals

- Live writers, application upgrades, schema conversion and independent
  Plex identity cloning. Synthetic fixtures do not prove real-account playback.

## Detailed design

**PostgreSQL.** Stop clients and PostgreSQL cleanly. Copy `/data/svc/postgres`: all
databases, roles, WAL and transaction state. [Filesystem backup][pg-backup] requires
the stopped server and complete cluster. Reject external tablespaces/WAL paths and
links. Require matching build, extensions, locale, image and architecture.

Seed databases with transactions, roles, sequences, large objects and extensions.
Export both source states, import into a fresh VM and query known records/invariants.
Check acknowledged writes survive; operators stop/resume source services. Test
`--service postgres`: unrelated sentinels are absent from export and unchanged at
import. Never initialize over failed import or let image SQL overwrite records.

**Plex.** Copy `/data/svc/plex` state (databases, metadata, artwork, preferences and
watched state) and `/data/svc/plex-media` media, including caches. Stop writers,
scanners, callbacks and transcoding before reading, as [Plex requires][plex-move].

Full round trips preserve library state, artwork, media hashes, paths, modes and
access grants. Test `--service plex` for state only and `--service plex-media` for
media only. Neither claims full migration. Importing one into a stopped VM must leave
the other's sentinel bytes and metadata unchanged.

Preserve Plex identity/preferences and leave target apps stopped. Fence the source
before startup; assert no source sign-out or token rewriting. Synthetic fixtures
prove data behavior; real-account playback stays outside credential-free CI.

**Common matrix.** For each app/source state, test full export/full import, service
export/default import and full export/service import. Include extra `/data` paths,
hidden/empty files, nested/empty directories, unusual modes and approved owners.
Compare pre-start paths, bytes, modes, timestamps and owners with capture inventory.
Assert exclusions and fresh credentials; export logs, validate them, never restore.

Test LUKS with correct/missing/wrong keys, archive privacy, invalid service names,
absent selections and image/architecture mismatch. Refuse disk access to running VMs,
occupied roots and unsupported owners; preserve other data. Reject raw directories,
SQL dumps and old seed/sync syntax without guessing formats.

Inject failure during transfer, decompression and directory publication. Refuse
running writers, wanted-up states, remaining descendants and missing supervision.
A restart during capture, including a complete up/down cycle, invalidates output.
Disconnect/timeout changes no service state. Incomplete import blocks boot; only the
same archive/scope may finish its receipt. Completed import never replays at boot.

Run the CLI on Azure, AWS, GCP, Lima, QEMU, Firecracker and bhyve: disk transfers
with VMs off and SSH absent; SSH transfers with VMs on and apps down. No guest
shell in either path. Test source/destination state pairs and cross-cloud moves.
Verify boot trust, confinement and refusal to execute imported code; measure costs.

## Drawbacks

The matrix needs VM time/storage; real Plex account tests need separate credentials.

## Alternatives Considered

- Archive-listing assertions miss wrong bytes, ownership and application behavior.
- Unit tests alone miss service ordering, provider delivery and boot races.
- Reusing seed/sync success tests would preserve the semantics being removed.

## Security Considerations

Use public fixtures and bounded diagnostics; never publish exported real databases,
Plex tokens or SSH/LUKS secrets as CI artifacts. Exercise traversal, duplicate names,
links, devices, corrupt manifests, expansion limits and trailing compressed frames.
Verify denied keys, host-key mismatch, forbidden commands and scope isolation.

## Reliability Considerations

Gate delivery on the real matrix; unavailable providers remain unverified. Test
disk-full, collisions, lifecycle/update races, reboot and SSH loss. Failed captures
leave no complete artifact. Check source bytes/records remain intact, export changes
no service state, and interrupted online import blocks startup and permits retry.

[export]: data-export.md
[import]: data-import.md
[pg-backup]: https://www.postgresql.org/docs/18/backup-file.html
[plex-move]:
  https://support.plex.tv/articles/201370363-move-an-install-to-another-system/
