# Application import behavior and verification

The [data import contract](data-import.md) defines host snapshots and the guest mount.

## Plex application semantics

`plex-media` owns `/data/svc/plex-media` and alone writes imported media. Plex
and the separate transcoder retain read access. The importer verifies the
manifest and complete source checksum before changing destination files.

A new init refuses any existing destination data. Before installing files, the
importer durably records the batch ID under the private
`.werewolf-import-state` directory and holds an exclusive lock. An interrupted
operation can resume only with that same batch ID. It cannot silently mix an
unfinished batch with a different snapshot. A completed snapshot is not reapplied
on reboot, so replay cannot undo local changes.

Each new or changed file is written to a reserved temporary file in its private state
directory, on the same filesystem as the pinned destination. The importer checks the
source read, sets permissions, syncs the complete file, renames it, and syncs the
directory. Init uses a non-replacing rename; sync replaces a regular file atomically.
Identical existing files retain their inode. Destination symlinks, special files and
file/directory conflicts are errors. Files are never truncated in place, including
hard-linked files. A stale private temporary symlink is unlinked, never followed.
Destination-only files are not used as scratch space, even if their names resemble
temporaries.

Sync is atomic **per file**, not across the entire tree. A failed batch can have
some completed replacements; other old files remain intact. Its pending receipt
is kept and the same snapshot must finish before a different batch can proceed.
The host retains the recorded snapshot for recovery. Reselect the pending ID
with `howl import NAME --retry SNAPSHOT-ID`, then cold-start the VM through Howl.
The retained manifest preserves its original mode; retry cannot turn init into
sync. Do not delete receipts to make a failed batch appear completed.

After all file and directory changes are durable, the pending receipt becomes
the completed receipt. Only then does `plex-media` publish a runtime readiness
file. Plex setup waits for that file. Missing or corrupt data, conflicts, short
reads, permission errors, write errors and disk exhaustion therefore cannot be
hidden behind a healthy server with a partly initialized media library.

## Verification

The shared import tests cover init conflicts, recursive copying, completed
replay, interrupted retries, pending-batch conflicts, checksum and mode changes,
source links, destination links, hard links, stale temporaries, type conflicts,
atomic file replacement, unchanged inodes and destination-only preservation.
Host tests build real ext4 artifacts, check private permissions and content
checksums, retain previous artifacts, reject overlap and reserved names, and
prove failed staging or corruption cannot silently replace usable input.

`make check-plex-import` builds a disposable protected Plex fixture with
operator SSH and immutable test probes. It checks actual Secure Boot, IPE,
verified root and TPM rollback protection; read-only import mount flags; media
ownership; refusal to map imported native code; decoding imported media through
the separate Plex worker; replay and sync across cold starts; staging while
running; rejected source links; non-destructive init refusal; and recovery by
reselecting a completed snapshot; repeating a sync with identical source to repair
destination drift; and retaining media through a verified A/B image update.
Its extra SSH access belongs to the fixture.
No Plex account is needed; account registration and client playback remain
separate tests.
