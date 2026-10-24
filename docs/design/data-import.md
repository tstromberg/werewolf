# Data import and sync

## Contract

Imports are application input. They do not become boot images, configuration
archives, executable packages, or TPM authority. The operator selects a local
source; Howl snapshots it into a separate, read-only ext4 disk. Init mounts it
at `/run/werewolf/import`. A confined application importer decides how to use it.

There are two operations:

```sh
howl create movies --with plex --build --import ./media CONFIG...
howl import movies ./media
howl sync movies ./media
```

`create --import` and `import` request **init**: initialize an empty application
destination. `sync` adds files and replaces changed files, preserving files found
only at the destination. Neither operation deletes files, clears a database,
formats `/data`, changes enrollment, or modifies the original source.

The standalone commands support protected local Lima and QEMU machines. They
stage data for the next **cold start through Howl**. Staging can happen while the
VM runs: the running QEMU keeps its already-open, immutable disk. A guest reboot
alone does not change the attached disk. The commands never stop a running VM.
Use the normal stop/create lifecycle when ready to apply the selected snapshot.
Only the latest selected snapshot is attached; this is not a queue of jobs.

Forms opt in to modes with `imports: [init, sync]`. The supported modes are
included in the signed boot manifest's deployment definition. Old definitions
admit init only. A sync command for an image without sync support is refused
before staging. Database restores remain init-only unless their form explicitly
implements sync; file sync is not a database replication protocol.

Cloud attachment, protected bhyve imports, online application, exports, deletion,
ownership preservation, and rsync-compatible filters are outside this version.

## Host snapshot and publication

The machine directory is private (0700). Howl copies regular files recursively into a
private scratch directory outside the source. Files are normalized to 0644 and
directories to 0755. It copies bytes, rather than preserving hard links, source
ownership, ACLs, extended attributes, or executable bits. Hidden files are included;
there are no implicit filters or ignore-file rules. Symlinks, special files and set-id
entries are refused. The names `.werewolf-import`, `.werewolf-import-state`,
`.werewolf-import-part`, `import-failed`, and `lost+found` are reserved and refused in
source data.

Each traversal opens child directories without following links. Regular files
are opened with `O_NOFOLLOW|O_NONBLOCK` and checked after opening; exchanging a
file for a FIFO cannot make the opener wait indefinitely. Copying checks size,
inode and change timestamps before and after reading. A changed source aborts
staging. This detects ordinary concurrent changes; it is not a filesystem-wide
point-in-time snapshot. Quiesce writers when consistency across files matters.
Sources and outputs must not overlap: staging inside the source would otherwise
recursively import its own scratch directory or VM disks.

The snapshot identity hashes the mode, sorted relative names, entry types and
file contents. A small `.werewolf-import` manifest contains version 1, mode and
identity. Howl builds a new filesystem from these staged regular files. It does
not accept an arbitrary filesystem image as a volume to mount: an input image
file is itself copied as ordinary data.

An installed snapshot lives at `imports/IDENTITY/disk.img`, with a private
`record.json` recording its mode, byte length and SHA-256. The image and record
are synced before their directory is installed with a non-replacing rename.
The private `import.json` selection is replaced atomically and its parent synced.
A failed or repeated build never truncates an existing artifact. Identical input
and mode reuse the recorded snapshot. An ordinary repeated `create --import`
may reuse the same init snapshot but cannot implicitly select different input.

Previous snapshots are retained for recovery. Before attachment, Howl requires an
ordinary image file with the recorded length and digest. Missing, truncated, substituted
or corrupt selected images are errors, not optional empty imports. A crash during
selection can leave the old or new complete selection; neither image is deleted.
Interrupted host staging can leave private scratch directories, which are never
attached. Targets must stay on one filesystem; a cross-filesystem rename fails without a
copy-and-truncate fallback. Snapshot and history storage can be large: staging and
filesystem construction require space in addition to the source and guest data. There is
no automatic history collection in this version.

The protected lifecycle uses the machine's existing lock to serialize selection
with create/start. Selection changes application input only. It does not rebuild
or re-sign a UKI, alter a measured command line, or reset TPM state. Both provider
paths attach the selected disk with `readonly=on`; Lima uses its private QEMU
wrapper, preserving `mounts: []` and avoiding host directory sharing.

## Guest mount boundary

Init mounts exactly one ext4 disk labelled `werewolf-import`, with
`ro,nosuid,nodev,noexec,nosymfollow`. The directory exists even without a disk.
Multiple labelled disks or mount failures leave `import-failed` instead of a
partially usable mount. Importers must treat that marker as a failure.

Only a service with an explicit read grant can read the mounted input. The
service owns its application destination; it receives no additional root or
mount privileges. IPE still admits code only from the selected dm-verity root.
The import's checksum identifies and checks application data; it does not grant
that data code trust. Interpreters and applications must still treat content as
untrusted input. A privileged malicious host remains outside this boundary.

## Plex application semantics

`plex-media` owns `/data/svc/plex-media` and alone writes imported media. Plex
and the separate transcoder retain read access. The importer verifies the
manifest and complete source identity before changing destination files.

A new init refuses any existing destination data. Before installing files, the
importer durably records the snapshot identity under the private
`.werewolf-import-state` directory and holds an exclusive lock. An interrupted
operation can resume only with that same identity. It cannot silently mix an
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

## Database importers

MariaDB and PostgreSQL retain their application-specific initialization. A dump
is streamed into new data, and successful initialization is committed by the
form. Valkey copies a snapshot because its format requires a file. Transport
metadata does not turn these operations into file sync. Existing data is never
removed merely because a new import disk has been selected.

## Verification

The shared import tests cover init conflicts, recursive copying, completed
replay, interrupted retries, pending-batch conflicts, checksum and mode changes,
source links, destination links, hard links, stale temporaries, type conflicts,
atomic file replacement, unchanged inodes and destination-only preservation.
Host tests build real ext4 artifacts, check private permissions and deterministic
identity, retain previous artifacts, reject overlap and reserved names, and
prove failed staging or corruption cannot silently replace usable input.

`test/check-plex-import` builds a disposable protected Plex fixture with
operator SSH and immutable test probes. It checks actual Secure Boot, IPE,
verified root and TPM rollback protection; read-only import mount flags; media
ownership; refusal to map imported native code; decoding imported media through
the separate Plex worker; replay and sync across cold starts; staging while
running; rejected source links; non-destructive init refusal; and recovery by
reselecting a completed snapshot. Its extra SSH access belongs to the fixture.
No Plex account is needed; account registration and client playback remain
separate tests.
