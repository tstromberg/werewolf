# Data import and sync

## Contract

Imports are application input, never boot images, configuration archives, executable
packages or TPM authority. The operator names a local source; Howl snapshots it into a
separate, read-only ext4 disk, which init mounts at `/run/werewolf/import` for a
confined application importer.

`howl create NAME --import DIR` and `howl import NAME DIR` request **init**: initialize
an empty application destination. `howl sync NAME DIR` adds files and replaces changed
ones, keeping files found only at the destination. Neither deletes files, clears a
database, formats `/data`, changes enrollment or modifies the source.

The standalone commands serve protected local Lima and QEMU machines. They stage data
for the next **cold start through Howl**, even while the VM runs (its QEMU keeps the
open, immutable disk, and a guest reboot changes nothing), and never stop it. Only the
latest selection is attached; this is not a queue of jobs.

Forms opt in with `imports: [init, sync]` in the signed boot manifest's deployment
definition; older definitions admit init only, and a sync for an image without it is
refused before staging. Database restores stay init-only unless their form implements
sync: file sync is not database replication. Cloud attachment, protected bhyve, online
application, exports, deletion, ownership and rsync-style filters come later.

## Host snapshot and publication

The machine directory is private (0700). Howl copies the source's regular files, hidden
ones included, into private scratch outside it: bytes only, 0644 (directories 0755),
with no hard links, ownership, ACLs, extended attributes, executable bits or implicit
filters. Symlinks, special files, set-id entries and the reserved names
(`.werewolf-import`, `.werewolf-import-state`, `.werewolf-import-part`, `import-failed`,
`lost+found`) are refused.

Traversal never follows links; files open with `O_NOFOLLOW|O_NONBLOCK` and are checked
once open, so a swapped-in FIFO cannot stall it. A size, inode or change time that
differs before and after reading aborts staging. That catches ordinary concurrent
changes, but it is no point-in-time snapshot: quiesce writers when consistency across
files matters. Sources and outputs must not overlap.

The checksum hashes the mode, sorted relative names, entry types and contents. Each
explicit import or sync also gets a securely random batch ID, kept with the mode,
checksum and version 1 in a small `.werewolf-import` manifest. A reboot replays the
batch; a new sync can repair a changed destination from an unchanged source. Howl builds
a new filesystem from the staged files; it never mounts a supplied image.

A snapshot installs as `imports/BATCH-ID/disk.img` beside a private `record.json` (batch
ID, checksum, mode, length, SHA-256), both synced, then renamed into place without
replacing; `import.json`, the selection, is replaced atomically and its parent synced.
No build truncates an artifact. A repeated `create --import` reuses the selected init
batch only when its checksum matches; explicit import and sync make new batches;
`--retry` reselects one without rebuilding it.

Previous snapshots stay for recovery. Howl attaches only an ordinary file of the
recorded length and digest: anything else is an error, never an empty import. A crash
leaves the old or the new complete selection and deletes no image; interrupted staging
leaves only private scratch, never attached. A cross-filesystem rename fails, never
copying. Snapshots need space beyond the source and guest data; none are collected yet.

The machine's lock serializes selection with create and start. Selection rebuilds or
re-signs no UKI, alters no measured command line and resets no TPM state. Both providers
attach the disk `readonly=on`, Lima through its private QEMU wrapper, with `mounts: []`.

## Guest mount boundary

Init mounts exactly one ext4 disk labelled `werewolf-import`,
`ro,nosuid,nodev,noexec,nosymfollow`, and the directory exists without one. Several
labelled disks, or a failed mount, leave `import-failed` instead of a partly usable
mount, and importers must treat it as failure.

Only a service with an explicit read grant reads the input; it owns its destination and
gets no further root or mount privilege. IPE admits code only from the selected
dm-verity root: the checksum grants data no code trust, so applications must treat it as
untrusted input. A privileged malicious host is outside this boundary.

## Plex application semantics

`plex-media` owns `/data/svc/plex-media` and alone writes imported media; Plex and the
separate transcoder read it. The importer verifies the manifest and whole source
checksum before changing a destination file.

A new init refuses any existing destination data. Before installing files, the importer
durably records the batch ID in private `.werewolf-import-state`, under an exclusive
lock: an interrupted operation resumes only with that batch, never mixing it with
another snapshot. A completed snapshot is not reapplied on reboot, so replay cannot undo
local changes.

Each new or changed file goes to a reserved temporary in that state directory, on the
destination's filesystem, and is checked, given its permissions, synced and renamed,
then the directory synced. Init never replaces; sync replaces a regular file atomically;
identical files keep their inode. Destination symlinks, special files and file/directory
conflicts are errors. Nothing is truncated in place, hard links included; a stale
temporary symlink is unlinked, not followed; destination-only files are never scratch.

Sync is atomic **per file**, not per tree: a failed batch may leave some files replaced,
and its pending receipt makes that snapshot finish before any other. Reselect it with
`howl import NAME --retry SNAPSHOT-ID` and cold-start through Howl; retry keeps its
mode, so cannot turn init into sync. Never delete a receipt to fake success.

Only once every change is durable does the pending receipt become complete and
`plex-media` publish the readiness file Plex setup waits for. Missing or corrupt data,
conflicts, short reads, permission or write errors and a full disk cannot hide behind a
healthy server with a half-loaded library.

## Database importers

MariaDB and PostgreSQL keep their own initialization: a dump streams into new data, and
the form commits success. Valkey copies a snapshot, as its format needs a file. Neither
becomes file sync, and selecting a new import disk never by itself removes data.

## Verification

Shared importer tests and host tests cover each rule above, the host tests on real ext4
artifacts. `make check-plex-import` boots a disposable protected Plex fixture, whose
operator SSH and test probes are its alone. It checks Secure Boot, IPE, the verified
root and TPM rollback protection; the read-only mount and media ownership; refusal to
map imported native code; decoding through the separate worker; replay and sync across
cold starts; staging while running; refused source links and init over data; recovery by
reselection; drift repair by repeated sync; and media kept through a verified A/B
update. Account registration and playback are separate tests.
