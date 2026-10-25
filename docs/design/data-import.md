# Data import and sync

## Contract

Imports are application input. They do not become boot images, configuration archives,
executable packages, or TPM authority. The operator selects a local source; Howl
snapshots it into a separate, read-only ext4 disk. Init mounts it at
`/run/werewolf/import`. A confined application importer decides how to use it.

The standalone commands serve protected local Lima and QEMU machines. They stage data
for the next **cold start through Howl**, even while the VM runs (its QEMU keeps the
open, immutable disk, and a guest reboot changes nothing), and never stop it. Only the
latest selection is attached; this is not a queue of jobs.

`create --import` and `import` request **init**: initialize an empty application
destination. `sync` adds files and replaces changed files, preserving files found only
at the destination. Neither operation deletes files, clears a database, formats `/data`,
changes enrollment, or modifies the original source.

The standalone commands support protected local Lima and QEMU machines. They stage data
for the next **cold start through Howl**. Staging can happen while the VM runs: the
running QEMU keeps its already-open, immutable disk. A guest reboot alone does not
change the attached disk. The commands never stop a running VM. Use the normal
stop/create lifecycle when ready to apply the selected snapshot. Only the latest
selected snapshot is attached; this is not a queue of jobs.

Forms opt in to modes with `imports: [init, sync]`. The supported modes are included in
the signed boot manifest's deployment definition. Old definitions admit init only. A
sync command for an image without sync support is refused before staging. Database
restores remain init-only unless their form explicitly implements sync; file sync is not
a database replication protocol.

Cloud attachment, protected bhyve imports, online application, exports, deletion,
ownership preservation, and rsync-compatible filters are outside this version.

## Host snapshot and publication

The machine directory is private (0700). Howl copies the source's regular files, hidden
ones included, into private scratch outside it: bytes only, 0644 (directories 0755),
with no hard links, ownership, ACLs, extended attributes, executable bits or implicit
filters. Symlinks, special files, set-id entries and the reserved names
(`.werewolf-import`, `.werewolf-import-state`, `.werewolf-import-part`, `import-failed`,
`lost+found`) are refused.

Each traversal opens child directories without following links. Regular files are opened
with `O_NOFOLLOW|O_NONBLOCK` and checked after opening; exchanging a file for a FIFO
cannot make the opener wait indefinitely. Copying checks size, inode and change
timestamps before and after reading. A changed source aborts staging. This detects
ordinary concurrent changes; it is not a filesystem-wide point-in-time snapshot. Quiesce
writers when consistency across files matters. Sources and outputs must not overlap:
staging inside the source would otherwise recursively import its own scratch directory
or VM disks.

The content checksum hashes the mode, sorted relative names, entry types and file
contents. Each explicit import or sync also gets a securely random batch ID. A small
`.werewolf-import` manifest contains version 1, mode, batch ID and content checksum. A
reboot replays the same batch; a new sync can repair a changed destination even when its
source checksum is unchanged. Howl builds a new filesystem from these staged regular
files. It does not accept an arbitrary filesystem image as a volume to mount: an input
image file is itself copied as ordinary data.

An installed snapshot lives at `imports/BATCH-ID/disk.img`, with a private `record.json`
recording its batch ID, content checksum, mode, byte length and image SHA-256. The image
and record are synced before their directory is installed with a non-replacing rename.
The private `import.json` selection is replaced atomically and its parent synced. A
failed or repeated build never truncates an existing artifact. An ordinary repeated
`create --import` reuses the selected init batch when its content checksum matches; it
cannot implicitly select different input. Explicit import/sync commands create new
batches. `--retry` reselects the original batch without rebuilding it.

Previous snapshots stay for recovery. Howl attaches only an ordinary file of the
recorded length and digest: anything else is an error, never an empty import. A crash
leaves the old or the new complete selection and deletes no image; interrupted staging
leaves only private scratch, never attached. A cross-filesystem rename fails, never
copying. Snapshots need space beyond the source and guest data; none are collected yet.

The protected lifecycle uses the machine's existing lock to serialize selection with
create/start. Selection changes application input only. It does not rebuild or re-sign a
UKI, alter a measured command line, or reset TPM state. Both provider paths attach the
selected disk with `readonly=on`; Lima uses its private QEMU wrapper, preserving
`mounts: []` and avoiding host directory sharing.

## Guest mount boundary

Init mounts exactly one ext4 disk labelled `werewolf-import`, with
`ro,nosuid,nodev,noexec,nosymfollow`. The directory exists even without a disk. Multiple
labelled disks or mount failures leave `import-failed` instead of a partially usable
mount. Importers must treat that marker as a failure.

Only a service with an explicit read grant can read the mounted input. The service owns
its application destination; it receives no additional root or mount privileges. IPE
still admits code only from the selected dm-verity root. The import's checksum
identifies and checks application data; it does not grant that data code trust.
Interpreters and applications must still treat content as untrusted input. A privileged
malicious host remains outside this boundary.

## Plex application semantics

See [application import behavior](data-import-application.md#plex-application-semantics)
for atomic file installation, receipts, retry and readiness.

## Database importers

MariaDB and PostgreSQL retain their application-specific initialization. A dump is
streamed into new data, and successful initialization is committed by the form. Valkey
copies a snapshot because its format requires a file. Transport metadata does not turn
these operations into file sync. Existing data is never removed merely because a new
import disk has been selected.

## Verification

See [verification](data-import-application.md#verification) for unit and protected Plex
lifecycle coverage.
