# Data

The root is never written. `/data` is the one writable place, and it can
hold real data: what is on it may be the only copy. So init formats a disk
once, while it is blank, and never again. When something is wrong, it
leaves the disk as it is and says why.

| Given | /data |
| --- | --- |
| nothing, or a form without `mke2fs` (`minimal`) | tmpfs capped at 25% of RAM: nothing is kept, and a runaway service fills it rather than exhausting memory |
| `werewolf.data=DEV` | ext4 on the disk labelled `werewolf-data` (`prod` and the forms on it) |
| `werewolf.data=DEV`, and `data.key` in the config | the same in LUKS2, keyed by `data.key` |
| `werewolf.slots=` | `/boot/data` on the `/boot` ext4 filesystem |

The kernel command line says whether there is a disk, and the config
whether it is encrypted; the form only has the tools or not. So a disk is
used only where one is asked for, and a disk that is slow to appear, or
gone, never quietly becomes RAM: `werewolf.data` stays on the command line
for as long as the machine keeps its data there.

`/data` holds `/data/svc/<service>` and `/data/home/<user>`, and is mounted
`noatime,nosuid,nodev,noexec`.

**The disk** is found by its label, so its device name may change. It is
formatted only when there is none with the label yet, `werewolf.data=DEV`
names it, it holds no config tar, and `blkid` finds nothing on it. A disk
with our label is never formatted again. One the form cannot use is left
as it is:

- the wrong type: plain when the config has a `data.key`, LUKS when it
  has none, or another filesystem;
- a `data.key` that does not open it;
- a second disk with the label: which one is `/data` is not init's to
  guess, and an attached disk must not take the real one's place;
- damage `e2fsck -p` will not repair. `-p` fixes only what is safe without
  a person; the rest is a person's, with the disk attached to a machine
  that has e2fsprogs and cryptsetup.

**`data.key` must be 32 random bytes or more** (`head -c 32 /dev/urandom`).
LUKS2 is made with a quick key derivation, which a random key needs no
slower one for. So init refuses to make LUKS2 with a shorter key, and warns
when one opens a disk made before.

**When /data is unavailable**, because of any of those, because
`werewolf.data` names nothing usable, or because a slot's
directory cannot be bound, it is an empty, read-only tmpfs. The console and
`/run/werewolf/nodata` say why. A service that needs `/data` fails where it
can be seen, rather than writing to RAM what it believes is kept. A slot on
probation does not commit, so an update that broke `/data` falls back to
the slot before it.

**Encryption** protects snapshots, backups and recycled volumes, so the key
must not be stored beside them: on a single-disk provider, deliver the
config as user-data. init deletes the key from `/run/config` once the volume
is open. A disk made without a key stays plain, and one made with a key
is never opened without it. Keep each
machine's key somewhere other than the machine, since without it the data
is gone. Encryption does not detect tampering.

**Export and import.** `howl export NAME --output backup.tar.zst` captures
`/data`, excluding machine authority, audit logs and system state. `--service NAME`
selects exactly `/data/svc/NAME`. Archives use Zstandard level 1 and preserve paths,
bytes, ownership, modes and timestamps. They are private, mode 0600, and plaintext;
keep them as carefully as credentials.

`howl import NAME backup.tar.zst` restores into empty application data on a stopped
VM with the same image and architecture. A new local destination uses an approved
matching image kept by Howl; supply its deployment configuration with `--config`.
On another host, select the matching published release with `--with FORM --version
SERIAL`. It goes through normal image verification; archives never authorize code.
The destination remains stopped; `howl start NAME` starts its saved image and
configuration. A selected-service import preserves companion
roots and never merges occupied data. Fence the source before starting a replacement
that shares application identity. Plex state (`plex`) and media (`plex-media`) are
separate selections.

The current storage adapter accepts stopped local QEMU and Lima machines with
standalone raw destination disks. Unsupported providers and running storage are
refused. New destinations retain the approved image's disk size; v1 does not grow
disks. A networkless Linux appliance reads a detached source copy or installs onto
the stopped destination; Howl never mounts guest filesystems on the host. Encrypted
data needs `--data-key FILE`. Cleanly stopped export is the least dangerous approach.

A running source can export over pinned SSH when its image includes `data-export`.
The owner stops all application services first, keeps them down until export exits,
and starts them afterward. Export checks supervision and clean PostgreSQL shutdown;
it never stops services or powers off the VM. Stop clients before their databases.
For example, with an already pinned host key and an authorized security key:

```sh
howl ssh root@database -- service-down-v1 postgres
howl export database --output database.tar.zst
howl ssh root@database -- service-up-v1 postgres
```

Repeat the explicit stop/start requests for other application services as needed.
These fixed operations work without a shell. The opt-in endpoint refuses system
service control, PTYs, SFTP and forwarding. A failed export leaves service state
alone; the owner decides when to resume. `--host HOST --port PORT` selects a remote
SSH address using the same saved host-key pin. Connection failure never falls back
to copying possibly live storage. See the [export design](design/pending/data-export.md).

Directory, SQL and raw media seeds, `create --import` and `sync` have been replaced
by this archive interface. Database startup initializes only an empty service or
uses the restored physical data. Image-owned SQL setup still runs normally.

**Updates** roll back the image, not `/data`. A release that changes how a
service stores its data should change it only once its slot has committed
(`/run/werewolf/committed` exists), or keep a format the release before it
can still read. Otherwise a fallback runs the old release against data it
cannot read.

Under QEMU and Lima, `howl create NAME` gives each machine its own boot disk,
`build/machines/NAME/disk.img`, holding its slots and /data, which a second
create of the name keeps; `howl delete NAME` removes it, and `howl run` makes
a new one each time.
Delete a machine for a blank disk when adding or removing `data.key`, since a
plain disk and a LUKS one refuse each other's config.
