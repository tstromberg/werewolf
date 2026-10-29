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

**Export and import.** `howl export NAME --output backup.tar.zst` captures `/data`,
including logs, excluding machine authority and system state. `--service NAME`
selects exactly `/data/svc/NAME`. Archives use Zstandard level 1 and preserve paths,
bytes, ownership, modes and timestamps. They are private, mode 0600, and plaintext;
keep them as carefully as credentials.

Full exports include logs; import validates and discards them, retaining target logs.
Online log snapshots can omit new writes or fail during rotation/truncation.

`howl import NAME backup.tar.zst` restores into empty application data with the same
image and architecture. Disk-based import requires a stopped VM; online import uses
the restricted SSH interface with all applications stopped. A new local VM uses an
approved matching image kept by Howl; supply its deployment configuration with
`--config`. On another host, local VMs select a matching published release with
`--with FORM --version SERIAL`; cloud v1 needs the owner-approved image cache.
Normal image verification still applies; archives never
authorize code. An offline destination remains stopped; `howl start NAME` starts its
saved image and configuration. A selected-service import preserves companion roots
and never merges occupied data. Fence the source before starting a replacement that
shares identity. Plex state (`plex`) and media (`plex-media`) are separate.

The storage adapter accepts stopped QEMU, Lima, Firecracker and x86_64 bhyve
machines, plus enrolled AWS, Azure and GCP VMs. Local targets need standalone raw
disks. Create empty Firecracker destinations first; use new names for cloud import.
Running storage is refused. V1 keeps the approved disk size. A networkless appliance
reads an export copy or installs onto a stopped disk. Only export copies replay
journals; damage is refused. Howl never mounts guest filesystems on the host.
Encrypted data needs `--data-key FILE`. Cleanly stopped export is safest.
Linux disk transfers use `psmisc` and sudo/doas for a read-only inode-use check;
the archive processor and VM helper still run as the owner.

A running VM can transfer over pinned SSH when its image includes `data-export`.
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
SSH address using the same saved host-key pin. Connection failure never falls back to
copying possibly live storage. See the [export
design](design/pending/data-export.md).

Online import uses the same host-key pin and owner authorization. It leaves apps
stopped, rejects occupied selected roots and blocks service-start requests while
publication is pending. Use `howl import NAME backup.tar.zst --service plex` for a
running local VM, or add `--host HOST --port PORT --identity FILE` for a remote VM.
Interrupted publication can be retried with the same archive and scope; a reboot
with a pending receipt requires offline recovery before applications may start.

## Cloud disks and manual transfer

Cloud disk transfer uses logged-in `aws`, `gcloud` or `az` and private storage.
Keep the VM cleanly stopped; fence other operators and automation during transfer.
Howl checks the saved VM identity, location, power state and boot disk. GCP export
requires `cloudbuild.googleapis.com` and the export worker's documented permissions;
`WEREWOLF_GCP_EXPORT_ACCOUNT` selects an existing worker. Temporary buckets enforce
private access and disable soft deletion. Credentials travel in private pipes.

Offline cloud import uses a new name and stages a pristine, approved disk locally.
It creates no VM and changes no existing cloud disk or firmware state. Supply
`--config DIR` and optionally `--size TYPE`; `howl start NAME` publishes the restored
disk and creates a fresh VM, with new TPM/firmware authority. Existing running VMs
can import over SSH. Existing stopped cloud VMs require manual `--disk` staging.
Failed publication retains local staging. If a cloud VM exists before its identity
was recorded, start refuses to adopt it; inspect it through the provider CLI.

For manual transport, download the stopped disk with the provider CLI. AWS snapshot
blocks form raw disks; convert Azure's fixed VHD or GCP's `disk.raw` to raw disks.
Keep it unmounted on the host and use the enrolled VM:

```sh
howl export database --disk ./disk.raw --output backup.tar.zst
howl import database backup.tar.zst --disk ./disk.raw
```

Import with `--disk` writes only that local file. Upload and swap with the provider
CLI, preserving Secure Boot, TPM state and Azure VMGS. Retain the original until a
verified boot. Use short-lived storage grants and revoke them afterward; never put
signed URLs or access tokens in shell arguments or history.

## Transfer tests

`make check-data-transfer` runs the isolated storage helper and real PostgreSQL
restores through Howl. The fixture has no shell. It checks full and single-service
archives, stopped disk and powered-on SSH destinations, writer refusals,
interrupted input, occupied roots, metadata and database queries.

The VM runner defaults to Lima on macOS, QEMU on Linux and bhyve on FreeBSD.
Run `build/host/data-app-check build/host/howl build/ARCH/transfer-control` after
building those tools to select a provider with `DATA_TRANSFER_PROVIDER`. AWS, GCP and
Azure also accept `DATA_TRANSFER_SIZE`; the provider CLI's environment selects the
test project, zone or resource group. `DATA_TRANSFER_PATH=ssh` selects only online
SSH cases and does not qualify disk support. The default, `all`, requires both
paths. Missing credentials or infrastructure leave a provider unqualified.

Archive import replaces directory/SQL/media seeds, `create --import` and `sync`.
Database startup initializes only empty data; image-owned SQL setup still runs.

**Updates** roll back the image, not `/data`. A release that changes how a
service stores its data should change it only once its slot has committed
(`/run/werewolf/committed` exists), or keep a format the release before it
can still read. Otherwise a fallback runs the old release against data it
cannot read.

QEMU/Lima keep each VM's slots and data on its own boot disk; a repeated create
keeps it, delete removes it, and run uses a fresh disk. Adding/removing `data.key`
requires a blank disk: plain and LUKS disks refuse each other's configuration.
