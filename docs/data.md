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
| `werewolf.victim=` | a directory on the victim's filesystem ([bite](bite.md)) |

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

**Backups** are yours. werewolf keeps `/data` across reboots and updates,
and copies it nowhere.

**Updates** roll back the image, not `/data`. A release that changes how a
service stores its data should change it only once its slot has committed
(`/run/werewolf/committed` exists), or keep a format the release before it
can still read. Otherwise a fallback runs the old release against data it
cannot read.

Under QEMU, `howl create NAME --on qemu` gives each machine a sparse 8 GiB
`build/machines/NAME/data.img`, which a second create of the name keeps;
`howl delete NAME` removes it, and `howl run` makes a blank one each time.
Delete a machine for a blank disk when adding or removing `data.key`, since a
plain disk and a LUKS one refuse each other's config.
