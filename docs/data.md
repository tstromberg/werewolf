# Data

The root is never written. `/data` is the one writable place, and it can
hold real data: what is on it may be the only copy. So init formats a disk
once, while it is blank, and never again. When something is wrong, it
leaves the disk as it is and says why.

| Present | /data |
| --- | --- |
| no storage tools | tmpfs capped at 25% of RAM: nothing is kept, and a runaway service fills it rather than exhausting memory |
| `mke2fs` | ext4 on the disk labelled `werewolf-data` |
| `mke2fs`, `cryptsetup` | the same in LUKS2, keyed by `data.key` |
| `werewolf.victim=` | a directory on the victim's filesystem ([bite](bite.md)) |

`/data` holds `/data/svc/<service>` and `/data/home/<user>`, and is mounted
`noatime,nosuid,nodev,noexec`.

**The disk** is found by its label. It is formatted only when
`werewolf.data=DEV` names it, it is not the config disk, and `blkid` finds
nothing on it. A disk with our label is never formatted again. One the form
cannot use is left as it is:

- the wrong type: plain where the form wants LUKS, or the reverse;
- no `data.key`, or one that does not open it;
- damage `e2fsck -p` will not repair. `-p` fixes only what is safe without
  a person; the rest is a person's, with the disk attached to a machine
  that has e2fsprogs and cryptsetup.

**When /data is unavailable**, because of any of those, because
`werewolf.data` names nothing usable, or because a bitten machine's
directory cannot be bound, it is an empty, read-only tmpfs. The console and
`/run/werewolf/nodata` say why. A service that needs `/data` fails where it
can be seen, rather than writing to RAM what it believes is kept. A slot on
probation does not commit, so an update that broke `/data` falls back to
the slot before it.

**Encryption** protects snapshots, backups and recycled volumes, so the key
must not be stored beside them: on a single-disk provider, deliver the
config as user-data. init deletes the key from `/run/config` once the volume
is open. `crypt` needs a key; without one it formats nothing. Keep each
machine's key somewhere other than the machine, since without it the data
is gone. Encryption does not detect tampering.

**Backups** are yours. werewolf keeps `/data` across reboots and updates,
and copies it nowhere.

**Updates** roll back the image, not `/data`. A release that changes how a
service stores its data should change it only once its slot has committed
(`/run/werewolf/committed` exists), or keep a format the release before it
can still read. Otherwise a fallback runs the old release against data it
cannot read.

`make run` attaches a sparse 8 GiB `build/<arch>/data.img`, shared by every
form of an arch. Delete it for a blank disk, and when switching between
`disk` and `crypt`, which refuse each other's.
