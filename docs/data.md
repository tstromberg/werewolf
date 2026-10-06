# Data

The root is never written. `/data` is the one writable place, and
everything on it is cache: losing it costs a cold start, never a broken
machine. That is why every failure here ends in reformatting.

| Present | /data |
| --- | --- |
| no storage tools | tmpfs capped at 25% of RAM, so a runaway cache fills up rather than exhausting memory |
| `mke2fs` | ext4 on the disk labelled `werewolf-data` |
| `mke2fs`, `cryptsetup` | the same in LUKS2, keyed by `data.key` |
| `werewolf.victim=` | a directory on the victim's filesystem ([bite](bite.md)) |

`/data` holds `/data/svc/<service>` and `/data/home/<user>`, and is mounted
`noatime,nosuid,nodev,noexec`.

**The disk** is found by its label. It is formatted only when
`werewolf.data=DEV` names it, it is not the config disk, and `blkid` finds
nothing on it; anything else is refused and the machine runs from RAM. A
disk with our label that the form cannot use (the wrong type, a key that
does not open it, damage `e2fsck -p` cannot repair) is reformatted, with a
console line saying why.

**Encryption** protects snapshots, backups and recycled volumes, so the key
must not be stored beside them: on a single-disk provider, deliver the
config as user-data. init deletes the key from `/run/config` once the volume
is open. Without a key, `crypt` uses a throwaway one, and `/data` does not
survive a reboot. Encryption does not detect tampering.

`make run` attaches a sparse 8 GiB `build/<arch>/data.img`; delete it for a
blank disk.
