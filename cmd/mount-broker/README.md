# mount-broker

## Summary

mount-broker mounts the few filesystems root's programs need after boot,
when fence's Landlock domain forbids everyone in it to mount. Each
connection sends one word (`grub`, `esp`, `victim` or `shutdown`) and holds
its mount until it closes.

## Background

fence puts every process in a Landlock domain that refuses `mount`,
`umount` and `pivot_root`, root's included. A few programs must still write
filesystems the machine does not keep mounted writable: slot-keep (GRUB's
environment, at commit), slot-update (a new slot), bite-cleanup (the old
distro), and stage 3 (shutting `/data` and the victim down). init starts
the broker before it execs fence, so the broker alone stays outside that
domain. Programs ask through `lib/broker.zig`.

## Goals

- No program but the broker can mount after boot.
- The broker fixes what it mounts and how: an asker sends a word, never a
  path, a device or an option.
- A mount lasts no longer than the connection that asked for it.

## Non-Goals

- Serving anyone but root.
- Choosing a filesystem by path. It goes by UUID or FAT serial, from the
  kernel command line only, parsed as stage0 parses it (`lib/cmdline.zig`).

## Detailed design

- **The socket** is `/run/werewolf/mount-broker.sock`, made under umask
  077; `SO_PEERCRED` must say uid 0. At most eight askers at once.
- **The words**: `grub` (the filesystem with GRUB's environment,
  `werewolf.grubenv`'s UUID), `esp` (`werewolf.esp`'s FAT serial) and
  `victim` (`werewolf.victim`'s UUID) mount at `/run/werewolf/mnt/WORD`.
  `shutdown` unmounts `/data` (or makes it read-only if busy), removes its
  LUKS mapping, and remounts the victim read-only, which writes its journal
  in place for GRUB. The answer is one line: `ok PATH`, `ok`, or `no WHY`.
- **Finding**: each block device's first bytes are read and identified
  (ext4, xfs, btrfs, FAT), and the UUID or serial compared. If two devices
  match, as a clone or snapshot beside the real disk would, it refuses.
- **Mounting**: the mount is built detached with
  `nosuid,nodev,noexec,nosymfollow`, then attached. bite names paths by
  where their links lead (`readlink -f`), so no link needs following. One
  asker holds a word at a time; another is told it is busy.
- **Releasing**: when the asker closes or dies, the broker unmounts plainly,
  never lazily, since a lazy unmount would hide a mount some process still
  has open. If it is busy, the word stays held and the broker retries each
  second; the refusal is logged once, and so is the unmount.
- **Confined**: CAP_SYS_ADMIN only, locked (`lib/sandbox.zig`), and a
  seccomp allowlist: its socket calls, the new mount calls, classic
  `mount(2)` only to remount read-only, `umount2` only without flags, and
  the one device-mapper ioctl that removes a mapping. It runs nothing.
- **Logging**: each event is one JSON line on the console.

## Drawbacks

- Any root process may ask, and `shutdown` takes `/data` from running
  services; root could reboot anyway.
- A mount held by a stuck asker keeps others waiting for that word.

## Alternatives Considered

### Let those programs mount
Each would need CAP_SYS_ADMIN and to stay outside fence's domain. The
broker is one small process holding it, for four words.

### Take a path or device from the asker
Then a compromised asker chooses what the most privileged process mounts.
A word leaves it nothing to choose.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| A non-root asker | Refused by `SO_PEERCRED`, on a socket only root can open. |
| An asker naming what to mount | It cannot: one word, everything else fixed here. |
| A forged command line copy | The broker reads `/proc/cmdline`, never a file under `/run`. |
| An attached disk taking the real one's place | Two devices with the same UUID or serial are refused. |
| A mount without its restrictions | Built detached with them, then attached. |
| The broker turned | CAP_SYS_ADMIN only, locked, under a seccomp allowlist; it runs nothing. |
| Root replacing a slot | **Open:** any root process may ask for `victim`, or write under it while the updater holds it (one mount namespace); checking the asker's program fails, as a process can connect, then exec. Verified boot fails a root image not its release's, and the slot falls back. |

## Reliability Considerations

- **Never exits** once listening: without it no slot can be kept, and the
  machine falls back to the slot that last worked. A failing `poll` pauses
  100 ms rather than spinning.
- **Mounts end with their askers**, however they end.
- **Tested**: `check-slot` (slot-keep, bite-cleanup), `check-updater`
  (slot-update), and every shutdown.
