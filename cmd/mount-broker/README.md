# mount-broker

## Summary

Mounts, for root's own programs, the few filesystems werewolf needs after
boot, which fence's Landlock domain forbids anyone in it to mount. Each
connection takes one word (`grub`, `esp`, `victim` or `shutdown`) and holds
its mount until it closes.

## Background

fence puts every process in a Landlock domain that refuses `mount`,
`umount` and `pivot_root`, root's included. A few programs must still
write filesystems the machine does not keep mounted writable: slot-keep
(GRUB's environment, at commit), slot-update (a new slot), bite-cleanup
(the distro), and stage 3 (shutting `/data` and the victim down). init
starts the broker before it becomes fence, so the broker alone stays
outside that domain; `lib/broker.zig` is how a program asks.

## Goals

- No program but the broker can mount after boot.
- What it mounts, and how, is fixed here: an asker supplies a word, never a
  path, a device or an option.
- A mount lasts no longer than the connection that asked for it.

## Non-Goals

- Serving anyone but root: other askers are turned away.
- Choosing a filesystem by path: by UUID or FAT serial, from the kernel's
  command line and what init wrote.

## Detailed design

- **The socket**, `/run/werewolf/mount-broker.sock`, made under umask 077,
  root's alone; `SO_PEERCRED` must say uid 0. At most eight askers.
- **The words**: `grub` (the filesystem holding GRUB's environment, from
  `/run/werewolf/grubenv`), `esp` (`werewolf.esp`'s FAT serial), `victim`
  (`werewolf.victim`'s UUID), each at `/run/werewolf/mnt/WORD`; `shutdown`
  (`/data` unmounted, or read-only if busy; its LUKS mapping removed; the
  victim read-only, which writes its journal into place for GRUB).
- **Finding the filesystem**: each block device's first bytes read and
  identified (ext4, xfs, btrfs, FAT), and its UUID or serial compared. Two
  devices that match are refused, as a clone or snapshot attached beside
  the real disk would make them.
- **Mounting**: built detached, `nosuid,nodev,noexec`, then attached. One
  asker holds a word at a time; another is told it is busy.
- **Releasing**: when the asker closes, or dies, the mount is unmounted,
  lazily if busy.
- **Confined**: CAP_SYS_ADMIN alone and locked (`lib/sandbox.zig`), and a
  seccomp filter of its socket's calls, the new mount calls, the classic
  `mount(2)` only to remount read-only, `umount2` only plainly or lazily,
  and the one device-mapper ioctl that removes a mapping.

## Drawbacks

- Any root process may ask, and `shutdown` takes `/data` from running
  services; root could reboot anyway.
- A mount held by a stuck asker keeps others waiting for that word.

## Alternatives Considered

### Let those programs mount
They would need CAP_SYS_ADMIN and to stay outside fence's domain, each one.
The broker is one small process holding it, for four words.

### Take a path or device from the asker
Then a compromised asker chooses what the most privileged process mounts.
A word leaves it nothing to choose.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| A non-root asker | Refused by `SO_PEERCRED`, on a socket only root can open. |
| An asker naming what to mount | It cannot: one word, everything else fixed here. |
| An attached disk taking the real one's place | Two devices with the same UUID or serial are refused. |
| A mount without its restrictions | Built detached, `nosuid,nodev,noexec`, then attached. |
| The broker turned | CAP_SYS_ADMIN alone and locked, under a seccomp allowlist; it runs nothing. |

## Reliability Considerations

- **Never exits**: without it no slot can be kept, so a machine whose broker
  will not start falls back to the slot that last worked. A failing `poll`
  pauses a moment rather than spinning.
- **Mounts end with their askers**, however they end.
- **Tested**: `check-slot` (slot-keep, bite-cleanup), `check-updater`
  (slot-update), and every shutdown.
