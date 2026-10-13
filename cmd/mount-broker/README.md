# mount-broker

## Summary

mount-broker mounts the few filesystems root's programs need after boot, when fence's Landlock
domain forbids everyone in it to mount. Each connection sends one word (`grub`, `victim` or
`shutdown`) and holds its mount until it closes. The EFI partition is never lent as a mount: for a
few fixed operations the broker works on it detached and closes it.

## Background

fence puts every process in a Landlock domain that refuses `mount`, `umount` and `pivot_root`,
root's included. A few programs must still write filesystems the machine does not keep mounted
writable: slot-keep (GRUB's environment, at commit), slot-update (a new slot), bite-cleanup (the old
distro), and stage 3 (shutting `/data` and the victim down). init starts the broker before it execs
fence, so the broker alone stays outside that domain. Programs ask through `lib/broker.zig`.

## Goals

- No program but the broker can mount after boot.
- The broker fixes devices, paths and mount options; callers request named operations.
- A mount lasts no longer than the connection that asked for it.

## Non-Goals

- Serving anyone but root.
- Choosing a filesystem by path. It goes by UUID or FAT serial, from the kernel command line only,
  parsed as stage0 parses it (`lib/cmdline.zig`).

## Detailed design

- **The socket** is `/run/werewolf/mount-broker.sock`, made under umask 077; `SO_PEERCRED` must say
  uid 0. At most eight askers at once.
- **The words**: `grub` (the filesystem with GRUB's environment, `werewolf.grubenv`'s UUID) and
  `victim` (`werewolf.victim`'s UUID) mount at `/run/werewolf/mnt/WORD`. `shutdown` unmounts `/data`
  (or makes it read-only if busy), removes its LUKS mapping, and remounts the victim read-only,
  which writes its journal in place for GRUB. The answer is one line: `ok PATH`, `ok`, or `no WHY`.
- **The EFI partition** (`werewolf.esp`'s FAT serial) has no word. The only askers are the
  supervised slot-keep and slot-update services, and the broker checks the asking process — its
  binary, `./run` invocation, service directory, and the runsv supervising it — before acting; an
  interactive root shell or a manually run binary is refused. It then performs one fixed operation
  on a detached mount and closes it: `esp-status` and `esp-commit` (slot-keep's entry), `esp-disarm`
  and `esp-arm` (one try of the other slot), `esp-inspect` (the other slot's boot-file digests), and
  `esp-install` (copy the staged, digest-named vmlinuz, stage0 and optional UKI of the other slot
  from slot-update's work directory, and arm it). The entry's command line is digest-named too:
  the staging directory is writable by guest root, so unbound options would let root choose the
  trial boot's boot context. No asker names a path, a file, an entry, or its contents.
- **Words are lent only where they have a use.** `grub` and `victim` require a bitten machine (a
  GRUB environment on the kernel command line) and one of the three programs that use them —
  slot-update, slot-keep, bite-cleanup — each recognized the same way. On a native machine the
  victim is lent only to slot-update's TPM retirement, whose boot state still lives there; other
  native installs move `root.erofs`, declarations and signed-image metadata through the `slot-root`,
  `slot-decl` and `slot-meta` operations, digest-checked like the ESP's. `shutdown` is answered only
  for runit's stage 3. Anything else is refused and logged.
- **Finding**: each block device's first bytes are read and identified (ext4, xfs, btrfs, FAT), and
  the UUID or serial compared. If two devices match, as a clone or snapshot beside the real disk
  would, it refuses.
- **Mounting**: the mount is built detached with `nosuid,nodev,noexec,nosymfollow`, then attached.
  bite names paths by where their links lead (`readlink -f`), so no link needs following. One asker
  holds a word at a time; another is told it is busy.
- **Releasing**: when the asker closes or dies, the broker unmounts plainly, never lazily, since a
  lazy unmount would hide a mount some process still has open. If it is busy, the word stays held
  and the broker retries each second; the refusal is logged once, and so is the unmount.
- **Identity**: a private [task-links](../task-links/README.md) helper reads executable/cwd links.
  It starts before init drops tracing authority and permits only metadata lookups and private IPC.
- **Confined**: CAP_SYS_ADMIN only, locked (`lib/sandbox.zig`), and a seccomp allowlist: its socket
  calls, the new mount calls, the file calls the ESP operations need (open, read, write, rename,
  unlink, mkdir, fsync, getdents), classic `mount(2)` only to remount read-only, `umount2` only
  without flags, and the one device-mapper ioctl that removes a mapping. It runs nothing.
- **Logging**: each event is one JSON line on the console.

## Drawbacks

- Stage 3 takes `/data` from running services; root already has reboot authority.
- A mount held by a stuck asker keeps others waiting for that word.

## Alternatives Considered

- Let callers mount: each needs CAP_SYS_ADMIN and must stay outside fence; the broker centralizes it.
- Accept paths/devices: a compromised caller chooses what is mounted. Fixed operations prevent that.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| A non-root asker | Refused by `SO_PEERCRED`, on a socket only root can open. |
| An asker naming what to mount | It cannot: one word, everything else fixed here. |
| A forged command line copy | The broker reads `/proc/cmdline`, never a file under `/run`. |
| An attached disk taking the real one's place | Two devices with the same UUID or serial are refused. |
| A mount without its restrictions | Built detached with them, then attached. |
| The broker turned | CAP_SYS_ADMIN only, locked, under a seccomp allowlist; it runs nothing. |
| Root replacing a slot through the ESP | The ESP is never lent: only the supervised slot-keep and slot-update services may ask, the broker derives the slots itself, writes only the staged artifacts whose size and SHA-256 the updater named, and never attaches the mount. A root shell asking is refused (logged `esp refused`). |
| Root replacing a slot through `victim` | **Mostly closed:** the word is refused on native machines (but for the updater's TPM retirement) and, on bitten machines, to anyone but slot-update, slot-keep and bite-cleanup in their service contexts; native slot files move through digest-checked broker operations. While a legitimate updater holds a bitten machine's mount, another root process in the same mount namespace can still write under it. Verified boot fails a root image not its release's, and the slot falls back. |
| Broker calls in the wrong situation | Words and operations check the boot's shape on the kernel command line (bitten, TPM-sealed, slot) and the asking service before acting; a GRUB word on a systemd-boot machine, a native victim ask, or a `shutdown` from anyone but stage 3 is refused and logged. |

## Reliability Considerations

- **Never exits** once listening: without it no slot can be kept, and the machine falls back to the
  slot that last worked. A failing `poll` pauses 100 ms before retrying.
- **Mounts end with their askers**, however they end.
- **Tested**: `check-slot`, `check-updater`, protected A/B lifecycle tests and every shutdown.
