# mount-broker

## Summary

mount-broker performs the few filesystem operations root's programs need after boot,
when fence's Landlock domain forbids everyone in it to mount. Callers ask over three
inherited `SOCK_SEQPACKET` socketpairs (`updater`, `keeper`, `stage`). Neither the EFI
partition nor `/boot` is ever lent as a mount: for each fixed operation the broker works
on a detached mount and closes it.

## Background

fence puts every process in a Landlock domain that refuses `mount`, `umount` and
`pivot_root`, root's included. Three callers must still touch filesystems the machine
does not keep mounted writable: slot-keep (the EFI entry, at commit), slot-update (a new
slot and TPM boot state), and stage 3 (shutting `/data` and `/boot` down). init starts
the broker before it execs fence, so the broker alone stays outside that domain.
Programs ask through `lib/broker.zig`.

## Goals

- No program but the broker can mount after boot.
- The broker fixes devices, paths and mount options; callers request named operations.
- Authority to ask is an inherited socketpair descriptor per role, never a path in
  `/run`.

## Non-Goals

- Serving any process that did not inherit a role descriptor.
- Choosing a filesystem by path. It goes by UUID or FAT serial, from the kernel command
  line only, parsed as stage0 parses it (`lib/cmdline.zig`).

## Detailed design

- **The channels** are three `AF_UNIX`, `SOCK_SEQPACKET` socketpairs created by init:
  descriptors `3` (`updater`), `4` (`keeper`) and `5` (`stage`) in the broker. Each
  service closes the client descriptors of the other roles on startup.
- **The EFI partition** (`werewolf.esp`'s FAT serial) is never attached. On `keeper`,
  the broker answers `esp-status` and `esp-commit`. On `updater`, it answers
  `esp-disarm` and `esp-arm` (one try of the other slot), `esp-inspect` (the other
  slot's boot-file digests), and `esp-install` (copy the staged, digest-named vmlinuz,
  stage0 and optional UKI of the other slot from slot-update's work directory, and arm
  it). The entry's command line is digest-named too: the staging directory is writable
  by guest root, so unbound options would let root choose the trial boot's boot context.
  No asker names a path, a file, an entry, or its contents.
- **The boot partition** (`werewolf.slots`'s ext4 UUID) is never attached either. On
  `updater`, the broker mounts it detached, copies digest-checked staged files into
  `/slot/{a,b}` (`slot-root`, `slot-decl`, `slot-meta`) or `/state/{0,1}`
  (`slot-state`), syncs, and closes the mount.
- **Shutdown**: on `stage`, `shutdown` unmounts `/data` (or makes it read-only if busy),
  removes its LUKS mapping, and remounts `/boot` read-only (flushing its journal) and
  unmounts it.
- **Finding**: each block device's first bytes are read and identified (ext4, FAT), and
  the UUID or serial compared. If two devices match, as a clone or snapshot beside the
  real disk would, it refuses.
- **Mounting**: each mount is built detached (`fsopen`, `fsconfig`, `fsmount`) with
  `nosuid,nodev,noexec,nosymfollow` and closed as soon as the operation finishes.
- **Updater runtime**: the updater alone can attach immutable `/usr` and the
  nonrecursive running root read-only at fixed, checked directories in its jail.
  Root-owned boot artifacts grant group 77 read/traverse access; `/boot` stays ro.
  Fixed `updater-ready` and `reboot` requests publish readiness and wake runit.
- **Confined**: CAP_SYS_ADMIN only, locked (`lib/sandbox.zig`), and a seccomp allowlist:
  `recvfrom`, `sendto`, `poll`, the new mount calls, the file calls the ESP and slot
  operations need (`openat`, `openat2`, `read`, `write`, `renameat`, `unlinkat`,
  `mkdirat`, `fsync`, `getdents64`), classic `mount(2)` only to remount read-only,
  `umount2` only without flags, and the one device-mapper ioctl that removes a mapping.
  It runs nothing.
- **Logging**: each event is one JSON line on the console.

## Drawbacks

- Stage 3 takes `/data` from running services; root already has reboot authority.

## Alternatives Considered

- Let callers mount: each needs CAP_SYS_ADMIN and must stay outside fence; the broker
  centralizes it.
- A listening socket in `/run` with `/proc` caller checks: vulnerable to `/proc` races
  and requires extra privileges to inspect callers. Inherited socketpairs need neither.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| An unauthorized root process asking | No socket path in `/run`; only processes that inherit a role descriptor can send to it, and each descriptor permits only its role's operations. |
| An asker naming what to mount | It cannot: fixed operations, everything else fixed here. |
| A forged command line copy | The broker reads `/proc/cmdline`, never a file under `/run`. |
| An attached disk taking the real one's place | Two devices with the same UUID or serial are refused. |
| A staged FIFO or symlink in `work_dir` | Opened with `openat2` (`RESOLVE_BENEATH \| RESOLVE_NO_SYMLINKS`), `O_NONBLOCK`, and verified `S_IFREG`. |
| The broker turned | CAP_SYS_ADMIN only, locked, under a seccomp allowlist; it runs nothing. |
| Root replacing a slot through the ESP or `/boot` | Neither is ever lent as a mount: the broker derives the slots itself, writes only the staged artifacts whose size and SHA-256 the updater named, and never attaches the mount. |

## Reliability Considerations

- **Never exits** once listening: without it no slot can be kept, and the machine falls
  back to the slot that last worked. A failing `poll` pauses 100 ms before retrying.
- **Tested**: `check-slot`, `check-updater`, protected A/B lifecycle tests and every
  shutdown.
