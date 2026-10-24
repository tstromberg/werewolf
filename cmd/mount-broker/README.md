# mount-broker

## Summary

mount-broker performs filesystem operations after fence forbids mounts. Callers use
three inherited socketpairs (`updater`, `keeper`, `stage`). Neither the EFI partition
nor `/boot` is lent as a mount: fixed operations use detached mounts and close them.

## Background

fence forbids `mount`, `umount` and `pivot_root` for every process, including root.
Three callers still need write access: slot-keep for the EFI entry, slot-update
for a new slot and TPM boot state, and stage 3 to shut down `/data` and `/boot`.
init starts the broker before fence, outside that domain. Callers use
`lib/broker.zig`.

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

- **Channels**: init creates three `AF_UNIX`, `SOCK_SEQPACKET` socketpairs: broker
  descriptors `3` (`updater`), `4` (`keeper`) and `5` (`stage`). Services close
  other roles' client descriptors on startup.
- **The EFI partition** (`werewolf.esp`'s FAT serial) is never attached. On `keeper`,
  the broker answers `esp-status` and `esp-commit`. On `updater`, it answers
  `esp-disarm` and `esp-arm` (one try of the other slot), `esp-inspect` (the other
  slot's boot-file digests), and `esp-install` (copy the staged, digest-named vmlinuz,
  stage0 and optional UKI of the other slot from slot-update's work directory, and arm
  it). The entry's command line is digest-named too: the staging directory is writable
  by guest root, so unbound options would let root choose the trial boot's boot context.
  No asker names a path, a file, an entry, or its contents.
- **Boot partition** (`werewolf.slots`'s ext4 UUID): `updater` mounts it detached,
  copies digest-checked staged files into `/slot/{a,b}` (`slot-root`, `slot-decl`,
  `slot-meta`) or `/state/{0,1}` (`slot-state`), syncs, then closes the mount.
- **Update reboot**: on `updater`, `reboot` sets two root-owned runit flags
  opened before confinement and wakes PID 1. Seccomp permits only those descriptors,
  modes and signal; the updater needs no filesystem override or signal capability.
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
- **Owner port**: opens the unique kernel-named `werewolf.owner` character device
  before confinement, root-only. Only the updater can request its descriptor.
  No request selects a path; other processes retain fence’s device restrictions.
- **Confined**: CAP_SYS_ADMIN only, locked (`lib/sandbox.zig`), and a seccomp allowlist:
  `recvfrom`, `sendto`, `sendmsg` (owner descriptor), `poll`, the new mount calls,
  and ESP/slot file calls (`openat`, `openat2`, `read`, `write`, `renameat`,
  `unlinkat`, `mkdirat`, `fsync`, `getdents64`), `mount(2)` only to remount read-only,
  `umount2` only without flags, and the one device-mapper ioctl that removes a mapping.

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
- **Stalled clients** cannot block other roles. Sends, including descriptor
  replies, are nonblocking. Failed sends, empty packets and EOF close the role's
  channel. `make check-mount-broker` tests reply-queue saturation in a private
  Linux mount namespace.
- **Tested**: `check-slot`, `check-updater`, protected A/B lifecycles and shutdown.
