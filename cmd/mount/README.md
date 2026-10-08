# mount

## Summary

werewolf's own `mount`, for init at boot: it mounts the few filesystems
werewolf uses, binds, and remounts, and can only ever tighten a mount.
`mount -t TYPE [-o OPTIONS] SOURCE TARGET`, `mount --bind SOURCE TARGET`,
`mount -o remount[,OPTIONS] TARGET`.

## Background

init needs `/proc`, `/sys`, `/dev`, RAM filesystems, a cgroup2 tree, the
victim's filesystem, `/data`, and a NoCloud seed. util-linux's mount takes
any option, including those that lift a restriction. This one is a tool that
cannot loosen a mount; root could still call mount(2) itself until fence's
Landlock domain forbids mounting to every process.

## Goals

- Every mount `nosuid` and `noexec`, `nodev` but for device filesystems, and
  `nosymfollow` but for proc, sysfs and devtmpfs, from the moment it is
  attached; `symfollow` withholds the last from a new mount or bind (`/data`).
- A remount that cannot lift `ro`, `nosuid`, `nodev`, `noexec` or
  `nosymfollow`, whatever it is told.
- Nothing mounted over `/etc`, `/usr` or the root.

## Non-Goals

- Being util-linux's mount: no fstab, no labels, no loop devices.
- Binding root: fence's Landlock and the seal do that.

## Detailed design

- **Allowlists**: only the filesystems init mounts (proc, sysfs,
  securityfs, cgroup2, devtmpfs, devpts, tmpfs, ext4 for `/data`, iso9660
  for a NoCloud seed), each named with `-t`, never probed; the options each
  takes, with their values checked; and the places mounts may go: `/proc`,
  `/sys`, `/dev`, `/run`, `/tmp`, `/var/tmp`, `/data`, `/victim`, `/mnt`.
- **A new mount** is built detached (`fsopen`, `fsconfig`, `fsmount`) with
  its restrictions, then attached (`move_mount`): no moment without them.
- **A bind** is cloned detached (`open_tree`), restricted the same, then
  attached.
- **A remount** is `mount_setattr` with nothing cleared, and the one
  filesystem option `hidepid=invisible`.
- **Refused outright**: `suid`, `dev`, `exec`, `strictatime`, and `rw` or
  `symfollow` on a remount.
- **Targets** are opened with `openat2`, symlinks refused, so a link in a
  writable directory cannot steer a mount.
- **Pledge** after parsing, before the kernel hears anything
  (`lib/sandbox.zig`): CAP_SYS_ADMIN alone, the bounding set emptied of the
  rest; a seccomp filter of the mount calls, `read`, `write`, `close` and
  exit.
- **On failure**, one line with the kernel's own reason, read from the
  filesystem context.

## Drawbacks

- The source of a block mount is a path the kernel resolves itself, links
  and all; only devtmpfs, root's, holds those.
- The victim's filesystem (ext4, xfs or btrfs) and the ESP are not its
  to mount: stage0 mounts the one, the broker the other.

## Alternatives Considered

### util-linux or busybox mount
Either takes any option, `exec` and `suid` included, and a shell-free image
carries neither.

### mount(2) with MS_REMOUNT
A classic remount sets the mount's flags whole, so it can lift what it does
not repeat; `mount_setattr` sets only what it is given.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| A mount that lacks its restrictions for a moment | Built detached, restricted, then attached. |
| A remount that loosens | `mount_setattr` with nothing cleared; loosening words refused. |
| A link steering a mount | Targets resolved with symlinks refused. |
| A mount over the system | Only werewolf's places; never `/etc`, `/usr` or `/`. |
| mount itself turned | CAP_SYS_ADMIN alone, and the mount calls; anything else kills it. |

## Reliability Considerations

- **Says why**: the kernel's own message for a refused option or source.
- **Tested**: every `make check` boot mounts all it needs through it.
