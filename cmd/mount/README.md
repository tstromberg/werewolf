# mount

## Summary

mount is werewolf's own `mount`, used by init at boot. It mounts, binds
and remounts the few filesystems werewolf uses, and can only add
restrictions to a mount, never lift them: `mount -t TYPE [-o OPTIONS]
SOURCE TARGET`, `mount --bind SOURCE TARGET`, `mount -o remount[,OPTIONS]
TARGET`.

## Background

init needs `/proc`, `/sys`, `/dev`, RAM filesystems, a cgroup2 tree,
`/data`, image-root binds and a NoCloud seed. util-linux's mount takes any
option, including those that lift a restriction. This tool cannot loosen a
mount, but it is not a lock: root could still call mount(2) itself until
fence's Landlock domain forbids mounting, and the seal
([lockdown.md](../../docs/design/lockdown.md)) binds root after that.

## Goals

- Every mount is `nosuid` and `noexec`, `nodev` except on device
  filesystems, and `nosymfollow` except on proc, sysfs and devtmpfs, from
  the moment it is attached. `symfollow` withholds `nosymfollow` from a new
  mount or bind (`/data`).
- A remount cannot lift `ro`, `nosuid`, `nodev`, `noexec` or
  `nosymfollow`, whatever it is told.
- Nothing mounted over `/etc`, `/usr` or the root.

## Non-Goals

- Being util-linux's mount: no fstab, no labels, no loop devices.
- Binding root: fence's Landlock and the seal do that.

## Detailed design

- **Allowlists**, failing closed: only the filesystems init mounts (proc,
  sysfs, securityfs, cgroup2, devtmpfs, devpts, tmpfs, ext4 for `/data`,
  iso9660 for a NoCloud seed), each named with `-t`, never probed; the
  options each takes, with their values checked; and the places mounts may
  go: `/proc`, `/sys`, `/dev`, `/run`, `/tmp`, `/var/tmp`, `/data`,
  `/victim`, `/mnt`, and `/oci` (image roots, `cmd/init/oci.zig`). A bound
  device node from `/dev` does not get `nodev`, so it still works.
- **A new mount** is built detached (`fsopen`, `fsconfig`, `fsmount`) with
  its restrictions, then attached (`move_mount`).
- **A bind** is cloned detached (`open_tree`), restricted the same way,
  then attached. A clone keeps every restriction its source has.
- **A remount** is `mount_setattr` with nothing cleared, plus the one
  filesystem option `hidepid=invisible`.
- **Refused outright**: `suid`, `dev`, `exec`, `strictatime`, and `rw` or
  `symfollow` on a remount.
- **Paths** are absolute, without `.` or `..`, and opened with `openat2`
  refusing symlinks, so a link in a writable directory cannot steer a mount.
- **Pledge** after parsing, before any mount call (`lib/sandbox.zig`):
  only CAP_SYS_ADMIN, with the rest gone from the bounding set too, and a
  seccomp filter of the mount calls, `read`, `write`, `close` and exit.
- **Output**: nothing on success; on failure, one line with the kernel's
  own reason, read from the filesystem context. It reads no environment.

## Drawbacks

- The kernel resolves a block mount's source path itself, following links;
  only devtmpfs, which only root writes, holds those paths.
- It cannot mount the victim's filesystem (ext4, xfs or btrfs) or the ESP:
  stage0 and the mount broker do.

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
