# Privilege separation after argon

**Status:** Implemented
[2026-10-13](https://github.com/werewolf-linux/werewolf/commit/68c56e1a)

Proposed and built, 2026-10-13
([argon-2023-10-13.md](../../audit/argon-2023-10-13.md)).
## Summary
Replace `/run/werewolf/mount-broker.sock` and `/proc` caller checks with three
inherited `SOCK_SEQPACKET` socketpairs, never lend `/boot` as a writable mount, and
tighten Landlock, `disk.zig`, and parser checks. Net effect: `cmd/task-links` and
`authorizeService` are deleted, and confined root cannot reach `mount-broker`.
## Background
Werewolf confines services with seccomp (`seal`), Landlock (`fence`, `leash`) and
dm-verity images ([lockdown.md](lockdown.md)). After an earlier audit
([muse-root-ace-2026-10-13.md](../../audit/muse-root-ace-2026-10-13.md)) showed a
root shell asking `mount-broker` to mount the ESP, `mount-broker` grew
`authorizeService` and `cmd/task-links`, inspecting
`/proc/PID/{exe,cmdline,cwd,status}` after `SO_PEERCRED`.

That fixed a symptom with a heuristic: `SO_PEERCRED` records who called `connect(2)`,
not who calls `write(2)` after `fork` or `execve`, and `/proc/PID/cmdline` is
caller-writable memory. A live check also found `/boot/state` owned by the builder's
UID (`501`), because `cmd/howl/disk.zig` zeroed only three paths.

## Goals
- Authority to reach `mount-broker` is an inherited descriptor, never a socket path
  or `/proc` check; `cmd/task-links` and `authorizeService` are deleted.
- Neither `/boot` nor the ESP is ever lent as a writable mount.
- A service without `exec` cannot `execveat` another `/usr` binary via `exec_fd`.
- `posture` verifies `/boot` owners, `/run/werewolf` read-only locks, and loopback
  bind addresses on every boot.

## Non-Goals
- Connection tracking (`nftables`/`conntrack`) in `fence`.
- Removing `uid 0` from `sshd`'s session monitor.

## Detailed design

### 1. Pass three role socketpairs (`init`, `runit-stage`, `mount-broker`)

Before `exec fence runit`, `init` opens three `AF_UNIX` `SOCK_SEQPACKET` socketpairs,
`updater`, `keeper` and `stage`, passes the server ends to `mount-broker` on
descriptors 3, 4 and 5, and places the client ends on 60, 61 and 62. The descriptor
*is* the role:

- **Delete `/run/werewolf/mount-broker.sock`, `authorizeService`, and
  `cmd/task-links`.** `mount-broker` never calls `bind`, `listen`, `accept`, or
  `SO_PEERCRED`, and never reads `/proc`.
- **Isolate client descriptors.** Stage 1 calls `broker.keepOnlyClient(null)`; stage
  2 closes `stage`'s descriptor (`62`) before `exec runsvdir`, so only PID 1 holds it
  for `/etc/runit/3` (`stop`). `slot-update` (`60`) and `slot-keep` (`61`) call
  `broker.keepOnlyClient(role)`, closing the other two and setting `PR_SET_DUMPABLE =
  0`; every other supervised program closes descriptors `>= 3`.
- **Never lend `/boot` as a mount.** `mount-broker` updates `/boot/slot/{a,b}` itself
  (`slot-root`, `slot-decl`, `slot-meta`) on a detached `fsmount` of `/boot`.
- **Harden `copyChecked`.** Open staged files with `openat2(RESOLVE_BENEATH |
  RESOLVE_NO_SYMLINKS)` and `O_RDONLY | O_NOFOLLOW | O_NONBLOCK`, then check
  `S_ISREG`.

### 2. Lock `/run/werewolf` read-only (`init`, `fence`)

In Landlock, `PATH_BENEATH` is recursive. `init` bind-mounts `/run/werewolf` to
itself and locks it read-only (`mount-ro /run/werewolf`) after creating
`/run/werewolf/{update,keep,posture,network,cloud}`, and `fence` grants write only on
those subdirectories (never `/run/werewolf` itself or `/run/runit`):

| Directory | Writer | Files |
| --- | --- | --- |
| `/run/werewolf/` (locked `ro`) | `init` only | `passwd`, `group`, `shadow`, `people`, `hosts`, `hostname`, `boot`, `nodata`, `rollback-checked` |
| `/run/werewolf/keep/` | `slot-keep` | `committed` (read by `stage0`'s deadman and `slot-update`) |
| `/run/werewolf/update/` | `slot-update` | `ready`, `status.json`, `control.sock` |
| `/run/werewolf/posture/` | `posture` | `posture.json` |

### 3. Pin `execveat` in Landlock (`leash`, `lib/seal.zig`)

Classic seccomp BPF cannot read `execveat`'s `pathname` pointer (`args[1]`), so
`execveat(exec_fd, "/usr/bin/other", ..., AT_EMPTY_PATH)` passes BPF. Landlock checks
the target inode: for any service without `exec`, `leash` grants
`LANDLOCK_ACCESS_FS_EXECUTE` only on `exec_fd` and its ELF loader, omitting `/usr`.

### 4. Builder, network, and parser checks

- **`cmd/howl/disk.zig` & `cmd/posture/files.zig`:** Walk the staged `/boot` tree to
  zero `uid`/`gid` and set `epoch` on every inode; `posture` checks the owners.
- **`cmd/fence/fence.zig`:** Omit `c.port == 0` from Landlock `CONNECT_TCP`; add
  `::ffff:0:0/96` and `2002::/16` to `non_public6`; block `169.254.169.254/32` for
  non-metadata users; `posture` verifies `loopback` ports bind `127.0.0.0/8` or
  `::1`.
- **`cmd/dhcp-client/dhcp-client.zig` & `lib/network.zig`:** Reject `169.254.0.0/16`
  in `usable()`; `valid()` refuses a route whose range overlaps `0.0.0.0/8`,
  `127.0.0.0/8`, `169.254.0.0/16` or `224.0.0.0/3`.
- **`cmd/slot-update/cve.zig` & `lib/apk.zig`:** Return `std.math.minInt(i64)` from
  `VersionReader.fail()`; share `lib/tar.zig`'s checksum check; widen
  `signatureSegment`'s length to `usize`; reject duplicate `APKINDEX`/`.PKGINFO`
  entries and match `.PKGINFO` `pkgname`/`pkgver` to the index.
- **`lib/compose.zig` & `lib/package.zig`:** Reject `.` and `..` path segments
  (`compose.prune`), symlinks (`compose.lay`) and control bytes (`package.pack`).

## Drawbacks

- Every non-broker supervised binary must close descriptors `>= 3` on startup.

## Alternatives Considered

- **Harden `authorizeService` with `pidfd_getfd` or `SCM_CREDENTIALS`.** Still trusts
  `/proc/PID/cmdline` and keeps a socket in `/run` that only three callers need.
- **A mount namespace for `slot-update`.** Linux forbids `mount(2)` under Landlock;
  detached `fsmount` operations in `mount-broker` keep one namespace.

## Security Considerations

Authority lives in file descriptors and Landlock inode sets created before `fence`.
Compromising `sshd` or a root shell gives no path to `mount-broker` or `/etc/shadow`.

## Reliability Considerations

A failed socketpair, mount lock or Landlock rule exits `init`, and the deadman boots
the previous slot. `posture` tests the `/boot` owners, the `/run/werewolf` lock and
the loopback bind addresses each boot.
