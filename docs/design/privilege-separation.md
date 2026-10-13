# Privilege separation after argon

Proposed, 2026-10-13 ([argon-2023-10-13.md](../audit/argon-2023-10-13.md)).

## Summary

Move `fence` from `runit` to `runsvdir` in stage 2, replace
`/run/werewolf/mount-broker.sock` and `/proc` caller checks with three inherited
socketpairs, and split `/run` and `/data` by owner in Landlock. Net effect: ~450
fewer lines of code (`cmd/task-links` deleted) and confined root can no longer
reach `mount-broker`, `/etc/shadow`, or the updater.

## Background

Werewolf confines services with seccomp (`seal`), Landlock (`fence`, `leash`),
and dm-verity images ([lockdown.md](lockdown.md)). After an earlier audit
([muse-root-ace-2026-10-13.md](../audit/muse-root-ace-2026-10-13.md)) showed a
root shell asking `mount-broker` to mount the ESP, `mount-broker` added
`authorizeService` and `cmd/task-links` to inspect `/proc/PID/{exe,cmdline,cwd,status}`
after `SO_PEERCRED`.

That fixed a symptom with a heuristic. `SO_PEERCRED` records who called
`connect(2)`, not who calls `write(2)` after `fork` or `execve`;
`/proc/PID/cmdline` is caller-writable memory; and because `fence` wraps
`runit`, `sshd` shares one Landlock domain, `/run`, and `/data` with `runsvdir`,
`slot-update`, and `slot-keep`. A live check via `howl ssh` also found
`/victim/werewolf/boot-state` owned by the builder's UID (`501`, user `t` in
the guest) because `cmd/howl/disk.zig` zeroed only three paths.

## Goals

- Authority to reach `mount-broker` is an inherited descriptor, never a socket
  path or `/proc` check; `cmd/task-links` and `authorizeService` are deleted.
- Root inside `fence` (`sshd`, a console shell) cannot signal the updater,
  write `/run/werewolf` or `/run/runit`, or touch `/data/werewolf/update`.
- A service without `exec` cannot `execveat` another `/usr` binary via `exec_fd`.
- `posture` verifies `/victim` owners, `/run/werewolf` read-only locks, and
  loopback bind addresses on every boot.

## Non-Goals

- Connection tracking (`nftables`/`conntrack`) in `fence`.
- Removing `uid 0` from `sshd`'s session monitor.

## Detailed design

### 1. Move `fence` to stage 2 and pass socketpairs (`init`, `runit-stage`, `mount-broker`)

Today `init` ends with `exec fence runit`, placing PID 1, `slot-update`,
`slot-keep`, and `sshd` in one Landlock domain. Instead, `init` sets `fence`'s
routing rules before `exec runit`, and `/etc/runit/2` (`runit-stage`) runs
`exec fence runsvdir -P /etc/sv`.

Before `exec runit`, `init` opens three `AF_UNIX` `SOCK_SEQPACKET`
socketpairs—`updater`, `keep`, and `stage`—and passes the server ends to
`mount-broker` on descriptors 3, 4, and 5. The descriptor index *is* the role:

- **Delete `/run/werewolf/mount-broker.sock`, `authorizeService`, and
  `cmd/task-links`.** `mount-broker` never calls `bind`, `listen`, `accept`, or
  `SO_PEERCRED`, and never reads `/proc`.
- **Start `slot-update` and `slot-keep` in `/etc/runit/1`** inside their own
  scoped Landlock domains (ABI 6), each inheriting only its socketpair end.
  Stage 2 closes `stage`'s descriptor before `exec fence runsvdir`; PID 1 keeps
  it for `/etc/runit/3` (`stop`) at shutdown. Because `fence` scopes signals,
  root inside `fence` cannot signal `runit`, `mount-broker`, `slot-update`, or `slot-keep`.
- **Never lend `/victim` on native boots.** Remove `Word.victim` when
  `ctx.release` is set. `mount-broker` updates `state.0`/`state.1` itself on a
  detached `fsmount` of `/victim` after checking `image.json.sig`.
- **Retire `update-control.sock` rollback.** `slot-update` writes status to
  `/run/werewolf/update-status.json` (`0644`); its control socket accepts only
  `check` and `try HASH` (verified by `fresh()`, never `rollback = true`).
- **Harden `copyChecked`.** Open staged files with `openat2(RESOLVE_BENEATH |
  RESOLVE_NO_SYMLINKS)` and `O_RDONLY | O_NOFOLLOW | O_NONBLOCK`, then check `S_ISREG`.

### 2. Sibling `/run/werewolf/<owner>/` directories (`init`, `fence`)

In Landlock, `PATH_BENEATH` is recursive: granting write on `/run/werewolf` to
let a helper write one file there also grants write on every subdirectory
beneath it. Putting every file in a sibling `/run/werewolf/<owner>/` directory
means **nothing ever gets a Landlock write rule on `/run/werewolf` itself**:

| Directory | Writer | Files |
| --- | --- | --- |
| `/run/werewolf/init/` | `init` only | `passwd`, `group`, `shadow`, `people`, `hosts`, `hostname`, `boot`, `nodata`, `rollback-checked` |
| `/run/werewolf/keep/` | `slot-keep` | `committed` (read by `stage0`'s deadman and `slot-update`) |
| `/run/werewolf/update/` | `slot-update` | `ready`, `status.json`, `control.sock` |
| `/run/werewolf/posture/` | `posture` | `posture.json` |
| `/run/werewolf/fence/` | processes inside `fence` | Shared runtime state inside the fence (alongside `/run/{svc,sshd,user,tmp}`) |
| `/data/werewolf/update/` | `slot-update` | Slot staging tree (`fence` grants only `/data/{svc,home,var}`) |

### 3. Pin `execveat` in Landlock (`leash`, `lib/seal.zig`)

Classic seccomp BPF cannot read `execveat`'s `pathname` pointer (`args[1]`), so
`execveat(exec_fd, "/usr/bin/other", ..., AT_EMPTY_PATH)` passes BPF. Landlock
checks the target inode: for any service without `exec`, `leash` grants
`LANDLOCK_ACCESS_FS_EXECUTE` only on `exec_fd` and its ELF loader, omitting `/usr`.

### 4. Builder, network, and parser checks

- **`cmd/howl/disk.zig` & `cmd/posture/files.zig`:** Walk the staged `/victim` tree to zero `uid`/`gid` and set `epoch` on every inode; `posture` walks `/victim` as well as `/`.
- **`cmd/fence/fence.zig`:** Omit `c.port == 0` from Landlock `CONNECT_TCP`; add `::ffff:0:0/96` and `2002::/16` to `non_public6`; block all protocols on `169.254.169.254/32` for non-metadata users; verify in `posture` that `loopback` ports bind `127.0.0.0/8` or `::1`.
- **`cmd/dhcp-client/dhcp-client.zig` & `lib/network.zig`:** Reject `169.254.0.0/16` in `usable()`, and verify in `valid()` that `[r.dst, r.dst | ~mask(r.prefix)]` never overlaps `0.0.0.0/8`, `127.0.0.0/8`, `169.254.0.0/16`, or `224.0.0.0/3`.
- **`cmd/slot-update/cve.zig` & `lib/apk.zig`:** Return `std.math.minInt(i64)` from `VersionReader.fail()`; share `lib/tar.zig`'s checksum check; widen `signatureSegment`'s length to `usize`; reject duplicate `APKINDEX`/`.PKGINFO` entries and match `.PKGINFO` `pkgname`/`pkgver` to the index.
- **`lib/compose.zig` & `lib/package.zig`:** Reject `.` and `..` segments after splitting on `/` (`compose.prune`), refuse symlinks in `compose.lay`, and reject bytes `<= 0x1f` or `0x7f` in `package.pack`.

## Drawbacks

- `slot-update` runs as a daemon started in stage 1 rather than under `runsvdir`.
- Forms writing directly to `/data/foo` must use `/data/{svc,var,home}`.

## Alternatives Considered

- **Harden `authorizeService` with `pidfd_getfd` or `SCM_CREDENTIALS`.** Still trusts `/proc/PID/cmdline` (user memory) and keeps a socket in `/run` that only three callers ever need.
- **Separate mount namespaces for `slot-update`.** Linux forbids `mount(2)` inside Landlock; a separate Landlock domain on `/data/werewolf/update` keeps one namespace.

## Security Considerations

Authority lives in file descriptors and Landlock inode sets created before stage 2 enters `fence`. Compromising `sshd` or a root shell gives no path to `mount-broker`, `/etc/shadow`, or the updater.

## Reliability Considerations

- **Fails closed:** any failed socketpair, read-only mount lock, or Landlock rule exits `init`; the deadman timer boots the previous slot.
- **Tested each boot** by `posture`: `/victim` owners, `/run/werewolf` read-only lock, loopback bind addresses, and broker descriptor isolation.
