# pledge

Built, 2026-10-06 (lib/seal.zig, cmd/seal, cmd/seal-watch, leash's
`pledge` line, cmd/mount-broker, cmd/leash-reap). Path bundles are not.

## Summary

A service file says in a few words what its program does, as on OpenBSD
(`pledge stdio rpath inet listen`), and gets the calls for those words
alone. The machine-wide seal refuses what no promise names, to root too.

## Background

`pledge` works because a program states what it does, not where its
libraries look. The seal began as a deny list (lockdown.md); a list of
calls per program would break with each glibc or Wolfi update.

## Goals

- Deny by default: a call no promise names is refused, even as the
  kernel gains new calls. Root is bound too, until reboot.
- No form lists calls: one table (lib/seal.zig) learns a new call once.
- A refusal by werewolf's own programs names the promise it lacked.

## Non-Goals

- Words for paths (Alternatives), or telling one call's uses apart.

## Detailed design

Two layers, never lifted. The machine: the seal, and fence's Landlock
domain ([fence.md](fence.md), Files), which refuses `mount` (hence
cmd/mount-broker). Each service: leash's Landlock rules, its filter, and
a cgroup whose `finish` kills the whole tree, detached daemons included.

### System calls: promises

A service file's `pledge` names its promises; its `read`, `write`,
`listen` and `connect` lines give it paths and ports. Each word is as
narrow as a call number allows, and the risky ones stand alone (`exec`,
`setuid`, `mount`, `memfd`, `watch`, `ipc`, `splice`). The words are in
[docs/forms.md](../forms.md#what-the-leash-holds); none brings `ptrace`
or the `never` calls (lib/README.md). A file without a `pledge` is
parked: there is no default. `/run/svc/NAME` and `/data/svc/NAME` are
`0700`, the service user's alone, unless its `share` line opens them
(`shared` 0711, `browseable` 0755).

### Two filters

The seal, on PID 1, allows werewolf's own promises (`base` in
lib/seal.zig) and every service's pledge (`/usr/share/werewolf/pledge`).
It matches call numbers, so the kernel answers allowed calls from its
seccomp cache however long the filter is. For six calls (`socket`,
`socketpair`, `setsockopt`, `pipe2`, `timer_create`, `clock_nanosleep`)
it reads arguments too, refusing to everyone the ways into kernel code
that exploits in CISA's KEV catalog used (lib/README.md). A refused call
fails as on a kernel without it, so a program that probes carries on;
seal-watch logs it once, with the promise that would allow it.

leash stacks the service's promises alone on the seal: a Python app that
pledged `stdio rpath inet listen` cannot fork, run a program, make a Unix
socket or a memory file, or change its ids. The kernel audits those
refusals; seal-watch never sees them. leash becomes the service by
`execveat` of a descriptor, the one exec a filter without `exec` allows.

## Drawbacks

- The seal is the union of every pledge and `base`, so `mount`, `exec`
  and `setuid` stay open machine-wide, to werewolf's own programs.
- One call's uses are not told apart. `openat` reads or writes, so
  `rpath` brings it and Landlock judges the path. `ioctl` and `prctl` are
  in `stdio`; capabilities and Landlock on devices hold what they reach.
  `clone`'s namespace flags are arguments; user namespaces are off.

## Alternatives Considered

### Path bundles
`dns`, `tls` and the like: leash's floor gives every service those paths.

### Kill the caller, as OpenBSD does
It outranks a service's ENOSYS, and kills runtimes that probe (libuv).

### A PID namespace per service
`hidepid`, per-service users and the cgroup already do its work.

## Security Considerations

- **Scripts and memory.** Landlock judges `execve`, not an interpreter
  reading a script, nor executable `mmap`; the filter still binds both.
- **`stat` and `inotify`.** Landlock mediates neither (as of ABI 9), so
  `watch` is its own promise and secrets stay in `/run/config`, not in
  paths. Reading `/proc` stays open; `hidepid` hides other users'.
- **A Unix socket's `connect`** is not judged by Landlock in Linux 6.18;
  sockets are made only in `/run`, behind directory modes.

## Reliability Considerations

- **Fails closed:** without the seal init exits and the slot falls back;
  a service whose file or filter fails is parked, with the reason.
- **Learnable:** a DEV=1 build allows and records calls (`make seal-learn`).
