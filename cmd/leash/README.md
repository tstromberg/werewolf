# leash

## Summary

leash starts a service someone else wrote (nginx, PostgreSQL, a JVM app) as
its own user, confined by Landlock for files and TCP ports, a seccomp pledge
and a cgroup, with no capability but a low port's; and narrows a program it runs.

## Background

runsv can only run `./run`, as root, with no arguments. werewolf's own
programs drop root themselves; other programs cannot. So `/etc/sv/NAME/run`
links to leash, which reads `/etc/sv/NAME/service` (`lib/service.zig`): a
key and words per line, `"` to group words, `#` at a word's start to comment.

| Key | Meaning |
| --- | --- |
| `exec`, `user`, `pledge` | required, once: the program and arguments; the user (never root); the promises (`lib/seal.zig`) |
| `before PROGRAM ARG...` | run first, in order, confined; each must exit 0 |
| `listen` / `connect tcp/PORT...` | ports it may bind / reach; a port below 1024 grants `CAP_NET_BIND_SERVICE`. `listen udp/PORT` is fence's to hold (Landlock names TCP alone), and leash's only for a low port's capability. `connect PATH` names a UNIX socket it may reach (Landlock ABI 9), beyond its own and those beneath what it writes |
| `read` / `write PATH...` | paths it may read / write, beyond the floor |
| `run PROGRAM...` | other programs it may start (with `pledge exec`) |
| `requires PATH...` | stay down unless each exists |
| `env NAME=VALUE`, `secret NAME PATH [optional]` | its environment, otherwise only `PATH`; a secret comes from a file and is never logged; if missing, park unless `optional` |
| `config NAME PATH [optional]` | copy a `/run/config` file to `/run/svc/SERVICE/NAME`, 0600; if missing, park unless `optional` |
| `setting`, `render` | settings, written by service-config (`lib/settings.zig`); a missing settings file reads as `{}` |
| `nofile N`, `memory MIB`, `cpu WEIGHT` | open-file limit; `memory.max` (resident memory, not address space); `cpu.weight`, a share of contended CPUs |
| `share strict\|shared\|browseable\|group`, `group NAME...` | who may enter its two directories: only its user (`0700`, the default); others, by a name they know, such as a socket (`0711`); others, listing too (`0755`); others by name, and services whose users have its user's group, writing too (`02771`, with a default ACL that makes what is made there the group's, whatever the umask). `group` joins other services' users' groups, to reach what they share with them (Valkey's socket) |
| `root /oci/NAME`, `dir PATH` | run inside an image in the root (docs/design/adhoc.md), without `render`; start directory |
| `narrow PROGRAM KEY WORD...` | run a `run` program narrowed: `pledge` (within the service's, no network), `read`, `write` (within the service's), `memory MIB` (`RLIMIT_DATA`) ([narrow.md](../../docs/design/narrow.md)) |

## Goals

- No service runs as root, or with any capability but binding a low port.
- A service reaches only the files, programs, ports and calls it declares.
- Its process tree is bounded (memory, 4096 tasks) and killed when it stops.
- A bad file never half-starts a service: it parks and logs why.

## Non-Goals

- Configuring or restarting the program, or confining werewolf's programs.

## Detailed design

1. **As root:** make fd 0 `/dev/null`; parse the whole file; check
   `requires`; read secrets and configs; make `/run/svc/NAME` and, while
   `/data` is usable, `/data/svc/NAME`, giving each (never its contents) to
   the user with the mode `share` asks; set `nofile`; join
   `/run/cgroup/svc/NAME` with `memory.max` and `pids.max` 4096. With `root`,
   chroot now, so every later path resolves in the image. Build a Landlock
   ruleset: the floor (`/usr`, `/proc`, a few files in `/etc` and `/dev`;
   with `root`, the whole image read-only), its directories and paths, each
   program and its ELF loader, its ports. `read`/`write` paths are opened with no symlink
   anywhere, since another service could plant one in `/data`.
2. **Drop root:** empty the bounding set but a low port's capability, set
   groups to its `group` lines' alone, set gid and uid, keep that
   capability ambient, set `no_new_privs`, and fail if root returns.
3. **Confined:** apply Landlock (also scoping signals and abstract sockets),
   copy configs, run `service-config`, then each `before`.
4. **Pledge and exec:** install a filter returning ENOSYS outside the
   promises, stacked on the seal (none while the machine learns), then
   `execveat` a descriptor opened earlier, which a pledge without `exec`
   allows. It starts in `dir`, else its data or (no `/data`) run directory.
5. **Narrowed:** run by `/etc/sv/NAME/narrow/PROGRAM`, the build's link
   for a `narrow` line, leash stacks that program's lines on the service's
   leash (a smaller floor without accounts or network files; its paths; it
   alone runnable; no TCP; its pledge) and execs it, without secrets.

## Drawbacks

- A dynamic program needs its ELF loader runnable, and the loader can run
  any readable program on an exec mount (`/usr`), still under its confinement.
- Landlock grants exec per file, so allowing one busybox applet allows all.
- `before` and `service-config` run before the pledge, and see secrets.
- Below Landlock ABI 6 (werewolf's kernel has 6), signals and abstract
  sockets are not scoped; below ABI 4, a service with ports parks.

## Alternatives Considered

- **systemd units:** a large PID 1 with its own parsers; leash exits first.
- **A container runtime:** namespaces add kernel surface (user namespaces are
  off) for what Landlock, seccomp and a cgroup already give one process tree.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| A wrong service file | Parsed whole first; any fault parks the service. |
| A privileged write or chown the service redirects | Copies are written after the drop, inside Landlock, by unlink and create, refusing symlinks. Only the directory itself is changed, through a descriptor opened `NOFOLLOW`. |
| Another service reading its files or reaching its sockets | Its directories are `0700` unless `share` opens them; `shared` (`0711`) admits only names one already knows. From Landlock ABI 9 a service reaches only the sockets its `connect` names, its own and those beneath what it writes. The build refuses a `read`, `write` or `connect` inside a strict service's directory (`lib/compose.zig`). |
| A fork bomb, or a child outliving its service | `pids.max` 4096, in a cgroup joined as root that it cannot leave; `leash-reap`, its `./finish`, writes `cgroup.kill`. |
| Forged console lines | fd 0 is `/dev/null`; no device ioctls are granted. |
| A narrowed program widening itself | Its lines come from the verified root, and Landlock domains and filters only stack; it keeps no descriptor but 0, 1 and 2. |

## Reliability Considerations

- **Park or retry:** what waiting cannot fix parks the service via runsv's
  control pipe; a path not made yet, or a missing `exec`, is retried.
- **Tested:** posture's `processes-services-leashed`, `-service-dirs` and
  `-leash-attack`, and `make check`'s `cgrouped`, on every form with a service.
