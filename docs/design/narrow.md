# narrow

Built, 2026-10-09: lib/service.zig, cmd/leash; webshell-example's `cat`.

## Summary

A service file's `narrow` lines put a program it runs on a narrower leash:
fewer promises, no network, fewer files. A media tool parsing strangers'
files, as Mastodon's ffmpeg does, then gets less than its service.

## Background

leash confines a service and the programs it runs alike
([cmd/leash](../../cmd/leash/README.md)). A bug in ffmpeg, which Sidekiq
runs on any uploaded video, gives Sidekiq's secrets, database, network and
media to an attacker; ffmpeg needs a file in, a file out and the CPU. Only
the verified `/usr` runs (fence), writable mounts follow no links, and
leash cannot mount.

## Goals

- A narrowed program's pledge is within its service's, without sockets; it
  reads its floor and paths, writes only its paths, and runs only itself.
- No service widens a narrowing or leaves its leash by one; the build
  refuses a narrowing its service could not hold, naming the line.
- `make check-shellfree-webshell-example`: narrowed `cat` reads the image,
  but not the account list or the app's own file, which plain `cat` reads.

## Non-Goals

- Libraries in the service's process (libvips through a Ruby binding).
- An application that cannot be pointed at a program's path.

## Detailed design

```
narrow /usr/bin/ffmpeg pledge stdio rpath wpath proc
narrow /usr/bin/ffmpeg read /data/svc/mastodon/media
narrow /usr/bin/ffmpeg write /run/svc/mastodon-sidekiq
narrow /usr/bin/ffmpeg memory 1024
```

**The build.** PROGRAM is a path a `run` line names (leash checks it is an
ELF program), its name no other narrowed program's. `pledge` is required,
within the service's, without `inet unix netlink packet connect listen`.
`read` lies within what the service may read (its `read` and `write`
lines, its directories, the floor), `write` within what it may write. The
service promises `rpath exec landlock seccomp`, which narrowing uses, and
has no `root`. leash checks again at start which directory is its own.

**The link.** The build makes `/etc/sv/NAME/narrow/PROGRAM`, a link to
`/usr/lib/werewolf/leash`, for each narrowed program (lib/compose.zig), and
leash parks the service without it. The application is pointed at it by its own setting
(`FFMPEG_BINARY`). The service may run leash and read its service file.

**The run.** leash, run by the link (AT_EXECFN) as the service, inside its
leash: closes at exec all descriptors but 0, 1 and 2; refuses root; reads
`/etc/sv/NAME/service` if root's alone; builds a Landlock domain of a
narrower floor (`/usr`, `/proc`, the CPU list, `/etc/ld.so.cache`,
`/etc/localtime`, three devices), its paths, and the program and its loader
to run, closing TCP, abstract sockets and signals; caps `RLIMIT_DATA`;
enters it; logs `leash: {"event":"narrow",...}` on stderr; pledges; and
`execveat`s the program with its arguments and environment, less what the
`secret` lines name. Domains and filters stack: the service's leash and the
seal still hold. A refusal is a `"refused"` line on stderr and exit 1;
refused calls and paths are audited as the service's are.

## Drawbacks

- `memory` caps the private memory it maps, not resident memory: a child
  cannot join a cgroup of its own without root. The service's still holds.
- The service may still run the program unnarrowed: narrowing keeps the
  program from the service, not the service from the program.

## Alternatives Considered

- **Links in `/run`, made at start, a policy beside them.** A link on a
  `nosymfollow` mount leads nowhere; a mount that follows links undoes a
  protection for every program.
- **seccomp user-notify on exec.** A supervisor reads each `execve`'s path
  from memory another thread can change before the kernel reads it.
- **A wrapper program per tool:** more programs to review, repeating leash.
- **A separate service fed by a queue:** its own user and cgroup, but the
  application must speak the queue; Mastodon runs ffmpeg as a command.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| The program widens its leash | Its lines come from the dm-verity root; domains and filters only stack, under `no_new_privs`. |
| The service escapes through leash | Unprivileged and not run by a link, leash refuses; by one, it only adds limits. |
| The service fakes the narrowing, answering leash's calls from a seccomp listener | The seal refuses a listener once it holds (lib/seal.zig); posture's `kernel-seccomp-listener`. |
| The service's secrets | Not in its environment; Landlock's ptrace scope hides the service's `/proc/PID/environ` and memory. |
| A socket the service left open | Closed at exec; no socket promise, no TCP. |

## Reliability Considerations

- Fails closed: a narrowing that cannot be set up runs nothing and says why
  on stderr; a missing link parks the service at start, not at an upload.
- Tested: unit tests (lib/service.zig, cmd/leash); webshell-example's console.
