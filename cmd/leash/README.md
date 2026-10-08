# leash

## Summary

Starts a service someone else wrote (nginx, PostgreSQL, a JVM app) as its
own user, on a leash: Landlock for files and TCP ports, a seccomp filter of
its promises, its own cgroup, and no capability but a low port's. runsv's
`/etc/sv/NAME/run` is a link to leash, which reads `/etc/sv/NAME/service`.

## Background

On a machine without a shell, runsv can only run `./run`, with no
arguments, as root. werewolf's own programs give root up themselves; a
program someone else wrote cannot. Its service file says, one directive a
line, what it may do: `exec`, `user`, `listen` and `connect` ports, `read`,
`write` and `run` paths, `pledge` promises, `env`, `secret`, `config`
(a file copied in, or `optional` and skipped when the machine lacks it),
`setting` and `render`, `memory`, `nofile`, `requires`, `before`.

## Goals

- No service runs as root, or with a capability beyond binding a low port.
- A service reaches only the files, programs and ports its file names.
- It makes only the system calls its promises bring, under the seal.
- Its whole process tree is bounded and reaped: memory, tasks, and a kill
  of every process when it stops.
- A bad file never half-starts a service: it parks, and says why.

## Non-Goals

- Configuring the program itself: its own files, or `render`ed settings.
- Restarting it: runsv does.
- Confining werewolf's own programs, which confine themselves.

## Detailed design

1. **The file, checked whole** before anything is done: every key known,
   paths absolute and clean, ports, promises, names, no root user.
2. **As root**: requirements checked; secrets and config files read (only
   paths the image names); `/run/svc/NAME` and `/data/svc/NAME` made its
   user's, the directory alone, never what is inside; `nofile`; its cgroup
   joined, with `memory.max` from `memory` and `pids.max` of 4096; a
   Landlock ruleset built of the floor (`/usr`, `/proc`, a few files in
   `/etc`, `/dev/null`, `/dev/zero`, `/dev/urandom`), its own directories,
   its paths, its program and ELF loader, and its ports.
3. **Root given up**: the bounding set emptied but for a low port's
   capability, groups, gid and uid changed, capabilities set and ambient
   for that one alone, `no_new_privs`, and a check that root is gone.
4. **Leashed**: Landlock applied, scoped from signals and abstract sockets
   outside it, every refusal audited after exec too; config files copied, as the service, into its own
   directory; settings rendered by `service-config`; each `before` run.
5. **Pledged**: a seccomp filter of its promises that answers ENOSYS, and
   has the kernel audit each, stacked on the seal; then leash becomes the program by `execveat` of a
   descriptor opened before, which a pledge without `exec` still allows.

## Drawbacks

- A dynamically linked program needs its ELF loader runnable, and the
  loader, run itself, loads any program the service can read where the
  mount allows: the image's `/usr`. What it loads stays under the same
  user, Landlock and pledge.
- `before` programs and `service-config` run before the pledge, under the
  seal and Landlock alone.
- Secrets are environment variables: `before` programs inherit them.
- Below Landlock ABI 6 (older host kernels), signals and abstract sockets
  go unscoped; werewolf's own kernel has ABI 6.

## Alternatives Considered

### systemd units
systemd is a large daemon with its own parsers, running as PID 1; leash
starts once per service and is gone before the service runs.

### A container runtime
Namespaces add kernel surface (user namespaces are off machine-wide) for
what Landlock, seccomp and a cgroup already give one process tree.

### Per-service seccomp alone
Without Landlock, a service could read or write any file its uid can; the
two together bound both what it calls and what it touches.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| A service file that is wrong | Checked whole first; any fault parks the service, nothing done. |
| A privileged write the service redirects | Copies are made after root is given up, inside Landlock, refusing links and replacing rather than truncating. |
| A recursive chown handing over a file | Only the service's directory itself is chowned, with `NOFOLLOW`. |
| A service that forks without end | `pids.max` of 4096, in a cgroup it joined as root and cannot leave. |
| A detached child outliving its service | `leash-reap`, its `./finish`, writes `cgroup.kill`. |
| Low port binding | `CAP_NET_BIND_SERVICE` alone, ambient; nothing else, in any set. |
| The console | fd 0 is `/dev/null`; no device ioctls are granted. |

## Reliability Considerations

- **Park or retry, never half-start:** what waiting cannot fix parks the
  service and tells runsv; a path another service has not made yet exits,
  for runsv to try again in a second.
- **Nothing of leash runs once the service starts**, so it costs nothing.
- **Tested:** posture's `processes-services-leashed`, `processes-leash-attack`
  and `make check`'s `cgrouped`, on every form with a service.
