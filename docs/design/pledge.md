# pledge

Proposed, 2026-10-06. The mount broker and the machine-wide rules are
built (cmd/mount-broker, fence.md's Files); promises are leash's floor,
less the words. System-call promises (below) are being built.

OpenBSD's `pledge` restricts a program to classes of work, and `unveil` to
the parts of the filesystem it names. What makes them usable is that a
program never lists the files every program needs: the `dns` promise
brings `/etc/resolv.conf` and `/etc/hosts` with it, `getpw` brings
`/etc/passwd` and `/etc/group`, `tty` brings `/dev/tty`. A program states
what it does, not where its libraries look.

werewolf can do the same with Landlock, in two layers: one for the whole
machine, set by `fence` before runit starts, which nothing can lift, and
one per service, set by `leash` (shell-free.md) as it starts each one.

## The machine

`fence` already restricts every process to binding declared ports
(fence.md). It would also handle filesystem access, with no exceptions for
any program to write:

| | Allowed | Not, for anyone, root included |
| --- | --- | --- |
| Read | everywhere | |
| Write | `/run`, `/tmp`, `/var/tmp`, `/data`, `/dev/null`, terminals | `/proc` and `/sys`: every sysctl and sysfs setting stays as boot left it; anything in the image |
| Execute | the image: `/usr`, `/etc/sv`, `/etc/runit` | anything written since boot, even after a remount |
| Make device nodes | | anywhere |
| Make sockets, FIFOs, symlinks | `/run` | `/tmp`, `/data`: no rendezvous points or symlink traps there |
| Device ioctls | terminals; what a form declares (`prod`, for LUKS: `/dev/mapper/control`) | everything else: loop, device-mapper, and the rest of the kernel's ioctl surface |

Reading stays open. The image is the same on every machine and holds no
secrets; those are in `/run/config`, root's alone, and other users'
processes are hidden by `hidepid`. Closing reads is what would force a
list of exceptions for every program, and buys little.

Writing to `/proc` and `/sys` closed for good is the largest gain: root can
no longer lower the sysctls init raised, or change the kernel through
sysfs, without waiting for the seal to drop capabilities.

### Mounting, through a broker

A Landlock domain that handles filesystem access also refuses `mount`,
`umount` and `pivot_root` to every process in it. werewolf mounts after
boot: the updater mounts the victim's filesystem to install a slot,
`slot-keep` writes GRUB's environment, and shutdown unmounts `/data` and
remounts `/victim` read-only.

So the machine-wide rules need a mount broker, OpenBSD's privilege
separation applied to mounting: a small program init starts before
`fence`, outside the domain, which does a fixed list of mounts on
request, over a socket in `/run` that only root can reach:

| Request | Does |
| --- | --- |
| `victim-rw` | mount the victim's filesystem read-write at a private place, for an install, and return when unmounted |
| `shutdown` | unmount `/data`, close LUKS, remount `/victim` read-only |

It takes no paths and no options from the asker: each request is a word,
and what it does is in the program. Its own sandbox allows the mount
calls and nothing else of note.

## Services: promises

A service file (shell-free.md) would name promises, each a bundle of what
a class of work needs, and the service's own paths would come with it:

| Promise | Brings |
| --- | --- |
| `dns` | read `/etc/hosts`, `/etc/resolv.conf`, `/etc/services`, `/etc/nsswitch.conf`; send UDP and TCP to port 53 |
| `tls` | read `/etc/ssl` |
| `users` | read `/etc/passwd`, `/etc/group` |
| `tty` | read and write its terminal |
| `tmp` | a private directory in `/tmp` |
| `inet` | the `connect` and `listen` lines of its .net |

Every service also gets its own `/run/svc/NAME` and `/data/svc/NAME`, the
image's libraries, `/dev/null` and `/dev/urandom`, without asking. The
`read` and `write` lines in a service file then name only what is truly
its own, never a file every program needs.

The .net files could use the same words: `connect _update dns tcp/443`.

## System calls: promises

The seal (lockdown.md) was a list of 28 system calls refused to everyone.
It becomes the other way round: a system call is refused unless a promise
allows it. And the promises are the same words, so a service file says
what the program does once, and gets the calls, the paths and the ports
for it:

```
exec    /usr/bin/python3 /usr/lib/app/main.py
user    app
listen  tcp/8080
pledge  stdio rpath inet listen
```

No form keeps a list of system calls. Which calls a promise brings is
werewolf's to know, in one table (lib/seal.zig), for both architectures:
when a Wolfi update starts making a new call for the same work, the table
learns it once, and every form has it.

### The words

Each is as narrow as a system call number allows, and the risky ones
stand alone, so a program that needs one asks for that one:

| Promise | Allows |
| --- | --- |
| `stdio` | what every program does with what it already holds: read and write descriptors, memory, time, signals, waiting, polling, pipes, its own ids, terminal ioctls |
| `rpath` | opening, reading and looking at files and directories |
| `wpath` | changing them: creating, removing, renaming, linking, modes, owners, times, syncing |
| `inet` | creating IPv4 and IPv6 sockets |
| `unix` | creating Unix sockets and socket pairs |
| `netlink` | creating netlink sockets: reading, and with `netadmin`, changing, addresses and routes |
| `packet` | creating packet sockets (and the form's `packet` allowance) |
| `connect` | connecting a socket |
| `listen` | binding, listening and accepting |
| `proc` | creating processes and threads, waiting for them, signalling them |
| `exec` | running another program: one its service file names on a `run` line, as Landlock allows |
| `setuid` | changing user ids |
| `setgid` | changing group ids |
| `setgroups` | changing supplementary groups |
| `caps` | changing capabilities |
| `chroot` | changing its root directory |
| `mount` | mounting, and the new mount API |
| `umount` | unmounting |
| `namespace` | entering or making namespaces (`unshare`, `setns`) |
| `seccomp` | installing a seccomp filter of its own |
| `landlock` | confining itself with Landlock |
| `memfd` | anonymous memory files |
| `ipc` | System V shared memory, semaphores and message queues |
| `sendfile` | `sendfile`: copying a file's pages to a socket or file without reading them. werewolf's own programs make it (Zig's standard library copies files with it); a service, only if it pledges it: nginx does |
| `splice` | `splice` and `tee`: moving pages between pipes, files and sockets. Nothing here needs them |
| `mlock` | locking memory |
| `settime` | setting the clock |
| `hostname` | setting the host and domain names |
| `syslog` | reading the kernel's log |

What no promise allows is refused to everyone: tracing (`ptrace`), and
the never list, which no word can bring back: eBPF, kernel tracing,
modules, `kexec`, `io_uring`, `userfaultfd`, open-by-handle, the kernel
keyring, other processes' memory, 16-bit code and I/O ports, and old calls
nothing here makes.

### Two filters

The seal, on PID 1, allows the promises werewolf's own programs need (in
`minimal`), and every promise any service on the machine makes, which
the build reads from the service files. It reads system call numbers,
so the kernel answers every allowed call from its cache and the filter
costs nothing more for being long, but for five calls it also reads
arguments of, to refuse to everyone, root included, what no promise
brings, the way into kernel code that exploits in CISA's KEV catalog went
through (docs/cve-mitigation-survey.md):

| Call | Refused when it asks for | Answered |
| --- | --- | --- |
| `socket` | a family no promise names: AF_ALG, RDS, TIPC, VSOCK, `AF_KEY`, XDP… | `EAFNOSUPPORT` |
| `setsockopt` | `TCP_ULP` at the TCP level: kernel TLS, and every other upper-layer protocol | `ENOENT` |
| `pipe2` | `O_NOTIFICATION_PIPE`: a watch queue | `ENOPKG` |
| `timer_create`, `clock_nanosleep` | a CPU-time clock, its own or another process's | `EINVAL` |

Each answer is the kernel's own, had it been built without the feature,
so a program that probes for one carries on without it. These five calls
are the only ones the kernel's cache cannot answer, and none is made
often enough to notice.

leash then gives each service a filter of its own, stacked on the seal,
of its promises alone. That one may look at arguments, since a service
creates few sockets: `inet`, `unix`, `netlink` and `packet` are the
socket's family. So a Python application that pledged `stdio rpath inet
listen` cannot fork, run a program, make a Unix socket or a memory file,
or change its ids, even though another service on the machine may.

leash becomes the service by executing a descriptor of its program
(`execveat`, `AT_EMPTY_PATH`), the one exec a service's filter allows
without `exec`: and Landlock lets a service execute nothing but its own
program and what its `run` lines name, so without `exec` it can become
itself again, and nothing else. The `before` programs, which prepare a
service (`pg-init`, `nginx -t`), run before the pledge, under the rest of
the leash.

A service file without a `pledge` line is parked, with the reason on the
console: there is no default to fall back on. `seal` shows each service's
pledge, the machine's promises, and what was refused this boot, to whom,
and which promise would have allowed it.

### When a call is refused

Refused calls fail as if the kernel had no such call (ENOSYS), which
programs expect of an older kernel and handle; those refused for their
arguments, as above, as if it had no such feature. `seal-watch`, which init
starts before the seal, hears each refusal that the seal's filter refers
to it, says it once on the console with the promise that would allow it,
and counts it; `seal` shows what the machine allows and what it refused:

```
seal-watch: {"event":"refused","call":"memfd_create","promise":"memfd","pid":412}
seal-watch: {"event":"refused","call":"socket","promise":"never","why":"socket family","arg":38,"pid":97}
```

It hears only the programs the machine's promises alone bind, werewolf's
own: a leashed service's filter refuses first, and the kernel takes that
ENOSYS over the seal's listener, so those refusals fail unseen. Past 512
calls it counts the rest together, as `other`, said once, so no flood of
calls can hold the console.

A DEV=1 build booted with `werewolf.seal=learn` allows and records every
call instead, with the program that made it, the service it runs as, and
its promise: what a new service needs, in the words its service file would
use.

### What it cannot tell apart

- **Reading a file from writing one.** `openat` is one call either way;
  whether a file may be written is Landlock's, by path (leash's `write`).
  So `rpath` brings `openat`, and `wpath` only what changes a file without
  opening it.
- **One `ioctl` or `prctl` from another.** Both are in `stdio`, as almost
  every program makes them (a terminal's size; a thread's name). What they
  could do that matters is held elsewhere: capabilities, no_new_privs,
  Landlock on device files.
- **A namespace made by `clone`.** Its flags are arguments. User
  namespaces are off for everyone (lockdown.md), and the rest need
  `CAP_SYS_ADMIN`, which no process holds once fence has dropped it, root
  included.

## Order

1. The mount broker, which the machine-wide rules depend on. Done:
   `grub`, `esp`, `victim` and `shutdown`, the mounts held as long as the
   asker's connection; `slot-keep`, `slot-update`, `bite-cleanup` and stage
   3 ask it, through lib/broker.zig.
2. The machine-wide rules, in `fence`. Done (fence.md, Files);
   `posture`'s `files-system-writes` checks them.
3. Promises in service files, with `leash`: paths and ports (Services:
   promises), and system calls (System calls: promises), with the seal
   following them.

## Service lifecycle: a cgroup each

A pledge and a leash bound what a service *does*; a cgroup bounds what it
*leaves behind*. A compromised service can `fork`, `setsid` and `exec` the
one program it is allowed, leaving a daemon that reparents to PID 1 and
outlives the request -- a backdoor, confined but alive, that a bare runit
would not reap, since runsv signals only the process it supervises.

So each leashed service is its own cgroup. init mounts cgroup2 at
`/run/cgroup` -- under `/run`, not `/sys`, because fence keeps `/sys`
read-only machine-wide, and leash and the reaper must write cgroup files
from inside that domain, where only `/run` is writable -- and delegates
`memory` and `pids` to a `svc` subtree. leash, as root before it drops,
makes `/run/cgroup/svc/NAME`, sets `memory.max` from the service file's
`memory`, and joins; the service and everything it forks, detached
children included, stay in that cgroup, and a dropped service cannot leave
it (its Landlock grants only `/run/svc/NAME`). When runsv stops the
service -- `sv down`, a crash, a restart, shutdown -- it runs the
service's `finish`, `leash-reap`, which writes `cgroup.kill`: the kernel
kills the whole tree at once. So a detached backdoor dies with the service
that spawned it, not only at the next reboot.

`memory.max` caps resident memory, not address space, so it binds the JVM
and V8 (which reserve virtual space eagerly) as well as an interpreter --
unlike `RLIMIT_AS`, which a VM's reservations blow past. A per-service PID
namespace would add little over this: `hidepid` and the per-service uid
already hide other services from a compromised one, and the cgroup already
delivers the kill-the-whole-tree guarantee, so werewolf keeps the one
mechanism, not two.

## Not covered

- **Scripts and memory.** Landlock judges `execve`, not an interpreter
  reading a script, nor `mmap` of executable memory (verified-boot.md). A
  runtime form is an interpreter by design; its promises decide what the
  interpreter may then call, so native shellcode from `mmap` is bound by
  the same seccomp filter as the program, and reaches no more than its
  pledge allows.
- **`stat` and `inotify`.** Landlock mediates neither as of ABI 9: a
  confined program can `stat` any path (existence, size, mode leak, not
  contents), and `inotify` on a directory it cannot read would see file
  events by name. So watching is its own promise (`watch`), off unless a
  service asks; `stat` stays open, and secrets are kept out of paths, in
  `/run/config`, root's alone.
- **Reading `/proc`.** Left open; `hidepid` keeps other users' processes
  out of view.
- **Connecting to a Unix socket by path.** Linux 6.18's Landlock does not
  judge it. Sockets live only in `/run`, under the directories' owners.
- **Root and the broker.** Any root process can ask the broker for the
  victim's filesystem, read-write, and while the updater holds it any
  root process can write under it, since the mount is in the one
  namespace. Telling askers apart by program does not close this: a
  process can connect and then exec one that is allowed, and an attacker
  with root can as well wait for the updater's own mount. What the rules
  take from root is writing the machine's settings and disks underneath
  their filesystems, and mounting anything else; what keeps root from
  replacing a slot is verified boot (verified-boot.md): a root image not
  its release's fails its hash tree, and the slot falls back.
