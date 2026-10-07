# pledge

Proposed, 2026-10-06. The mount broker and the machine-wide rules are
built (cmd/mount-broker, fence.md's Files); promises are leash's floor,
less the words.

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

## Order

1. The mount broker, which the machine-wide rules depend on. Done:
   `grub`, `esp`, `victim` and `shutdown`, the mounts held as long as the
   asker's connection; `slot-keep`, `slot-update`, `bite-cleanup` and stage
   3 ask it, through lib/broker.zig.
2. The machine-wide rules, in `fence`. Done (fence.md, Files);
   `posture`'s `files-system-writes` checks them.
3. Promises in service files, with `leash`.

## Not covered

- **Scripts and memory.** Landlock judges `execve`, not an interpreter
  reading a script, nor `mmap` of executable memory (verified-boot.md).
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
