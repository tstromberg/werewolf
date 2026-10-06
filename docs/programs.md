# werewolf's programs

werewolf writes its own programs only where the image needs one and no
package will do: `dhcp`, `cloud`, `mount`, `update`, `status`. Each is a single
static Zig binary, built ReleaseSafe from one source file. They are written
the way OpenBSD writes its daemons: assume the input is hostile and the
code has a bug, and arrange that the bug can do nothing.

## The rules

1. **Separate the privileges.** The part that reads untrusted input, from
   the network or from another program's output, is not the part that
   changes the machine. Split them into two processes, as OpenBSD's
   dhclient and ntpd do: an unprivileged one that does the work, and a small
   privileged one that does only what needs privilege.
2. **Pass facts, not requests.** The two processes talk in fixed-size
   messages. The privileged side checks every field again, and treats a
   message it does not like as a compromised peer: it ends both.
3. **Give everything up early.** Do what needs privilege first: open the
   sockets and files, then drop. The unprivileged side runs as its own
   user, chrooted to the empty `/var/empty`, with no capabilities and an
   empty bounding set, and checks that root cannot be had back. The
   privileged side keeps the one capability it needs, with securebits
   locked so root's uid brings no others.
4. **Allow, never deny.** A seccomp filter names the system calls a
   process may make, with arguments where they matter: which descriptor,
   which ioctl. Any other call kills the process, as does a call made as
   another architecture. Landlock confines what it may write to the
   directories it owns. no_new_privs is always set.
5. **Do it before the input arrives.** The sandbox is complete before the
   first byte of untrusted input is read. Filters on a socket go on, and
   are locked, before it is bound.
6. **Parse strictly.** Every length is checked against what is there.
   Unknown things are ignored, malformed things are rejected, and only the
   fields actually used are read. Validation happens where the data is
   parsed and again where it is applied.
7. **Fail closed.** An allowlist that does not match, a sandbox step that
   fails, a peer that misbehaves: each ends the program. runit restarts it.
8. **Allocate nothing after setup**, where a program runs for long: fixed
   buffers, or an arena freed on each pass. Memory does not grow with
   uptime.
9. **Run nothing else.** No shell, no hook scripts, no helper programs
   where a system call will do.
10. **Log facts.** One JSON line per event on stdout, with the kernel's own
    reason for any failure. Text from outside is escaped or not logged.

ReleaseSafe turns an out-of-bounds access or an overflow into a stopped
program rather than a corrupted one. The rules are for the bugs it does
not catch.

## Where each program stands

| Program | Runs | Separation and confinement |
| --- | --- | --- |
| `dhcp` | always, when there is no static address | Two processes. The engine runs as `_dhcp`, chrooted, with no capabilities, under seccomp, which lets it send and receive on its packet socket and write to the parent, and little else. The parent has `CAP_NET_ADMIN` alone, under seccomp (four ioctls) and Landlock (`/run/werewolf/dhcp`). A kernel socket filter passes only DHCP replies. |
| `cloud` | once at boot, on a known cloud with no local config | Two processes. The fetcher runs as `_cloud`, chrooted, with no capabilities, under seccomp: an IPv4 TCP socket to the metadata server, and little else. The parent has no capabilities, never touches the network, and writes only beneath `/run/werewolf/cloud` (Landlock); it checks the fetched tar and writes a new one of what passed, so init extracts only what werewolf wrote. |
| `modules` | once at boot: stage0 on a slot, init on a RAM root | One process: nothing it reads comes from outside the image, and the kernel judges each module's signature. It loads nothing unless lockdown or `module.sig_enforce` is on; opens the list and every module beneath the module directory with symlinks refused; pledges to `CAP_SYS_MODULE` under seccomp (`finit_module`, read, write, close, exit); and closes the loader whatever happens, reading `kernel.modules_disabled` back to say so. |
| `net` | once at boot, for a static address | One process: its arguments come from the kernel command line and are parsed strictly. It opens its socket, then pledges to `CAP_NET_ADMIN` under seccomp allowing `ioctl` only for its five requests. A gateway outside the subnet gets a host route first. |
| `mount` | once per mount: init at boot, `commit`, the updater, `bite --cleanup` | One process: it reads only its arguments, then sets `no_new_privs` and keeps `CAP_SYS_ADMIN` alone under seccomp before asking anything of the kernel. One-way: mounts are built and restricted detached, and remounts are `mount_setattr(2)` with nothing to clear. Allowlisted types, options and targets; paths resolved without symlinks. |
| `update` | at boot and every 20 hours | Not yet: one process, as root, running apk and mkfs.erofs. It goes away when the updater installs signed releases instead of building ([design/verified-boot.md](../design/verified-boot.md), phase 3); the part that remains should fetch and verify unprivileged. |
| `status` | the demo form, every minute | Partly: grype runs as the grype user; the page writer runs as root. |

## Writing one

Start from `dhcp/dhcp.zig`: its `Filter` builds a seccomp allowlist,
`dropTo` gives up a process for good, and `landlock` confines writes. Test
what can be tested without a kernel (parsers, the filters' jumps, message
layouts), give the parser a fuzz target, and check the sandbox on a
running machine: `/proc/PID/status` should show the uid, `CapEff`,
`CapBnd`, `NoNewPrivs: 1` and `Seccomp: 2` you meant.
