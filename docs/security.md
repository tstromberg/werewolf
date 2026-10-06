# Security

werewolf assumes it will be attacked, and is built to have little to
attack, to make what is closed stay closed, and to come back from any
failure on an image that worked. This page says what is in place, what is
not yet, and how to check it on a running machine. Where it is going is in
[design/verified-boot.md](../design/verified-boot.md).

## Approach

- **Carry less.** Each form holds only what it needs. `minimal` is 10
  packages and listens on nothing; there is no systemd, no PAM in use, no
  compiler, no package manager outside `autoupdate`.
- **Close things for good.** What can be locked until reboot is locked at
  boot, before any service runs: the module loader, kernel lockdown,
  ptrace. Root cannot reopen them.
- **Keep only data.** The root is never written, so a reboot returns the
  machine to its image. What persists is data on `/data`, which nothing
  executes, and which init formats only while it is blank.
- **Fail back, not forward.** A new image boots once and stays only if it
  proves itself; every failure ends on the slot that last worked.
- **Separate and confine our own code.** werewolf's programs follow
  OpenBSD's practice: what reads untrusted input runs apart from what
  changes the machine, as its own user, chrooted, with no capabilities, and
  under a seccomp allowlist ([programs.md](programs.md)).
- **Trust no one new.** Updates come from Wolfi and Alpine directly, checked
  against keys in the image. There is no build server and no signing key of
  ours.

## In place

### The image

| | |
| --- | --- |
| No setuid or setgid files | apko's `paths:` clear them from PAM's `unix_chkpwd`, and from util-linux `mount` in stage0; the updater clears any a new package brings |
| Few listeners | `minimal`, `dhcp`, `disk`, `crypt`, `bitten`, `autoupdate`, `prod`: none. `sshd`, `prod-ssh`, `lima`: 22. `demo`: 80. Each form declares its ports in `/etc/werewolf/listen`, and `make check` fails on any other |
| ssh | keys only (`PasswordAuthentication no`, `KbdInteractiveAuthentication no`, `UsePAM no`); root by key only; no X11 or agent forwarding; `LogLevel VERBOSE`. Host keys are made at each boot and never outlive the machine |
| Secrets | the config tar's contents go to `/run/config`, tmpfs, 0700. `data.key` is deleted once the volume is open |

### Boot

init's stdin is `/dev/null`, so nothing can stall a boot waiting for input.
The kernel is told `init=/init`: a kernel whose `/init` will not run would
otherwise fall back to `/bin/sh`, a root shell on the console.

Before runit starts, init closes, for the life of the machine:

| | Stops | Undone by root? |
| --- | --- | --- |
| `kernel.modules_disabled=1` | loading any kernel code | no |
| lockdown at integrity | `kexec`, `/dev/mem`, unsigned modules | no: it only rises |
| `kernel.yama.ptrace_scope=3` | ptrace and `/proc/<pid>/mem`, so no process writes code into another | no |
| `vm.memfd_noexec=2` | running code from a memfd | yes: it binds non-root code and child namespaces, not root |
| `kernel.kptr_restrict=2`, `kernel.dmesg_restrict=1` | leaking kernel addresses | yes |
| `kernel.unprivileged_bpf_disabled=1` | BPF for non-root users | no |
| `net.ipv4.ip_forward=0` | routing through the machine | yes |
| `kernel.io_uring_disabled=2` | io_uring, a large kernel interface nothing here uses | yes |
| `kernel.sysrq=0` | the magic SysRq keys from a console; `/proc/sysrq-trigger`, which stage0's deadman uses, is not affected | yes |
| ICMP redirects, IPv4 and IPv6 | a neighbour rewriting the machine's routes; none are sent either | yes |
| `user.max_user_namespaces=0` | an ordinary user mounting its own filesystems (without `noexec`) in a private namespace, and the kernel code namespaces open to it | yes |
| `fs.protected_symlinks=1`, `protected_hardlinks=1`, `protected_fifos=2`, `protected_regular=2` | planting a link, FIFO or file in `/tmp` for a root process to follow or write | yes |
| `vm.mmap_rnd_bits` 33 (aarch64), 32 (x86_64) | guessing where a program's code and heap are: Alpine's defaults are 18 and 28 | yes |
| `vm.mmap_min_addr=65536` | mapping the page a kernel null-pointer bug would read | yes |
| `net.core.bpf_jit_harden=1` | users' socket and seccomp filters planting chosen machine code in the kernel (JIT spraying) | yes |
| `kernel.panic_on_oops=1`, and `kernel.panic=10` if the command line gave none | a kernel left wrong by a failed exploit running on for another try | yes |

None of these costs a program anything: a database or `../scan` runs as
fast with them as without.

Some hardening has no runtime switch, so it is on the kernel command line,
which the build writes from the form ([design/lockdown.md](../design/lockdown.md),
*Command line*): `debugfs=off`; `proc_mem.force_override=never`, so a
process cannot rewrite its own code through `/proc/self/mem`, as a shell
and `dd` do to run a program where nothing written may run; on x86_64
`ia32_emulation=0`, no 32-bit system calls; on aarch64 `kvm-arm.mode=none`,
since Alpine builds KVM into the kernel and starts it whenever a host lends
the guest EL2, which would let root reach the host's nested
virtualization. A form that runs virtual machines says so with an
allowance, `kvm`, and its guests still cannot nest (`qemu-host`).

Last, init seals PID 1, and nothing after it, root included, can undo
the seal before a reboot ([design/lockdown.md](../design/lockdown.md)):

| | Stops |
| --- | --- |
| A seccomp filter, which every process inherits | eBPF, perf, module and kexec calls, io_uring, userfaultfd, the kernel keyring, file handles, another process's memory, `modify_ldt` and I/O ports, and old unused calls: 24 system calls on aarch64, answered `ENOSYS`; any other architecture's call, on aarch64 a 32-bit program's, ends the process |
| The capability bounding set | loading kernel code (`CAP_SYS_MODULE`, `CAP_BPF`, `CAP_PERFMON`), hardware and `/dev/mem` (`CAP_SYS_RAWIO`), tracing (`CAP_SYS_PTRACE`), device files (`CAP_MKNOD`) and what nothing here uses; once fence has set the network policy, `CAP_NET_ADMIN` and `CAP_NET_RAW` too, but on forms that allow them, as `dhcp` and those built on it do for their DHCP client |

The filter costs something, by choice: a process under any filter enters
each system call by the kernel's slower path. On werewolf's kernel that is
about 25 ns a call, measured at 125 against 150 ns for `getpid`: 2–5% of a
small `read` or `write`, a fraction of a percent of a CPU for a busy
database, and nothing for work that seldom calls the kernel. Every program
in a Docker container pays the same already. The filter's length costs
nothing, so what the seal adds later is free (*What the seal costs*).

What root can undo, no one else can: each guards against ordinary users,
and against root only once services stop running as root.

Lockdown is raised through securityfs, not on the kernel command line, so
it holds however the machine was booted, and it is raised before any
module loads: by stage0 on a slot, by init on a RAM root. So the kernel
loads only modules signed by the key it was built with, Alpine's, and
refuses the rest rather than loading them and noting a taint. Each refusal
is in the kernel log: `ptrace attach of "runit"[1] was attempted by …`, `Lockdown:
head: /dev/mem,kmem,port is restricted`.

### Storage

| | |
| --- | --- |
| The root | `root.erofs`, mounted read-only at `/` by stage0 on every form: from the initramfs, or on a bitten machine from its slot. No overlay: what the system writes (accounts, keys, hostname, `resolv.conf`, runit's state) lives in `/run`, through links |
| Memory filesystems | `/tmp`, `/var/tmp`, `/run` and `/dev/shm` are `nosuid,nodev,noexec`, as are `/proc`, `/sys` and securityfs, and `/dev` and `/dev/pts` `nosuid,noexec`, so nothing written to memory runs. Only `/tmp` and `/dev/shm` are writable by everyone; `/run` is root's. `/proc` is `hidepid=invisible`: each user sees only its own processes |
| `/data` | the machine's data. On a disk or a bitten machine, `nosuid,nodev,noexec`; `crypt` puts it in LUKS2, keyed from the config, never from beside the disk. A disk init has used is never formatted again: one it cannot use (the wrong type, no key or the wrong one, damage `e2fsck -p` will not repair) is left alone, `/data` is an empty read-only tmpfs, and a new slot will not commit. In RAM (forms without storage tools) it is tmpfs, `nosuid,nodev,noexec` like `/tmp` |
| The victim's filesystem | read-only at `/victim`; the few writers mount it separately |

### Mounts

Everything werewolf mounts goes through its own tool,
[mount/mount.zig](../mount/mount.zig), installed as `/usr/lib/werewolf/mount`
in every form. util-linux's `mount` is in none of them: in Wolfi it brings
SELinux's libraries, and busybox's cannot set `nosuid`, `nodev` or `noexec`.

- **One-way, and the kernel holds it to that.** A new mount is built
  detached and gets `nosuid`, `noexec` and, but for device filesystems,
  `nodev` before it is attached; a bind is cloned and restricted the same
  way. A remount is `mount_setattr(2)` with nothing to clear, so it cannot
  lift `ro`, `nosuid`, `nodev`, `noexec` or `nosymfollow` whatever it is
  given. `suid`, `dev`, `exec`, and `rw` on a remount, are refused.
- **Allowlists.** Only werewolf's filesystems (proc, sysfs, securityfs,
  devtmpfs, devpts, tmpfs, ext4, xfs, btrfs, iso9660, vfat), only the options each
  is given, with their values checked, and only under `/proc`, `/sys`,
  `/dev`, `/run`, `/tmp`, `/data`, `/victim` and `/mnt`: nothing is mounted
  over `/etc`, `/usr` or the root.
- **No symlinks.** Paths are absolute and clean, and resolved with symlinks
  refused, so a link planted in `/tmp` cannot steer a mount.
- **Pledged.** Before it asks the kernel for anything it sets
  `no_new_privs`, drops every capability but `CAP_SYS_ADMIN`, and installs a
  seccomp filter of the dozen system calls it makes. Anything else kills it.
- **Quiet.** No environment, no files read, nothing printed on success; on
  failure, one line with the kernel's own reason.

It is a tool that cannot loosen a mount, not a lock: root can run a program
of its own that calls `mount(2)` (*Not yet*).

### Updates and slots

The updater installs nothing apk has not verified against keys in the
image. Alpine's kernel is checked against Alpine's keys, which matched byte
for byte at alpinelinux.org and in Alpine's git. Every update writes a
report with the sha256 of each source it read, so an auditor can derive the
same CVE list ([updater.md](updater.md)).

A new slot gets one boot. `panic=10` and `softlockup_panic=1` turn a crash
or a lockup into a reboot onto the previous slot, and stage0's deadman
reboots a slot that has not committed in ten minutes ([bite.md](bite.md)).

### bite

bite removes nothing and repartitions nothing, and refuses rather than
strand a machine: Secure Boot on, a disk or NIC it cannot drive, a layout
it does not understand. `bite-cleanup` removes the distro, and with it
cloud-init's user-data, once werewolf has committed.

## Not yet

- **root can remount.** The root is read-only, and everywhere writable
  is `noexec`, but a process running as root can call mount(2) itself and
  make anything writable or `exec`, `/` included, and can undo the sysctls
  marked "yes" above. Where the form has a shell (sshd, lima, prod-ssh, and
  `DEV=1` builds) that takes no more than a script and busybox's `mount`.
  Mount options and sysctls bind everyone else; IPE (phase 4 of the design)
  and services that do not run as root are what will bind root.
- **A bitten machine's kernel and stage0 are unchecked.** root can replace
  them, or GRUB's config, and keep them across reboots. Secure Boot is off,
  since Alpine's kernel is not signed for it.
- **Images are built on the machine** that runs them, so no signature on
  one could mean anything.
- **Scripts, where there is a shell.** The forms that log people in (sshd,
  lima, prod-ssh) carry busybox, whose `sh` runs any script. The others,
  minimal and prod among them, have no shell or interpreter at all, and
  `posture` checks that they do not.
- **Machines bitten before 2026-10-06 keep bite's old command line.**
  bite's GRUB entries now read each slot's kernel arguments from GRUB's
  environment, which the updater sets for each slot it installs; entries
  written before then hold the arguments of that day, until bitten again.
  posture's `kernel-cmdline` names what such a machine lacks.
- **The host is trusted.** A hypervisor can change any guest.

Phases 2 to 5 of [the design](../design/verified-boot.md) close all but the
last two.

## Not done, by choice

Nothing here may slow what the machines run: a database, or `../scan`.
The one exception is the seal, whose 25 ns a system call buys what nothing
else can (*Boot*, above).
`posture` checks these only when asked, with `--extended`. What costs
nothing is done in their place.

- **Freed memory wiped** (`init_on_free`): allocation-heavy work pays for
  it. Done instead, at no cost: memory cleared as it is handed out
  (`init_on_alloc`, the kernel's default), kernel caches kept apart
  (`slab_nomerge`), pages handed out shuffled, and the kernel stack's
  offset randomized (the kernel's default).
- **Forced CPU mitigations** (Speculative Store Bypass): every process
  would pay, and whether the flaw is there is the host CPU's; a guest under
  a hypervisor that hides the control cannot have it at all. Done instead:
  werewolf's own long-lived programs (dhcp, cloud, the updater, sshd and its
  sessions) ask for it for themselves, where the CPU allows.
- **Reverse-path filtering** (`rp_filter`), strict or loose: the kernel
  checks a packet's source by looking up the reply as root sending it, so
  under fence's per-user rules it would drop the replies to every
  connection a service makes as itself (updates, cloud config, grype's
  database). fence already takes arriving traffic only to served ports, or
  from the ports and protocols the machine connects to, and logs impossible
  sources.
- **IPv6 router advertisements ignored**: IPv6 is on, and they are how most
  networks give it a route. Done instead: taken on the machine's NIC alone,
  and only for a route and up to four addresses, so a rogue router cannot
  rank itself above the real one, add a route to steal one destination, or
  flood the NIC with addresses (`network-ipv6-ra-limits`).

## Checking a machine

`make check` does this on every form ([testing.md](testing.md)). By hand,
as root, on the console (`make run` gives a root shell there) or over ssh:

| Check | Command | Expect |
| --- | --- | --- |
| Lockdown | `cat /sys/kernel/security/lockdown` | `none [integrity] confidentiality` |
| It stays up | `echo none >/sys/kernel/security/lockdown` | `Operation not permitted` |
| Module loader | `cat /proc/sys/kernel/modules_disabled` | `1` |
| ptrace | `cat /proc/sys/kernel/yama/ptrace_scope` | `3` |
| The seal | `grep Seccomp: /proc/1/status` | `Seccomp: 2` |
| It stays off | `sysctl -w kernel.yama.ptrace_scope=0` | `Invalid argument` |
| Another process's memory | `cat /proc/1/mem` | `Permission denied` |
| Kernel memory | `head -c1 /dev/mem` | `Operation not permitted` |
| memfds | `cat /proc/sys/vm/memfd_noexec` | `2` |
| setuid and setgid files | `find / -xdev \( -perm -4000 -o -perm -2000 \) -type f` | nothing |
| Listeners | `netstat -ltn` | 22, or nothing |
| `/data` | `grep ' /data ' /proc/mounts` | `nosuid,nodev,noexec` among the options |
| Memory filesystems | `grep -E ' /(var/)?(tmp\|run\|dev/shm) ' /proc/mounts` | `nosuid,nodev,noexec` on each |
| `/run` is root's | `chpst -u nobody touch /run/x` | `Permission denied` |
| User namespaces | `cat /proc/sys/user/max_user_namespaces` | `0` |
| Planted symlinks | `chpst -u nobody ln -s /run/x /tmp/x; echo hi >/tmp/x` | `Permission denied` |
| Other users' processes | `chpst -u nobody ls /proc` | no numbered entries but its own |
| ssh | `sshd -T \| grep -iE '^(passwordauth\|kbdinteractive\|permitrootlogin\|usepam)'` | `no`, `no`, `prohibit-password`, `no` |

init also says it on the console: `werewolf: lockdown: integrity`.

## Tested

`make check` runs these as [test/checks](../test/checks) on every form and
on a slot, on every push, on x86_64 and arm64 ([testing.md](testing.md)),
trying each attack as `nobody` where an ordinary user is the attacker. It
boots every form a second time on the disks the first boot left, to show
`/data` comes back as it was left; boots `crypt` without a key, to show it
refuses; and offers init and stage0 a module with its signature cut off,
to show the kernel refuses that too. It also holds each item under "Not yet" to being still open, so
this page cannot fall behind the machines.

By hand, on 2026-10-06, a bitten Debian 13 VM in Lima took the lockdown
image as an update would: installed in its other slot, booted once,
committed after 64 s, and became GRUB's default. Its updater then checked
Wolfi and Alpine under the new settings and found it current. An update
that builds a slot under them is not yet tested.
