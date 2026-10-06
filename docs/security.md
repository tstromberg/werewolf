# Security

werewolf assumes it will be attacked, and is built to have little to
attack, to make what is closed stay closed, and to come back from any
failure on an image that worked. This page says what is in place, what is
not yet, and how to check it on a running machine. Where it is going is in
[design/verified-boot.md](../design/verified-boot.md).

## Approach

- **Carry less.** Each form holds only what it needs. `minimal` is 20
  packages and listens on nothing; there is no systemd, no PAM in use, no
  compiler, no package manager outside `autoupdate`.
- **Close things for good.** What can be locked until reboot is locked at
  boot, before any service runs: the module loader, kernel lockdown,
  ptrace. Root cannot reopen them.
- **Nothing to keep.** The root is never written; `/data` is cache. A
  reboot returns the machine to its image, and losing `/data` costs a cold
  start.
- **Fail back, not forward.** A new image boots once and stays only if it
  proves itself; every failure ends on the slot that last worked.
- **Trust no one new.** Updates come from Wolfi and Alpine directly, checked
  against keys in the image. There is no build server and no signing key of
  ours.

## In place

### The image

| | |
| --- | --- |
| No setuid or setgid files | apko's `paths:` clear them from util-linux `mount` and PAM's `unix_chkpwd`; the updater clears any a new package brings |
| Few listeners | `minimal`, `disk`, `crypt`, `bitten`, `autoupdate`: none. `sshd`, `lima`: 22. `sshd-cloudflared`: 22 and an outbound tunnel |
| ssh | keys only (`PasswordAuthentication no`, `KbdInteractiveAuthentication no`, `UsePAM no`); root by key only; no X11 or agent forwarding; `LogLevel VERBOSE`. Host keys are made at each boot and never outlive the machine |
| Secrets | the config tar's contents go to `/run/config`, tmpfs, 0700. cloudflared's token travels in its environment, not argv. `data.key` is deleted once the volume is open |

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

Lockdown is raised by init through securityfs, not on the kernel command
line, so it holds however the machine was booted. Each refusal is in the
kernel log: `ptrace attach of "runit"[1] was attempted by …`, `Lockdown:
head: /dev/mem,kmem,port is restricted`.

### Storage

| | |
| --- | --- |
| The root | a RAM root, or on a bitten machine `root.erofs`, read-only, under a tmpfs overlay. Writes vanish at reboot |
| `/data` | cache only. On a disk or a bitten machine, `nosuid,nodev,noexec`; `crypt` puts it in LUKS2, keyed from the config, never from beside the disk. In RAM (forms without storage tools) it is plain tmpfs, like `/tmp` |
| The victim's filesystem | read-only at `/victim`; the few writers mount it separately |

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
it does not understand. `bite --cleanup` removes the distro, and with it
cloud-init's user-data, once werewolf has committed.

## Not yet

- **Any user can run what it writes** to `/tmp`, `/run`, `/dev/shm`, or a
  `/data` in RAM: Wolfi's busybox `mount` cannot set `noexec`.
- **root can write the running root** (the RAM root, or the overlay) and
  run what it writes, and can remount `/data` and `/victim`.
- **A bitten machine's kernel and stage0 are unchecked.** root can replace
  them, or GRUB's config, and keep them across reboots. Secure Boot is off,
  since Alpine's kernel is not signed for it.
- **Images are built on the machine** that runs them, so no signature on
  one could mean anything.
- **Scripts.** busybox `sh` is in every image and runs any script.
- **The host is trusted.** A hypervisor can change any guest.

Phases 2 to 5 of [the design](../design/verified-boot.md) close all but the
last two.

## Checking a machine

`make check` does this on every form ([testing.md](testing.md)). By hand,
as root, on the console (`make run` gives a root shell there) or over ssh:

| Check | Command | Expect |
| --- | --- | --- |
| Lockdown | `cat /sys/kernel/security/lockdown` | `none [integrity] confidentiality` |
| It stays up | `echo none >/sys/kernel/security/lockdown` | `Operation not permitted` |
| Module loader | `cat /proc/sys/kernel/modules_disabled` | `1` |
| ptrace | `cat /proc/sys/kernel/yama/ptrace_scope` | `3` |
| It stays off | `sysctl -w kernel.yama.ptrace_scope=0` | `Invalid argument` |
| Another process's memory | `cat /proc/1/mem` | `Permission denied` |
| Kernel memory | `head -c1 /dev/mem` | `Operation not permitted` |
| memfds | `cat /proc/sys/vm/memfd_noexec` | `2` |
| setuid and setgid files | `find / -xdev \( -perm -4000 -o -perm -2000 \) -type f` | nothing |
| Listeners | `netstat -ltn` | 22, or nothing |
| `/data` | `grep ' /data ' /proc/mounts` | on a disk, `nosuid,nodev,noexec` among the options |
| ssh | `sshd -T \| grep -iE '^(passwordauth\|kbdinteractive\|permitrootlogin\|usepam)'` | `no`, `no`, `prohibit-password`, `no` |

init also says it on the console: `werewolf: lockdown: integrity`.

## Tested

`make check` runs these as [test/checks](../test/checks) on every form and
on a slot, on every push, on x86_64 and arm64 ([testing.md](testing.md)). It
also holds each item under "Not yet" to being still open, so this page
cannot fall behind the machines.

By hand, on 2026-10-06, a bitten Debian 13 VM in Lima took the lockdown
image as an update would: installed in its other slot, booted once,
committed after 64 s, and became GRUB's default. Its updater then checked
Wolfi and Alpine under the new settings and found it current. An update
that builds a slot under them is not yet tested.
