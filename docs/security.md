# Security

werewolf limits what a compromised process can reach, including a process
running as root. The kernel enforces these limits. Rebooting restores the
image; data persists on `/data`. The host and the boot chain remain part of
the trust boundary.

## In place

### Boot

Before starting services, init sets the kernel protections, installs the
seccomp seal, and execs fence. Fence applies Landlock, drops capabilities,
and becomes runit. Services and login sessions inherit these restrictions
and cannot remove them. A failed seal or fence ends PID 1 and panics the
kernel. On a slot, the next boot falls back to the last working image.

Some protections are one-way even without fence: disabling module loading,
raising lockdown to confidentiality, setting `kernel.yama.ptrace_scope=3`
and `kernel.unprivileged_bpf_disabled=1`. Others depend on fence to prevent
later changes.

**Root cannot open `/proc/sys` files for writing after fence.** This covers
settings the kernel otherwise lets root lower, such as `vm.memfd_noexec`,
`kernel.kptr_restrict` and `kernel.io_uring_disabled`. Fence also denies
writes to `/sys` and access to disks and unnamed devices.

Linux sysctl changes use ordinary file operations on `/proc/sys`. The old
`_sysctl(2)` syscall was removed in Linux 5.5 and no pledge permits it.
There is no `sysctl` promise: seccomp filters calls; Landlock restricts the
files those calls reach. Neither `rpath` nor `wpath` grants a service access
outside fence's domain. The seal also restricts `syslog(2)` to reading the
log: root cannot use it to change `kernel.printk` or clear the log.

Landlock checks file access when a file is opened. It does not revoke
writable descriptors opened beforehand. Init closes its sysctl descriptors
after each write. Boot helpers started before fence have separate limits:
the mount broker retains `CAP_SYS_ADMIN`; DHCP renewal keeps
`CAP_NET_ADMIN` and confines writes to its state directory; seal-watch
drops root and uses a narrow filter. Stage0's deadman keeps the authority
to reboot an uncommitted slot. These helpers do not inherit fence's domain.

| Protection | Effect |
| --- | --- |
| Module loader closed; confidentiality lockdown | No new modules, unsigned kexec, or unrestricted kernel memory access |
| `kernel.yama.ptrace_scope=3` | No ptrace or access to another process's memory through `/proc/PID/mem` |
| `vm.memfd_noexec=2` | No executable memfds |
| `kernel.kptr_restrict=2`, `kernel.dmesg_restrict=1` | Kernel addresses hidden; kernel log restricted to privileged readers |
| `kernel.io_uring_disabled=2`, `user.max_user_namespaces=0` | No io_uring or new user namespaces |
| `kernel.sysrq=0`, `dev.tty.legacy_tiocsti=0` | No console SysRq keys or legacy terminal input injection; the deadman can still use `sysrq-trigger` |
| `fs.protected_*` | Symlink, hard-link, FIFO and regular-file protections in shared directories |
| Full address randomization, `vm.mmap_min_addr=65536` | Harder address guessing; no mappings in the first 64 KiB |
| `kernel.panic_on_oops=1`, `kernel.warn_limit=1` | An oops or the first subsequent kernel warning panics; a nonzero panic timeout reboots |
| Memory-Deny-Write-Execute | No writable executable mappings or later execution of written memory; inherited unless the form allows `jit` |
| Locked audit rules; console loglevel 6 | Refused execs, Landlock accesses and service syscalls reach the kernel log and serial console |

The command line disables debugfs, forced writes through `/proc/self/mem`,
and, on x86_64, 32-bit syscall emulation. IPv6 and KVM are disabled unless
the form allows them. Init refuses an invalid command line or a required
kernel protection it cannot apply. See [lockdown](design/lockdown.md) and
[init's settings](../cmd/init/kernel.zig).

### Calls, capabilities and services

The machine seal allows the union of werewolf's base promises and the
services' pledges. Unlisted calls are refused, including new kernel calls.
No promise allows eBPF, perf, module loading, kexec, io_uring, userfaultfd,
kernel keyrings or another process's memory. Foreign syscall architectures
and x32 calls kill the caller. Argument checks close additional interfaces,
including AF_ALG, kernel TLS, notification pipes and seccomp listeners.

Init drops capabilities for loading kernel code, accessing hardware,
tracing, creating device nodes and controlling audit. Fence drops
`CAP_SYS_ADMIN`, `CAP_NET_ADMIN` and `CAP_NET_RAW`; forms may explicitly
retain the network capabilities. Packet capture and network administration
therefore weaken the network boundary on those forms.

Leash gives each service its own user, filesystem rules, port rules and
pledge filter. Service declarations name any capabilities retained.
Werewolf's programs separate untrusted input from privileged operations
and narrow their own privileges ([programs](programs.md)).

Fence's routing policy denies undeclared traffic in both directions.
Landlock restricts TCP bind and connect ports. The policy is stateless and
usually names ports rather than destination hosts; a permitted HTTPS
connection is not limited to one server ([fence](design/fence.md)).

The image has no setuid or setgid files. Forms declare their listeners;
`minimal` and `prod` have none. SSH defaults to touched security keys, with
no passwords or forwarding. `playground` accepts ordinary keys too.

### Files and mounts

The root is read-only EROFS, verified block by block with dm-verity. A
changed block fails to read. Its expected hash comes from stage0, whose
authenticity depends on the boot chain. There is no writable root overlay.

Writable mounts are `nosuid,nodev,noexec`, except device filesystems need
device access. Fence permits writes only to declared writable trees and
devices. It permits execution beneath `/usr` and `/oci`; leash narrows this
for each service. Mount flags and Landlock alone do not authenticate every
executable mapping. Opt-in [IPE builds](design/ipe.md) enforce one signed
verity root for native executables and mappings, including boot helpers.

`/proc` uses `hidepid=invisible`. Writable mounts use `nosymfollow` except
`/data` and kernel-managed filesystems. `/run` is root's; `/tmp` and
`/dev/shm` are shared. Secrets are unpacked into `/run/config`, mode 0700.
The data key is removed after opening the encrypted volume.

Persistent `/data` uses LUKS2 when given a key. Init formats only blank
storage. An existing volume it cannot open or repair is left untouched;
`/data` becomes an empty read-only tmpfs and the slot cannot commit.

After fence, mounting requires the [mount broker](../cmd/mount-broker/README.md).
It accepts fixed requests for boot, slot and shutdown work, never arbitrary
paths or mount options. Mounts are restricted before attachment. Root can
still ask for these mounts; the broker is part of the trusted code.

### Updates

Package updates verify repository signatures before composing a new image.
Published releases have signed manifests. Enrolled IPE machines install
complete [signed slot bundles](design/prebuilt-images.md); signing keys
stay off the guest. Locally composed images have no release signature.

A new slot gets one boot attempt and stays selected only after committing.
A panic, failed boot or the deadman's timeout returns to the previous
slot. Persistent data is not rolled back. See [updates](updater.md) and
[releases](releases.md).

## Not yet

- **Authenticated boot on every deployment.** Signed loaders and UKIs
  require firmware enforcement and enrolled keys. Bite's existing GRUB
  path remains mutable. A signed image alone does not protect an unchecked
  kernel, stage0 or command line. Posture reports the actual boot state.
- **Hardware rollback protection.** Update serial checks do not prevent
  booting an older signed image through mutable boot state. A protected TPM
  floor remains necessary ([verified boot](design/verified-boot.md)).
- **Broker access restricted by caller purpose.** Any root process can
  request its supported mounts, including filesystems holding boot files.
- **Scripts and JIT input.** An interpreter can execute writable input.
  Forms with shells or runtimes retain that exposure; `jit` also leaves
  Memory-Deny-Write-Execute off. IPE does not authenticate scripts.
- **Links on `/data`.** Package assembly needs them. Code walking data
  must refuse links where following one would cross a trust boundary.
- **Kernel-started helpers.** They do not inherit PID 1's seal. Init
  empties `kernel.modprobe` and `kernel.hotplug`, and bounds helpers to
  `CAP_SYS_BOOT`; fence prevents later writes to their sysctls.
- **Old bite installations.** GRUB entries from before 2026-10-06 retain
  their original command line until bitten again. `kernel-cmdline` detects
  missing settings.
- **The host.** A hypervisor can change a guest's memory or boot input.

## Not done, by choice

`posture --extended` reports these additional controls:

- Wiping freed memory adds allocation overhead. Memory is cleared on
  allocation; slab caches stay separate and page allocation is shuffled.
- Forced CPU mitigations can slow workloads and depend on host support.
  Werewolf's long-lived programs request their own where available.
- Reverse-path filtering conflicts with fence's per-user routing rules.
- Forms allowing IPv6 accept constrained router advertisements because
  many networks need them for a route.

Seccomp has a measured cost: on an M4 Max with Alpine's 6.18 kernel,
`getpid` took about 150 ns with a filter versus 125 ns without. This is a
syscall benchmark, not a guarantee about application overhead.

## Checking a machine

Run `/usr/lib/werewolf/posture --json` as root. It also runs each boot and
saves `/run/werewolf/posture.json`. A setting's current value alone does
not prove that it cannot change.

- `files-system-writes` tries `O_WRONLY` and `O_RDWR` on sysctls under
  `kernel`, `vm`, `user`, `fs` and `net`, plus sysfs and a disk. It writes
  nothing. Existing targets must return `EACCES`; `kernel.printk` must exist.
- `kernel-log-control` tries `syslog(SYSLOG_ACTION_CONSOLE_LEVEL)` with the
  current valid level. It must be refused, so the probe detects the
  alternate interface without lowering logging on an unprotected machine.
- Other checks test executable mounts, memfds, the seal, capabilities,
  network restrictions and audit. `--attack` adds service escape probes.

`make check` boots images and checks their posture; form declarations name
expected weaknesses. See [posture](posture.md) and [testing](testing.md).
