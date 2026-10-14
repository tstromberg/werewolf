# Security

Werewolf assumes a service will be compromised. It limits what that
service can read, change, execute and reach over the network. Gaining root
does not remove those limits: the kernel enforces them, and the process
cannot turn them off. Some boot helpers hold broader authority and remain
part of the trusted code.

This page describes machines with security restrictions enabled. Development
images can log some otherwise-denied system calls instead of blocking them
(learning mode), and can provide a console shell.

## From boot to a running service

Before starting services, init (process 1) sets the kernel protections and
installs the seal, a seccomp filter that limits system calls. It then starts
fence, which sets network and file-access rules, gives up kernel privileges
called capabilities, and becomes runit, the service supervisor. Services and
login sessions inherit these restrictions. A process can narrow them further,
but cannot remove them.

The seal denies system calls by default. It allows calls needed by Werewolf's
own programs and by services. Services declare named groups of allowed calls,
called promises, in their form: the configuration describing a VM's packages,
services and permissions. New system calls stay blocked until the policy names
them. The leash program applies each service's promises, user account, file
permissions and port rules. Extra capabilities must also be declared in the form.

System-call and file-access rules serve different purposes. Seccomp decides whether a process
may make a call; Landlock decides which files and TCP ports it may reach.
For example, a service may need `openat` to read configuration, but that
does not give it access to every file. Werewolf's own programs also separate
untrusted input from privileged work and give up privileges they no longer
need ([programs](programs.md)).

If the seal or fence cannot be applied, init does not start services.
Init exits, causing the kernel to panic and stop the machine.

## Keeping kernel protections set

Some kernel protections are one-way. Once module loading is disabled,
root cannot load another module. Kernel lockdown, which restricts access to
kernel memory and hardware, cannot be lowered from confidentiality mode.
Setting `kernel.yama.ptrace_scope=3` prevents tracing another
process, and `kernel.unprivileged_bpf_disabled=1` cannot be reset during
that boot.

Other settings would normally remain writable by root. Fence closes that
route: processes subject to its Landlock rules cannot open `/proc/sys` files for
writing, even as root. Settings such as `vm.memfd_noexec`,
`kernel.kptr_restrict` and `kernel.io_uring_disabled` therefore stay set.
The same rules deny writes to `/sys` and access to disks and devices
the policy does not name.

Sysctls are kernel settings normally changed by writing files in `/proc/sys`.
There is no `sysctl` promise. The file-access promises `rpath` and `wpath` cannot
override fence. The old `_sysctl(2)` call was removed in Linux 5.5; no promise allows
it. An alternate interface still needs its own restriction: `syslog(2)`
can change `kernel.printk` without opening a file. The seal permits reading
the log through that call, but refuses console changes and log clearing.

Denying new opens does not revoke access through an already-open file descriptor.
Init closes each sysctl descriptor after writing it. New boot code must do the
same: passing an open descriptor to a confined process would preserve its
earlier access.

The protections reduce both the kernel code an attacker can reach and
the information available to an exploit. The seal refuses eBPF, perf,
module and kexec calls, io_uring, userfaultfd, kernel keyrings and the
`process_vm_*` calls for another process's memory. It also checks arguments
to close interfaces such as AF_ALG, kernel TLS, notification pipes and new
seccomp listeners. Calls using an unexpected architecture or x86's x32 calling
convention kill the caller.

Kernel addresses are hidden, kernel logs require privilege, and user
namespaces are disabled. Address randomization and a minimum mapping
address make memory exploits harder. The command line disables debugfs,
forced writes through `/proc/self/mem`, and, on x86_64, 32-bit syscall
emulation. IPv6 and KVM are disabled unless the form allows them. The
[settings in init](../cmd/init/kernel.zig) and
[lockdown design](design/lockdown.md) give the exact controls.

A kernel fault (an oops) or the first warning after the warning limit is set
causes a panic and reboot. This stops a kernel left damaged by a failed exploit
from continuing to run. It also means an attacker who can provoke such a
warning can cause a denial of service.

The kernel logs blocked program execution, file access and service system calls.
The audit configuration is locked, and init removes the capability that controls
it. Notices reach the serial console so the host can retain them outside
the guest. The seal-watch program separately reports calls refused by the seal.

## The helpers outside fence

A few programs must start before fence and do not inherit its restrictions.
They need separate limits, and their security matters to the whole
machine.

The mount broker keeps `CAP_SYS_ADMIN` to mount filesystems during updates,
acceptance of a trial boot, and shutdown. It accepts fixed requests, not
arbitrary paths or mount options. Its seccomp filter limits
the calls it can make, but it remains privileged code outside Landlock.
Code execution inside the broker would cross the boundary that confines
services. Any root process can ask for its supported mounts, including
filesystems holding boot files
([mount broker](../cmd/mount-broker/README.md)).

The DHCP renewal process keeps `CAP_NET_ADMIN`, but its Landlock rules limit
writes to its state directory. Seal-watch gives up root and installs a filter
that prevents further file opens. Stage0, the early boot program, leaves a
watchdog called deadman that can reboot a trial image not yet accepted as healthy.

Programs started by the kernel itself also sit outside init's seal.
Init empties `kernel.modprobe` and `kernel.hotplug`, and limits kernel
helpers to `CAP_SYS_BOOT`. Fence prevents its descendants from rewriting
those sysctls to arrange for another program to run.

## What an attacker can keep or execute

The root filesystem uses EROFS, a read-only format. The kernel's dm-verity
checks each block against its expected hash when reading it; changed blocks
fail to read. There is no writable layer over the image.
The expected hash comes from stage0, so the check depends on the integrity
of the boot chain.

Writable mounts refuse execution and ignore setuid bits. They also ignore
device files, except on device filesystems. Fence permits execution beneath
`/usr` and `/oci`; leash restricts each service further. The image contains
no setuid or setgid files, and init removes capabilities for loading kernel
code, accessing hardware, tracing processes and creating device nodes.

Memory-Deny-Write-Execute prevents memory mappings that are both writable and
executable, and adding execute permission to mappings that lacked it. Processes
inherit it unless the form allows `jit` (just-in-time compilation, which
generates machine code at runtime). Such forms give up that protection.

These controls do not make an interpreter's input trustworthy. A shell or
runtime can read and execute a script from writable storage. Mount flags
and Landlock also do not authenticate every executable mapping. Images built with
the optional [Integrity Policy Enforcement (IPE)](design/ipe.md) feature restrict
native executables and mappings to one verified filesystem named by a signed
policy, including for boot helpers. IPE does not authenticate scripts.

Persistent state lives on `/data`, encrypted with LUKS2 when a key is
supplied. Init formats only blank storage. If it cannot open or repair an
existing volume, it leaves it untouched, mounts an empty read-only tmpfs
at `/data`, and prevents the trial image from being accepted as healthy.

Shared temporary directories use link and file protections. Writable
mounts refuse symlink traversal with `nosymfollow`, except `/data` and
kernel-managed filesystems. Building update images needs links on `/data`, so
code walking that tree must reject links that would give access outside
its permitted files.

`/proc` hides other users' processes. Root owns `/run`; `/tmp` and `/dev/shm`
are shared. Boot secrets are unpacked into `/run/config`, accessible only to
root (mode 0700). The data key is removed after the encrypted volume is opened.

## Reaching other machines

Each form declares which ports services listen on and what traffic they send.
Fence denies undeclared traffic in both directions; Landlock also restricts
TCP ports. The network policy does not track connections and usually names ports
rather than destination hosts. Permission to connect to HTTPS therefore does not
confine a process to one server ([fence](design/fence.md)).

Fence drops `CAP_SYS_ADMIN`, `CAP_NET_ADMIN` and `CAP_NET_RAW`. Forms may
explicitly retain the network capabilities for packet capture or network
administration. Those allowances weaken the network boundary: a process
with them can reconfigure networking or send traffic below fence's rules.

`minimal` and `prod` have no listening services. Where SSH is present, it defaults
to hardware security keys requiring a touch, with no passwords or forwarding.
`playground` accepts ordinary keys too. Each form's configuration and posture
results show these differences.

## Updates and the next boot

Package updates verify repository signatures before composing an image.
Published releases have signed manifests. IPE machines configured to trust a
signed update channel install complete [signed system images](design/prebuilt-images.md),
with signing keys kept off the guest. Images assembled locally have no release signature.

Updates use two slots, each holding a system image. A new image gets one boot
attempt; committing marks it healthy and selects it for future boots. A panic,
failed boot or the deadman watchdog's timeout returns to the previous slot.
This recovers the system image; persistent data is not rolled back
([updates](updater.md), [releases](releases.md)).

Authentication must extend through the boot chain to protect that next
boot. Firmware must verify bootloader and kernel bundle signatures against
trusted keys. These bundles are called unified kernel images (UKIs).
An unchecked kernel, stage0 or command line can defeat these restrictions even if the root image was signed.

The updater checks image version numbers, but changing the boot configuration
can still select an older signed image. Preventing this requires a minimum
accepted version protected by a Trusted Platform Module (TPM); that protection
is unfinished ([verified boot](design/verified-boot.md)).

These protections operate inside the guest. The hypervisor can change its
memory and boot input and must be trusted.

## Not done, by choice

Some additional controls have costs or conflict with the network policy.
Freed memory is not wiped because of the performance cost; memory is
cleared on allocation, slab caches stay separate and page allocation is
shuffled. CPU vulnerability mitigations are not forced for every process.
Werewolf's long-lived programs request them where the host supports them.

Reverse-path filtering conflicts with fence's per-user routing. Forms
allowing IPv6 accept constrained router advertisements because many
networks need them to obtain a route. `posture --extended` reports these
choices.

The seal also has a cost. On an M4 Max with Alpine's 6.18 kernel,
`getpid` took about 150 ns with a filter versus 125 ns without. That
measurement does not predict an application's total overhead.

## Checking a machine

Run `/usr/lib/werewolf/posture --json` as root to test the machine's protections.
The posture program also runs each boot and saves `/run/werewolf/posture.json`.
A setting's current value alone does not prove that an attacker cannot
change it.

The `files-system-writes` check tries both write-only and read/write opens
on sysctls under `kernel`, `vm`, `user`, `fs` and `net`, plus `/sys` and a
disk. It writes nothing. Existing targets must return `EACCES` (permission denied), and
`kernel.printk` must exist. The `kernel-log-control` check also tries
`syslog(SYSLOG_ACTION_CONSOLE_LEVEL)` with the current valid level. The call
must be refused; using the current level keeps the probe safe on an
unprotected machine.

Other checks test executable mounts, anonymous memory-backed files (`memfd`),
the seal, capabilities, network restrictions and audit. `--attack` tries service escapes.
`make check` boots images and checks their posture; each form declares its
expected weaknesses ([posture](posture.md), [testing](testing.md)).

The [sysctl review](audit/muse-sysctl-2026-10-12.md) records the reproduced
`syslog` bypass, its fix, and the tested limits of this boundary.
