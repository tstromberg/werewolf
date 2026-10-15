# Security

Werewolf assumes a service will be compromised. It limits what that
service can read, change, execute and reach over the network, and root
does not lift those limits: the kernel enforces them. A few boot helpers
hold more authority and remain trusted code. This page describes a
machine with every protection ([a machine without
some](#protections-a-machine-can-be-made-without)).

## From boot to a running service

init (process 1) sets the kernel protections and installs the seal, a
seccomp filter that refuses every system call no promise names
([lib/seal.zig](../lib/seal.zig)). It then starts fence, which sets the
network and file-access rules, drops capabilities, and becomes runit, the
service supervisor. Services and logins inherit these restrictions and
can narrow them, never lift them. If the seal or fence cannot be
applied, init exits and the kernel panics.

A service declares in its form the promises (named groups of system
calls) it needs, its user, its files and its ports, and leash applies
them ([pledge.md](design/pledge.md)); a new system call stays refused
until a promise names it. Seccomp decides whether a process may make a
call, Landlock which files and TCP ports it may reach. Werewolf's own
programs are privilege-separated ([programs.md](programs.md)).

## Keeping kernel protections set

Some protections are one-way for the boot: the module loader closed,
lockdown in confidentiality mode, `kernel.yama.ptrace_scope=3` and
`kernel.unprivileged_bpf_disabled=1` cannot be lowered, by root either.
The rest would stay writable by root, so fence closes the route: under
its Landlock rules no process can open a file in `/proc/sys` for writing,
write `/sys`, or open a disk or device the policy does not name; no
promise overrides that. `syslog(2)` can set `kernel.printk` without a
file, so the seal lets it read the log and refuses the rest. A
descriptor opened before confinement keeps its access, so init closes
each sysctl file after writing it.

The seal refuses eBPF, perf, module and kexec calls, io_uring,
userfaultfd, kernel keyrings and the `process_vm_*` calls, and checks
arguments to close AF_ALG, kernel TLS, notification pipes and new seccomp
listeners; a call in another architecture, or x86's x32 convention,
kills the caller. User namespaces are off; the command line disables
debugfs, forced writes through `/proc/self/mem` and, on x86_64, 32-bit
emulation; IPv6 and KVM are off unless the form allows them. An oops, or
a warning once the limit is set, panics and reboots: a damaged kernel
does not run on, at the price of a denial of service.
[cmd/init/kernel.zig](../cmd/init/kernel.zig) holds every setting,
[lockdown.md](design/lockdown.md) the reasoning, and the
[survey](cve-mitigation-survey.md) what each stops.

The kernel logs refused execs, file access and service system calls; the
audit configuration is locked, and init drops the capability that
controls it. Notices reach the serial console, so the host keeps them
outside the guest. seal-watch reports what the seal refuses.

## The helpers outside fence

The mount broker keeps `CAP_SYS_ADMIN` to mount during updates, slot
commits and shutdown. It takes fixed requests, not paths or options,
lends no mount, and answers only the updater, slot-keep and runit's
shutdown stage, each through a descriptor init gave it. It is privileged
code outside Landlock: code execution in it crosses the boundary that
confines services ([cmd/mount-broker/README.md](../cmd/mount-broker/README.md)).
The DHCP renewal keeps `CAP_NET_ADMIN`, with Landlock on its writes;
seal-watch drops root and refuses itself further opens; stage0 leaves
deadman, a watchdog that reboots a trial slot not yet committed. Helpers
the kernel starts itself sit outside init's seal, so init empties
`kernel.modprobe` and `kernel.hotplug` and limits them to `CAP_SYS_BOOT`.

## What an attacker can keep or execute

The root is EROFS, read-only, with no writable layer, and dm-verity
checks each block as it is read; the expected hash comes from stage0, so
this rests on the boot chain ([verified-boot.md](design/verified-boot.md)).
Writable mounts refuse execution, setuid bits and, outside device
filesystems, device files. Fence permits execution beneath `/usr` and
`/oci`; leash narrows each service further. The image has no setuid or
setgid file, and init drops the capabilities for loading kernel code,
reaching hardware, tracing and making device nodes.
Memory-Deny-Write-Execute refuses a mapping both writable and executable
in every process, unless the form allows `jit`. None of this makes an
interpreter's input trustworthy: a runtime can run a script from
writable storage. Images built with [IPE](design/ipe.md) hold native
executables and mappings to one verified filesystem named by a signed
policy; IPE does not authenticate scripts either.

Persistent state lives on `/data`, LUKS2 when a key is supplied. init
formats only blank storage; a volume it cannot open is left untouched,
`/data` becomes an empty read-only tmpfs, and the trial slot cannot
commit. Writable mounts refuse symlink traversal (`nosymfollow`) except
`/data`, which update builds need links on, so code walking it must
refuse links that lead outside its permitted files. `/proc` hides other
users' processes. Boot secrets are unpacked into `/run/config`, root's
alone; the data key is removed once the volume is open.

## Reaching other machines

Each form declares the ports its services listen on and the traffic they
send; fence drops the rest both ways, and Landlock restricts TCP ports
too. The policy does not track connections and names ports rather than
hosts: leave to connect to HTTPS does not confine a process to one server
([fence.md](design/fence.md)). Fence drops `CAP_SYS_ADMIN`,
`CAP_NET_ADMIN` and `CAP_NET_RAW`; a form that keeps the network
capabilities can send below fence's rules. `minimal` and `prod` listen
on nothing. Where sshd runs, it takes security keys with a touch, no
passwords, no forwarding; `playground` accepts ordinary keys too.

## Updates and the next boot

The updater verifies repository signatures before composing an image;
releases carry signed manifests; IPE machines trusting a signed channel
install complete [signed images](design/prebuilt-images.md), the keys
kept off the guest. Two slots each hold an image. A new one gets one
boot; committing marks it healthy, and a panic, a failed boot or
deadman's timeout returns to the previous slot. That recovers the image,
not `/data` ([updater.md](updater.md), [releases.md](releases.md)).
To protect the next boot, firmware must verify the signed unified kernel
image (loader, kernel, stage0, command line): an unchecked one defeats
the rest even with a signed root. A changed boot configuration can still
select an older signed image; the TPM-held minimum version that prevents
it is unfinished ([verified-boot.md](design/verified-boot.md)). All of
this runs inside the guest, so the hypervisor must be trusted.

## Protections a machine can be made without

Three protections reach across reboots: Secure Boot checks the boot
files, a TPM records which releases may boot, and IPE runs only native
code from the verified root. `howl --disable=secureboot,tpm,ipe` makes a
machine without them, which every provider but Lima and QEMU needs for
now ([cli](design/cli.md)). Nothing disables them by default: a build
refuses an image that would lack a protection `--disable` does not name,
and says how to give it; make's test builds name theirs (`DISABLE`). The
command line names what the machine lacks (`werewolf.disable`), and
posture and the login message say so. The keys a build signs with live
in `$XDG_DATA_HOME/howl` (`~/.local/share/howl`), never in `build/`: a
machine takes only updates signed with them, so back that directory up.

| Disabled | What that allows |
| --- | --- |
| `secureboot` | Boot files that are not signed run. Unsigned boot code could ignore the TPM, so `tpm` goes with it. |
| `tpm` | Booting an older signed release. |
| `ipe` | The machine builds its next slot from packages in `/data`, where root can change it before it boots. Native code is held to the verified root by mount flags and Landlock only. |

One profile provides all three, so for now they go together. Without
them a running machine keeps its seal, fence and verified root: root
still cannot run a program the image lacks, but can choose what boots
next. `--dev` makes a development image: busybox-full, seal learning
mode (refused calls logged, not blocked) and, with `werewolf.debug=1`,
a root shell on the console without a password. It needs
`--disable=secureboot,tpm,ipe`; howl never publishes it, and posture's
`processes-no-root-console` fails while the shell is offered.

## Not done, by choice

Freed memory is not wiped, for its cost: memory is cleared on
allocation, slab caches stay separate and page allocation is shuffled.
CPU mitigations are not forced on every process; werewolf's long-lived
programs ask for them. Reverse-path filtering conflicts with fence's
per-user routing, and a form that allows IPv6 takes constrained router
advertisements, which many networks need for a route. `posture
--extended` reports these. The seal costs about 25 ns a call (`getpid`
on an M4 Max: 150 ns against 125).

## Checking a machine

`/usr/lib/werewolf/posture --json`, as root, tries each protection
rather than reading its setting, and runs at every boot
([posture.md](posture.md)); `make check` holds every form's posture to
the weaknesses it declares ([testing.md](testing.md)). The [sysctl
review](audit/muse-sysctl-2026-10-12.md) records the reproduced
`syslog` bypass, its fix and the tested limits.
