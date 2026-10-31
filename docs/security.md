# Security

Werewolf assumes a service will be compromised. It limits what that service can read,
change, execute and reach over the network, and root does not lift those limits: the
kernel enforces them. A few boot helpers hold more authority and remain trusted code.
This page describes a machine with every protection ([a machine without
some](#protections-a-machine-can-be-made-without)).
## From boot to a running service
init (process 1) sets the kernel protections and installs the seal, a seccomp filter
that refuses every system call no promise names ([lib/seal.zig](../lib/seal.zig)). It
then starts fence, which sets the network and file-access rules, drops capabilities,
and becomes runit, the service supervisor. Services and logins inherit these
restrictions and can narrow them, never lift them. If the seal or fence cannot be
applied, init exits and the kernel panics.

A service declares in its form the promises (named groups of system calls) it needs,
its user, its files and its ports, and leash applies them
([pledge.md](design/implemented/pledge.md)); a new system call stays refused until a
promise names it. Seccomp decides whether a process may make a call, Landlock which
files and TCP ports it may reach. Werewolf's own programs are privilege-separated
([programs.md](programs.md)).
## Keeping kernel protections set
Some protections are not settings at all: werewolf's kernel has no module loader,
`bpf` system call, io_uring, user namespaces, kexec or SysRq
([custom-kernel.md](design/implemented/custom-kernel.md)), and forces lockdown to
confidentiality. `kernel.yama.ptrace_scope=3` is one-way for the boot: it cannot be
lowered, by root either. The rest would stay writable by root, so fence closes the
route: under its Landlock rules no process can open a file in `/proc/sys` for
writing, write `/sys`, or open a disk or device the policy does not name; no promise
overrides that. `syslog(2)` can set `kernel.printk` without a file, so the seal lets
it read the log and refuses the rest. A descriptor opened before confinement keeps
its access, so init closes each sysctl file after writing it.

The seal refuses eBPF, perf, module and kexec calls, io_uring, userfaultfd, kernel
keyrings and the `process_vm_*` calls, and checks arguments to close AF_ALG, kernel
TLS, notification pipes and new seccomp listeners; a call in another architecture, or
x86's x32 convention, kills the caller. User namespaces, debugfs, IPv6 and, on
x86_64, 32-bit emulation are not built; the command line disables forced writes
through `/proc/self/mem`, and KVM unless the form allows it. An oops, or a warning
once the limit is set, panics and reboots: a damaged kernel does not run on, at the
price of a denial of service. [cmd/init/kernel.zig](../cmd/init/kernel.zig) holds
every setting, [lockdown.md](design/implemented/lockdown.md) the reasoning, and the
[survey](cve-mitigation-survey.md) what each stops.

The kernel logs refused execs, file access and service system calls. The audit
configuration is locked; init drops its controlling capability. Shared printk rate
limiting is off so startup bursts cannot suppress audit evidence. Notices reach the
captured serial console. seal-watch reports refusals.
## The helpers outside fence

The mount broker keeps `CAP_SYS_ADMIN` to mount during updates, slot commits and
shutdown. It takes fixed requests, not paths or options, lends no mount, and answers
only the updater, slot-keep and runit's shutdown stage, each through a descriptor
init gave it. It is privileged code outside Landlock: code execution in it crosses
the boundary that confines services
([cmd/mount-broker/mount-broker.8.md](../cmd/mount-broker/mount-broker.8.md)). The
DHCP renewal keeps `CAP_NET_ADMIN`, with Landlock on its writes; seal-watch drops
root and refuses itself further opens; stage0 leaves deadman, a watchdog that reboots
a trial slot not yet committed. Helpers the kernel starts itself sit outside init's
seal, so init empties `kernel.modprobe` and `kernel.hotplug` and limits them to
`CAP_SYS_BOOT`.

## What an attacker can keep or execute

The root is EROFS, read-only, with no writable layer, and dm-verity checks each block
as it is read; the expected hash comes from stage0, so this rests on the boot chain
([verified-boot.md](design/implemented/verified-boot.md)). Writable mounts refuse
execution, setuid bits and, outside device filesystems, device files. Fence permits
execution beneath `/usr` and `/oci`; leash narrows each service further. The image
has no setuid or setgid file, as the build and the updater clear those bits whatever
a package ships, and init drops the capabilities for loading kernel code, reaching
hardware, tracing and making device nodes. Memory-Deny-Write-Execute refuses a
mapping both writable and executable in every process, unless the form allows `jit`;
a memory file (`memfd`) escapes it and the mount flags once mapped, so only such a
form may promise it. None of this makes an interpreter's input trustworthy: a runtime
can run a script from writable storage. Images built with
[IPE](design/implemented/ipe.md) hold native executables and mappings to one verified
filesystem named by a signed policy; IPE does not authenticate scripts either.

Address randomization covers the kernel and every program's code, data, stack and
heap. werewolf's programs are static PIEs; the build refuses an executable stack, or
a program at a fixed address that `lib/image.zig` does not name with its reason:
Wolfi's runit, Go programs Wolfi builds without `-buildmode=pie` (gitea, prometheus
and others) and upstream binaries shipped as they are, whose code an exploit finds
without a leak. posture fails a kernel not randomized (arm64 with no boot seed) or
booted with an argument turning it off. On x86_64, timing side channels can still
reveal the kernel's base to local code.

Persistent state lives on `/data`, LUKS2 when a key is supplied. init formats only
blank storage; a volume it cannot open is left untouched, `/data` becomes an empty
read-only tmpfs, and the trial slot cannot commit. Writable mounts refuse symlink
traversal (`nosymfollow`) except `/data`, where user data may hold links; TLS front
ends never read application `/data` trees, and programs walking `/data` refuse links
outside their tree. `/proc` hides other users' processes. Boot secrets are unpacked
into `/run/config`, root's alone; the data key is removed once the volume is open.

## Reaching other machines

Each form declares the ports its services listen on and the traffic they send; fence
drops the rest both ways, and Landlock restricts TCP ports too. The policy does not
track connections and names ports rather than hosts: leave to connect to HTTPS does
not confine a process to one server ([fence.md](design/implemented/fence.md)). Fence
drops `CAP_SYS_ADMIN`, `CAP_NET_ADMIN` and `CAP_NET_RAW`; a form that keeps the
network capabilities can send below fence's rules. `minimal` and `prod` listen on
nothing. Where sshd runs, it takes security keys with a touch, no passwords, no
forwarding; `playground` accepts ordinary keys too.

## Updates and the next boot

The updater verifies repository signatures before composing an image; releases carry
signed manifests; IPE machines trusting a signed channel install complete [signed
images](design/implemented/prebuilt-images.md), the keys kept off the guest. Two
slots each hold an image. A new one gets one boot; committing marks it healthy, and a
panic, a failed boot or deadman's timeout returns to the previous slot. That recovers
the image, not `/data` ([updater.md](updater.md), [releases.md](releases.md)). To
protect the next boot, firmware must verify the signed unified kernel image (loader,
kernel, stage0, command line): an unchecked one defeats the rest even with a signed
root. A changed boot configuration could select an older signed image, so a protected
machine's first boot takes its TPM, and stage0 refuses any release below its
channel's floor, which rises to the running release before a slot is replaced
([independent-updates.md](design/implemented/independent-updates.md)). All of this
runs inside the guest, so the hypervisor must be trusted.

## Protections a machine can be made without

Three protections reach across reboots: Secure Boot checks the boot files, a TPM
records which releases may boot, and IPE runs only native code from the verified
root. `howl
--disable=secureboot,tpm,ipe` makes a machine without them, which every provider but
Lima, QEMU, Firecracker, x86_64 bhyve and, for `--build` images, GCP, AWS and Azure
needs for now ([cli](design/implemented/cli.md)). Firecracker defaults to IPE with
host-pinned boot files and warns that Secure Boot and TPM rollback protection are
unavailable. Other providers disable nothing by default. A build refuses an image
that would lack a protection `--disable` does not name, and says how to give it. Make
builds also default to no disabled protections; legacy test images require an
explicit command-line `DISABLE=secureboot,tpm,ipe`, and an inherited environment
value is refused. The command line names what the machine lacks (`werewolf.disable`),
and posture and the login message say so. The keys a build signs with live in
`$XDG_DATA_HOME/howl` (`~/.local/share/howl`), never in `build/`: a machine takes
only updates signed with them, so back that directory up.

| Disabled | What that allows |
| --- | --- |
| `secureboot` | Boot files that are not signed run. Unsigned boot code could ignore the TPM, so `tpm` goes with it. |
| `tpm` | Booting an older signed release. |
| `ipe` | The machine builds its next slot from packages in `/data`, where root can change it before it boots. Native code is held to the verified root by mount flags and Landlock only. |

Firecracker's
[host-pinned boot files](design/implemented/firecracker-boot.md) retain IPE,
dm-verity, the seal and fence. This supplies neither firmware Secure Boot nor a TPM
release floor: the trusted host can replace the record or restore older vulnerable
state. Keep it outside guest access. Changed boot files fail closed; legacy mode
keeps guest-controlled A/B updates without pinning those files.

Other providers supply all three protections. Without them a running machine keeps
its seal, fence and verified root: root still cannot run a program the image lacks,
but can choose what boots next. `--dev` makes a local development image: mksh,
BusyBox tools, root SSH through a Howl-managed Ed25519 key, optional seal learning
(refused calls logged, not blocked) and, with `werewolf.debug=1`, a passwordless root
console. The key lives under `$XDG_DATA_HOME/howl/keys/dev/`; `howl ssh root@NAME`
uses it. Playground's keys are separate. With the checked debug command line and
Howl's dev config marker, init mounts `/run/howl-dev` as executable RAM for SSH
uploads. [Test iteration](design/implemented/local-test-iteration.md) uses SSH and
`sh-shim`, without BusyBox or a console shell, and confines a selected driver with
its declared leash policy. Dev images require protections off:
`--disable=secureboot,tpm,ipe`, and
are never published. A root console fails posture.

## Not done, by choice

Freed memory is not wiped, for its cost: memory is cleared on allocation, slab caches
stay separate and page allocation is shuffled. CPU mitigations are not forced on
every process; werewolf's long-lived programs ask for them. Reverse-path filtering
conflicts with fence's per-user routing. `posture --extended` reports these. The seal
costs about 25 ns a call (`getpid` on an M4 Max: 150 ns against 125).
