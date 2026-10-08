# Lockdown

Proposed, 2026-10-06.

Once a werewolf machine has booted, root should not be able to change the
running kernel, watch or hook it, or reach beyond what each service needs.
OpenBSD gets this from `securelevel`: privileged setup happens at boot, then
a one-way switch takes it away. Linux has no single switch, but it has the
parts: lockdown, one-way sysctls, a seccomp filter on PID 1, and a reduced
capability bounding set. init sets them all before `exec runit`, and
nothing that runs after it can undo them.

[verified-boot.md](verified-boot.md) decides what code may run. This
design limits what code that does run can do with root, on Alpine's kernel
today and on ours later.

The constraint throughout is speed: werewolf exists for heavy compute, so
anything that costs measurable throughput is left out, and listed as such.

## Today

init closes the module loader after loading the form's modules, raises
lockdown to `integrity`, and sets:

```
kernel.modules_disabled=1        kernel.yama.ptrace_scope=3
kernel.kptr_restrict=2           vm.memfd_noexec=2
kernel.dmesg_restrict=1          net.ipv4.ip_forward=0
kernel.unprivileged_bpf_disabled=1
```

No form ships a setuid file, and `/data` is `nosuid,nodev,noexec`. Still:

- **root can load eBPF.** `unprivileged_bpf_disabled` stops other users
  only. A BPF program can hook syscalls through tracepoints, filter or
  rewrite traffic on an interface (XDP, tc), and hide a backdoor that no
  process on the machine owns. Lockdown at `integrity` refuses
  `bpf_probe_write_user` and nothing else of BPF's.
- **root can trace the kernel.** kprobes, perf, tracefs and BPF reads of
  kernel memory are allowed below `confidentiality`.
- **root can undo most sysctls.** Only `modules_disabled`, `ptrace_scope=3`
  and `memfd_noexec=2` are one-way. root can turn user namespaces and
  io_uring back on, or write a new `core_pattern`.
- **Every capability is available.** Every service runs as root, with the
  full bounding set.
- **The kernel's whole syscall surface is reachable**, including io_uring,
  user namespaces and 32-bit compat syscalls, all frequent sources of
  privilege escalation, and none of which werewolf uses.
- **Services share root's view.** Every process sees every other in
  `/proc`, and a compromised service can read `/run/config` and write
  `/data`.

## Not goals

- **Kernel exploits.** These measures shrink what an attacker can reach in
  the kernel and raise the cost of exploiting it; they do not remove bugs.
- **What code runs.** That is IPE's, in verified-boot.md.
- **Persistence.** That is the boot chain's, also in verified-boot.md.
- **Anything that costs speed** (see *Left out*).

## Threat model

| Attacker | Today | When done |
| --- | --- | --- |
| Code running as a service's user | sees every process; reaches io_uring, user namespaces, compat syscalls | sees its own processes; reaches only the syscalls and paths its service needs |
| root, during a boot | loads eBPF; traces the kernel; re-enables what sysctls disabled; holds every capability | cannot call `bpf`, `perf_event_open`, `kexec_*`, the module calls or io_uring at all; lockdown at `confidentiality`; the dropped capabilities are gone for every process until reboot |
| root, on a form allowed eBPF | as above | loads eBPF and traces the kernel, as the form asked; still no `bpf_probe_write_user`, kexec, modules, io_uring or ptrace |
| A kernel exploit | the whole syscall surface; a wrong kernel state keeps running | a smaller surface; an oops panics, and the slot falls back if it repeats |

## Design

### Lockdown at confidentiality

init raises lockdown to `confidentiality`, not `integrity`, unless the form
allows eBPF (see *Allowances*). It only ever rises, so it is set in init
through securityfs, as now, rather than on a command line that bitten
machines do not get updated.

`confidentiality` adds to `integrity`: kprobes, perf on the kernel, tracefs,
BPF reads of kernel memory, `/proc/kcore` and the XFRM secrets. These are
debugging tools; nothing in a workload's path calls them, so the cost is
debuggability, not speed. They are also what eBPF tracing is made of, so a
form allowed eBPF stays at `integrity`, which still refuses
`bpf_probe_write_user`. Our kernel (verified-boot.md) serves every form, so
it keeps `CONFIG_LOCK_DOWN_KERNEL_FORCE_INTEGRITY=y`, and init raises the
rest.

### Sysctls

Added to init's existing list. Each is free at runtime. The `ebpf` and
`io_uring` allowances change `kptr_restrict` and `io_uring_disabled`; the
rest hold on every form.

| Sysctl | Why |
| --- | --- |
| `kernel.kexec_load_disabled=1` | one-way; lockdown already refuses unsigned kexec, this refuses all of it |
| `kernel.io_uring_disabled=2` | io_uring is a large, frequently exploited surface; glibc does not use it |
| `user.max_user_namespaces=0` | user namespaces hand any user a root-like view of kernel code; nothing here uses containers |
| `kernel.panic_on_oops=1` | a kernel left in a bad state by a failed exploit reboots instead of running on; `panic=10` and A/B slots make that safe |
| `kernel.warn_limit=1` | the same for the first warning after boot: Alpine's kernel only warns when it catches a corrupted list, an overflowing reference count or a KFENCE fault, until our kernel's `CONFIG_BUG_ON_DATA_CORRUPTION`. Done |
| `kernel.sysrq=0` | no magic SysRq from the console |
| `fs.suid_dumpable=0` | no core dumps of processes that changed credentials |
| `fs.protected_symlinks=1`, `fs.protected_hardlinks=1` | the kernel's defaults are 0; distributions set them from systemd |
| `fs.protected_fifos=2`, `fs.protected_regular=2` | no writing to others' FIFOs and files in sticky directories such as `/tmp` |
| `net.ipv4.conf.all.rp_filter=1` | drop packets whose source could not be routed back; one NIC makes strict mode safe |
| `net.ipv4.conf.all.accept_redirects=0`, `send_redirects=0`, `accept_source_route=0` | ignore and send no ICMP redirects or source routes |
| `net.ipv6.conf.all.accept_redirects=0`, `accept_source_route=0` | the same for IPv6 |

init also sets `ulimit -c 0`, so nothing it starts writes core dumps.

The ones that are not one-way, root could undo. Two later layers make them
stick: the seccomp filter denies the syscalls outright, and a
read-only `/proc/sys` with `CAP_SYS_ADMIN` dropped stops remounting it (see
*Open questions*).

### A seccomp filter on PID 1

A seccomp filter is inherited by every child and every exec, and can never
be removed, by root or anyone. Installed by init just before runit, it
covers every process the machine will run. It **denies by default**: a
system call is refused unless a promise the machine made allows it
(pledge.md, System calls: promises), so what no promise names is refused
even as the kernel gains new calls. A refused call fails with `ENOSYS`, as
a kernel built without it would answer, so a program that probes for one
falls back.

The machine's promises are werewolf's own (`seal.base` in lib/seal.zig)
and every promise its services pledge, which the build gathers from the
service files. A handful of calls are in **no** promise, refused however a
form is built:

| Syscalls | Why |
| --- | --- |
| `bpf` | all eBPF: no programs, maps, links or BPF LSM programs |
| `perf_event_open` | perf, and the tracepoint and kprobe attachment BPF uses |
| `init_module`, `finit_module`, `delete_module` | already closed by `modules_disabled` |
| `kexec_load`, `kexec_file_load` | already closed by lockdown and the sysctl |
| `io_uring_setup`, `io_uring_enter`, `io_uring_register` | makes `io_uring_disabled` permanent |
| `userfaultfd` | not built in Alpine's kernel; refused in case ours builds it |
| `open_by_handle_at`, `name_to_handle_at` | walk past mount and chroot boundaries by inode handle |
| `add_key`, `keyctl`, `request_key` | the kernel keyring; cryptsetup's use of it is over before init hands over |
| `process_vm_readv`, `process_vm_writev` | read or write another process; Yama already refuses |
| `acct`, `swapon`, `swapoff`, `quotactl`, `quotactl_fd`, `lookup_dcookie`, `uselib`, `iopl`, `ioperm`, `vhangup` | unused here; old, rarely audited code |
| `modify_ldt` (x86_64) | the LDT, which only 16-bit code needs, and a past exploit primitive; `ia32_emulation=0` already closes `int 0x80` |

Done: init installs the filter itself (`seal()`, cmd/init/init.zig), from
the machine's promises and with the architecture check below. What the
promises do not allow goes to `seal-watch`, which refuses it (ENOSYS),
says so once with the promise that would allow it, and counts it for the
`seal` command; a leashed service holds itself to its own pledge with a
second filter (leash). `ptrace` is in no promise; `syslog` is its own
promise (`syslog`), which the base makes, since busybox's `dmesg` reads
the kernel's log through it and test/checks reads it so. posture's `kernel-seal` checks PID 1 carries a
filter, `processes-leash-attack` that a service's pledge refuses what it
did not promise, and `kernel-legacy` that `modify_ldt` is refused.
`make seal-learn` writes what each form needs by booting it with every
call allowed and recorded (pledge.md).

The machine seal looks at syscall numbers, and at the arguments of five
calls alone. The kernel (5.11 and later) caches, per syscall, that the
filter always allows it, and skips the filter on those calls, so the
table's length costs nothing. The five are refused, to everyone, for what
they ask: `socket` for a family no promise names (AF_ALG among them),
`setsockopt` for `TCP_ULP` (kernel TLS), `pipe2` for
`O_NOTIFICATION_PIPE` (watch queues), and `timer_create` and
`clock_nanosleep` for a CPU-time clock: each the way into a kernel bug
exploited in the wild (pledge.md, Two filters; docs/cve-mitigation-survey.md).
None is on a hot path. A service's own filter (leash) checks a new
socket's family against its own promises.

#### What the seal costs

Not nothing, and the only thing in this design that is not. A process
under any seccomp filter enters every system call through the kernel's
slower path, which checks the cache; without one it does not. Measured on
2026-10-06, 20 million `getpid` calls, on an Apple M4 Max:

| Filter | werewolf's kernel (Alpine's 6.18), ns a call | Ubuntu 26.04's (Linux 7.0), ns a call |
| --- | --- | --- |
| none | 124–125 | 114–115 |
| one instruction, allow everything | | 131–133 |
| the seal | 150–151 | 131–132 |
| 200 comparisons | 150 | 129–133 |

werewolf's kernel was booted under QEMU with HVF, its `/init` a program
that timed the calls, installed the filter, and timed them again; Ubuntu's
in a Lima VM. So about 25 ns a system call on werewolf's kernel, 15 on
Ubuntu's, whatever the filter holds: the cache works, and the cost is
having a filter at all. `getpid` is the cheapest call
there is; against a `read` or `write` of a few kilobytes, which take 0.5 to
1 µs, it is 2–5%, and a busy database making a few hundred thousand calls a
second spends a fraction of a percent of a CPU on it. Work that seldom
calls the kernel, as `../scan` matching rules, pays nothing. Every program
in a Docker container pays the same already, under Docker's default
filter.

werewolf pays it, by choice: it is the one way to deny by default for
good, root included, and to close what no setting can (`modify_ldt` on
x86_64, 32-bit system calls on aarch64); a longer promise list costs
nothing more. Our kernel (*Our kernel*, below) builds `modify_ldt` and the
32-bit interfaces out; the seal denies by default regardless.

It is a deny list, not an allow list: an allow list kept for every
program on the machine would break with each glibc or Wolfi update. It is
becoming an allow list of a different kind, of promises rather than system
calls (pledge.md, System calls: promises): forms say what their services
do, in a few words, and werewolf alone keeps which calls each word
brings, so an update that makes a new call for the same work is learned
once, for every form.

On a 64-bit kernel with compat syscalls built in, the filter checks the
architecture and kills any 32-bit syscall (done): werewolf ships no 32-bit code,
and the compat entry points are a second, separately numbered surface. On
x86_64 it also kills any number with bit 30 set: an x32 call, made under
x86_64's own architecture, which would otherwise pass every comparison as
another number. Alpine's kernel has no x32 ABI; a kernel that had one
would not open the table.

The seal fails closed, as fence does: a filter, a capability or a helper
setting (below) that cannot be set ends PID 1, and the machine falls back
to the slot that last worked.

#### The kernel's own helpers

The kernel starts some programs itself, from kthreadd, not PID 1: a core
dump piped to a program (`kernel.core_pattern = |PROGRAM`), `modprobe` for a
module request (`kernel.modprobe`), and the uevent helper (`kernel.hotplug`,
which Alpine's kernel builds in as `/sbin/hotplug`). Neither the filter
nor PID 1's bounding set reaches them, and root, which can write those
sysctls, could have one run with every capability. So the seal also sets
`kernel.usermodehelper.bset` and `inheritable` to `CAP_SYS_BOOT` alone, for
the kernel's orderly poweroff: they only fall, and only for a holder of
`CAP_SYS_MODULE`, which the seal then takes. init also empties
`kernel.hotplug`. posture's `kernel-helpers` checks both.

Not closed: such a helper is still not under the filter, so root can have
one make the refused calls that need no capability. Our kernel's
`CONFIG_STATIC_USERMODEHELPER` lets the kernel start no program but one,
which can be none; a read-only `/proc/sys`, once `CAP_SYS_ADMIN` goes, stops
root naming one.

### The capability bounding set

A capability dropped from PID 1's bounding set before it execs runit is
gone for every process after it, uid 0 included, and cannot come back
short of a reboot. Done: init drops these as it seals, but for the
network's two, which fence drops once it has set the network policy it
needs `CAP_NET_ADMIN` for, unless the form allows them (*Allowances*).
posture's `kernel-bounding-set` checks PID 1's bounding set:

| Capability | Takes away |
| --- | --- |
| `CAP_BPF`, `CAP_PERFMON` | BPF and perf, a second time |
| `CAP_SYS_MODULE`, `CAP_SYS_RAWIO` | modules, raw I/O ports and `/dev/mem`, a second time |
| `CAP_SYS_PTRACE` | ptrace and `/proc/<pid>/mem`, a second time |
| `CAP_NET_RAW` | packet sockets, and with them classic BPF socket filters: how BPFDoor listens without `bpf()` or an open port |
| `CAP_NET_ADMIN` | changes to addresses, routes, tc, XDP and, once it exists, nftables: the firewall init loads is the firewall |
| `CAP_SYS_ADMIN` | mounting, the new mount API's `fsconfig` (CVE-2022-0185), and the rest of the kernel's largest privileged surface. fence drops it, on every form, once its Landlock restriction, which needs it, is set; the mount broker, started before fence, makes the few mounts after boot |
| `CAP_MAC_ADMIN`, `CAP_MAC_OVERRIDE` | LSM policy; IPE's, once verified-boot.md lands |
| `CAP_SYS_TIME`, `CAP_SYS_PACCT`, `CAP_LINUX_IMMUTABLE`, `CAP_AUDIT_CONTROL`, `CAP_CHECKPOINT_RESTORE`, `CAP_WAKE_ALARM`, `CAP_BLOCK_SUSPEND`, `CAP_MKNOD` | unused here |

`CAP_SYSLOG` stays, though first listed: with `dmesg_restrict=1` it is
what reads the kernel's log, which `dmesg`, posture's proofs of a refusal
and test/checks all read. Without `CAP_SYS_RAWIO` the kernel refuses
`/dev/mem` before lockdown is asked, so that refusal is no longer logged;
posture accepts it.

It keeps what sshd, runit and the updater use: `CAP_SETUID`, `CAP_SETGID`,
`CAP_SYS_CHROOT`, `CAP_KILL`, `CAP_DAC_*`, `CAP_CHOWN`, `CAP_FOWNER`,
`CAP_SYS_BOOT`, `CAP_AUDIT_WRITE` and `CAP_NET_BIND_SERVICE`.

`bpf()` also accepts `CAP_SYS_ADMIN`, which is why the seccomp filter, not
the bounding set, is the layer that settles eBPF.

### Allowances

Some workloads need what the seal takes away. eBPF agents and tools
(Falco, Tetragon, Cilium, bpftrace) need `bpf()` and kernel tracing; packet
capture and DHCP need packet sockets. A form asks for each with an empty
file in its folder, `etc/werewolf/allow/<name>`, and gets back only that:

| Allowance | Gives back |
| --- | --- |
| `ebpf` | `bpf` and `perf_event_open` in the filter; `CAP_BPF`, `CAP_PERFMON`, and `CAP_NET_ADMIN` for XDP and tc; lockdown stays at `integrity`; `kptr_restrict=1` and `CAP_SYSLOG`, so root can read kernel addresses, from which libbpf and bpftrace resolve symbols |
| `packet` | `CAP_NET_RAW`: packet sockets, and the classic BPF filters on them, for tcpdump. DHCP needs none: its renewal opens its socket before fence |
| `netadmin` | `CAP_NET_ADMIN`: addresses, routes and fence's rules. DHCP needs none: its renewal starts before fence and keeps its own |
| `io_uring` | the io_uring syscalls in the filter, and `io_uring_disabled=0`, for workloads built on it |
| `ipv6` | IPv6. Without it the kernel is booted with `ipv6.disable=1`, which leaves out the address family and every path through it (CVE-2026-53362); fence then sets IPv4's rules alone. Done |
| `pty` | pseudo-terminals, for ssh logins: init mounts devpts. Without it `/dev/ptmx` opens nothing, for root too, so the TTY layer's pseudo-terminal code (CVE-2014-0196) is out of every process's reach, and nothing after boot can mount it. Done: the forms with logins (`sshd`, `prod-ssh`, `lima`; `qemu-host` through `sshd`); `bastion` forbids terminals (`PermitTTY no`) and has none |
| `kvm` | KVM, to run virtual machines: on aarch64 the build leaves out `kvm-arm.mode=none`; on x86_64 the form lists `kvm-intel` and `kvm-amd` in its `.modules`, and the build loads them with `nested=0`. Done: `qemu-host` |
| `nested-kvm` | needs `kvm`: the guests may run virtual machines too, `kvm-arm.mode=nested` or `nested=1`. Done |
| `jit` | memory written and then run. Without it init sets Memory-Deny-Write-Execute on PID 1 (`PR_SET_MDWE`, `PR_MDWE_REFUSE_EXEC_GAIN`), which every process inherits and none can lift: no mapping is writable and executable at once, or made executable once written. Done: `node`, `jre`, `example-aspnet` (V8, HotSpot, .NET), `php` (PCRE2's JIT, `pcre.jit=1` by default) and `postgresql` (LLVM, `jit = on` by default), and the forms built on them. `qemu-host` has none, so QEMU runs guests under KVM alone: TCG, its emulator, would need it |

`kvm`, `nested-kvm`, `packet`, `netadmin`, `ipv6`, `pty` and `jit` are built;
`ebpf` and `io_uring` wait for a form that needs them. No form keeps either network
capability: DHCP's renewal, started by init before fence, holds them
alone. The
Makefile holds the one list of names (`ALLOWANCES`), and a name not in it
fails the build, as does `nested-kvm` without `kvm`. Allowances that
change what the kernel is told at boot become data the build writes,
`/usr/share/werewolf/cmdline` and the parameters in `werewolf.modules`, and
everything that boots or loads the image reads that data rather than
deciding again (*Command line*, below).

Even with `ebpf`, root cannot write user memory from BPF
(`bpf_probe_write_user`, refused at `integrity`), let other users load BPF,
load modules, kexec or ptrace. uprobes do not need ptrace.

- **The image decides, nothing else.** Allowances are files in the root
  image, which is read-only and, with verified-boot.md, signed. They are
  never read from the command line, the config tar or NoCloud, and
  `werewolf.debug=1` does not loosen anything: on a bitten machine root can
  rewrite all of those, and a switch there is one an attacker can flip.
- **They only accumulate.** Form folders are laid base first, so a form
  inherits every allowance in its include chain and cannot drop one. The
  Makefile records them with the form's other files, so the updater carries
  them into the next slot.
- **init knows allowances, not forms.** It reads `/etc/werewolf/allow`;
  which form put a file there is the build's business.
- **The posture line names them**, so an auditor sees at once that a
  machine is one that can load eBPF.
- **The filter stays a table of numbers.** An allowance removes entries; it
  adds no argument checks, so the kernel's cache still applies.

A form allowed `ebpf` gives root back what eBPF rootkits are made of. That
is the price of running an eBPF agent, and why it is a form of its own
rather than a switch on every form.

That form is `prod-ebpf`. It includes `prod`, as production forms do,
and adds nothing but the `ebpf` and `packet` files: it is the base for an
eBPF agent's form, which adds the agent and no tools an attacker could use
to explore. Include chains are linear, so allowances are not mixins; a
form takes them from its chain or carries the files itself.

### The helper

busybox cannot install a seccomp filter or change the bounding set. init,
now a Zig program, installs PID 1's filter itself, and will drop the
bounding set the same way, so the seal needs no helper. One static Zig
program, `/usr/lib/werewolf/leash`, is still the plan for the per-service
sandboxing below; what follows describes it as first designed, sealing
too. It has no dependencies beyond Zig's standard library. The
filter and the dropped capabilities are fixed tables compiled into it, less
what `/etc/werewolf/allow` names. init ends with:

```sh
exec /usr/lib/werewolf/leash -seal -- runit
```

`-seal` sets `no_new_privs`, drops the bounding set, installs the filter,
and execs. It logs what it did on one line before the exec.

Zig is needed today only for forms with autoupdate; this makes it needed
for every form.

### Mounts

- **`/proc` with `hidepid=invisible`**: a user sees only their own
  processes. root sees all.
- **`/tmp`, `/run`, `/dev/shm` with `nosuid,nodev,noexec`**: verified-boot.md
  phase 2. Today `/tmp` and `/dev/shm` are where any user can write and run
  a binary.
- **`/proc/sys` read-only**, bind-mounted over itself, once `CAP_SYS_ADMIN`
  can be dropped. Until then root can remount it.

### Services

The README says services must sandbox themselves; in practice none do.
Each service is started by `leash`, which works like OpenBSD's `unveil` and
`pledge`, from a `service` file in its directory that replaces the `run`
script. [shell-free.md](shell-free.md) defines the format; cloudflared's is:

```
exec    /usr/bin/cloudflared --no-autoupdate tunnel run
user    cloudflared
secret  TUNNEL_TOKEN /run/config/cloudflared/token
connect tcp/443 tcp/7844
```

| Key | Mechanism |
| --- | --- |
| `user` | its own uid and gid, from the image's `/etc/passwd`; `chpst -u` does the same today, without the rest |
| `read`, `write`, `run` | Landlock filesystem rules: everything else is invisible to reads and writes, and cannot be run. `/dev` is closed to every process by fence's domain but for the devices werewolf names; a service that needs another has no way to ask yet (*Open questions*) |
| `listen`, `connect` | Landlock TCP rules (ABI 4, Linux 6.7): the ports it may bind and reach |
| (always) | Landlock scoping (ABI 6, Linux 6.12): no abstract UNIX sockets or signals outside its own domain |
| (always) | `no_new_privs`, an empty bounding set and no capabilities, but `CAP_NET_BIND_SERVICE` for a port below 1024: `mount`, `umount2`, `pivot_root`, `chroot`, `unshare`, `setns` and `reboot` are refused by the kernel already, with user namespaces off, so a second seccomp filter would add nothing; the seal's covers the rest |

Landlock checks run on path lookup and connect; nothing of leash runs once
the service has started. leash starts no service as root: one that needs
root (sshd, the updater) sandboxes itself or is not yet sandboxed, below.

| Service | Runs as | Notes |
| --- | --- | --- |
| nginx, the demo's status page and scan | their own users | leashed (forms/demo/README.md) |
| cloudflared | `cloudflared` | its QUIC to Cloudflare is UDP, which Landlock cannot restrict yet |
| sshd | root | not leashed: its privilege separation needs root; it is for test forms, and leaves production (roadmap) |
| autoupdate | root | not leashed: needs `mount` and `reboot`; its fetching and parsing run in children as `_update`, under Landlock and seccomp (docs/updater.md) |
| commit, powerbtn, console | root | not leashed: small programs of werewolf's own |

### Posture

An auditor should be able to check the running state rather than trust
this document. init logs one structured line before it hands over:

```
{"event":"posture","allow":[],"lockdown":"confidentiality","modules_disabled":1,"seccomp":"filter","no_new_privs":1,"cap_bnd":"…","setuid_files":0,"listening":[],"sysctls":{"kernel.io_uring_disabled":2,"user.max_user_namespaces":0}}
```

`seccomp` and `cap_bnd` come from `/proc/1/status` after the seal, so a
later check in `slot-keep` reads them from PID 1 rather than from init's
intentions. CI's boot test (verified-boot.md, *Releases*) checks the same,
and that `bpf()`, `perf_event_open()` and `io_uring_setup()` fail as root,
or, on `prod-ebpf`, that a BPF program loads and
`bpf_probe_write_user` does not.

### Command line

Some hardening has no runtime switch. The build writes what the image asks
for, from its architecture and allowances (Makefile, `KERNEL_ARGS`), into
the image as `/usr/share/werewolf/cmdline` and beside it as the slot's
`cmdline`. bite and `boot/mkdisk` write it into the entries they make; the
Makefile's `run` and `check` and `lima.yaml` pass it; the updater's next
entry takes it from the image and replaces any argument of the same name,
so an edited entry does not outlive an update. posture's `kernel-cmdline`
fails a machine booted without it.

| Argument | Cost | Our kernel instead |
| --- | --- | --- |
| `debugfs=off` | none | `# CONFIG_DEBUG_FS is not set` |
| `proc_mem.force_override=never` | none: only debuggers write read-only memory through `/proc/PID/mem`, and ptrace is off | `CONFIG_PROC_MEM_NO_FORCE=y` |
| `ia32_emulation=0` (x86_64) | none | `# CONFIG_IA32_EMULATION is not set` |
| `kvm-arm.mode=none` (aarch64, unless `kvm`) | none | none: one kernel serves `qemu-host` too |
| `slab_nomerge` | a little memory: caches of the same size stay apart, so one overflow cannot reach another type | `# CONFIG_SLAB_MERGE_DEFAULT is not set` |
| `page_alloc.shuffle=1` | none measurable | `CONFIG_SHUFFLE_PAGE_ALLOCATOR=y` |

All are done. bite's GRUB entries do not hold the image's arguments but
read them from GRUB's environment, `werewolf_args_a` and `werewolf_args_b`,
which bite sets for the slot it installs and the updater for each slot it
builds, so a bitten machine boots each slot with that slot's image's
arguments, as a native disk's entries do. Machines bitten before
2026-10-06 keep the entries bite wrote then until bitten again;
posture's `kernel-cmdline` says which arguments they lack.

### Our kernel

When verified-boot.md phase 4 builds our own `linux-virt`, it also changes
what Alpine's config leaves out or in. All cost nothing measurable, or
remove code no form calls. One kernel serves every form, so it keeps eBPF,
kprobes and tracing for `prod-ebpf`; the seal removes them elsewhere.

| Option | Alpine today | Why |
| --- | --- | --- |
| `CONFIG_RANDOMIZE_BASE=y` | off on arm64 | KASLR: the arm64 kernel loads at the same address every boot |
| `CONFIG_SLAB_FREELIST_HARDENED=y` | off | free-list pointers checked and obfuscated |
| `CONFIG_SHADOW_CALL_STACK=y` | off (arm64) | return addresses kept where overflows cannot reach |
| `CONFIG_FORTIFY_SOURCE=y` | off on arm64 | bounds checks on string and memory functions, as x86_64 has |
| `CONFIG_BUG_ON_DATA_CORRUPTION=y` | off | a corrupted kernel list stops the kernel |
| `CONFIG_STATIC_USERMODEHELPER=y` | off | the kernel can start no program as root but one, which can be none |
| `CONFIG_LOCK_DOWN_KERNEL_FORCE_INTEGRITY=y` | none | lockdown from the first instruction; init raises it further where eBPF is not allowed |
| `# CONFIG_COMPAT`, `# CONFIG_IA32_EMULATION` | on | no 32-bit syscall surface |
| `# CONFIG_MODIFY_LDT_SYSCALL` | on (x86_64) | no LDT, a past exploit primitive |
| `# CONFIG_HIBERNATION`, `# CONFIG_KEXEC` | on | nothing hibernates or kexecs |
| `# CONFIG_KALLSYMS_ALL` | on | fewer symbols for an exploit to find |
| `# CONFIG_BINFMT_MISC` | module | no registering interpreters for new binary formats |
| `# CONFIG_CRYPTO_USER_API`, `# CONFIG_TLS`, `# CONFIG_WATCH_QUEUE`, `# CONFIG_BRIDGE_NF_EBTABLES`, `# CONFIG_OVERLAY_FS`, no USB sound, video or HID | module, or off | code exploited in the wild that no form uses (docs/cve-mitigation-survey.md); the `crypt` form opens LUKS2 without AF_ALG |
| `CONFIG_POSIX_CPU_TIMERS_TASK_WORK=y` | on | closes CVE-2025-38352's race |
| `CONFIG_RANDOM_KMALLOC_CACHES=y` | off | each `kmalloc` size split into 16 caches, picked by call site, so a heap spray rarely lands beside the object it aims at; Ubuntu ships it on |
| `CONFIG_SLAB_BUCKETS=y` | off | the allocations users steer most (`msg_msg`, `setxattr` and `memdup_user` buffers) in caches of their own, away from the kernel's objects; Ubuntu ships it on |
| `CONFIG_MSEAL_SYSTEM_MAPPINGS=y`, `# CONFIG_CHECKPOINT_RESTORE` | off; on | the vdso, vvar and sigpage sealed (`mseal`) in every process, so an exploit cannot move or remap them; it needs checkpoint and restore, which nothing here uses, left out |

Two more need the kernel built with clang, not GCC, as Alpine and Ubuntu
build it: `CONFIG_ARM64_BTI_KERNEL`, branch targets checked in the kernel
itself (its Kconfig excludes GCC for a code-generation bug), and kCFI
(`CONFIG_CFI_CLANG`, `CONFIG_CFI` in newer kernels), indirect calls
checked against their type, Android's main defence for the kernel's
control flow. Ubuntu's GCC-built 7.0 has neither. Choosing the compiler is the first decision of
this phase.

Until then, the build checks Alpine's config for those it relies on
already (tools/kernel-config-check.zig): it fails if Alpine builds AF_ALG,
kernel TLS, ebtables, nf_tables, x_tables, overlayfs, USB or HID into the
kernel, where the closed module loader would not keep them out, or turns
on watch queues, USB sound or video, or turns off
`POSIX_CPU_TIMERS_TASK_WORK`.

The runtime layers stay: they are what this design rests on while we use
Alpine's kernel, and cost nothing once the code they guard is gone.

## Left out

Each of these makes exploitation harder, and each costs throughput or
capacity that werewolf exists to deliver:

| Measure | Cost |
| --- | --- |
| `init_on_free=1` | 1–5% on allocation-heavy work; `init_on_alloc` is already on |
| `nosmt` | half the vCPUs |
| `mitigations=auto,nosmt` or beyond | the same, and more |
| hardened_malloc | glibc's malloc, chosen for speed |
| `CONFIG_KSTACK_ERASE` (stackleak) | a stack wipe on every syscall return |
| `CONFIG_INIT_ON_FREE_DEFAULT_ON`, `CONFIG_PAGE_TABLE_CHECK` | as `init_on_free`; page-table checks on every mapping change |
| auditd, IMA measurement | a daemon and a hash per open; IPE's refusals reach the console without either |

## Phases

Each phase ships on its own.

1. **Runtime settings**, in init's shell: lockdown to `confidentiality`
   unless `/etc/werewolf/allow/ebpf` exists, the sysctls by allowance,
   `ulimit -c 0`, `hidepid`, and the command-line arguments in bite, the
   Makefile and Lima. No new code. Done so far, with checks in
   test/checks: `user.max_user_namespaces=0`, the `fs.protected_*` sysctls,
   `hidepid=invisible`, and `nosuid,nodev,noexec` on `/tmp`, `/run` and
   `/dev/shm`, with `/run` root's alone, all through werewolf's one-way
   `mount` (cmd/mount/mount.zig), which also keeps a mount from being loosened
   by werewolf's own scripts. The seal is what will stop root.
2. **The seal**: init's PID 1 filter and bounding set, less the
   allowances. Closes eBPF, perf, io_uring and the rest for good on every
   form that did not ask for them. Done, but for the `ebpf` and
   `io_uring` allowances, which no form asks for yet.
3. **`prod-ebpf`**, and CI booting it with a BPF program.
4. **Services**: their own users, and each `run` script through `leash`.
5. **Posture**: the boot line, the check in `slot-keep`, and CI's boot test.
6. **Our kernel's config**, with verified-boot.md phase 4.

## Alternatives considered

- **Lockdown at `integrity` everywhere**, as verified-boot.md has it.
  `confidentiality` costs nothing but kernel tracing, which root has no
  business doing on a machine that runs no eBPF agent, and it is what stops
  a BPF or kprobe rootkit from reading the kernel.
- **A command-line switch for eBPF**, such as `werewolf.ebpf=1`. Root on a
  bitten machine can rewrite GRUB's entries, so the switch would be the
  attacker's too. The image is the one place root cannot change.
- **Building eBPF out of the kernel.** One kernel serves every form; a
  second kernel for `prod-ebpf` doubles the builds and CVE tracking
  for what the seal already takes away.
- **The BPF LSM, to deny `bpf()`.** Uses the thing it guards against, and
  needs a loader and pinned programs we would have to protect from root.
  The seccomp filter is a table and one syscall.
- **util-linux `setpriv`.** It drops the bounding set and sets
  `no_new_privs`, and recent versions apply Landlock and a prebuilt seccomp
  filter. It would avoid a Zig program for forms without autoupdate, but
  splits the policy across flags and a separately built filter file, and
  ties us to whichever util-linux Wolfi ships.
- **minijail, nsjail, bubblewrap.** Each brings a dependency and more than
  we need; bubblewrap and nsjail lean on user namespaces, which we turn off.
- **An allow list on PID 1.** Breaks with each glibc or tool update, and
  forces argument checks the kernel cannot cache.
- **`perf_event_paranoid=3`.** A Debian and Android patch, not upstream; the
  filter denies `perf_event_open` instead.
- **Seccomp on `clone` and `clone3` for `CLONE_NEWUSER`.** `clone3` passes
  its flags in memory seccomp cannot read; `max_user_namespaces=0` does the
  job without the argument check.

## Open questions

- **DHCP** (`cmd/dhcp-client/dhcp-client.zig`, used when the command line names no
  address) separates its own privileges, as OpenBSD's dhclient does. It
  opens and filters its packet socket as root, then forks. The engine,
  which alone reads the network, runs as `_dhcp`, chrooted to `/var/empty`,
  with no capabilities and a seccomp allowlist. The parent keeps only
  `CAP_NET_ADMIN`, to apply leases, under seccomp and Landlock. So it
  needs `CAP_NET_RAW` and `CAP_NET_ADMIN` only when it starts. Done: init
  starts its renewal before fence, so it keeps them, and fence drops both
  for every process after it; no form allows `packet` or `netadmin`.
- **fentry and fexit.** Alpine's kernel lacks `CONFIG_FUNCTION_TRACER`, so
  BPF programs that attach through trampolines fail; kprobes, tracepoints,
  uprobes, XDP, tc and cgroup programs work. Confirm which agents fall back
  to kprobes, and whether our kernel should build it.
- **The BPF LSM.** Alpine's kernel builds it but leaves it out of
  `CONFIG_LSM`, and turning it on takes `lsm=` on the command line, which
  is shared by every form. Agents that enforce through it (Tetragon's
  enforcement, KubeArmor) need our kernel, or a command line only the
  `prod-ebpf` writes.
- **Landlock and UDP.** Landlock has no UDP rules yet; cloudflared's QUIC
  and DNS go unrestricted until it does.
- **The capability set on 6.18.** Confirm each dropped capability breaks
  nothing in boot, commit, the updater or sshd, under CI's boot test.
- **`hidepid` under busybox.** Its `mount` passes options as filesystem
  data, which `hidepid` is; confirm it works on a remount of `/proc`.
- **Devices for a form.** fence closes `/dev` but for what werewolf's own
  programs use. A form whose service needs a device (a GPU, a TPM, a
  serial line) would need to name it, as it names ports: a `device` line
  in the service file that the build gathers into fence's list, as it
  gathers promises. No form needs one yet.
