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
covers every process the machine will run. It denies, with `ENOSYS`, as
a kernel built without them would answer, so a program that probes for one
falls back:

| Syscalls | Why |
| --- | --- |
| `bpf` | all eBPF: no programs, maps, links or BPF LSM programs |
| `perf_event_open` | perf, and the tracepoint and kprobe attachment BPF uses |
| `init_module`, `finit_module`, `delete_module` | already closed by `modules_disabled`; denied again for the audit trail |
| `kexec_load`, `kexec_file_load` | already closed by lockdown and the sysctl |
| `io_uring_setup`, `io_uring_enter`, `io_uring_register` | makes `io_uring_disabled` permanent |
| `userfaultfd` | not built in Alpine's kernel; denied in case ours builds it |
| `open_by_handle_at`, `name_to_handle_at` | walk past mount and chroot boundaries by inode handle |
| `add_key`, `keyctl`, `request_key` | the kernel keyring; cryptsetup's use of it is over before init hands over |
| `process_vm_readv`, `process_vm_writev` | read or write another process; Yama already refuses, denied again for the trail |
| `acct`, `swapon`, `swapoff`, `quotactl`, `lookup_dcookie`, `uselib`, `iopl`, `ioperm`, `vhangup` | unused here; old, rarely audited code |
| `modify_ldt` (x86_64) | the LDT, which only 16-bit code needs, and a past exploit primitive; `ia32_emulation=0` already closes `int 0x80`. Done |

Done: init installs the filter itself (`seal()`, init/init.zig), with
every row above that the architecture has, and the architecture check
below. `syslog` is not denied, though first listed: busybox's `dmesg`
reads the kernel's log through it, and test/checks reads it so. No form
yet asks for `ebpf` or `io_uring`, so those allowances are not built; a
form that needs one adds it then. posture's `kernel-seal` checks PID 1
carries a filter, and `kernel-legacy` that `modify_ldt` is refused.

The filter looks at syscall numbers only, never arguments. The kernel
(5.11 and later) then caches, per syscall, that the filter always allows it,
and skips the filter on those calls, so the table's length costs nothing.

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

werewolf pays it, by choice: it is the one way to close for good, root
included, what no setting can (`modify_ldt` on x86_64, 32-bit system calls
on aarch64), and every entry added to the table later costs nothing more.
Our kernel (*Our kernel*, below) builds `modify_ldt` and the 32-bit
interfaces out; the seal stays for the rest of the table.

It is a deny list, not an allow list. An allow list for every program on
the machine would break with each glibc or Wolfi update; per-service allow
lists belong in the services' sandboxes, below.

On a 64-bit kernel with compat syscalls built in, the filter checks the
architecture and kills any 32-bit syscall (done): werewolf ships no 32-bit code,
and the compat entry points are a second, separately numbered surface.

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
| `CAP_MAC_ADMIN`, `CAP_MAC_OVERRIDE` | LSM policy; IPE's, once verified-boot.md lands |
| `CAP_SYS_TIME`, `CAP_SYS_PACCT`, `CAP_LINUX_IMMUTABLE`, `CAP_AUDIT_CONTROL`, `CAP_CHECKPOINT_RESTORE`, `CAP_WAKE_ALARM`, `CAP_BLOCK_SUSPEND`, `CAP_MKNOD` | unused here |

`CAP_SYSLOG` stays, though first listed: with `dmesg_restrict=1` it is
what reads the kernel's log, which `dmesg`, posture's proofs of a refusal
and test/checks all read. Without `CAP_SYS_RAWIO` the kernel refuses
`/dev/mem` before lockdown is asked, so that refusal is no longer logged;
posture accepts it.

It keeps what sshd, runit and the updater use: `CAP_SETUID`, `CAP_SETGID`,
`CAP_SYS_CHROOT`, `CAP_KILL`, `CAP_DAC_*`, `CAP_CHOWN`, `CAP_FOWNER`,
`CAP_SYS_BOOT`, `CAP_AUDIT_WRITE`, `CAP_NET_BIND_SERVICE`, and, for now,
`CAP_SYS_ADMIN` (see *Open questions*).

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
| `packet` | `CAP_NET_RAW`: packet sockets, and the classic BPF filters on them, for tcpdump and a DHCP client. Done: `dhcp` |
| `netadmin` | `CAP_NET_ADMIN`: addresses and routes, as a DHCP client renewing changes them, and fence's rules. Done: `dhcp` |
| `io_uring` | the io_uring syscalls in the filter, and `io_uring_disabled=0`, for workloads built on it |
| `kvm` | KVM, to run virtual machines: on aarch64 the build leaves out `kvm-arm.mode=none`; on x86_64 the form lists `kvm-intel` and `kvm-amd` in its `.modules`, and the build loads them with `nested=0`. Done: `qemu-host` |
| `nested-kvm` | needs `kvm`: the guests may run virtual machines too, `kvm-arm.mode=nested` or `nested=1`. Done |

`kvm`, `nested-kvm`, `packet` and `netadmin` are built; `ebpf` and
`io_uring` wait for a form that needs them. Every form built on `dhcp`
keeps both network capabilities, as its client must. The
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

That form is `prod-ebpf`. It includes `autoupdate`, as production forms do,
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
| `read`, `write`, `run` | Landlock filesystem rules: everything else is invisible to reads and writes, and cannot be run |
| `listen`, `connect` | Landlock TCP rules (ABI 4, Linux 6.7): the ports it may bind and reach |
| (always) | Landlock scoping (ABI 6, Linux 6.12): no abstract UNIX sockets or signals outside its own domain |
| (always) | `no_new_privs`, an empty bounding set and no capabilities, but `CAP_NET_BIND_SERVICE` for a port below 1024: `mount`, `umount2`, `pivot_root`, `chroot`, `unshare`, `setns` and `reboot` are refused by the kernel already, with user namespaces off, so a second seccomp filter would add nothing; the seal's covers the rest |

Landlock checks run on path lookup and connect; nothing of leash runs once
the service has started. leash starts no service as root: one that needs
root (sshd, the updater) sandboxes itself or is not yet sandboxed, below.

| Service | Runs as | Notes |
| --- | --- | --- |
| nginx, the demo's status page and scan | their own users | leashed (docs/demo.md) |
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
later check in `commit` reads them from PID 1 rather than from init's
intentions. CI's boot test (verified-boot.md, *Releases*) checks the same,
and that `bpf()`, `perf_event_open()` and `io_uring_setup()` fail as root,
or, on `prod-ebpf`, that a BPF program loads and
`bpf_probe_write_user` does not.

### Command line

Some hardening has no runtime switch. The build writes what the image asks
for, from its architecture and allowances (Makefile, `KERNEL_ARGS`), into
the image as `/usr/share/werewolf/cmdline` and beside it as the slot's
`cmdline`. bite and `disk/build` write it into the entries they make; the
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
   `mount` (mount/mount.zig), which also keeps a mount from being loosened
   by werewolf's own scripts. The seal is what will stop root.
2. **The seal**: init's PID 1 filter and bounding set, less the
   allowances. Closes eBPF, perf, io_uring and the rest for good on every
   form that did not ask for them. Done, but for the `ebpf` and
   `io_uring` allowances, which no form asks for yet.
3. **`prod-ebpf`**, and CI booting it with a BPF program.
4. **Services**: their own users, and each `run` script through `leash`.
5. **Posture**: the boot line, the check in `commit`, and CI's boot test.
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

- **`CAP_SYS_ADMIN`.** `commit` mounts the boot partition and the updater
  mounts the victim's filesystem, both at runtime. Until those move into
  init or out of the machine (verified-boot.md phase 3), root keeps
  `CAP_SYS_ADMIN`, and with it can remount `/proc/sys` and undo the
  reversible sysctls. Forms without either could drop it now.
- **DHCP** (`dhcp/dhcp.zig`, used when the command line names no
  address) separates its own privileges, as OpenBSD's dhclient does. It
  opens and filters its packet socket as root, then forks. The engine,
  which alone reads the network, runs as `_dhcp`, chrooted to `/var/empty`,
  with no capabilities and a seccomp allowlist. The parent keeps only
  `CAP_NET_ADMIN`, to apply leases, under seccomp and Landlock. So the
  dhcp service needs `CAP_NET_RAW` and `CAP_NET_ADMIN` only when it starts,
  and the seal can leave it those two at start; `packet` need not widen.
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
