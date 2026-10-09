# Lockdown

Proposed, 2026-10-06. Built (cmd/init, lib/seal.zig, cmd/fence) but for
`confidentiality` lockdown, the `ebpf` and `io_uring` allowances, our kernel.

## Summary

Once a werewolf machine has booted, root cannot change the running kernel,
watch or hook it, or reach beyond what each service needs, until a reboot.

## Background

OpenBSD's `securelevel` takes privilege away after boot. Linux has the
parts: lockdown, one-way sysctls, seccomp on PID 1, the bounding set and
Landlock. Without them root can load eBPF rootkits and trace the kernel,
and anyone can reach io_uring, user namespaces and 32-bit calls, which
exploits favour. [verified-boot.md](verified-boot.md) decides what code
runs; this design limits what it may do.

## Goals

- Not even root can load or trace kernel code, or regain a capability.
- A service reaches only the calls, paths and ports its service file grants.
- Only the seal costs throughput, and posture proves every control.

## Non-Goals

- Removing kernel bugs, deciding what code runs, or stopping persistence.

## Detailed design

Each control holds until a reboot. [security.md](../security.md) has more.

| Control | Stops | posture check |
| --- | --- | --- |
| Lockdown `integrity`; module loader closed | `/dev/mem`, unsigned kexec, new kernel code | `kernel-lockdown`, `kernel-modules-closed` |
| Sysctls: ptrace 3, no user namespaces or io_uring, hidden pointers and log, link protections, panic on oops and first warning; MDWE unless `jit` | other processes' memory; paths exploits start from; a corrupt kernel running on; written code running | `kernel-ptrace`, `kernel-userns`, `kernel-oops`, `kernel-write-xor-execute` |
| The seal: seccomp on PID 1 | every call no promise names; other architectures' calls | `kernel-seal`, `kernel-legacy`, `kernel-af-alg` |
| Bounding set; helpers' set `CAP_SYS_BOOT`, `kernel.hotplug` and `modprobe` empty | modules, BPF, perf, raw I/O, ptrace, mknod; after fence, network changes, packet sockets, mounts; helpers with every capability | `kernel-bounding-set`, `kernel-helpers` |
| fence's Landlock domain | writing `/proc/sys`, mounting, opening devices | `files-system-writes`, `files-device-reads` |
| `hidepid=invisible`; memory filesystems `noexec` | seeing others' processes; running what one wrote | `processes-hidden`, `files-exec-refused` |
| Command line, from the image's arch and allowances: `debugfs=off`, `proc_mem.force_override=never`, `slab_nomerge`, `page_alloc.shuffle=1`, `ipv6.disable=1`, `ia32_emulation=0`, `kvm-arm.mode=none` | what has no runtime switch | `kernel-cmdline` |
| leash, for services someone else wrote ([README](../../cmd/leash/README.md)); werewolf's root programs separate themselves ([programs.md](../programs.md)) | a service reaching past its grant | `processes-services-leashed`, `processes-leash-attack` |
| Audit of refused execs, locked (`lib/audit.zig`) | an intruder's first step unrecorded | `kernel-exec-log` |

**The seal** passes a call only if a promise allows it, werewolf's own or a
service's ([pledge.md](pledge.md)), so calls new kernels add are refused
too. seal-watch answers the rest `ENOSYS`, so probing programs fall back.
`bpf()` also accepts `CAP_SYS_ADMIN`, so the seal is what stops eBPF.

**What the seal costs.** Any filter takes the kernel's slower path, though
its length is free, since verdicts are cached. On an M4 Max, `getpid` took
125 ns bare and 150 sealed (Alpine's 6.18): 2–5% of a small `read`.

### Allowances

A form takes back a default by name in form.yaml's `allow` (`lib/allow.zig`):
`kvm`, `nested-kvm` (`qemu-host`), `packet`, `netadmin`, `ipv6`, `pty`
(`sshd`) and `jit` (`node`, `jre`, `php`, `postgresql`, `example-aspnet`).
Only the image decides: nothing reads one from the command line or config.

**Not built: eBPF.** `ebpf` would give `prod-ebpf` `bpf`, `perf_event_open`,
`CAP_BPF`, `CAP_PERFMON` and `CAP_NET_ADMIN`, never `bpf_probe_write_user`.
Other forms would raise lockdown to `confidentiality`, losing only tracing.

**Our kernel** (verified-boot.md phase 4) adds arm64 KASLR, hardened free
lists, shadow stacks, data-corruption checks and a static usermode helper,
and drops compat calls, the LDT, kexec and exploited code no form uses.
BTI and kCFI need it built with clang, which Alpine and Ubuntu do not use.

### Open questions

- **fentry, fexit.** Alpine lacks `FUNCTION_TRACER`; which agents fall back?
- **The BPF LSM** is not in `CONFIG_LSM`, so enforcing agents need our kernel.
- **Landlock and UDP.** Landlock has no UDP rules, so QUIC and DNS are open.
- **Devices.** fence closes `/dev`; a GPU or TPM would need a `device` line.

## Drawbacks

- 25 ns a call; no ptrace or perf; any kernel warning reboots the machine.
- Left out for their cost: `init_on_free`, `nosmt`, forced mitigations,
  hardened_malloc, stackleak, `PAGE_TABLE_CHECK`, auditd and IMA.

## Alternatives Considered

- **A command-line switch for eBPF**: root on a bitten machine rewrites GRUB.
- **`integrity` everywhere**, as today, lets a kprobe rootkit read the kernel.
- **eBPF built out** needs a second kernel; **the BPF LSM** uses eBPF.
- **A list of calls**: allowed, it breaks on glibc updates; refused, it ages.

## Security Considerations

After fence, root cannot write `/proc/sys`, mount, load or trace kernel
code, ptrace or open packet sockets. Open (security.md): the mount broker
and DHCP's renewal run outside fence, the kernel's helpers outside the seal.

## Reliability Considerations

- **Fails closed.** A control not set ends PID 1; the last good slot boots.
- **Logged.** seal-watch logs each refusal once; posture checks each boot.
