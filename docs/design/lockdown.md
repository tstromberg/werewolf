# Lockdown

Proposed, 2026-10-06. Built (cmd/stage0, cmd/init, lib/seal.zig, cmd/fence)
but for the `ebpf` and `io_uring` allowances; our kernel is
[custom-kernel.md](custom-kernel.md).

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
| Lockdown forced to `confidentiality`; no module loader (`CONFIG_MODULES` off) | `/dev/mem`, kexec, new kernel code | `kernel-lockdown`, `kernel-modules-closed` |
| Sysctls: ptrace 3, no user namespaces or io_uring (both also not built), hidden pointers and log, link protections, panic on oops and first warning; MDWE unless `jit` | other processes' memory; paths exploits start from; a corrupt kernel running on; written code running | `kernel-ptrace`, `kernel-userns`, `kernel-oops`, `kernel-write-xor-execute` |
| The seal: seccomp on PID 1 | every call no promise names; other architectures' calls | `kernel-seal`, `kernel-legacy`, `kernel-af-alg` |
| Bounding set; helpers' set `CAP_SYS_BOOT`, `kernel.hotplug` and `modprobe` empty or absent | modules, BPF, perf, raw I/O, ptrace, mknod; after fence, network changes, packet sockets, mounts; helpers with every capability | `kernel-bounding-set`, `kernel-helpers` |
| fence's Landlock domain | writing `/proc/sys`, mounting, opening devices | `files-system-writes`, `files-device-reads` |
| `hidepid=invisible`; memory filesystems `noexec` | seeing others' processes; running what one wrote | `processes-hidden`, `files-exec-refused` |
| Command line, from the image's arch and allowances (`lib/compose.zig`): `proc_mem.force_override=never`, `slab_nomerge`, `page_alloc.shuffle=1`, and KVM kept off without `kvm` (`kvm-arm.mode=none`; on x86 `initcall_blacklist=vt_init,svm_init`); debugfs, IPv6 and 32-bit emulation are not built | what has no runtime switch | `kernel-cmdline` |
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
`kvm`, `nested-kvm` (`qemu-host`), `packet`, `netadmin`, `pty`
(`sshd`), `jit` (`node`, `jre`, `php`, `postgresql`, `aspnet-example`) and
`sh` (`sh-shim`).
Only the image decides: nothing reads one from the command line or config.

**Not built: eBPF.** `ebpf` would give `prod-ebpf` `bpf`, `perf_event_open`,
`CAP_BPF`, `CAP_PERFMON` and `CAP_NET_ADMIN`, never `bpf_probe_write_user`.
It would hold lockdown at `integrity`; every form now raises it to
`confidentiality`, losing only tracing.

**Our kernel** ([custom-kernel.md](custom-kernel.md)), built with Clang for
kCFI, adds arm64 KASLR, hardened free lists, shadow call stacks,
data-corruption checks and a static usermode helper, and drops modules,
compat calls, the LDT, kexec, BPF, io_uring and exploited code no form uses.

### Open questions

- **eBPF agents.** Our kernel builds no `bpf` call, BPF LSM or
  `FUNCTION_TRACER`, so `ebpf` needs a kernel revision; which agents fall back?
- **Landlock and UDP.** fence already holds UDP to each user's declared
  ports; Landlock's UDP rules (ABI 10) would repeat it ([linux-7.md](linux-7.md)).
- **Devices.** fence closes `/dev`; a GPU or TPM would need a `device` line.

## Drawbacks

- 25 ns a call; no ptrace or perf; any kernel warning reboots the machine.
- Left out for their cost: `init_on_free`, `nosmt`, forced mitigations,
  hardened_malloc, `PAGE_TABLE_CHECK`, auditd and IMA.

## Alternatives Considered

- **A command-line switch for eBPF**: an unsigned boot configuration can weaken policy.
- **`integrity` everywhere**, as before, lets a kprobe rootkit read the kernel.
- **The BPF LSM** uses eBPF.
- **A list of calls**: allowed, it breaks on glibc updates; refused, it ages.

## Security Considerations

After fence, root cannot write `/proc/sys`, mount, load or trace kernel
code, ptrace or open packet sockets. Open (security.md): the mount broker
and DHCP's renewal run outside fence, the kernel's helpers outside the seal.

## Reliability Considerations

- **Fails closed.** A control not set ends PID 1; the last good slot boots.
- **Logged.** seal-watch logs each refusal once; posture checks each boot.
