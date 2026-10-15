# Our kernel

Proposed, 2026-10-15. Replaces `boot/build-kernel` ([ipe.md](ipe.md), phase 4 of
[verified-boot.md](verified-boot.md)) and Alpine's `linux-virt` on every machine. The
repository `werewolf-linux/kernel` follows [glibc-neutered](glibc-neutered.md).

## Summary

A kernel for virtual machines whose configuration is one explicit list: every option
that is on is named with the form or hypervisor that needs it; everything else is off,
including what future kernels add. Built with Clang for kCFI, tuned for throughput with
PostgreSQL as the yardstick, published as signed APKs hours after each `stable` release.

## Background

werewolf boots Alpine's `linux-virt`: 2,572 options on x86_64, 884 of them modules,
of which forms load nineteen; the rest is reachable code posture works to prove off.
IPE needs our own build anyway (phase 4, opt-in). [linux-7.md](linux-7.md) wanted 7.x
for Landlock's socket rules and declined Alpine's `linux-stable` for its patch lag.
Building from kernel.org removes the lag: the series is what kernel.org's
[releases.json](https://www.kernel.org/releases.json) names `stable`, 7.2 today.

## Goals

- Every form passes `make check` on QEMU, both arches; prod-ssh on every provider.
- Under 40% of `linux-virt`'s options (971 of 2,572 on x86_64 today).
- `kernel-hardening-checker` reports no `FAIL` outside the repository's exceptions.
- pgbench on the postgresql form: TPS and p99 no worse than on `linux-virt`.
- A kernel.org point release is in the stable repository within two hours, both arches.

## Non-Goals

- Source patches beyond the MDWE line in `security/ipe/hooks.c`; release candidates.
- Accelerated-networking VFs (mlx5, MANA), GPUs, nested TPMs; hardware, Xen, VMware.

## Detailed design

**Source.** `scripts/refresh.py` takes the highest non-EOL `stable` version from
`releases.json`, verifies `linux-VERSION.tar.sign` against the committed keys of Greg
Kroah-Hartman and Linus Torvalds, and locks the tarball's SHA-256 with our own files.

**Configuration.** `config/common.cfg`, `config/x86_64.cfg` and `config/aarch64.cfg`
name every option that is on, one per line with its reason. `make config` runs
`make KCONFIG_ALLCONFIG=<fragments> allnoconfig`, so nothing unnamed is on, then checks
that each line held (an unmet dependency fails its line and is added, visibly) and that
`config/deny.cfg`, what no `select` may bring back, holds. The result is committed as
`config/ARCH.config`, the build's input byte for byte; `olddefconfig` must not change
it. A new series adds its options off. Alpine's `virt` config seeded the first list and
stays a report, `make compare`, never an input.

| On, by need | Options |
| --- | --- |
| QEMU, Lima VZ, bhyve, Proxmox | `VIRTIO_PCI`, `VIRTIO_BLK`, `VIRTIO_NET`, `VIRTIO_CONSOLE` (hvc0), `HW_RANDOM_VIRTIO`, `SCSI_VIRTIO`, `BLK_DEV_SR`+`ISO9660_FS` (cidata), `SERIAL_8250`, `SERIAL_AMBA_PL011`, `GPIO_PL061`+`KEYBOARD_GPIO`, `ACPI_BUTTON`+`INPUT_EVDEV`, `TCG_TIS`, `RTC_DRV_PL031`/`RTC_DRV_EFI` |
| Firecracker | `VIRTIO_MMIO` with `CMDLINE_DEVICES`, both arches |
| AWS, GCP, Azure | `BLK_DEV_NVME`, `ENA_ETHERNET`, `GVE`, `HYPERV`+`HYPERV_STORAGE`+`HYPERV_NET`+`HYPERV_TIMER`, `TCG_CRB`, `ACPI_APEI`, `X86_MCE`+`MEMORY_FAILURE`, `HOTPLUG_PCI_ACPI`, `EFI`, `EFI_STUB`, `EFIVAR_FS`, `DMI_SYSFS` |
| werewolf | `EROFS_FS`+`ZIP_ZSTD`, `DM_VERITY`, `DM_CRYPT`, `BLK_DEV_LOOP`, `EXT4_FS`, `VFAT_FS`+`NLS_CODEPAGE_437`+`NLS_UTF8`, `TMPFS`, `DEVTMPFS`, `SECURITYFS`, `SECURITY_IPE`+`IPE_PROP_DM_VERITY`, `SECURITY_LANDLOCK` (ABI 10 in 7.2: UNIX-socket rules for leash, UDP rules, `ADD_RULE_QUIET`, `RESTRICT_SELF_TSYNC`), `SECURITY_YAMA`, `SECURITY_LOCKDOWN_LSM`, `SECCOMP_FILTER`, `AUDIT`+`AUDITSYSCALL`, `CGROUPS` with `MEMCG`, `CGROUP_PIDS`, `FAIR_GROUP_SCHED`, `IP_MULTIPLE_TABLES` (fence), `PACKET` (DHCP), `UNIX`, `INET`, `SYSVIPC`, `POSIX_CPU_TIMERS_TASK_WORK`, `IKCONFIG_PROC`, `KVM` (`qemu-host`; `kvm-arm.mode=none` elsewhere), `CRYPTO_AES_NI_INTEL`/`CRYPTO_AES_ARM64_CE_BLK`, `CRYPTO_XTS`, SHA-256 |
| Self-protection, Clang 22 (Wolfi `clang-22`, `lld-22`, `llvm-22`, pinned) | `LTO_CLANG_THIN`, `CFI` (kCFI; no GCC release has it), `KSTACK_ERASE`, `INIT_STACK_ALL_ZERO`, `ZERO_CALL_USED_REGS`, `UBSAN_BOUNDS`+`UBSAN_TRAP`, `RANDOMIZE_BASE` on both arches, `RANDOMIZE_MEMORY`, `RANDOMIZE_KSTACK_OFFSET_DEFAULT`, `STACKPROTECTOR_STRONG`, `VMAP_STACK`, `STRICT_KERNEL_RWX`, `DEBUG_WX`, `SLAB_FREELIST_RANDOM`, `SLAB_FREELIST_HARDENED`, `KMALLOC_PARTITION_TYPED` (7.2: Clang allocation tokens give each type its own kmalloc cache, so type confusion cannot be groomed), `SLAB_BUCKETS`, `SHUFFLE_PAGE_ALLOCATOR`, `INIT_ON_ALLOC_DEFAULT_ON`, `HARDENED_USERCOPY`, `FORTIFY_SOURCE`, `BUG_ON_DATA_CORRUPTION`, `LIST_HARDENED`, `SCHED_STACK_END_CHECK`, `MSEAL_SYSTEM_MAPPINGS`, `LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY`, `SECURITY_DMESG_RESTRICT`, `PROC_MEM_NO_FORCE`, `STATIC_USERMODEHELPER` with an empty path, `LEGACY_VSYSCALL_NONE`, `LSM="landlock,lockdown,yama,ipe"`, `SYSTEM_TRUSTED_KEYS=release/ipe.crt` (the committed production certificate; `IPE_CRT=` overrides it for a local kernel), `IPE_BOOT_POLICY=boot/ipe-boot.policy` |
| x86 | `X86_FRED` (7.1 default: hardware event delivery, no SYSCALL/IDT paths), LASS where the CPU has it (7.1; needs `LEGACY_VSYSCALL_NONE`), `X86_KERNEL_IBT`, `X86_USER_SHADOW_STACK`, `X86_INTEL_TSX_MODE_OFF`, every `MITIGATION_*`, `KVM_GUEST`, `PARAVIRT_SPINLOCKS`, `PARAVIRT_TIME_ACCOUNTING`, `HALTPOLL_CPUIDLE` (poll before HLT: lower wakeup latency for PostgreSQL's latches) |
| arm64 | errata workarounds for every Arm and Ampere core, as each runs only on the CPU it names; `ARM64_CONTPTE`, `ARM64_HAFT`, `ARM64_TLB_RANGE`; `ARM64_PTR_AUTH`, `ARM64_BTI` (user space only: kernel BTI needs Clang < 21 in 7.2, and kCFI covers forward edges), `ARM64_MTE`, `ARM64_GCS`, `ARM64_POE`, `ARM64_LSUI` (7.1: user access without lifting PAN), `SHADOW_CALL_STACK` (`DYNAMIC_SCS`), `ARM64_E0PD`, `ARM64_EPAN`, `ARM64_SW_TTBR0_PAN`; 7.2 unmaps the linear alias of kernel data and hardens the cBPF JIT seccomp uses |
| Throughput | `PREEMPT_LAZY` (7.0 removed `NONE` and `VOLUNTARY` on x86 and arm64; lazy preempts fair tasks only at the tick, the server model), `HZ_250`, `NO_HZ_IDLE` (not `NO_HZ_FULL`: it costs every syscall and engages only with `nohz_full=`), `HYPERV_TIMER` (`clock_gettime` stays in the vDSO: `EXPLAIN ANALYZE`, `track_io_timing`), `NUMA` without balancing, `TRANSPARENT_HUGEPAGE_MADVISE` with shmem and tmpfs at `advise` and `HUGETLBFS` (`huge_pages=try`; `always` gives compaction stalls), `LRU_GEN_ENABLED` (7.2's reclaim rewrite: up to 30% on YCSB), `SCHED_CACHE` (7.2: a process's tasks share an LLC), `PER_VMA_LOCK`, `RSEQ` with `RSEQ_SLICE_EXTENSION`, `MEMBARRIER`, `MQ_IOSCHED_DEADLINE` alone, no `BLK_CGROUP`, CUBIC default with `TCP_CONG_BBR` and `NET_SCH_FQ` available, `NR_CPUS=512`, generic x86-64 (Proxmox's `kvm64` lacks v2; kernel code gains little from v3) |

| Off, with the reason | Options |
| --- | --- |
| No code after boot | `MODULES` (the loader and `/proc/modules` cease to exist) |
| No form uses it | `NETFILTER`, `BRIDGE`, `VLAN_8021Q`, `BONDING`, `TUN`, `VETH`, `WIREGUARD`, `IPV6` (`ipv6.disable=1` on every form today; a revision restores it), `TLS`, `MPTCP`, `XFRM`, `INET_DIAG`, `IP_PNP`, `IP_MULTICAST`, `VSOCKETS`, `IO_URING` (PostgreSQL 18 keeps `io_method=worker`), `BPF_SYSCALL` (seccomp's cBPF needs only `BPF_JIT`), `AIO`, `USERFAULTFD`, `KCMP`, `CHECKPOINT_RESTORE`, `USER_NS`, `FHANDLE`, `UID16`, `SYSFS_SYSCALL`, `SGETMASK_SYSCALL`, `POSIX_MQUEUE`, `COREDUMP`, `BINFMT_MISC`, `KEXEC`, `HIBERNATION`, `PM_SLEEP`, `MEMORY_HOTPLUG`, `CPU_FREQ`, `COMPAT`, `IA32_EMULATION`, `X86_X32_ABI`, `MODIFY_LDT_SYSCALL`, `X86_VSYSCALL_EMULATION`, `X86_MSR`, `X86_CPUID`, `X86_IOPL_IOPERM`, `DEVMEM`, `DEVPORT`, `PROC_KCORE`, `PROC_VMCORE`, `ARMV8_DEPRECATED`, `XEN`, `IOMMU_SUPPORT` (every device is the host's), `KSM`, `SWAP`, `ZSWAP`, `ZRAM`, `NUMA_BALANCING`, `SCHED_AUTOGROUP`, `SCHED_CORE`, `VT`, `FB`, `DRM`, `SOUND`, `USB`, `HID`, `WATCHDOG`, `PVPANIC`, `ATA`, every `ARCH_*` SoC, `PID_NS`, `NET_NS`, `IPC_NS`, `UTS_NS`, `TIME_NS` (no program creates one), `FTRACE`, `KPROBES`, `DEBUG_FS`, `MAGIC_SYSRQ`, `DEBUG_INFO`, `KALLSYMS_ALL`, `LATENCYTOP`, `PROFILING`, `CRYPTO_USER_API`, `STAGING` |
| Costs more than it protects here | `INIT_ON_FREE_DEFAULT_ON` (zeroes every freed page, 5–10% on fork-heavy PostgreSQL), `PAGE_TABLE_CHECK` and `DEBUG_VIRTUAL` (page-fault-path cost for debug-grade checks), `RANDSTRUCT` (a public reproducible build keeps no secret), `KFENCE` (a sampling debugger), `EFI_DISABLE_PCI_DMA` and `RESET_ATTACK_MITIGATION` (physical attacks) |
| Stays, though it looks like surface | `KVM` (one form; `/dev/kvm` is unlinked elsewhere), `IKCONFIG_PROC` (the evidence posture reads), `PERF_EVENTS` and `MICROCODE` (x86 selects both; the sysctl stays at 3, the hypervisor refuses microcode), `KALLSYMS` (readable oopses, with `kptr_restrict=2`) |

**Package.** `linux-werewolf-7.2.11-rN` (N is `policy.json`'s revision), kernel release
`7.2.11-werewolf`: `boot/vmlinuz-werewolf` (bzImage, or a raw arm64 `Image`),
`boot/config-7.2.11-werewolf`, `boot/kernel-package`, `boot/ipe.crt`; no `lib/modules`.
Melange builds it in glibc-neutered's runners, reproducibly; R2 `apk/kernel/` holds the
stable repository `https://dist.werewolf-linux.org/apk/kernel` and immutable snapshots.
Each GitHub release carries the config, implied options, checker report and boot logs.

**werewolf changes**, in order:

| Where | Change |
| --- | --- |
| `boot/` | `kernel.yaml` names our repository and `release/packages.pub`; `alpine-keys`, `build-kernel`, `kernel-source`, `ipe-kernel.melange.yaml`, `tools/sign-kernel`, `test/check-kernel-*` and `kernel-repro.yml` go |
| Names | the `linux-virt-` prefix (`lib/cve.zig`, `cmd/howl/packages.zig`, `cmd/slot-update`, `release/*`) becomes `linux-werewolf-`; the updater adds `linux-werewolf` from our repository with werewolf's key and drops `allow_legacy_sha1` |
| Modules | `modules:` lines, modload and `werewolf.modules` go; stage0 no longer deletes `/usr/lib/modules` |
| `cmd/init` | stops writing the sysctls of removed features (`modules_disabled`, `modprobe`, `io_uring_disabled`, `unprivileged_bpf_disabled`, `max_user_namespaces`, `sysrq`, `bpf_jit_harden`); unlinks `/dev/kvm` without the `kvm` allowance; `console=tty0` leaves x86 command lines; `werewolf.disable=ipe` adds `ipe.enforce=0` for local builds |
| Checks | posture reads `/proc/config.gz` for `kernel-modules-closed`, `kernel-io-uring`, `kernel-bpf`, `kernel-userns` and `boot-sig-enforced`; `lib/ipe.zig` accepts `FORCE_CONFIDENTIALITY` |

## Drawbacks

A kernel to keep patched forever, though kernel.org patches and CI builds. A series
every nine to ten weeks, each a provider test pass. Our Clang build shares no binary
with anyone's. A dropped driver or protocol, IPv6 included, waits for a revision.

## Alternatives Considered

### Merge our policy over Alpine's config
Less typing, but what is on becomes "Alpine's defaults plus `olddefconfig`'s choices",
readable only by diffing, and new series add options silently.

### Keep modules for what one form needs (KVM, dm-crypt, drivers)
Keeps the loader, signing, modload and the `KMODULE` policy to save about 2 MB of text.

### GCC, as Alpine; kernel.org `longterm`; Alpine's `linux-stable`
No kCFI until GCC 17, and kCFI is the one mitigation that changes the exploit class.
`longterm` is older code with fewer reviews; `policy.json` can name it. Alpine's
`linux-stable` lags and opens what we close ([linux-7.md](linux-7.md)).

## Security Considerations

Everything reachable is used by a form today, and the fragment names which; the four
exceptions are in the table above. A machine's trust roots shrink to werewolf's key and
Wolfi's. kernel.org is trusted through two committed developer keys, checked before
anything is hashed. The IPE certificate is public; a kernel trusting another key is a
different build, refused by Secure Boot and the updater. Mitigations stay `auto`.

## Reliability Considerations

Every provider boot is a gate: QEMU on both arches in the kernel repository's CI before
publication, werewolf's provider A/B tests before a release picks the kernel up. Drift
fails closed: a fragment line that stops holding, a config `olddefconfig` would change,
a series kernel.org has ended. A published APK is never replaced; A/B slots keep the
previous kernel. `PANIC_ON_OOPS` and `PANIC_TIMEOUT=10` reboot a wedged kernel.
