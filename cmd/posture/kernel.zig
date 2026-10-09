//! kernel holds posture's kernel checks: lockdown, modules, sysctls, the
//! CPU, memory, and the features exploits reach for.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const linux = std.os.linux;
const testing = std.testing;

const allow = @import("allow");
const audit = @import("audit");
const posture = @import("posture.zig");
const inChild = @import("attacks.zig").inChild;
const errnoText = @import("network.zig").errnoText;
const Posture = posture.Posture;
const capBit = posture.capBit;
const exists = posture.exists;
const joined = posture.joined;
const lessString = posture.lessString;
const listAdd = posture.listAdd;
const statusField = posture.statusField;
const trim = posture.trim;

/// read_only is a string constant, so it lives in read-only memory.
const read_only: []const u8 = "posture: read-only";

/// writesOwnReadOnly reports whether this process can write its own
/// read-only memory through /proc/self/mem, which Linux allows by default
/// (proc_mem.force_override). It writes the same bytes back, so a write that
/// lands changes nothing.
fn writesOwnReadOnly() bool {
    const rc = linux.open("/proc/self/mem", .{ .ACCMODE = .WRONLY, .CLOEXEC = true }, 0);
    if (linux.errno(rc) != .SUCCESS) return false;
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    const n = linux.pwrite(fd, read_only.ptr, read_only.len, @intCast(@intFromPtr(read_only.ptr)));
    return linux.errno(n) == .SUCCESS and n == read_only.len;
}

/// makes32BitSyscall reports whether a 32-bit getpid through int 0x80
/// works. A kernel without 32-bit calls raises SIGSEGV, which is handled
/// here so it is not logged. x86_64 only.
fn makes32BitSyscall() bool {
    const act: linux.Sigaction = .{
        .handler = .{ .handler = &refused },
        .mask = linux.sigemptyset(),
        .flags = 0,
    };
    _ = linux.sigaction(.SEGV, &act, null);
    const pid = asm volatile ("int $0x80"
        : [ret] "={eax}" (-> u32),
        : [number] "{eax}" (@as(u32, 20)), // getpid, in the 32-bit table
        : .{ .r8 = true, .r9 = true, .r10 = true, .r11 = true, .memory = true });
    return @as(i32, @bitCast(pid)) == linux.getpid();
}

fn refused(_: linux.SIG) callconv(.c) void {
    linux.exit_group(0);
}

pub fn check(p: *Posture) !void {
    const level = lockdownLevel(p.read("/sys/kernel/security/lockdown"));
    const locked = isLocked(level);
    const lowered = locked and p.root and !p.refused("/sys/kernel/security/lockdown", "none");
    try p.add(.{
        .id = "kernel-lockdown",
        .area = "kernel",
        .name = "Kernel lockdown",
        .why = "Root cannot change the running kernel: no /dev/mem, no unsigned code, no " ++
            "hibernation images.",
        .how = if (p.root)
            "lockdown is integrity or higher, and writing none is refused"
        else
            "lockdown is integrity or higher",
        .result = if (locked and !lowered) .pass else .fail,
        .detail = level,
    });
    try p.oneWay(
        "kernel-modules-closed",
        "Kernel module loading closed",
        "No new kernel code can be loaded after boot, by anyone.",
        "kernel/modules_disabled",
        "1",
        "0",
    );
    const tainted = std.fmt.parseInt(u64, p.sysctl("kernel/tainted"), 10) catch
        std.math.maxInt(u64);
    try p.add(.{
        .id = "kernel-modules-signed",
        .area = "kernel",
        .name = "Only signed kernel modules",
        .why = "Every module in the kernel was signed by whoever built the kernel.",
        .how = "the kernel's unsigned-module taint (bit 13) is clear",
        .result = if (tainted & (1 << 13) == 0) .pass else .fail,
    });
    const kexec_off = std.mem.eql(u8, p.sysctl("kernel/kexec_load_disabled"), "1");
    try p.add(.{
        .id = "kernel-kexec",
        .area = "kernel",
        .name = "No booting another kernel",
        .why = "Root cannot replace the running kernel with kexec.",
        .how = "kernel.kexec_load_disabled is 1, or lockdown (integrity) refuses unsigned " ++
            "kexec",
        .result = if (kexec_off or locked) .pass else .fail,
    });
    try p.oneWay(
        "kernel-ptrace",
        "No process debugging",
        "No process can read or change another's memory, root's included.",
        "kernel/yama/ptrace_scope",
        "3",
        "0",
    );
    try p.oneWay(
        "kernel-bpf",
        "BPF only for root",
        "Ordinary users cannot load BPF programs into the kernel.",
        "kernel/unprivileged_bpf_disabled",
        "1",
        "0",
    );
    try p.sysctls(
        "kernel-hidden",
        "kernel",
        "Kernel addresses and log hidden",
        "An exploit cannot read kernel addresses or the kernel's log.",
        &.{ .{ "kernel/kptr_restrict", "2" }, .{ "kernel/dmesg_restrict", "1" } },
    );
    const paranoid = p.sysctl("kernel/perf_event_paranoid");
    const perf = std.fmt.parseInt(i32, paranoid, 10) catch -9;
    try p.add(.{
        .id = "kernel-perf",
        .area = "kernel",
        .name = "Performance events restricted",
        .why = "Ordinary users cannot watch the kernel through performance counters.",
        .how = "kernel.perf_event_paranoid is 2 or more",
        .result = if (perf >= 2) .pass else .fail,
        .detail = paranoid,
    });
    try p.sysctls(
        "kernel-userns",
        "kernel",
        "No user namespaces",
        "Removes kernel code that privilege-escalation exploits often start from.",
        &.{.{ "user/max_user_namespaces", "0" }},
    );
    try p.sysctls(
        "kernel-io-uring",
        "kernel",
        "No io_uring",
        "Removes a large interface that has carried many kernel exploits.",
        &.{.{ "kernel/io_uring_disabled", "2" }},
    );
    try p.sysctls(
        "kernel-sysrq",
        "kernel",
        "No SysRq",
        "The console's magic keys cannot dump memory or reboot.",
        &.{.{ "kernel/sysrq", "0" }},
    );
    try p.sysctls(
        "kernel-core-dumps",
        "kernel",
        "No core dumps of privileged programs",
        "A program that changed its privileges leaves no memory dump behind.",
        &.{.{ "fs/suid_dumpable", "0" }},
    );

    // A hypervisor in the guest reaches the host's nested-virtualization
    // code. arm64 kernels build KVM in and start it whenever the host gives
    // the guest EL2, so closing the module loader does not help.
    const kvm = exists(p.io, "/dev/kvm") or exists(p.io, "/sys/class/misc/kvm");
    try p.add(.{
        .id = "kernel-no-hypervisor",
        .area = "kernel",
        .name = "No hypervisor inside",
        .why = "The machine cannot run virtual machines of its own, so root cannot reach " ++
            "the host's nested-virtualization code, where guest-to-host escapes are found.",
        .how = "neither /dev/kvm nor /sys/class/misc/kvm exists",
        .result = if (kvm) .fail else .pass,
        .detail = if (kvm) "KVM is running" else "",
    });
    // Where KVM runs, its guests must not nest hypervisors: a guest's root
    // reaches the host through nested virtualization (CVE-2026-53359).
    // x86_64's vendor modules expose a parameter; aarch64's KVM nests only
    // when the command line asks.
    var nested: std.ArrayList(u8) = .empty;
    for ([_][]const u8{ "kvm_intel", "kvm_amd" }) |m| {
        const on = trim(p.read(try p.gpa.print("/sys/module/{s}/parameters/nested", .{m})));
        if (std.mem.eql(u8, on, "Y") or std.mem.eql(u8, on, "1"))
            try listAdd(p.gpa, &nested, "{s}.nested is {s}", .{ m, on });
    }
    var args = std.mem.tokenizeAny(u8, p.read("/proc/cmdline"), " \n");
    while (args.next()) |a| if (std.mem.eql(u8, a, "kvm-arm.mode=nested"))
        try listAdd(p.gpa, &nested, "kvm-arm.mode=nested", .{});
    try p.add(.{
        .id = "kernel-no-nested",
        .area = "kernel",
        .name = "Guests cannot nest",
        .why = "Virtual machines run here cannot run their own, so a guest's root cannot " ++
            "reach this host through nested virtualization.",
        .how = "KVM is not running, or kvm_intel's and kvm_amd's nested parameter is off, " ++
            "and the command line has no kvm-arm.mode=nested",
        .result = if (kvm and nested.items.len > 0) .fail else .pass,
        .detail = if (!kvm) "no KVM" else nested.items,
    });
    const debugfs = hasFilesystem(p.read("/proc/filesystems"), "debugfs");
    try p.add(.{
        .id = "kernel-debugfs",
        .area = "kernel",
        .name = "No kernel debug filesystem",
        .why = "debugfs, a large window onto the kernel's internals that lockdown only " ++
            "partly closes, cannot be mounted, even by root.",
        .how = "debugfs is not in /proc/filesystems",
        .result = if (debugfs) .fail else .pass,
        .detail = if (debugfs) "debugfs is available" else "",
    });
    const forced = writesOwnReadOnly();
    try p.add(.{
        .id = "kernel-proc-mem",
        .area = "kernel",
        .name = "Read-only memory stays read-only",
        .why = "A program cannot rewrite its own code through /proc/self/mem, as a shell " ++
            "and dd do to run a program where nothing written may run (DDexec).",
        .how = "writing to a read-only page of this program through /proc/self/mem is " ++
            "refused (it writes the bytes already there)",
        .result = if (forced) .fail else .pass,
        .detail = if (forced) "the write went through" else "",
    });
    try legacy(p);
    // Capabilities gone from PID 1's bounding set are gone for every process
    // until reboot. NET_ADMIN and NET_RAW may stay if the form allows them.
    const status = p.read("/proc/1/status");
    const bnd = statusField(status, "CapBnd");
    const allowed = try p.allowances();
    var held: std.ArrayList(u8) = .empty;
    next: for (bounded_caps) |c| {
        if (c.allowance()) |kept| for (allowed) |a| if (std.mem.eql(
            u8,
            a,
            @tagName(kept),
        )) continue :next;
        if (capBit(status, "CapBnd", @backingInt(c)) orelse false)
            try listAdd(p.gpa, &held, "{s}", .{c.name()});
    }
    try p.add(.{
        .id = "kernel-bounding-set",
        .area = "kernel",
        .name = "Root's capabilities bounded",
        .why = "Not even root can load kernel code, reach hardware or ports, trace " ++
            "processes, make device files, mount or configure filesystems, or, unless the " ++
            "machine's form allows it, change the network or open packet sockets.",
        .how = "PID 1's CapBnd in /proc/1/status lacks each of them; every process descends " ++
            "from PID 1",
        .result = if (bnd == null) .skip else if (held.items.len == 0) .pass else .fail,
        .detail = if (bnd == null)
            "cannot read /proc/1/status"
        else if (held.items.len > 0)
            try p.gpa.print("held: {s}", .{held.items})
        else
            "",
    });
    // Programs the kernel starts itself (core dump pipes, modprobe, the
    // uevent helper) descend from kthreadd, not PID 1, so only these sysctls
    // bound them. Only root can read them.
    const helpers = helperCaps(p.sysctl("kernel/usermodehelper/bset"));
    const hotplug = p.sysctl("kernel/hotplug");
    const modprobe = p.sysctl("kernel/modprobe");
    var helper_held: std.ArrayList(u8) = .empty;
    if (helpers) |set| for (helper_denied) |c| {
        if (set & (@as(u64, 1) << @backingInt(c)) != 0)
            try listAdd(p.gpa, &helper_held, "{s}", .{c.name()});
    };
    try p.add(.{
        .id = "kernel-helpers",
        .area = "kernel",
        .name = "Kernel-started programs bounded",
        .why = "A program the kernel starts itself, which neither PID 1's seccomp filter " ++
            "nor its bounding set reaches, cannot load kernel code, reach hardware, trace " ++
            "processes, mount or change the network, and no program is started on every " ++
            "device event or to load a module.",
        .how = "kernel.usermodehelper.bset lacks each of those capabilities, and " ++
            "kernel.hotplug and kernel.modprobe are empty",
        .result = if (!p.root)
            .skip
        else if (helpers == null)
            .fail
        else if (helper_held.items.len == 0 and hotplug.len == 0 and modprobe.len == 0)
            .pass
        else
            .fail,
        .detail = if (!p.root)
            "readable by root alone"
        else if (helpers == null)
            "cannot read kernel.usermodehelper.bset"
        else if (helper_held.items.len > 0)
            try p.gpa.print("held: {s}", .{helper_held.items})
        else if (hotplug.len > 0)
            try p.gpa.print("kernel.hotplug is {s}", .{hotplug})
        else if (modprobe.len > 0)
            try p.gpa.print("kernel.modprobe is {s}", .{modprobe})
        else
            "",
    });
    // A seccomp filter on PID 1 binds every later process, root's too, until
    // reboot. werewolf's seal (cmd/init/seal.zig) installs it.
    const filtered = std.mem.eql(u8, statusField(status, "Seccomp") orelse "", "2");
    try p.add(.{
        .id = "kernel-seal",
        .area = "kernel",
        .name = "Every process under a seccomp filter",
        .why = "System calls nothing here makes are refused for every process, root's " ++
            "included, by a filter on PID 1 that no one can remove.",
        .how = "/proc/1/status reads Seccomp: 2, a filter, which every process inherits",
        .result = if (status.len == 0) .skip else if (filtered) .pass else .fail,
        .detail = if (status.len == 0)
            "cannot read /proc/1/status"
        else if (!filtered)
            try p.gpa.print("Seccomp: {s}", .{statusField(status, "Seccomp") orelse "absent"})
        else
            "",
    });
    try writeXorExecute(p);
    try aslr(p);
    const min_addr = p.sysctl("vm/mmap_min_addr");
    try p.add(.{
        .id = "kernel-null-page",
        .area = "kernel",
        .name = "Low memory unmappable",
        .why = "No program can map the first 64 KiB of memory, where a kernel bug that " ++
            "follows a null pointer would find it.",
        .how = "vm.mmap_min_addr is 65536 or more",
        .result = if ((std.fmt.parseInt(u64, min_addr, 10) catch 0) >= 65536) .pass else .fail,
        .detail = try p.gpa.print(
            "vm.mmap_min_addr is {s}",
            .{if (min_addr.len > 0) min_addr else "absent"},
        ),
    });
    // Only root can read it. If absent, the kernel has no BPF JIT.
    const harden = p.sysctl("net/core/bpf_jit_harden");
    try p.add(.{
        .id = "kernel-bpf-jit",
        .area = "kernel",
        .name = "Users' BPF compiled hardened",
        .why = "The socket and seccomp filters any user may install are compiled with their " ++
            "constants blinded, so they cannot plant chosen machine code in the kernel (JIT " ++
            "spraying).",
        .how = "net.core.bpf_jit_harden is 1 or 2, or the kernel has no BPF JIT",
        .result = if (!p.root)
            .skip
        else if (harden.len == 0 or std.mem.eql(u8, harden, "1") or
            std.mem.eql(u8, harden, "2"))
            .pass
        else
            .fail,
        .detail = if (!p.root)
            "readable by root alone"
        else if (harden.len == 0)
            "no BPF JIT"
        else
            try p.gpa.print("net.core.bpf_jit_harden is {s}", .{harden}),
    });
    const oops = p.sysctl("kernel/panic_on_oops");
    const warn = p.sysctl("kernel/warn_limit");
    const panic_s = p.sysctl("kernel/panic");
    try p.add(.{
        .id = "kernel-oops",
        .area = "kernel",
        .name = "A kernel bug stops the kernel",
        .why = "A kernel that hits a bug, or catches its own memory corrupted, as a " ++
            "failed exploit often makes it, reboots rather than running on for the " ++
            "exploit to try again.",
        .how = "kernel.panic_on_oops is 1, kernel.warn_limit is 1, so the first warning " ++
            "panics too, and kernel.panic is not 0 (below 0 reboots at once), so the " ++
            "panic reboots rather than hangs",
        .result = if (std.mem.eql(u8, oops, "1") and std.mem.eql(u8, warn, "1") and
            (std.fmt.parseInt(i64, panic_s, 10) catch 0) != 0)
            .pass
        else
            .fail,
        .detail = try p.gpa.print(
            "kernel.panic_on_oops is {s}, kernel.warn_limit is {s}, kernel.panic is {s}",
            .{ oops, warn, panic_s },
        ),
    });
    // Some hardening can only be set at boot. The build writes the image's
    // command line from the form's allowances; a machine booted from an
    // edited or stale loader entry lacks protections nothing can add later.
    const own = p.read("/usr/share/werewolf/cmdline");
    const missing = try missingArgs(p.gpa, own, p.read("/proc/cmdline"));
    try p.add(.{
        .id = "kernel-cmdline",
        .area = "kernel",
        .name = "Booted as the image asks",
        .why = "The kernel was started with every hardening argument the image asks for, " ++
            "which it cannot be given later.",
        .how = "every argument in /usr/share/werewolf/cmdline is in /proc/cmdline",
        .result = if (own.len == 0) .skip else if (missing.len == 0) .pass else .fail,
        .detail = if (own.len == 0)
            "not werewolf: no /usr/share/werewolf/cmdline"
        else if (missing.len > 0)
            try p.gpa.print("missing: {s}", .{missing})
        else
            "",
    });
    // If absent, the kernel has no userfaultfd.
    const uffd = p.sysctl("vm/unprivileged_userfaultfd");
    try p.add(.{
        .id = "kernel-userfaultfd",
        .area = "kernel",
        .name = "No userfaultfd for users",
        .why = "Ordinary users cannot stall the kernel at a page fault, the usual way to " ++
            "win the race in a kernel exploit.",
        .how = "vm.unprivileged_userfaultfd is 0, or the kernel has no userfaultfd",
        .result = if (uffd.len == 0 or std.mem.eql(u8, uffd, "0")) .pass else .fail,
        .detail = if (uffd.len == 0)
            "no userfaultfd"
        else
            try p.gpa.print("vm.unprivileged_userfaultfd is {s}", .{uffd}),
    });
    try p.add(.{
        .id = "kernel-vsyscall",
        .area = "kernel",
        .name = "No vsyscall page",
        .why = "No code sits at the one fixed address every process shares, for an exploit " ++
            "to jump to.",
        .how = "/proc/self/maps has no [vsyscall] mapping (vsyscall=none)",
        .result = if (std.mem.indexOf(u8, p.read("/proc/self/maps"), "[vsyscall]") == null)
            .pass
        else
            .fail,
    });
    // Children inherit PID 1's limits, and only root can raise a hard limit.
    const core = hardCoreLimit(p.read("/proc/1/limits"));
    try p.add(.{
        .id = "kernel-core-limit",
        .area = "kernel",
        .name = "No core dumps at all",
        .why = "A program that crashes leaves no copy of its memory, and the secrets in it, " ++
            "on disk.",
        .how = "PID 1's hard limit on core file size (/proc/1/limits) is 0, so no process " ++
            "it starts can raise its own",
        .result = if (core) |c| (if (std.mem.eql(u8, c, "0")) .pass else .fail) else .skip,
        .detail = if (core) |c|
            try p.gpa.print("hard limit is {s}", .{c})
        else
            "cannot read /proc/1/limits",
    });
    try memory(p);
    // werewolf skips these by choice because they slow workloads
    // (docs/security.md, "Not done, by choice"), so only --extended checks them.
    if (p.extended) try costly(p);
    const modules = p.read("/proc/modules");
    const protocols = p.read("/proc/net/protocols");
    const filesystems = p.read("/proc/filesystems");
    const rare = try featuresPresent(p.gpa, &rare_features, modules, protocols, filesystems);
    try p.add(.{
        .id = "kernel-rare-features",
        .area = "kernel",
        .name = "No rarely used protocols or filesystems",
        .why = "Kernel code for old protocols, filesystems and buses, where exploits keep " ++
            "being found, is not in the running kernel.",
        .how = "none of " ++ comptime joined(&rare_features) ++
            " in /proc/modules, /proc/net/protocols or /proc/filesystems",
        .result = if (rare.len == 0) .pass else .fail,
        .detail = rare,
    });
    const exploited = try featuresPresent(
        p.gpa,
        &exploited_features,
        modules,
        protocols,
        filesystems,
    );
    try p.add(.{
        .id = "kernel-exploited-modules",
        .area = "kernel",
        .name = "No modules exploited in the wild",
        .why = "Kernel code that exploits in CISA's catalog of known exploited " ++
            "vulnerabilities went through (AF_ALG, kernel TLS, nf_tables, ebtables, " ++
            "x_tables, overlayfs) is not in the running kernel.",
        .how = "none of " ++ comptime joined(&exploited_features) ++
            " in /proc/modules, /proc/net/protocols or /proc/filesystems",
        .result = if (exploited.len == 0) .pass else .fail,
        .detail = exploited,
    });
    try exploitEntries(p);
}

/// cpuVulnerable lists the CPU flaws the kernel reports itself vulnerable
/// to, or null if it reports on none.
fn cpuVulnerable(p: *Posture) !?[]const u8 {
    const dir = "/sys/devices/system/cpu/vulnerabilities";
    var d = Dir.cwd().openDir(p.io, dir, .{ .iterate = true }) catch return null;
    defer d.close(p.io);
    var names: std.ArrayList([]const u8) = .empty;
    var it = d.iterate();
    while (it.next(p.io) catch null) |e| try names.append(p.gpa, try p.gpa.dupe(u8, e.name));
    std.mem.sort([]const u8, names.items, {}, lessString);
    var found: std.ArrayList(u8) = .empty;
    for (names.items) |name| {
        const text = trim(p.read(try p.gpa.print("{s}/{s}", .{ dir, name })));
        if (std.mem.startsWith(u8, text, "Vulnerable")) try listAdd(p.gpa, &found, "{s}", .{name});
    }
    return found.items;
}

/// exploitEntries tries the first step of four exploited kernel bugs as the
/// exploit would, so it finds the code whether built in, loaded, or loaded
/// on demand (docs/cve-mitigation-survey.md).
fn exploitEntries(p: *Posture) !void {
    const alg = linux.socket(AF_ALG, linux.SOCK.SEQPACKET | linux.SOCK.CLOEXEC, 0);
    const alg_e = linux.errno(alg);
    if (alg_e == .SUCCESS) _ = linux.close(@intCast(alg));
    try p.add(.{
        .id = "kernel-af-alg",
        .area = "kernel",
        .name = "No kernel crypto sockets",
        .why = "No program can drive the kernel's crypto code through an AF_ALG socket, " ++
            "the way into CVE-2025-39964 and CVE-2026-31431 (Copy Fail), which writes " ++
            "into the cached copy of any file it can read.",
        .how = "socket(AF_ALG) fails",
        .result = if (alg_e == .SUCCESS) .fail else .pass,
        .detail = if (alg_e == .SUCCESS) "opened" else errnoText(alg_e),
    });

    // Without kernel TLS, setsockopt fails with ENOENT, or the seal refuses
    // it. With kernel TLS, an unconnected socket gets ENOTCONN.
    const tcp = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    var ulp_e = linux.errno(tcp);
    if (ulp_e == .SUCCESS) {
        ulp_e = linux.errno(linux.setsockopt(@intCast(tcp), SOL_TCP, TCP_ULP, "tls", 3));
        _ = linux.close(@intCast(tcp));
    }
    try p.add(.{
        .id = "kernel-ktls",
        .area = "kernel",
        .name = "No kernel TLS",
        .why = "No program can hand a socket's TLS records to the kernel, the way into " ++
            "CVE-2025-39682.",
        .how = "setsockopt(TCP_ULP, \"tls\") on a TCP socket fails with ENOENT, no such " ++
            "protocol, or ENOSYS, the seal's refusal",
        .result = if (linux.errno(tcp) != .SUCCESS)
            .skip
        else if (ulp_e == .NOENT or ulp_e == .NOSYS)
            .pass
        else
            .fail,
        .detail = if (linux.errno(tcp) != .SUCCESS)
            "cannot open a TCP socket"
        else
            errnoText(ulp_e),
    });

    var fds: [2]i32 = undefined;
    const pipe = linux.syscall2(.pipe2, @intFromPtr(&fds), O_CLOEXEC | O_NOTIFICATION_PIPE);
    const pipe_e = linux.errno(pipe);
    if (pipe_e == .SUCCESS) for (fds) |fd| {
        _ = linux.close(fd);
    };
    try p.add(.{
        .id = "kernel-watch-queue",
        .area = "kernel",
        .name = "No notification pipes",
        .why = "No program can make a watch-queue pipe, the way into CVE-2022-0995.",
        .how = "pipe2(O_NOTIFICATION_PIPE) fails",
        .result = if (pipe_e == .SUCCESS) .fail else .pass,
        .detail = if (pipe_e == .SUCCESS) "made" else errnoText(pipe_e),
    });

    // Without devpts mounted, /dev/ptmx fails with ENODEV. A form that
    // allows pty, for ssh logins, mounts it and passes as allowed.
    const ptmx = linux.open(
        "/dev/ptmx",
        .{ .ACCMODE = .RDWR, .NOCTTY = true, .CLOEXEC = true },
        0,
    );
    const ptmx_e = linux.errno(ptmx);
    if (ptmx_e == .SUCCESS) _ = linux.close(@intCast(ptmx));
    const pty_allowed = for (try p.allowances()) |a| {
        if (std.mem.eql(u8, a, @tagName(allow.Allowance.pty))) break true;
    } else false;
    try p.add(.{
        .id = "kernel-no-pty",
        .area = "kernel",
        .name = "No pseudo-terminals",
        .why = "No program, root included, can open a pseudo-terminal, the way into " ++
            "CVE-2014-0196 and the TTY layer's other bugs, unless the machine's form " ++
            "allows it for logins.",
        .how = "open(/dev/ptmx) fails, as it does with no devpts mounted, or the form " ++
            "allows pty",
        .result = if (ptmx_e != .SUCCESS or pty_allowed) .pass else .fail,
        .detail = if (ptmx_e != .SUCCESS)
            errnoText(ptmx_e)
        else if (pty_allowed)
            "allowed: pty"
        else
            "opened",
    });
}

/// legacy tries the 32-bit and 16-bit interfaces a 64-bit x86 kernel keeps
/// for old programs: int 0x80, and the LDT that 16-bit code needs. int 0x80
/// runs in a child that handles the refusal's SIGSEGV, so nothing is logged.
fn legacy(p: *Posture) !void {
    const id = "kernel-legacy";
    const name = "No 32-bit or 16-bit system calls";
    const why = "The separate system-call paths kept for old programs, a frequent source of " ++
        "kernel bugs, cannot be reached.";
    if (builtin.cpu.arch != .x86_64) return p.add(.{
        .id = id,
        .area = "kernel",
        .name = name,
        .why = why,
        .how = "tried on x86_64 alone",
        .result = .skip,
        .detail = "only a 32-bit program can make a 32-bit system call here",
    });
    const int80 = inChild(makes32BitSyscall, false);
    var ldt: [16]u8 = undefined;
    const ldt_read = linux.syscall3(.modify_ldt, 0, @intFromPtr(&ldt), ldt.len);
    var open: std.ArrayList(u8) = .empty;
    if (int80 orelse false) try listAdd(p.gpa, &open, "int 0x80 works", .{});
    if (linux.errno(ldt_read) == .SUCCESS) try listAdd(p.gpa, &open, "modify_ldt works", .{});
    try p.add(.{
        .id = id,
        .area = "kernel",
        .name = name,
        .why = why,
        .how = "a 32-bit getpid through int 0x80 is refused, and so is modify_ldt(2) " ++
            "reading the LDT",
        .result = if (open.items.len > 0) .fail else if (int80 == null) .skip else .pass,
        .detail = if (open.items.len > 0)
            open.items
        else if (int80 == null)
            "could not fork to try int 0x80"
        else
            "",
    });
}

/// aslr checks address randomization is at the kernel's maximum: the
/// mmap_rnd_bits of a 4K-page kernel with 48-bit addresses, as x86_64 and
/// aarch64 servers run. Only root can read it.
fn aslr(p: *Posture) !void {
    const full: ?u8 = switch (builtin.cpu.arch) {
        .x86_64 => 32,
        .aarch64 => 33,
        else => null,
    };
    const va = p.sysctl("kernel/randomize_va_space");
    const bits = p.sysctl("vm/mmap_rnd_bits");
    const ok = std.mem.eql(u8, va, "2") and
        (std.fmt.parseInt(u8, bits, 10) catch 0) >= (full orelse 0);
    try p.add(.{
        .id = "kernel-aslr",
        .area = "kernel",
        .name = "Full address randomization",
        .why = "An exploit cannot guess where a program's code, libraries and heap are.",
        .how = "kernel.randomize_va_space is 2, and vm.mmap_rnd_bits is the kernel's most: " ++
            "32 on x86_64, 33 on aarch64",
        .result = if (full == null or !p.root) .skip else if (ok) .pass else .fail,
        .detail = if (full == null)
            "no known maximum on this architecture"
        else if (!p.root)
            "vm.mmap_rnd_bits is readable by root alone"
        else
            try p.gpa.print(
                "kernel.randomize_va_space is {s}, vm.mmap_rnd_bits is {s} of {d}",
                .{ va, bits, full.? },
            ),
    });
}

/// memory checks the kernel memory hardening that costs programs nothing.
/// It judges what is in effect, not the command line alone, since a kernel
/// may enable it by default (Alpine's clears memory on allocation).
fn memory(p: *Posture) !void {
    const cmdline = p.read("/proc/cmdline");
    var missing: std.ArrayList(u8) = .empty;
    // Merged caches show in sysfs as links to the cache they share.
    const merged = if (slabAliases(p)) |n|
        n > 0
    else
        (try unsetArgs(p.gpa, cmdline, &.{"slab_nomerge"})).len > 0;
    if (merged) try listAdd(p.gpa, &missing, "kernel caches merged", .{});
    const shuffle = trim(p.read("/sys/module/page_alloc/parameters/shuffle"));
    const shuffled = if (shuffle.len > 0)
        std.mem.eql(u8, shuffle, "Y")
    else
        (try unsetArgs(p.gpa, cmdline, &.{"page_alloc.shuffle"})).len == 0;
    if (!shuffled) try listAdd(p.gpa, &missing, "pages not shuffled", .{});
    // If the log has rotated, trust the command line if it says on; else unknown.
    const alloc = heapInit(memAutoInit(p), "heap alloc") orelse
        if ((try unsetArgs(p.gpa, cmdline, &.{"init_on_alloc"})).len == 0) true else null;
    if (alloc == false) try listAdd(p.gpa, &missing, "memory not cleared as it is handed out", .{});
    try p.add(.{
        .id = "kernel-memory-hardening",
        .area = "kernel",
        .name = "Kernel memory hardened",
        .why = "Memory is cleared as it is handed out, kernel objects of one kind never " ++
            "share a cache with another's, and pages are handed out in no predictable " ++
            "order, so leaked data and memory corruption are harder to use.",
        .how = "no merged caches in /sys/kernel/slab (slab_nomerge), page_alloc's shuffle " ++
            "parameter is Y, and the kernel's boot line says heap alloc:on (or " ++
            "init_on_alloc is on the command line)",
        .result = if (missing.items.len > 0) .fail else if (alloc == null) .skip else .pass,
        .detail = if (missing.items.len > 0)
            missing.items
        else if (alloc == null)
            "the kernel's log no longer holds its mem auto-init line"
        else
            "",
    });
}

/// slabAliases counts the caches in /sys/kernel/slab merged into another,
/// or returns null if it cannot be read.
fn slabAliases(p: *Posture) ?usize {
    var d = Dir.cwd().openDir(p.io, "/sys/kernel/slab", .{ .iterate = true }) catch return null;
    defer d.close(p.io);
    var n: usize = 0;
    var it = d.iterate();
    while (it.next(p.io) catch return null) |e| {
        if (e.kind == .sym_link) n += 1;
    }
    return n;
}

/// memAutoInit returns the kernel's boot "mem auto-init:" line, or "".
fn memAutoInit(p: *Posture) []const u8 {
    const rc = linux.open(
        "/dev/kmsg",
        .{ .ACCMODE = .RDONLY, .NONBLOCK = true, .CLOEXEC = true },
        0,
    );
    if (linux.errno(rc) != .SUCCESS) return "";
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    var record: [8192]u8 = undefined;
    while (true) {
        const n = linux.read(fd, &record, record.len);
        switch (linux.errno(n)) {
            .SUCCESS => if (std.mem.indexOf(u8, record[0..n], "mem auto-init:")) |i| {
                const line = record[i..n];
                return p.gpa.dupe(
                    u8,
                    line[0 .. std.mem.findScalar(u8, line, '\n') orelse line.len],
                ) catch "";
            },
            .PIPE => {}, // older records were overwritten; keep reading
            else => return "",
        }
    }
}

/// costly adds the kernel checks werewolf fails by choice, for --extended:
/// wiping freed memory and forcing CPU mitigations slow every workload.
fn costly(p: *Posture) !void {
    const free_on = heapInit(memAutoInit(p), "heap free") orelse
        ((try unsetArgs(p.gpa, p.read("/proc/cmdline"), &.{"init_on_free"})).len == 0);
    try p.add(.{
        .id = "kernel-memory-wipe",
        .area = "kernel",
        .name = "Freed memory wiped",
        .why = "Memory is cleared as it is freed, so what a program or the kernel held does " ++
            "not linger for a later bug to read.",
        .how = "the kernel's boot line says heap free:on, or the command line turns on " ++
            "init_on_free",
        .result = if (free_on) .pass else .fail,
        .detail = if (free_on) "" else "init_on_free is off",
    });
    const vulnerable = try cpuVulnerable(p);
    try p.add(.{
        .id = "kernel-cpu-mitigations",
        .area = "kernel",
        .name = "CPU flaws mitigated",
        .why = "No known processor flaw lets one program read another's memory, or the " ++
            "kernel's.",
        .how = "no file in /sys/devices/system/cpu/vulnerabilities reads Vulnerable",
        .result = if (vulnerable) |v| (if (v.len == 0) .pass else .fail) else .skip,
        .detail = vulnerable orelse "the kernel reports no CPU flaws",
    });
}

/// writeXorExecute checks Memory-Deny-Write-Execute, which werewolf's init
/// sets and every process inherits. It also tries a writable and executable
/// anonymous mapping, unmapped at once if made, which must be refused.
fn writeXorExecute(p: *Posture) !void {
    const PR_GET_MDWE = 66;
    const PR_MDWE_REFUSE_EXEC_GAIN = 1;
    const rc = linux.prctl(PR_GET_MDWE, 0, 0, 0, 0);
    const known = linux.errno(rc) == .SUCCESS;
    const set = known and rc & PR_MDWE_REFUSE_EXEC_GAIN != 0;
    const len = std.heap.pageSize();
    const addr = linux.mmap(
        null,
        len,
        .{ .READ = true, .WRITE = true, .EXEC = true },
        .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
        -1,
        0,
    );
    const mapped = linux.errno(addr) == .SUCCESS;
    if (mapped) _ = linux.munmap(@ptrFromInt(addr), len);
    try p.add(.{
        .id = "kernel-write-xor-execute",
        .area = "kernel",
        .name = "No memory both writable and executable",
        .why = "Code an exploit writes into a program's memory never runs: no mapping is " ++
            "writable and executable at once, or made executable once written, so only " ++
            "programs and libraries from files run.",
        .how = "prctl(PR_GET_MDWE) reports PR_MDWE_REFUSE_EXEC_GAIN, inherited from PID 1, " ++
            "and an anonymous mapping that is readable, writable and executable is refused",
        .result = if (set and !mapped) .pass else .fail,
        .detail = if (mapped)
            "a writable and executable mapping was made"
        else if (!known)
            "the kernel has no Memory-Deny-Write-Execute (Linux 6.3)"
        else if (!set)
            "Memory-Deny-Write-Execute is off"
        else
            "",
    });
}

/// lockdownLevel returns the bracketed level: "none [integrity] confidentiality".
fn lockdownLevel(text: []const u8) []const u8 {
    const a = std.mem.findScalar(u8, text, '[') orelse return "unavailable";
    const b = std.mem.findScalarPos(u8, text, a, ']') orelse return "unavailable";
    return text[a + 1 .. b];
}

fn isLocked(level: []const u8) bool {
    return std.mem.eql(u8, level, "integrity") or std.mem.eql(u8, level, "confidentiality");
}

/// missingArgs lists the words of want that are not in have.
fn missingArgs(gpa: Allocator, want: []const u8, have: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var w = std.mem.tokenizeAny(u8, want, " \n");
    next: while (w.next()) |arg| {
        var h = std.mem.tokenizeAny(u8, have, " \n");
        while (h.next()) |x| if (std.mem.eql(u8, x, arg)) continue :next;
        try listAdd(gpa, &out, "{s}", .{arg});
    }
    return out.items;
}

/// hasFilesystem reports whether /proc/filesystems lists name: "nodev\tdebugfs", "\text4".
fn hasFilesystem(text: []const u8, name: []const u8) bool {
    var it = std.mem.tokenizeScalar(u8, text, '\n');
    while (it.next()) |line| {
        const tab = std.mem.findScalarLast(u8, line, '\t') orelse continue;
        if (std.mem.eql(u8, line[tab + 1 ..], name)) return true;
    }
    return false;
}

/// rare_features is kernel code few machines use and exploits keep finding
/// bugs in, named as /proc/modules, /proc/net/protocols (without "v6") and
/// /proc/filesystems name it.
const rare_features = [_][]const u8{
    "dccp",          "sctp",        "rds",         "tipc",      "n_hdlc",
    "ax25",          "netrom",      "x25",         "rose",      "decnet",
    "econet",        "af_802154",   "ipx",         "appletalk", "psnap",
    "p8022",         "p8023",       "can",         "atm",       "bluetooth",
    "firewire_core", "thunderbolt", "usb_storage", "cramfs",    "freevxfs",
    "jffs2",         "hfs",         "hfsplus",     "squashfs",  "udf",
    "cifs",          "ksmbd",       "gfs2",        "cfg80211",  "mac80211",
};

/// exploited_features is kernel code that exploits in CISA's KEV catalog
/// used and no werewolf form loads: AF_ALG, kernel TLS, nf_tables, ebtables,
/// x_tables and overlayfs (docs/cve-mitigation-survey.md).
const exploited_features = [_][]const u8{
    "af_alg",    "algif_aead", "algif_skcipher", "algif_hash", "algif_rng", "tls",
    "nf_tables", "ebtables",   "ip_tables",      "x_tables",   "overlay",
};

/// AF_ALG and the constants below are named here because Zig's standard
/// library lacks them (O_NOTIFICATION_PIPE reuses O_EXCL's bit) or a raw
/// call needs them as plain numbers.
const AF_ALG = 38;

const SOL_TCP = 6;

const TCP_ULP = 31;

const O_CLOEXEC = 0o2000000;

const O_NOTIFICATION_PIPE = 0o200;

/// featuresPresent lists those of names the running kernel has.
fn featuresPresent(
    gpa: Allocator,
    names: []const []const u8,
    modules: []const u8,
    protocols: []const u8,
    filesystems: []const u8,
) ![]const u8 {
    var found: std.ArrayList(u8) = .empty;
    for (names) |name| {
        if (hasFilesystem(filesystems, name) or firstWordIs(modules, name) or
            firstWordIs(protocols, name)) try listAdd(gpa, &found, "{s}", .{name});
    }
    return found.items;
}

/// firstWordIs reports whether a line of text starts with the word name, in
/// any case, optionally followed by "v6": "sctp 475136 0 - Live", "SCTPv6 ...".
fn firstWordIs(text: []const u8, name: []const u8) bool {
    var it = std.mem.tokenizeScalar(u8, text, '\n');
    while (it.next()) |line| {
        var word = line[0 .. std.mem.indexOfAny(u8, line, " \t") orelse line.len];
        if (std.ascii.endsWithIgnoreCase(word, "v6")) word = word[0 .. word.len - 2];
        if (std.ascii.eqlIgnoreCase(word, name)) return true;
    }
    return false;
}

/// heapInit reports whether the mem auto-init line says what (heap alloc,
/// heap free) is on, or null if it does not say.
fn heapInit(line: []const u8, what: []const u8) ?bool {
    const i = std.mem.indexOf(u8, line, what) orelse return null;
    const rest = line[i + what.len ..];
    if (std.mem.startsWith(u8, rest, ":on")) return true;
    if (std.mem.startsWith(u8, rest, ":off")) return false;
    return null;
}

/// unsetArgs lists the switches in names the command line does not turn
/// on. A switch is on bare or set to 1, y or on; as in the kernel, the last
/// setting wins.
fn unsetArgs(gpa: Allocator, cmdline: []const u8, names: []const []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (names) |name| {
        var on = false;
        var it = std.mem.tokenizeAny(u8, cmdline, " \t\n");
        while (it.next()) |arg| {
            if (std.mem.eql(u8, arg, name)) {
                on = true;
            } else if (std.mem.startsWith(u8, arg, name) and arg.len > name.len and
                arg[name.len] == '=')
            {
                const v = arg[name.len + 1 ..];
                on = std.mem.eql(u8, v, "1") or std.ascii.eqlIgnoreCase(v, "y") or
                    std.ascii.eqlIgnoreCase(v, "on");
            }
        }
        if (!on) try listAdd(gpa, &out, "{s}", .{name});
    }
    return out.items;
}

/// askToStop asks the kernel to stop auditing. It returns null if refused,
/// or else what went wrong.
fn askToStop() ?[]const u8 {
    audit.setEnabled(0) catch |err| return if (err == error.Refused) null else @errorName(err);
    return "audit was turned off";
}

/// logged checks that refusals are recorded and reach the console. An exec
/// of a directory, which every kernel refuses, must leave an audit record
/// in the kernel log (lib/audit.zig).
pub fn logged(p: *Posture) !void {
    _ = inChild(execRoot, false);
    // kauditd writes the record a moment after the call returns, so retry.
    const needles = [_][]const u8{
        "type=1300",
        "success=no",
        try p.gpa.print(" ppid={d} ", .{linux.getpid()}),
    };
    var on_record = false;
    for (0..20) |_| {
        if (posture.logHas(p.kernelLog(), &needles)) {
            on_record = true;
            break;
        }
        p.io.sleep(.fromMilliseconds(50), .awake) catch {};
    }
    // Ask audit to stop only if it reads locked, or is unreadable for lack
    // of the capability that stopping also needs. Unlocked audit, as on
    // other distributions, would really stop.
    const stopped: ?[]const u8 = if (!p.root)
        null
    else if (audit.enabledNow()) |now|
        if (now == audit.locked) askToStop() else "audit is not locked"
    else |err| switch (err) {
        error.Refused => askToStop(),
        else => @errorName(err),
    };
    const how = "running / as a program, which every kernel refuses, leaves its audit record " ++
        "(type=1300, success=no) in the kernel log";
    try p.add(.{
        .id = "kernel-exec-log",
        .area = "kernel",
        .name = "Refused execs logged, for good",
        .why = "An intruder's first step, running something the machine refuses, leaves a " ++
            "line in the kernel's log that nothing on the machine can prevent or stop.",
        .how = if (p.root) how ++ ", and asking the kernel to stop auditing is refused" else how,
        .result = if (on_record and stopped == null) .pass else .fail,
        .detail = if (!on_record)
            "no audit record of a refused exec"
        else
            stopped orelse "",
    });
    // Audit, lockdown, Yama and Landlock refusals are notices (level 5),
    // which reach the console only at console_loglevel 6 or more. The
    // console must be one a cloud captures, serial or hypervisor, not a
    // virtual terminal nobody watches.
    var printk = std.mem.tokenizeAny(u8, p.sysctl("kernel/printk"), " \t");
    const level = std.fmt.parseInt(u8, printk.next() orelse "", 10) catch 0;
    const console = capturedConsole(p.read("/proc/consoles"));
    try p.add(.{
        .id = "kernel-console-log",
        .area = "kernel",
        .name = "Refusals reach the console",
        .why = "What the kernel refused is seen off the machine, on a console a cloud " ++
            "captures, not only in a log an intruder may read.",
        .how = "kernel.printk's console level is 6 or more, so notices show, and " ++
            "/proc/consoles lists an enabled serial or hypervisor console",
        .result = if (level >= 6 and console != null) .pass else .fail,
        .detail = if (level < 6)
            try p.gpa.print("console loglevel is {d}", .{level})
        else if (console == null)
            "no serial or hypervisor console"
        else
            "",
    });
}

/// execRoot runs / as a program, which the kernel refuses (EACCES) and audits.
fn execRoot() bool {
    const argv = [_:null]?[*:0]const u8{"/"};
    const envp = [_:null]?[*:0]const u8{};
    _ = linux.execve("/", &argv, &envp);
    return false;
}

/// capturedConsole returns the first enabled, writable console in
/// /proc/consoles that is not a virtual terminal (tty0, tty1, …), or null.
/// A line is "ttyS0  -W- (EC p a)  4:64".
fn capturedConsole(consoles: []const u8) ?[]const u8 {
    var lines = std.mem.tokenizeScalar(u8, consoles, '\n');
    while (lines.next()) |line| {
        var f = std.mem.tokenizeAny(u8, line, " \t");
        const name = f.next() orelse continue;
        const ops = f.next() orelse continue;
        const flags = line[std.mem.findScalar(u8, line, '(') orelse continue ..];
        if (std.mem.findScalar(u8, ops, 'W') == null) continue;
        if (std.mem.findScalar(u8, flags, 'E') == null) continue;
        if (std.mem.startsWith(u8, name, "tty") and name.len > 3 and
            std.ascii.isDigit(name[3])) continue;
        return name;
    }
    return null;
}

test capturedConsole {
    try testing.expectEqualStrings(
        "ttyS0",
        capturedConsole(
            "tty0                 -WU (EC p  )    4:1\nttyS0                -W- (E  p a)    4:64\n",
        ).?,
    );
    try testing.expectEqualStrings("hvc0", capturedConsole("hvc0  -W- (EC p a)  229:0\n").?);
    try testing.expectEqual(null, capturedConsole("tty0                 -WU (EC p  )    4:1\n"));
    try testing.expectEqual(null, capturedConsole("ttyS0  -W- (  p a)  4:64\n"));
    try testing.expectEqual(null, capturedConsole(""));
}

/// hardCoreLimit returns the hard limit on a /proc/PID/limits "Max core file
/// size" line, or null.
fn hardCoreLimit(limits: []const u8) ?[]const u8 {
    const label = "Max core file size";
    var it = std.mem.tokenizeScalar(u8, limits, '\n');
    while (it.next()) |line| {
        if (!std.mem.startsWith(u8, line, label)) continue;
        var f = std.mem.tokenizeAny(u8, line[label.len..], " \t");
        _ = f.next() orelse return null; // skip the soft limit
        return f.next();
    }
    return null;
}

/// bounded_caps are the capabilities kernel-bounding-set wants gone from
/// PID 1's bounding set, unless an allowance keeps them.
const bounded_caps = [_]allow.Cap{
    .sys_module, .sys_rawio, .sys_ptrace, .mknod,   .perfmon,
    .bpf,        .sys_admin, .net_admin,  .net_raw,
};

/// helper_denied is what kernel-helpers wants gone from the helpers' bounding set.
const helper_denied = [_]allow.Cap{
    .net_admin,  .net_raw,   .sys_module, .sys_rawio,
    .sys_ptrace, .sys_admin, .perfmon,    .bpf,
};

/// helperCaps parses kernel.usermodehelper.bset, "LOW\tHIGH", as one set, or null.
fn helperCaps(text: []const u8) ?u64 {
    var it = std.mem.tokenizeAny(u8, text, " \t\n");
    const low = std.fmt.parseInt(u32, it.next() orelse return null, 10) catch return null;
    const high = std.fmt.parseInt(u32, it.next() orelse return null, 10) catch return null;
    if (it.next() != null) return null;
    return @as(u64, high) << 32 | low;
}

test lockdownLevel {
    try testing.expectEqualStrings(
        "integrity",
        lockdownLevel("none [integrity] confidentiality\n"),
    );
    try testing.expectEqualStrings("unavailable", lockdownLevel(""));
    try testing.expect(isLocked("confidentiality"));
    try testing.expect(!isLocked("none"));
}

test missingArgs {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const want = "debugfs=off proc_mem.force_override=never\n";
    try testing.expectEqualStrings(
        "",
        try missingArgs(
            a,
            want,
            "console=hvc0 debugfs=off proc_mem.force_override=never init=/init\n",
        ),
    );
    try testing.expectEqualStrings(
        "proc_mem.force_override=never",
        try missingArgs(a, want, "debugfs=off proc_mem.force_override=always\n"),
    );
    try testing.expectEqualStrings(
        "debugfs=off, proc_mem.force_override=never",
        try missingArgs(a, want, ""),
    );
    try testing.expectEqualStrings("", try missingArgs(a, "", "x"));
}

test hasFilesystem {
    const text = "nodev\tsysfs\nnodev\tdebugfs\n\text4\nnodev\tdebugfs2\n";
    try testing.expect(hasFilesystem(text, "debugfs"));
    try testing.expect(hasFilesystem(text, "ext4"));
    try testing.expect(!hasFilesystem(text, "tracefs"));
    try testing.expect(!hasFilesystem("nodev\tsysfs\n", "debugfs"));
}

test featuresPresent {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const modules = "virtio_net 61440 0 - Live 0x0\nsctp 475136 2 - Live 0x0\nusb_storage 86016 " ++
        "0 - Live 0x0\n";
    const protocols = "protocol  size sockets  memory press maxhdr  slab module     cl co di ac " ++
        "io in de sh ss gs se re sp bi br ha uh gp em\nDCCPv6    1272      0      -1   NI       " ++
        "0   yes  dccp_ipv6   y  y\nTCP       2432      3       3   no     320   yes  kernel    " ++
        "  y  y\n";
    const filesystems = "nodev\tsysfs\n\text4\n\tsquashfs\n\terofs\n";
    try testing.expectEqualStrings(
        "dccp, sctp, usb_storage, squashfs",
        try featuresPresent(a, &rare_features, modules, protocols, filesystems),
    );
    try testing.expectEqualStrings(
        "",
        try featuresPresent(
            a,
            &rare_features,
            "virtio_net 61440 0 - Live 0x0\n",
            "TCP 2432\nUDPv6 1472\n",
            "\text4\n",
        ),
    );
    try testing.expectEqualStrings(
        "nf_tables, overlay",
        try featuresPresent(
            a,
            &exploited_features,
            "nf_tables 368640 0 - Live 0x0\nvirtio_net 61440 0 - Live 0x0\n",
            "TCP 2432\n",
            "nodev\toverlay\n\text4\n",
        ),
    );
    // A name must be a whole word: hfsplus is not hfs, candle is not can.
    try testing.expect(!firstWordIs("hfsplus 1 0\ncandle 1 0\n", "hfs"));
    try testing.expect(!firstWordIs("candle 1 0\n", "can"));
}

test heapInit {
    const line = "mem auto-init: stack:all(zero), heap alloc:on, heap free:off";
    try testing.expectEqual(true, heapInit(line, "heap alloc"));
    try testing.expectEqual(false, heapInit(line, "heap free"));
    try testing.expectEqual(null, heapInit("", "heap alloc"));
    try testing.expectEqual(null, heapInit("heap alloc:maybe", "heap alloc"));
}

test unsetArgs {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const names = [_][]const u8{
        "init_on_alloc",
        "init_on_free",
        "slab_nomerge",
        "page_alloc.shuffle",
        "randomize_kstack_offset",
    };
    try testing.expectEqualStrings(
        "",
        try unsetArgs(
            a,
            "init=/init init_on_alloc=1 init_on_free=on slab_nomerge page_alloc.shuffle=y " ++
                "randomize_kstack_offset=1\n",
            &names,
        ),
    );
    try testing.expectEqualStrings(
        "init_on_alloc, init_on_free, slab_nomerge, page_alloc.shuffle, randomize_kstack_offset",
        try unsetArgs(a, "console=ttyS0 panic=10\n", &names),
    );
    // The last setting wins, and a longer name is a different switch.
    try testing.expectEqualStrings(
        "init_on_alloc",
        try unsetArgs(a, "init_on_alloc=1 init_on_alloc=0", &.{"init_on_alloc"}),
    );
    try testing.expectEqualStrings(
        "slab_nomerge",
        try unsetArgs(a, "slab_nomerge_x", &.{"slab_nomerge"}),
    );
}

test hardCoreLimit {
    const limits =
        \\Limit                     Soft Limit           Hard Limit           Units
        \\Max file size             unlimited            unlimited            bytes
        \\Max core file size        0                    unlimited            bytes
        \\Max open files            1024                 4096                 files
    ;
    try testing.expectEqualStrings("unlimited", hardCoreLimit(limits).?);
    try testing.expectEqualStrings(
        "0",
        hardCoreLimit(
            "Max core file size        0                    0                    bytes\n",
        ).?,
    );
    try testing.expectEqual(null, hardCoreLimit(""));
}

test helperCaps {
    try testing.expectEqual(1 << 22, helperCaps("4194304\t0\n").?);
    try testing.expectEqual((1 << 41) - 1, helperCaps("4294967295\t511").?);
    try testing.expectEqual(null, helperCaps(""));
    try testing.expectEqual(null, helperCaps("1"));
    try testing.expectEqual(null, helperCaps("1 2 3"));
    try testing.expectEqual(null, helperCaps("x 0"));
}
