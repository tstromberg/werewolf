//! posture: measure a Linux machine's security posture, and print it as a
//! list of what passed and failed, or as JSON.
//!
//!     posture           check, print, and exit 1 if any check fails
//!     posture --json    the same, as JSON, with why and how each was checked
//!     posture --line    the same, as one line for a console or a log:
//!                       posture: fail=ID,ID pass=N skip=N {JSON}
//!     posture --noop    exit 0 at once: what the run-a-program checks run
//!
//! --extended adds the checks werewolf fails by choice, because meeting
//! them would slow what machines run, or is not yet shown safe with fence
//! (docs/security.md, "Not done, by choice"): wiping freed memory,
//! forced CPU mitigations, strict reverse-path filtering, and ignoring
//! IPv6 router advertisements. Any Linux can be measured against them.
//!
//! Each check says what it protects against in plain words, how it was
//! checked, and whether it passed. Where it is safe, a check tests rather
//! than reads: it asks the kernel to undo a one-way setting and expects a
//! refusal, and it copies itself into each writable place and into a memfd
//! and expects the copy not to start. It asks the kernel only when the
//! setting already reads as locked, when the refusal is certain, so a check
//! that fails never weakens the machine. Nothing touches another process or
//! /dev/mem, which would write to the kernel log, unless the kernel command
//! line has werewolf.check=1: werewolf's tests set it, and posture then also
//! attacks the machine and expects each attack refused (attacks, below).
//!
//! Run as root for the whole picture; as another user some checks read what
//! they can and some are skipped. It assumes nothing of werewolf: run it on
//! any Linux to compare. werewolf's own checks (its services, its declared
//! ports, /victim) are skipped where those do not exist.
//!
//! In werewolf it is also a service, run once a boot as /etc/sv/posture/run:
//! it waits for the other services to settle, so it sees the machine as it
//! runs, checks, keeps the JSON in /run/werewolf/posture.json, says the
//! --line on the console, and parks itself.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const linux = std.os.linux;

pub fn main(init: std.process.Init) !void {
    const gpa = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(gpa);
    if (args.len == 2 and std.mem.eql(u8, args[1], "--noop")) return;
    if (args.len == 2 and std.mem.eql(u8, args[1], "--probe")) std.process.exit(probe());
    if (std.mem.eql(u8, std.fs.path.basename(args[0]), "run")) return serve(io, gpa);
    var format: Format = .text;
    var extended = false;
    for (args[1..]) |a| {
        if (std.mem.eql(u8, a, "--extended") and !extended) {
            extended = true;
        } else if (std.mem.eql(u8, a, "--json") and format == .text) {
            format = .json;
        } else if (std.mem.eql(u8, a, "--line") and format == .text) {
            format = .line;
        } else {
            std.debug.print("usage: posture [--extended] [--json | --line]\n", .{});
            std.process.exit(2);
        }
    }

    var p: Posture = .{ .io = io, .gpa = gpa, .root = linux.geteuid() == 0, .extended = extended };
    try p.run();
    const report = try p.report();
    var out: Io.Writer.Allocating = .init(gpa);
    switch (format) {
        .text => try printText(&out.writer, report, columns()),
        .json => {
            try std.json.Stringify.value(report, .{ .whitespace = .indent_2 }, &out.writer);
            try out.writer.writeByte('\n');
        },
        .line => try printLine(gpa, &out.writer, report),
    }
    try Io.File.stdout().writeStreamingAll(io, out.written());
    if (report.summary.fail > 0) std.process.exit(1);
}

const Format = enum { text, json, line };

// --- attacking as nobody ---------------------------------------------------------

const attack_run = "/run/.posture-attack";
const attack_link = "/tmp/.posture-attack-link";
const attack_secret = "/tmp/.posture-attack-secret";
const attack_hard = "/tmp/.posture-attack-hard";
const attack_file = "/tmp/.posture-attack-file";

fn cleanAttacks() void {
    for ([_][:0]const u8{
        attack_run,
        attack_link,
        attack_secret,
        attack_hard,
        attack_file,
    }) |path| _ = linux.unlink(path);
}

/// attack, run in a child as nobody: uid and gid 65534, no other groups, no
/// new privileges. Whether it worked, or null if the child could not become
/// nobody.
fn asNobody(attack: *const fn () bool) ?bool {
    return inChild(attack, true);
}

/// attack, run in a child, as nobody if asked. Whether it worked, or null if
/// there was no child, or it could not become nobody. The child makes only
/// system calls: the parent may have threads.
fn inChild(attack: *const fn () bool, as_nobody: bool) ?bool {
    const rc = linux.fork();
    if (linux.errno(rc) != .SUCCESS) return null;
    if (rc == 0) {
        const nobody = 65534;
        const none = [0]linux.gid_t{};
        if (as_nobody and
            (linux.errno(linux.prctl(
                @backingInt(linux.PR.SET_NO_NEW_PRIVS),
                1,
                0,
                0,
                0,
            )) != .SUCCESS or
                linux.errno(linux.setgroups(0, &none)) != .SUCCESS or
                linux.errno(linux.setresgid(nobody, nobody, nobody)) != .SUCCESS or
                linux.errno(linux.setresuid(nobody, nobody, nobody)) != .SUCCESS))
            linux.exit_group(2);
        linux.exit_group(if (attack()) 1 else 0);
    }
    var status: i32 = 0;
    if (linux.errno(linux.wait4(@intCast(rc), &status, 0, null)) != .SUCCESS) return null;
    const s: u32 = @bitCast(status);
    if (!linux.W.IFEXITED(s)) return null;
    return switch (linux.W.EXITSTATUS(s)) {
        0 => false,
        1 => true,
        else => null,
    };
}

fn seesInit() bool {
    return linux.errno(linux.access("/proc/1", linux.F_OK)) == .SUCCESS;
}

fn writesRun() bool {
    return created(attack_run, 0o600);
}

fn plantsLink() bool {
    return linux.errno(linux.symlink(attack_run, attack_link)) == .SUCCESS;
}

fn linksSecret() bool {
    return linux.errno(linux.link(attack_secret, attack_hard)) == .SUCCESS;
}

fn plantsFile() bool {
    return created(attack_file, 0o644);
}

fn created(path: [:0]const u8, mode: linux.mode_t) bool {
    const rc = linux.open(
        path,
        .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .CLOEXEC = true },
        mode,
    );
    if (linux.errno(rc) != .SUCCESS) return false;
    _ = linux.close(@intCast(rc));
    return true;
}

/// Whether root can open path to write, creating it if it is not there.
fn opensForWrite(path: [:0]const u8, append: bool) bool {
    const rc = linux.open(
        path,
        .{ .ACCMODE = .WRONLY, .CREAT = true, .APPEND = append, .CLOEXEC = true },
        0o600,
    );
    if (linux.errno(rc) != .SUCCESS) return false;
    _ = linux.close(@intCast(rc));
    return true;
}

/// How opening path for writing, and nothing more, ends.
fn writeOpen(path: [:0]const u8) linux.E {
    const rc = linux.open(path, .{ .ACCMODE = .WRONLY, .CLOEXEC = true, .NOFOLLOW = true }, 0);
    if (linux.errno(rc) == .SUCCESS) _ = linux.close(@intCast(rc));
    return linux.errno(rc);
}

/// The first whole disk, /dev/vda say: not a loop, RAM or mapped device.
fn firstDisk(buf: *[64]u8) [:0]const u8 {
    const dir = linux.open(
        "/sys/block",
        .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true },
        0,
    );
    if (linux.errno(dir) != .SUCCESS) return "";
    defer _ = linux.close(@intCast(dir));
    var ents: [2048]u8 align(8) = undefined;
    const n = linux.getdents64(@intCast(dir), &ents, ents.len);
    if (linux.errno(n) != .SUCCESS) return "";
    var off: usize = 0;
    while (off < n) {
        const ent: *align(1) const linux.dirent64 = @ptrCast(&ents[off]);
        off += ent.reclen;
        const name = std.mem.sliceTo(@as([*:0]const u8, @ptrCast(&ent.name)), 0);
        const virtual = [_][]const u8{ ".", "loop", "ram", "dm-", "zram" };
        for (virtual) |v| {
            if (std.mem.startsWith(u8, name, v)) break;
        } else return std.mem.printSentinel(buf, "/dev/{s}", .{name}, 0) catch "";
    }
    return "";
}

/// What writesOwnReadOnly writes over: a string, so in read-only memory.
const read_only: []const u8 = "posture: read-only";

/// Whether this process can write to its own read-only memory through
/// /proc/self/mem, as Linux lets it by default (proc_mem.force_override).
/// It writes back the bytes already there, so a write that lands changes
/// nothing.
fn writesOwnReadOnly() bool {
    const rc = linux.open("/proc/self/mem", .{ .ACCMODE = .WRONLY, .CLOEXEC = true }, 0);
    if (linux.errno(rc) != .SUCCESS) return false;
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    const n = linux.pwrite(fd, read_only.ptr, read_only.len, @intCast(@intFromPtr(read_only.ptr)));
    return linux.errno(n) == .SUCCESS and n == read_only.len;
}

/// Whether a 32-bit getpid through int 0x80 returns this process's pid. A
/// kernel without 32-bit system calls answers with SIGSEGV, handled here so
/// it is not logged. x86_64 only.
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

/// Whether modify_ldt(2) reads the LDT. x86_64 only.
fn readsLdt() bool {
    var ldt: [16]u8 = undefined;
    return linux.errno(linux.syscall3(.modify_ldt, 0, @intFromPtr(&ldt), ldt.len)) == .SUCCESS;
}

fn hasAll(haystack: []const u8, needles: []const []const u8) bool {
    for (needles) |n| if (std.mem.indexOf(u8, haystack, n) == null) return false;
    return true;
}

// --- as a service ----------------------------------------------------------------

const service_json = "/run/werewolf/posture.json";
/// How long every other service must have run, or been down by choice.
const settle_s = 5;
/// How long to wait for that before checking anyway.
const settle_max_s = 60;

fn serve(io: Io, gpa: Allocator) !void {
    var waited: u32 = 0;
    while (waited < settle_max_s and
        !settled(io, gpa)) : (waited += 1) io.sleep(.fromSeconds(1), .awake) catch {};

    var p: Posture = .{ .io = io, .gpa = gpa, .root = linux.geteuid() == 0 };
    try p.run();
    const report = try p.report();
    var json: Io.Writer.Allocating = .init(gpa);
    try std.json.Stringify.value(report, .{ .whitespace = .indent_2 }, &json.writer);
    try json.writer.writeByte('\n');
    const tmp = service_json ++ ".tmp";
    Dir.cwd().writeFile(
        io,
        .{ .sub_path = tmp, .data = json.written() },
    ) catch |err| std.debug.print("posture: {s}: {s}\n", .{ tmp, @errorName(err) });
    Dir.rename(
        Dir.cwd(),
        tmp,
        Dir.cwd(),
        service_json,
        io,
    ) catch |err| std.debug.print("posture: {s}: {s}\n", .{ service_json, @errorName(err) });

    var line: Io.Writer.Allocating = .init(gpa);
    try printLine(gpa, &line.writer, report);
    try Io.File.stdout().writeStreamingAll(io, line.written());

    // Down, so runsv does not run it again until the next boot.
    const err = std.process.replace(io, .{ .argv = &.{ "/usr/bin/sv", "down", "." } });
    std.debug.print("posture: sv down: {s}\n", .{@errorName(err)});
    std.process.exit(1);
}

/// Whether every service but this one has settled, by runsv's own account.
fn settled(io: Io, gpa: Allocator) bool {
    var d = Dir.cwd().openDir(io, "/etc/sv", .{ .iterate = true }) catch return true;
    defer d.close(io);
    const now = nowSecs(io);
    var it = d.iterate();
    while (it.next(io) catch return false) |e| {
        if (std.mem.eql(u8, e.name, "posture")) continue;
        var f = d.openFile(
            io,
            gpa.print("{s}/supervise/status", .{e.name}) catch return false,
            .{},
        ) catch return false;
        defer f.close(io);
        var status: [20]u8 = undefined;
        const n = f.readPositionalAll(io, &status, 0) catch return false;
        if (n != status.len or !serviceSettled(status, now)) return false;
    }
    return true;
}

/// Whether runsv's supervise/status says the service is down because it
/// was asked to be, or has run for settle_s. The 20 bytes are the time of
/// the last change, as TAI64N (seconds since 1970 plus 2^62 + 10), the pid,
/// paused, want ('u' or 'd'), a term flag, and the state (0 down, 1 run, 2
/// finish).
fn serviceSettled(status: [20]u8, now: u64) bool {
    const since = std.mem.readInt(u64, status[0..8], .big) -| ((1 << 62) + 10);
    return switch (status[19]) {
        0 => status[17] == 'd',
        1 => now -| since >= settle_s,
        else => false,
    };
}

/// What posture prints.
pub const Report = struct {
    tool: []const u8 = "posture",
    version: u32 = 1,
    time: []const u8,
    /// The distribution, as /etc/os-release names it.
    os: []const u8,
    host: []const u8,
    kernel: []const u8,
    root: bool,
    /// What the machine's form took back of werewolf's defaults when it was
    /// built (/etc/werewolf/allow), sorted. The checks still measure it.
    allow: []const []const u8 = &.{},
    summary: struct { pass: usize = 0, fail: usize = 0, skip: usize = 0 },
    checks: []const Check,
};

pub const Check = struct {
    id: []const u8,
    /// kernel, processes, programs, files or network.
    area: []const u8,
    name: []const u8,
    /// What it protects against, in plain words.
    why: []const u8,
    /// How it was checked, exactly.
    how: []const u8,
    result: Result,
    /// What was found, when that adds to the result.
    detail: []const u8 = "",
};

pub const Result = enum {
    pass,
    fail,
    skip,

    fn mark(r: Result) []const u8 {
        return switch (r) {
            .pass => "✅",
            .fail => "❌",
            .skip => "⚠️",
        };
    }
};

const Posture = struct {
    io: Io,
    gpa: Allocator,
    root: bool,
    /// Also the checks werewolf fails by choice (--extended).
    extended: bool = false,
    checks: std.ArrayList(Check) = .empty,

    fn add(p: *Posture, c: Check) !void {
        try p.checks.append(p.gpa, c);
    }

    /// The names in /etc/werewolf/allow, sorted.
    fn allowances(p: *Posture) ![]const []const u8 {
        var names: std.ArrayList([]const u8) = .empty;
        var d = Dir.cwd().openDir(
            p.io,
            "/etc/werewolf/allow",
            .{ .iterate = true },
        ) catch return names.items;
        defer d.close(p.io);
        var it = d.iterate();
        while (it.next(p.io) catch null) |e| try names.append(p.gpa, try p.gpa.dupe(u8, e.name));
        std.mem.sort([]const u8, names.items, {}, lessString);
        return names.items;
    }

    fn report(p: *Posture) !Report {
        const uts = std.posix.uname();
        const os_release = p.read("/etc/os-release");
        var r: Report = .{
            .time = try rfc3339(p.gpa, nowSecs(p.io)),
            .os = prettyName(if (os_release.len > 0) os_release else p.read("/usr/lib/os-release")),
            .host = try p.gpa.dupe(u8, std.mem.sliceTo(&uts.nodename, 0)),
            .kernel = try p.gpa.dupe(u8, std.mem.sliceTo(&uts.release, 0)),
            .root = p.root,
            .allow = try p.allowances(),
            .summary = .{},
            .checks = p.checks.items,
        };
        for (p.checks.items) |c| switch (c.result) {
            .pass => r.summary.pass += 1,
            .fail => r.summary.fail += 1,
            .skip => r.summary.skip += 1,
        };
        return r;
    }

    fn run(p: *Posture) !void {
        try p.kernel();
        try p.processes();
        try p.programs();
        try p.files();
        try p.network();
        var args = std.mem.tokenizeAny(u8, p.read("/proc/cmdline"), " \n");
        while (args.next()) |arg| {
            if (p.root and std.mem.eql(u8, arg, "werewolf.check=1")) return p.attacks();
        }
    }

    // --- kernel ------------------------------------------------------------

    fn kernel(p: *Posture) !void {
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
        const tainted = std.fmt.parseInt(
            u64,
            trim(p.read("/proc/sys/kernel/tainted")),
            10,
        ) catch std.math.maxInt(u64);
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
        const perf = std.fmt.parseInt(
            i32,
            trim(p.sysctl("kernel/perf_event_paranoid")),
            10,
        ) catch -9;
        try p.add(.{
            .id = "kernel-perf",
            .area = "kernel",
            .name = "Performance events restricted",
            .why = "Ordinary users cannot watch the kernel through performance counters.",
            .how = "kernel.perf_event_paranoid is 2 or more",
            .result = if (perf >= 2) .pass else .fail,
            .detail = trim(p.sysctl("kernel/perf_event_paranoid")),
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

        // A hypervisor in the guest is the way to the host's nested
        // virtualization. arm64 kernels build KVM in, and start it whenever
        // the host lends the guest EL2; closing the module loader cannot help.
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
        // Where KVM runs, its guests must not run hypervisors of their own:
        // nested virtualization is the code a guest's root reaches the host
        // through (CVE-2026-53359). x86_64's vendor modules say so in a
        // parameter; aarch64's KVM nests only when the command line asks.
        var nested: std.ArrayList(u8) = .empty;
        for ([_][]const u8{ "kvm_intel", "kvm_amd" }) |m| {
            const on = trim(p.read(try p.gpa.print(
                "/sys/module/{s}/parameters/nested",
                .{m},
            )));
            if (std.mem.eql(u8, on, "Y") or
                std.mem.eql(
                    u8,
                    on,
                    "1",
                )) try nested.print(
                p.gpa,
                "{s}{s}.nested is {s}",
                .{ if (nested.items.len > 0) ", " else "", m, on },
            );
        }
        var args = std.mem.tokenizeAny(u8, p.read("/proc/cmdline"), " \n");
        while (args.next()) |a| if (std.mem.eql(
            u8,
            a,
            "kvm-arm.mode=nested",
        )) try nested.print(
            p.gpa,
            "{s}kvm-arm.mode=nested",
            .{if (nested.items.len > 0) ", " else ""},
        );
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
        try p.legacy();
        // The bounding set: what no process, root included, can hold again
        // before a reboot. The network's two only where the form allows them.
        const status1 = p.read("/proc/1/status");
        const bnd = statusField(status1, "CapBnd");
        const allow = try p.allowances();
        var held: std.ArrayList(u8) = .empty;
        next: for (bounded_caps) |c| {
            for (allow) |a| if (c.allow.len > 0 and std.mem.eql(u8, a, c.allow)) continue :next;
            if (capBit(
                status1,
                "CapBnd",
                c.n,
            ) orelse false) try held.print(
                p.gpa,
                "{s}{s}",
                .{ if (held.items.len > 0) ", " else "", c.name },
            );
        }
        try p.add(.{
            .id = "kernel-bounding-set",
            .area = "kernel",
            .name = "Root's capabilities bounded",
            .why = "Not even root can load kernel code, reach hardware or ports, trace " ++
                "processes, make device files, or, unless the machine's form allows it, change " ++
                "the network or open packet sockets.",
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
        // The programs the kernel starts itself (core dump pipes, modprobe,
        // the uevent helper) descend from kthreadd, not PID 1: only these
        // sysctls bound them. Readable by root alone.
        const umh = trim(p.read("/proc/sys/kernel/usermodehelper/bset"));
        const hotplug = trim(p.read("/proc/sys/kernel/hotplug"));
        var helper_held: std.ArrayList(u8) = .empty;
        if (helperCaps(umh)) |set| for (helper_denied) |c| {
            if (set & (@as(
                u64,
                1,
            ) << c.n) != 0) try helper_held.print(
                p.gpa,
                "{s}{s}",
                .{ if (helper_held.items.len > 0) ", " else "", c.name },
            );
        };
        try p.add(.{
            .id = "kernel-helpers",
            .area = "kernel",
            .name = "Kernel-started programs bounded",
            .why = "A program the kernel starts itself, which neither PID 1's seccomp filter " ++
                "nor its bounding set reaches, cannot load kernel code, reach hardware, trace " ++
                "processes, mount or change the network, and no program is started on every " ++
                "device event.",
            .how = "kernel.usermodehelper.bset lacks each of those capabilities, and " ++
                "kernel.hotplug is empty",
            .result = if (!p.root)
                .skip
            else if (helperCaps(umh) == null)
                .fail
            else if (helper_held.items.len == 0 and hotplug.len == 0)
                .pass
            else
                .fail,
            .detail = if (!p.root)
                "readable by root alone"
            else if (helperCaps(umh) == null)
                "cannot read kernel.usermodehelper.bset"
            else if (helper_held.items.len > 0)
                try p.gpa.print("held: {s}", .{helper_held.items})
            else if (hotplug.len > 0)
                try p.gpa.print("kernel.hotplug is {s}", .{hotplug})
            else
                "",
        });
        // A seccomp filter on PID 1 binds every process after it, root's
        // too, and nothing can remove it before a reboot: werewolf's seal
        // (cmd/init/init.zig) refuses there what no program here calls.
        const status = status1;
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
        try p.aslr();
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
        // Readable by root alone. Absent, the kernel has no BPF JIT.
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
        const panic_s = p.sysctl("kernel/panic");
        try p.add(.{
            .id = "kernel-oops",
            .area = "kernel",
            .name = "A kernel bug stops the kernel",
            .why = "A kernel that hits a bug, as a failed exploit often makes it, reboots " ++
                "rather than running on for the exploit to try again.",
            .how = "kernel.panic_on_oops is 1, and kernel.panic is above 0, so the panic " ++
                "reboots rather than hangs",
            .result = if (std.mem.eql(u8, oops, "1") and
                (std.fmt.parseInt(i64, panic_s, 10) catch 0) > 0)
                .pass
            else
                .fail,
            .detail = try p.gpa.print(
                "kernel.panic_on_oops is {s}, kernel.panic is {s}",
                .{ oops, panic_s },
            ),
        });
        // What the kernel can only be told at boot: werewolf's image names
        // it (the build writes it from the form's allowances), and a
        // machine booted without it, by a loader entry someone edited or
        // never rewrote, is missing protections no setting can add later.
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
        // Absent, the kernel has no userfaultfd.
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
        // Children inherit PID 1's limits, and only root can raise a hard one.
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
        try p.memory();
        // --extended only: what werewolf leaves undone by choice, since it
        // slows what machines run (docs/security.md, "Not done, by choice").
        if (p.extended) try p.costly();
        const rare = try rareFeatures(
            p.gpa,
            p.read("/proc/modules"),
            p.read("/proc/net/protocols"),
            p.read("/proc/filesystems"),
        );
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
    }

    /// The CPU flaws the kernel reports itself vulnerable to, by name, or
    /// null if it reports on none.
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
            if (std.mem.startsWith(
                u8,
                text,
                "Vulnerable",
            )) try found.print(p.gpa, "{s}{s}", .{ if (found.items.len > 0) ", " else "", name });
        }
        return found.items;
    }

    /// The 32-bit and 16-bit interfaces a 64-bit x86 kernel keeps for old
    /// programs, which none here are: int 0x80, and the LDT 16-bit code
    /// needs. Each is tried. The int 0x80 is made in a child that handles
    /// the SIGSEGV a refusal brings, so the kernel logs nothing.
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
        const ldt = readsLdt();
        var open: std.ArrayList(u8) = .empty;
        if (int80 orelse false) try open.appendSlice(p.gpa, "int 0x80 works");
        if (ldt) try open.print(
            p.gpa,
            "{s}modify_ldt works",
            .{if (open.items.len > 0) ", " else ""},
        );
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

    /// Address randomization at the most the kernel allows: mmap_rnd_bits
    /// for a 4K-page kernel with 48-bit addresses, which is what x86_64 and
    /// aarch64 servers run. Readable by root alone.
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

    // --- processes ---------------------------------------------------------

    fn processes(p: *Posture) !void {
        const mounts = p.read("/proc/self/mounts");
        try p.add(.{
            .id = "processes-hidden",
            .area = "processes",
            .name = "Processes hidden",
            .why = "A user sees only their own processes, not what else runs.",
            .how = "/proc is mounted hidepid=invisible",
            .result = if (hasOption(mounts, "/proc", "hidepid=invisible") or
                hasOption(mounts, "/proc", "hidepid=2"))
                .pass
            else
                .fail,
        });
        const setid = try p.findSetid();
        try p.add(.{
            .id = "processes-no-setid",
            .area = "processes",
            .name = "No setuid or setgid programs",
            .why = "No program gains privileges by being run.",
            .how = "no file on the root filesystem has either bit",
            .result = if (setid.len == 0) .pass else .fail,
            .detail = setid,
        });
        // A web server's workers, which face the network, are not root.
        if (p.root) {
            const nginx = try p.workerUids("nginx: worker");
            try p.add(.{
                .id = "processes-workers",
                .area = "processes",
                .name = "Web server workers unprivileged",
                .why = "The processes that answer requests cannot act as root.",
                .how = "every nginx worker runs as a uid other than 0",
                .result = if (nginx.found == 0) .skip else if (nginx.root == 0) .pass else .fail,
                .detail = if (nginx.found == 0) "no nginx running" else "",
            });
            try p.servicesLeashed();
        }
    }

    /// Each service leash starts, one with an /etc/sv/NAME/service file,
    /// runs as leash left it.
    fn servicesLeashed(p: *Posture) !void {
        var names: std.ArrayList([]const u8) = .empty;
        if (Dir.cwd().openDir(p.io, "/etc/sv", .{ .iterate = true })) |d| {
            var dir = d;
            defer dir.close(p.io);
            var it = dir.iterate();
            while (try it.next(p.io)) |e| {
                if (exists(p.io, try p.gpa.print("/etc/sv/{s}/service", .{e.name})))
                    try names.append(p.gpa, try p.gpa.dupe(u8, e.name));
            }
        } else |_| {}
        std.mem.sort([]const u8, names.items, {}, lessString);
        var bad: std.ArrayList(u8) = .empty;
        var running: usize = 0;
        for (names.items) |name| {
            const pid = trim(p.read(try p.gpa.print("/etc/sv/{s}/supervise/pid", .{name})));
            if (pid.len == 0) continue; // down, or parked
            const status = p.read(try p.gpa.print("/proc/{s}/status", .{pid}));
            if (status.len == 0) continue;
            running += 1;
            if (whyNotLeashed(status)) |why|
                try bad.print(
                    p.gpa,
                    "{s}{s} {s}",
                    .{ if (bad.items.len > 0) ", " else "", name, why },
                );
        }
        try p.add(.{
            .id = "processes-services-leashed",
            .area = "processes",
            .name = "Services others wrote run leashed",
            .why = "Programs werewolf did not write, nginx and PostgreSQL among them, run as " ++
                "users " ++
                "of their own, with no capability but binding a low port, and can gain none.",
            .how = "for each service with an /etc/sv/NAME/service file, its /proc/PID/status: " ++
                "no " ++
                "uid 0, no capability in any set but CAP_NET_BIND_SERVICE, and NoNewPrivs 1",
            .result = if (running == 0) .skip else if (bad.items.len == 0) .pass else .fail,
            .detail = if (running == 0) "no leashed service running" else bad.items,
        });
    }

    // --- programs ----------------------------------------------------------

    fn programs(p: *Posture) !void {
        try p.absent(
            "programs-no-shell",
            "No shell",
            "An intruder finds no shell to run commands with.",
            &.{ "sh", "ash", "bash", "dash", "zsh", "ksh", "mksh", "fish" },
        );
        try p.absent(
            "programs-no-downloaders",
            "No download or network tools",
            "An intruder cannot fetch more tools or open a connection out.",
            &.{
                "wget",
                "curl",
                "nc",
                "ncat",
                "netcat",
                "socat",
                "telnet",
                "tftp",
                "ftp",
                "ftpget",
                "ftpput",
                "scp",
                "sftp",
                "rsync",
            },
        );
        try p.absent(
            "programs-no-interpreters",
            "No script interpreters",
            "There is nothing to run a script with.",
            &.{
                "awk",
                "gawk",
                "mawk",
                "perl",
                "python",
                "python3",
                "ruby",
                "node",
                "lua",
                "luajit",
                "php",
                "php-fpm",
                "java",
                "tclsh",
                "expect",
            },
        );
        try p.absent(
            "programs-no-compilers",
            "No compilers",
            "Code cannot be built on the machine.",
            &.{ "cc", "gcc", "clang", "tcc", "as", "ld", "go", "rustc", "zig" },
        );
        try p.absent(
            "programs-no-module-tools",
            "No kernel module tools",
            "Nothing on the system can load, unload or list kernel modules.",
            &.{ "insmod", "modprobe", "rmmod", "lsmod", "kmod", "depmod" },
        );
        try p.absent(
            "programs-no-network-tools",
            "No network configuration tools",
            "An intruder cannot readdress the machine or change its routes with the usual tools.",
            &.{ "ifconfig", "ip", "route", "iptables", "nft", "tc", "ethtool" },
        );
        try p.absent(
            "programs-no-debuggers",
            "No debuggers",
            "Nothing to attach to a process or trace its calls.",
            &.{ "gdb", "lldb", "strace", "ltrace" },
        );

        // werewolf's services: each started straight from its program.
        var d = Dir.cwd().openDir(p.io, "/etc/sv", .{ .iterate = true }) catch return;
        defer d.close(p.io);
        var scripts: std.ArrayList(u8) = .empty;
        var programs_: usize = 0;
        var names: std.ArrayList([]const u8) = .empty;
        var it = d.iterate();
        while (it.next(p.io) catch null) |e| try names.append(p.gpa, try p.gpa.dupe(u8, e.name));
        std.mem.sort([]const u8, names.items, {}, lessString);
        for (names.items) |name| {
            const path = try p.gpa.print("/etc/sv/{s}/run", .{name});
            if (!exists(p.io, path)) continue;
            if (p.isElf(path)) {
                programs_ += 1;
            } else try scripts.print(
                p.gpa,
                "{s}{s}",
                .{ if (scripts.items.len > 0) ", " else "", name },
            );
        }
        try p.add(.{
            .id = "programs-services-no-shell",
            .area = "programs",
            .name = "Services start without a shell",
            .why = "Every service starts straight from its program, with no script between.",
            .how = "each /etc/sv/*/run leads to an ELF program, not a script",
            .result = if (scripts.items.len == 0) .pass else .fail,
            .detail = if (scripts.items.len > 0)
                try p.gpa.print("{d} without; scripts: {s}", .{ programs_, scripts.items })
            else
                "",
        });
    }

    /// None of names is on the system's PATH directories.
    fn absent(
        p: *Posture,
        id: []const u8,
        name: []const u8,
        why: []const u8,
        names: []const []const u8,
    ) !void {
        var found: std.ArrayList(u8) = .empty;
        var how: std.ArrayList(u8) = .empty;
        try how.appendSlice(p.gpa, "none of ");
        for (names, 0..) |n, i| {
            if (i > 0) try how.appendSlice(p.gpa, ", ");
            try how.appendSlice(p.gpa, n);
            for ([_][]const u8{
                "/bin",
                "/sbin",
                "/usr/bin",
                "/usr/sbin",
                "/usr/local/bin",
                "/usr/local/sbin",
            }) |dir| {
                const path = try p.gpa.print("{s}/{s}", .{ dir, n });
                if (!exists(p.io, path)) continue;
                try found.print(p.gpa, "{s}{s}", .{ if (found.items.len > 0) ", " else "", path });
                break;
            }
        }
        try how.appendSlice(p.gpa, " in /bin, /sbin, /usr/bin, /usr/sbin or /usr/local");
        try p.add(.{
            .id = id,
            .area = "programs",
            .name = name,
            .why = why,
            .how = how.items,
            .result = if (found.items.len == 0) .pass else .fail,
            .detail = found.items,
        });
    }

    // --- files -------------------------------------------------------------

    fn files(p: *Posture) !void {
        const mounts = p.read("/proc/self/mounts");
        try p.add(.{
            .id = "files-root-readonly",
            .area = "files",
            .name = "Read-only root",
            .why = "Nothing can change the running system's programs.",
            .how = "/ is mounted ro",
            .result = if (hasOption(mounts, "/", "ro")) .pass else .fail,
        });
        const nosuid = try missingOption(p.gpa, mounts, "nosuid", &.{});
        try p.add(.{
            .id = "files-nosuid-everywhere",
            .area = "files",
            .name = "setuid ignored everywhere",
            .why = "No filesystem, the root included, honours a setuid or setgid bit.",
            .how = "every mount in /proc/self/mounts is nosuid",
            .result = if (nosuid.len == 0) .pass else .fail,
            .detail = nosuid,
        });
        const noexec = try missingOption(p.gpa, mounts, "noexec", &.{"/"});
        try p.add(.{
            .id = "files-noexec-everywhere",
            .area = "files",
            .name = "Only the system's programs run",
            .why = "Every filesystem but the root refuses to run programs from it.",
            .how = "every mount in /proc/self/mounts but / is noexec",
            .result = if (noexec.len == 0) .pass else .fail,
            .detail = noexec,
        });
        // /dev and /dev/pts hold device nodes, terminals among them.
        const nodev = try missingOption(p.gpa, mounts, "nodev", &.{ "/dev", "/dev/pts" });
        try p.add(.{
            .id = "files-nodev-everywhere",
            .area = "files",
            .name = "Device files only in /dev",
            .why = "A device file made anywhere else is not honoured.",
            .how = "every mount in /proc/self/mounts but /dev and /dev/pts is nodev",
            .result = if (nodev.len == 0) .pass else .fail,
            .detail = nodev,
        });

        // The proof: a program put in each place does not start.
        var ran: std.ArrayList(u8) = .empty;
        var tried: std.ArrayList(u8) = .empty;
        for ([_][]const u8{
            "/tmp",
            "/var/tmp",
            "/run",
            "/dev/shm",
            "/dev/mqueue",
            "/data",
        }) |dir| {
            if (!exists(p.io, dir)) continue;
            try tried.print(p.gpa, "{s}{s}", .{ if (tried.items.len > 0) ", " else "", dir });
            if (p.runsFrom(dir)) try ran.print(
                p.gpa,
                "{s}{s}",
                .{ if (ran.items.len > 0) ", " else "", dir },
            );
        }
        try p.add(.{
            .id = "files-exec-refused",
            .area = "files",
            .name = "A program written there does not run",
            .why = "Malware dropped into a temporary or data directory cannot be started.",
            .how = try p.gpa.print(
                "a copy of this program, put in each of {s}, fails to start (or cannot be put " ++
                    "there)",
                .{tried.items},
            ),
            .result = if (ran.items.len == 0) .pass else .fail,
            .detail = if (ran.items.len > 0)
                try p.gpa.print("ran from {s}", .{ran.items})
            else
                "",
        });

        const sealed = std.mem.eql(u8, p.sysctl("vm/memfd_noexec"), "2");
        const memfd_ran = p.runsFromMemfd();
        try p.add(.{
            .id = "files-memfd-exec",
            .area = "files",
            .name = "No programs from memory",
            .why = "Code cannot run from an anonymous memory file, the usual way to run malware " ++
                "without writing it to disk.",
            .how = "vm.memfd_noexec is 2, and a copy of this program in a memfd fails to start",
            .result = if (sealed and !memfd_ran) .pass else .fail,
            .detail = if (memfd_ran)
                "a memfd program ran"
            else if (!sealed)
                try p.gpa.print("vm.memfd_noexec is {s}", .{p.sysctl("vm/memfd_noexec")})
            else
                "",
        });
        try p.sysctls("files-link" ++
            "s", "files", "Link and FIFO tricks " ++
            "blocked", "Symlinks, hard links and FIFOs in shared directories cannot be turned " ++
            "against another user.", &.{
            .{
                "fs/protected_symlinks",
                "1",
            },
            .{ "fs/protected_hardlinks", "1" },
            .{ "fs/protected_fifos", "2" },
            .{ "fs/protected_regular", "2" },
        });
        const open = try p.worldWritable();
        try p.add(.{
            .id = "files-world-writable",
            .area = "files",
            .name = "Shared places are sticky",
            .why = "Where everyone may write, no one can remove or replace another's files, and " ++
                "outside the temporary directories there is no file anyone may change.",
            .how = try p.gpa.print(
                "in {s}, every directory anyone may write is sticky, and outside /tmp, /var/tmp " ++
                    "and /dev/shm no file is writable by anyone",
                .{open.tried},
            ),
            .result = if (open.found.len == 0) .pass else .fail,
            .detail = open.found,
        });
        const loose = try p.accountFiles();
        try p.add(.{
            .id = "files-account-db",
            .area = "files",
            .name = "Account files root's alone",
            .why = "No one but root can add an account, change a password or read a password hash.",
            .how = "/etc/passwd, group, shadow and gshadow, and the directories their links " ++
                "lead to, are root's and writable by no one else, and shadow and gshadow are " ++
                "not readable by everyone",
            .result = if (loose.len == 0) .pass else .fail,
            .detail = loose,
        });
        const shadow = p.read("/etc/shadow");
        const unread = shadow.len == 0 and exists(p.io, "/etc/shadow");
        const accounts = try accountProblems(p.gpa, p.read("/etc/passwd"), shadow);
        try p.add(.{
            .id = "files-accounts",
            .area = "files",
            .name = "One root, and no empty passwords",
            .why = "No account but root has root's powers, and none can be logged into without " ++
                "a password or key.",
            .how = "only root has uid 0 in /etc/passwd, and no account in /etc/shadow has an " ++
                "empty password",
            .result = if (accounts.len > 0) .fail else if (unread) .skip else .pass,
            .detail = if (accounts.len > 0)
                accounts
            else if (unread)
                "cannot read /etc/shadow"
            else
                "",
        });
        if (mountType(mounts, "/victim") != null) try p.add(.{
            .id = "files-victim-readonly",
            .area = "files",
            .name = "Old system read-only",
            .why = "The system this machine replaced stays readable, not writable.",
            .how = "/victim is mounted ro",
            .result = if (hasOption(mounts, "/victim", "ro")) .pass else .fail,
        });
        if (p.root) {
            var disk_buf: [64]u8 = undefined;
            const disk = firstDisk(&disk_buf);
            var writable: std.ArrayList(u8) = .empty;
            const places = [_][:0]const u8{
                "/proc/sys/kernel/printk",
                "/sys/kernel/mm/transparent_hugepage/enabled",
                disk,
            };
            for (places) |path| {
                if (path.len == 0) continue;
                switch (writeOpen(path)) {
                    .ACCES, .NOENT => {},
                    else => try writable.print(
                        p.gpa,
                        "{s}{s}",
                        .{ if (writable.items.len > 0) ", " else "", path },
                    ),
                }
            }
            try p.add(.{
                .id = "files-system-writes",
                .area = "files",
                .name = "Kernel settings and disks not writable",
                .why = "Not even root can change a sysctl, a sysfs setting or a disk underneath " ++
                    "its filesystem, until the machine reboots.",
                .how = "opening a sysctl, a sysfs setting and the first disk for writing, " ++
                    "without writing, is refused with EACCES (Landlock, from fence)",
                .result = if (writable.items.len == 0) .pass else .fail,
                .detail = if (writable.items.len == 0)
                    ""
                else
                    try p.gpa.print("opened for writing: {s}", .{writable.items}),
            });
        }
    }

    /// Whether a copy of this program, put in dir, starts. A place it
    /// cannot be put is one it cannot start from.
    fn runsFrom(p: *Posture, dir: []const u8) bool {
        const path = p.gpa.print("{s}/.posture-exec-check", .{dir}) catch return true;
        defer Dir.cwd().deleteFile(p.io, path) catch {};
        Dir.cwd().copyFile(
            "/proc/self/exe",
            Dir.cwd(),
            path,
            p.io,
            .{ .permissions = .fromMode(0o755) },
        ) catch return false;
        return p.starts(path);
    }

    /// Whether a copy of this program in a memfd starts. memfd_create's flags
    /// are none but close-on-exec, as malware's would be.
    fn runsFromMemfd(p: *Posture) bool {
        const rc = linux.memfd_create("posture", linux.MFD.CLOEXEC);
        if (linux.errno(rc) != .SUCCESS) return false;
        const fd: i32 = @intCast(rc);
        defer _ = linux.close(fd);
        const self = Dir.cwd().readFileAlloc(
            p.io,
            "/proc/self/exe",
            p.gpa,
            .limited(64 << 20),
        ) catch return false;
        var off: usize = 0;
        while (off < self.len) {
            const n = linux.write(fd, self[off..].ptr, self.len - off);
            if (linux.errno(n) != .SUCCESS or n == 0) return false;
            off += n;
        }
        // The child reaches the memfd through this process's fd table.
        const path = p.gpa.print(
            "/proc/{d}/fd/{d}",
            .{ linux.getpid(), fd },
        ) catch return false;
        return p.starts(path);
    }

    /// Whether path starts, run with --noop, and exits 0.
    fn starts(p: *Posture, path: []const u8) bool {
        var child = std.process.spawn(
            p.io,
            .{
                .argv = &.{ path, "--noop" },
                .stdin = .ignore,
                .stdout = .ignore,
                .stderr = .ignore,
            },
        ) catch return false;
        const term = child.wait(p.io) catch return false;
        return switch (term) {
            .exited => |code| code == 0,
            else => false,
        };
    }

    // --- attacks, for werewolf's tests ---------------------------------------
    //
    // With werewolf.check=1 on the kernel command line, which only werewolf's
    // tests set, posture also attacks the machine as an intruder would, and
    // expects each attack refused. Two are meant to leave a line in the
    // kernel's log: the check is that the kernel both refused and said so.
    // The rest act as nobody, in a child, against files posture makes and
    // removes in /tmp and /run.

    fn attacks(p: *Posture) !void {
        const pid = linux.getpid();
        const comm = trim(p.read("/proc/self/comm"));

        // Yama names both sides by their command lines.
        const mem = p.refusedAndLogged(
            "/proc/1/mem",
            &.{ "\"[1] was attempted by \"", try p.gpa.print("\"[{d}]", .{pid}) },
        );
        try p.add(.{
            .id = "processes-mem-attack",
            .area = "processes",
            .name = "Another process's memory refused",
            .why = "Not even root can read or change a running program's memory, and the kernel " ++
                "logs every attempt.",
            .how = "opening /proc/1/mem fails, and the kernel logs Yama's refusal",
            .result = if (mem == .logged) .pass else .fail,
            .detail = mem.detail(),
        });
        // Without CAP_SYS_RAWIO, which werewolf's seal takes from every
        // process, the kernel refuses /dev/mem before lockdown is asked, and
        // so before it would log anything.
        const dev = p.refusedAndLogged(
            "/dev/mem",
            &.{try p.gpa.print("Lockdown: {s}: /dev/mem,kmem,port is restricted", .{comm})},
        );
        const rawio = capBit(p.read("/proc/self/status"), "CapEff", cap_sys_rawio) orelse true;
        try p.add(.{
            .id = "kernel-mem-attack",
            .area = "kernel",
            .name = "Physical memory refused",
            .why = "Not even root can read or write the machine's memory directly, and the " ++
                "kernel logs every attempt or refuses the capability it takes.",
            .how = "opening /dev/mem fails, and the kernel logs lockdown's refusal, or this " ++
                "process lacks CAP_SYS_RAWIO",
            .result = if (dev == .logged or (dev == .silent and !rawio)) .pass else .fail,
            .detail = if (dev == .silent and !rawio) "refused: no CAP_SYS_RAWIO" else dev.detail(),
        });

        defer cleanAttacks();
        cleanAttacks();
        const sees = asNobody(seesInit);
        try p.add(.{
            .id = "processes-hidden-attack",
            .area = "processes",
            .name = "Processes hidden from another user",
            .why = "A user, or an intruder running as one, cannot see what else runs.",
            .how = "as nobody, /proc/1 does not exist",
            .result = if (sees) |s| (if (s) .fail else .pass) else .skip,
            .detail = if (sees) |s| (if (s)
                "nobody sees /proc/1"
            else
                "") else "could not become nobody",
        });
        const writes = asNobody(writesRun);
        try p.add(.{
            .id = "files-run-attack",
            .area = "files",
            .name = "/run closed to other users",
            .why = "Another user cannot plant files where the services keep their state.",
            .how = "as nobody, creating a file in /run fails",
            .result = if (writes) |w| (if (w) .fail else .pass) else .skip,
            .detail = if (writes) |w| (if (w)
                "nobody wrote to /run"
            else
                "") else "could not become nobody",
        });

        // Each trick needs one side planted by nobody and the other tried
        // by root, or the other way around.
        var got: std.ArrayList(u8) = .empty;
        var missed = false;
        if (asNobody(plantsLink)) |planted| {
            if (planted and
                opensForWrite(
                    attack_link,
                    false,
                )) try got.appendSlice(p.gpa, "root wrote through nobody's symlink");
            missed = missed or !planted;
        } else missed = true;
        const secret = linux.open(
            attack_secret,
            .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .CLOEXEC = true },
            0o600,
        );
        if (linux.errno(secret) == .SUCCESS) {
            _ = linux.close(@intCast(secret));
            if (asNobody(linksSecret)) |linked| {
                if (linked) try got.print(
                    p.gpa,
                    "{s}nobody hard-linked root's file",
                    .{if (got.items.len > 0) ", " else ""},
                );
            } else missed = true;
        } else missed = true;
        if (asNobody(plantsFile)) |planted| {
            if (planted and
                opensForWrite(
                    attack_file,
                    true,
                )) try got.print(
                p.gpa,
                "{s}root opened nobody's file with O_CREAT",
                .{if (got.items.len > 0) ", " else ""},
            );
            missed = missed or !planted;
        } else missed = true;
        try p.add(.{
            .id = "files-links-attack",
            .area = "files",
            .name = "Link and file tricks refused",
            .why = "A file planted in a shared directory cannot make root write where it did " ++
                "not mean to, or reach root's files.",
            .how = "in /tmp, root writing through nobody's symlink, nobody hard-linking root's " ++
                "0600 file, and root opening nobody's file with O_CREAT each fail",
            .result = if (got.items.len > 0) .fail else if (missed) .skip else .pass,
            .detail = if (got.items.len > 0)
                got.items
            else if (missed)
                "could not set every trick up"
            else
                "",
        });
        try p.leashAttack();
    }

    /// A service leash starts as an unprivileged user does what its file
    /// grants and nothing more: posture leashes a copy of itself, which
    /// tries (probe, below) and says by its exit code what went as it
    /// should not.
    fn leashAttack(p: *Posture) !void {
        if (!exists(p.io, leash_bin)) return;
        var exe: [Dir.max_path_bytes]u8 = undefined;
        const self = exe[0 .. Dir.cwd().readLink(p.io, "/proc/self/exe", &exe) catch return];
        Dir.cwd().createDirPath(p.io, probe_dir) catch return;
        defer {
            Dir.cwd().deleteTree(p.io, probe_dir) catch {};
            Dir.cwd().deleteTree(p.io, "/run/svc/" ++ probe_name) catch {};
            Dir.cwd().deleteTree(p.io, "/data/svc/" ++ probe_name) catch {};
        }
        const file = try p.gpa.print(
            "# posture's probe (werewolf.check=1), granted TCP port 1 and nothing else\n" ++
                "exec {s} --probe\nuser nobody\nconnect tcp/1\n",
            .{self},
        );
        Dir.cwd().writeFile(
            p.io,
            .{ .sub_path = probe_dir ++ "/service", .data = file },
        ) catch return;
        var child = std.process.spawn(p.io, .{
            .argv = &.{leash_bin},
            .cwd = .{ .path = probe_dir },
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = .ignore,
        }) catch return;
        const term = child.wait(p.io) catch return;
        const code: u8 = if (term == .exited) @truncate(term.exited) else 0;
        var got: std.ArrayList(u8) = .empty;
        if (code & 0x80 != 0) {
            for (probe_tries, 0..) |what, i| {
                if (code & (@as(u8, 1) << @intCast(i)) != 0)
                    try got.print(p.gpa, "{s}{s}", .{ if (got.items.len > 0) ", " else "", what });
            }
        }
        try p.add(.{
            .id = "processes-leash-attack",
            .area = "processes",
            .name = "A leashed service stays on its leash",
            .why = "A service that is taken over can reach only the files, programs and ports " ++
                "its " ++
                "service file names.",
            .how = "this program, leashed as nobody and granted TCP port 1, cannot read " ++
                "/run/werewolf/hostname, write /tmp, run /usr/bin/sv or connect to port 2 on " ++
                "127.0.0.1, and can read /etc/passwd, write its own directory and connect to " ++
                "port 1",
            .result = if (code & 0x80 == 0) .fail else if (got.items.len == 0) .pass else .fail,
            .detail = if (code & 0x80 == 0) "the probe did not run" else got.items,
        });
    }

    const Refusal = enum {
        logged,
        silent,
        allowed,

        fn detail(r: Refusal) []const u8 {
            return switch (r) {
                .logged => "",
                .silent => "refused, but the kernel logged nothing",
                .allowed => "opened",
            };
        }
    };

    /// Whether opening path read-only is refused, with a line in the
    /// kernel's log, written after this open, that has every one of needles.
    fn refusedAndLogged(p: *Posture, path: [:0]const u8, needles: []const []const u8) Refusal {
        const kmsg_rc = linux.open(
            "/dev/kmsg",
            .{ .ACCMODE = .RDONLY, .NONBLOCK = true, .CLOEXEC = true },
            0,
        );
        const kmsg: ?i32 = if (linux.errno(kmsg_rc) == .SUCCESS) @intCast(kmsg_rc) else null;
        defer if (kmsg) |fd| {
            _ = linux.close(fd);
        };
        if (kmsg) |fd| _ = linux.lseek(fd, 0, linux.SEEK.END);

        const rc = linux.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
        if (linux.errno(rc) == .SUCCESS) {
            _ = linux.close(@intCast(rc));
            return .allowed;
        }
        const fd = kmsg orelse return .silent;
        // One record a read. Yama logs as the open returns; allow a moment.
        var record: [8192]u8 = undefined;
        for (0..20) |_| {
            while (true) {
                const n = linux.read(fd, &record, record.len);
                switch (linux.errno(n)) {
                    .SUCCESS => if (hasAll(record[0..n], needles)) return .logged,
                    .PIPE => {}, // records lost to newer ones: read on
                    else => break,
                }
            }
            p.io.sleep(.fromMilliseconds(100), .awake) catch {};
        }
        return .silent;
    }

    // --- network -----------------------------------------------------------

    fn network(p: *Posture) !void {
        var ports: std.ArrayList(u16) = .empty;
        for ([_][]const u8{
            "/proc/net/tcp",
            "/proc/net/tcp6",
        }) |f| try listenPorts(p.gpa, p.read(f), &ports);
        var list: std.ArrayList(u8) = .empty;
        for (ports.items, 0..) |port, i| try list.print(
            p.gpa,
            "{s}{d}",
            .{ if (i > 0) ", " else "", port },
        );
        // The machine's network policy (fence), or the older list of ports.
        const declared: ?[]const u8 = if (Dir.cwd().readFileAlloc(
            p.io,
            "/usr/share/werewolf/net",
            p.gpa,
            .limited(64 << 10),
        )) |net|
            try policyPorts(p.gpa, net)
        else |_|
            Dir.cwd().readFileAlloc(
                p.io,
                "/etc/werewolf/listen",
                p.gpa,
                .limited(64 << 10),
            ) catch null;
        var undeclared: std.ArrayList(u8) = .empty;
        if (declared) |text| for (ports.items) |port| {
            if (!isDeclared(
                text,
                port,
            )) try undeclared.print(
                p.gpa,
                "{s}{d}",
                .{ if (undeclared.items.len > 0) ", " else "", port },
            );
        };
        try p.add(.{
            .id = "network-ports",
            .area = "network",
            .name = "Only declared ports open",
            .why = "Nothing listens on the network that the machine is not meant to offer.",
            .how = "listening TCP ports (/proc/net/tcp, tcp6) are those the machine's policy " ++
                "declares (/usr/share/werewolf/net)",
            .result = if (declared == null)
                .skip
            else if (undeclared.items.len == 0)
                .pass
            else
                .fail,
            .detail = if (undeclared.items.len > 0)
                try p.gpa.print("undeclared: {s}", .{undeclared.items})
            else
                try p.gpa.print(
                    "listening: {s}",
                    .{if (list.items.len > 0) list.items else "none"},
                ),
        });
        try p.fence();
        try p.absentNamed(
            "network-no-login",
            "network",
            "No remote login",
            "There is no ssh or telnet server to log in through.",
            &.{ "sshd", "dropbear", "telnetd", "in.telnetd" },
        );
        try p.ssh();
        try p.sysctls(
            "network-no-forwarding",
            "network",
            "No routing",
            "The machine forwards no traffic for others.",
            &.{ .{ "net/ipv4/ip_forward", "0" }, .{ "net/ipv6/conf/all/forwarding", "0" } },
        );
        // A host takes and sends redirects on an interface if all or the
        // interface says so, so each interface must say no: all and default
        // do not reach an interface that was there before they were set.
        // IPv6 has only the interface's own setting. With IPv6 off, its
        // settings govern nothing.
        const v6_on = !p.ipv6Off();
        const redirects = [_][2][]const u8{
            .{
                "net/ipv4/conf/*/accept_redirects",
                "0",
            },
            .{ "net/ipv4/conf/*/secure_redirects", "0" },
            .{ "net/ipv4/conf/*/send_redirects", "0" },
            .{ "net/ipv6/conf/*/accept_redirects", "0" },
        };
        try p.sysctls(
            "network-redirects",
            "network",
            "ICMP redirects ignored",
            "Nobody on the network can reroute the machine's traffic, and it reroutes nobody's.",
            if (v6_on) &redirects else redirects[0..3],
        );
        // IPv4 takes a source route only if all and the interface both allow it.
        const source_route = [_][2][]const u8{
            .{ "net/ipv4/conf/all/accept_source_route", "0" },
            .{ "net/ipv6/conf/*/accept_source_route", "0" },
        };
        try p.sysctls(
            "network-source-route",
            "network",
            "Source routing refused",
            "Packets cannot choose their own way through the machine.",
            if (v6_on) &source_route else source_route[0..1],
        );
        // Router advertisements stay on (IPv6 takes its route from them), but
        // limited to what they must give.
        if (v6_on) try p.sysctls("network-ipv6-ra-limit" ++
            "s", "network", "Router advertisements " ++
            "limited", "A rogue router on the same network cannot rank itself above the real " ++
            "one, add a route to steal one destination's traffic, or flood the machine with " ++
            "addresses.", &.{
            .{
                "net/ipv6/conf/*/accept_ra_rtr_pref",
                "0",
            },
            .{ "net/ipv6/conf/*/accept_ra_rt_info_max_plen", "0" },
            .{ "net/ipv6/conf/*/max_addresses", "4" },
        });
        try p.sysctls(
            "network-martians",
            "network",
            "Impossible packets logged",
            "Packets from addresses that cannot be, a sign of spoofing, are logged.",
            &.{.{ "net/ipv4/conf/all/log_martians", "1" }},
        );
        // --extended only, as werewolf fails them by choice (docs/security.md,
        // "Not done, by choice"): strict reverse-path filtering waits until it
        // is shown to work with fence, and IPv6 takes its route from router
        // advertisements.
        if (p.extended) {
            // The kernel takes the stricter of all and the interface for both.
            try p.sysctls(
                "network-rp-filter",
                "network",
                "Spoofed sources dropped",
                "A packet claiming an address the machine would not reply to by that way is " ++
                    "dropped.",
                &.{.{ "net/ipv4/conf/all/rp_filter", "1" }},
            );
            if (v6_on) {
                try p.sysctls(
                    "network-ipv6-ra",
                    "network",
                    "Router advertisements ignored",
                    "Nobody on the network can give the machine an IPv6 address or route by " ++
                        "advertising one.",
                    &.{
                        .{ "net/ipv6/conf/*/accept_ra", "0" },
                        .{ "net/ipv6/conf/*/autoconf", "0" },
                    },
                );
            } else try p.add(.{
                .id = "network-ipv6-ra",
                .area = "network",
                .name = "Router advertisements ignored",
                .why = "Nobody on the network can give the machine an IPv6 address or route by " ++
                    "advertising one.",
                .how = "IPv6 is off, or net.ipv6.conf.*.accept_ra and autoconf are 0",
                .result = .pass,
                .detail = "IPv6 off",
            });
        }
        try p.sysctls(
            "network-syncookies",
            "network",
            "SYN flood protection",
            "A flood of half-open connections cannot exhaust it.",
            &.{.{ "net/ipv4/tcp_syncookies", "1" }},
        );
        try p.sysctls("network-stray-packet" ++
            "s", "network", "Stray packets " ++
            "ignored", "Pings to a broadcast address and bogus ICMP errors get no answer, and a " ++
            "forged reset cannot cut short a closing connection.", &.{
            .{
                "net/ipv4/icmp_echo_ignore_broadcasts",
                "1",
            },
            .{ "net/ipv4/icmp_ignore_bogus_error_responses", "1" },
            .{ "net/ipv4/tcp_rfc1337", "1" },
        });
    }

    /// Whether IPv6 is off: disable_ipv6 reads 1, or the kernel has none.
    fn ipv6Off(p: *Posture) bool {
        const v6 = p.sysctl("net/ipv6/conf/all/disable_ipv6");
        return v6.len == 0 or std.mem.eql(u8, v6, "1");
    }

    /// sshd's settings as it runs them, from sshd -T, which reads its
    /// configuration, Match blocks and defaults included, as sshd does.
    /// Nothing is checked where there is no sshd; sshd -T needs root.
    /// The kernel's memory hardening that costs a program nothing, judged by
    /// what is in effect rather than by the command line alone, since a
    /// kernel may have it on by default (Alpine's clears memory as it is
    /// handed out unless told not to).
    fn memory(p: *Posture) !void {
        const cmdline = p.read("/proc/cmdline");
        var missing: std.ArrayList(u8) = .empty;
        // Merged caches show in sysfs as links to the cache they share.
        const merged = if (p.slabAliases()) |n|
            n > 0
        else
            (try unsetArgs(p.gpa, cmdline, &.{"slab_nomerge"})).len > 0;
        if (merged) try missing.print(p.gpa, "kernel caches merged", .{});
        const shuffle = std.mem.trim(
            u8,
            p.read("/sys/module/page_alloc/parameters/shuffle"),
            " \n",
        );
        const shuffled = if (shuffle.len > 0)
            std.mem.eql(u8, shuffle, "Y")
        else
            (try unsetArgs(p.gpa, cmdline, &.{"page_alloc.shuffle"})).len == 0;
        if (!shuffled) try missing.print(
            p.gpa,
            "{s}pages not shuffled",
            .{if (missing.items.len > 0) ", " else ""},
        );
        const alloc = heapInit(
            p.memAutoInit(),
            "heap alloc",
        ) orelse if ((try unsetArgs(p.gpa, cmdline, &.{"init_on_alloc"})).len == 0) true else null;
        if (alloc == false) try missing.print(
            p.gpa,
            "{s}memory not cleared as it is handed out",
            .{if (missing.items.len > 0) ", " else ""},
        );
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

    /// How many caches in /sys/kernel/slab are another's, merged; null if
    /// it cannot be read.
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

    /// The kernel's "mem auto-init:" line, from the start of its log, or "".
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
                .PIPE => {}, // records lost to newer ones: read on
                else => return "",
            }
        }
    }

    /// Kernel checks werewolf fails by choice, for --extended: clearing
    /// freed memory and forced CPU mitigations cost every workload.
    fn costly(p: *Posture) !void {
        const free_on = heapInit(
            p.memAutoInit(),
            "heap free",
        ) orelse ((try unsetArgs(p.gpa, p.read("/proc/cmdline"), &.{"init_on_free"})).len == 0);
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
        const vulnerable = try p.cpuVulnerable();
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

    fn ssh(p: *Posture) !void {
        const sshd = for ([_][]const u8{ "/usr/sbin/sshd", "/usr/bin/sshd" }) |path| {
            if (exists(p.io, path)) break path;
        } else return;
        const settings: ?[]const u8 = if (!p.root) null else if (std.process.run(p.gpa, p.io, .{
            .argv = &.{ sshd, "-T" },
            .stdout_limit = .limited(1 << 20),
            .stderr_limit = .limited(64 << 10),
            .timeout = .{ .duration = .{ .raw = .fromSeconds(10), .clock = .awake } },
        })) |r| switch (r.term) {
            .exited => |code| if (code == 0) r.stdout else null,
            else => null,
        } else |_| null;
        const skipped = if (!p.root) "sshd -T needs root" else "sshd -T failed";

        var loose: std.ArrayList(u8) = .empty;
        if (settings) |s| {
            try loose.appendSlice(p.gpa, try sshMismatches(p.gpa, s, &ssh_settings));
            const config = "/etc/ssh/sshd_config";
            if (statx(p.gpa, config)) |st| if (st.uid != 0 or st.mode & 0o022 != 0)
                try loose.print(
                    p.gpa,
                    "{s}{s} is not root's alone",
                    .{ if (loose.items.len > 0) ", " else "", config },
                );
        }
        try p.add(.{
            .id = "network-ssh-config",
            .area = "network",
            .name = "ssh offers keys and nothing more",
            .why = "Logging in takes a key; no one gets in without a password, through another " ++
                "host's trust, or with their own environment, and a session cannot forward " ++
                "ports or tunnel past the machine's network policy.",
            .how = "sshd -T reports " ++ comptime sshSettingsText() ++
                ", and /etc/ssh/sshd_config is root's and writable by no one else",
            .result = if (settings == null) .skip else if (loose.items.len == 0) .pass else .fail,
            .detail = if (settings == null) skipped else loose.items,
        });
        const weak = if (settings) |s| try weakSshCrypto(p.gpa, s) else "";
        try p.add(.{
            .id = "network-ssh-crypto",
            .area = "network",
            .name = "ssh uses strong cryptography",
            .why = "No ssh connection can be made with a cipher, MAC, key exchange or signature " ++
                "that is broken or weakening.",
            .how = "sshd -T lists no CBC, arcfour or 3DES cipher, no MD5, SHA-1, 64-bit or " ++
                "truncated MAC, no SHA-1 or 1024-bit key exchange, and no ssh-rsa or ssh-dss " ++
                "signature",
            .result = if (settings == null) .skip else if (weak.len == 0) .pass else .fail,
            .detail = if (settings == null) skipped else weak,
        });
    }

    // werewolf's network policy (docs/design/fence.md): only declared ports can be
    // bound, only declared traffic sent, nothing unsolicited received, the
    // metadata server only for those named, IPv6 off. Each protection is
    // tested where a test is safe and quiet (a bind, a UDP connect, which
    // sends nothing, a connect the policy refuses at once), and fails where
    // it is missing, on any Linux.
    fn fence(p: *Posture) !void {
        const policy: []const u8 = Dir.cwd().readFileAlloc(
            p.io,
            "/usr/share/werewolf/net",
            p.gpa,
            .limited(64 << 10),
        ) catch "";

        const port = unusedPort(policy);
        const bound = probeBind(port);
        try p.add(.{
            .id = "network-bind",
            .area = "network",
            .name = "Undeclared ports cannot be opened",
            .why = "Not even root can start a listener on a port the machine is not meant to " ++
                "offer.",
            .how = try p.gpa.print(
                "bind() of a TCP socket to port {d}, which the policy does not declare, is " ++
                    "refused with EACCES (Landlock, inherited from PID 1)",
                .{port},
            ),
            .result = if (bound == .ACCES) .pass else .fail,
            .detail = try p.gpa.print("bind: {s}", .{errnoText(bound)}),
        });

        const sent = probeSend();
        try p.add(.{
            .id = "network-outbound",
            .area = "network",
            .name = "Only declared traffic leaves",
            .why = "A program can send nothing its form did not declare: no beacon, no " ++
                "exfiltration, no download.",
            .how = "connect() of a UDP socket to 192.0.2.1 port 9 (an address for " ++
                "documentation, never routed), which looks the route up without sending, is " ++
                "refused with EACCES (policy routing)",
            .result = if (sent == .ACCES) .pass else .fail,
            .detail = try p.gpa.print("connect: {s}", .{errnoText(sent)}),
        });

        const md = probeMetadata();
        try p.add(.{
            .id = "network-metadata",
            .area = "network",
            .name = "Cloud metadata server closed",
            .why = "Only the programs named can read the instance's metadata, where its config " ++
                "and any secrets in it are.",
            .how = "a TCP connect() to 169.254.169.254 port 80, for a second at most, is " ++
                "refused with EACCES",
            .result = switch (md) {
                .refused => .pass,
                .reached => .fail,
                // Nothing there and no policy to refuse it: not a cloud.
                .absent => if (policy.len == 0) .skip else .fail,
            },
            .detail = @tagName(md),
        });

        var rules: RuleSummary = .{};
        if (ruleDump(p.gpa, linux.AF.INET)) |dump| rules = summarizeRules(dump) else |_| {}
        try p.add(.{
            .id = "network-inbound",
            .area = "network",
            .name = "Unsolicited traffic dropped",
            .why = "Packets the machine did not ask for and does not serve are dropped " ++
                "unanswered, whatever is listening.",
            .how = "the IPv4 policy-routing rules (RTM_GETRULE) blackhole arriving TCP and UDP " ++
                "(or everything) before any rule delivers it to the local table, and refuse " ++
                "locally sent traffic that no rule allows",
            .result = if (rules.inbound_dropped and rules.outbound_refused) .pass else .fail,
            .detail = try p.gpa.print("arriving: {s}; sent: {s}", .{
                if (rules.inbound_dropped) "dropped unless declared" else "delivered",
                if (rules.outbound_refused) "refused unless declared" else "routed",
            }),
        });

        const v6_off = p.ipv6Off();
        var rules6: RuleSummary = .{};
        if (!v6_off) if (ruleDump(p.gpa, linux.AF.INET6)) |dump| {
            rules6 = summarizeRules(dump);
        } else |_| {};
        try p.add(.{
            .id = "network-ipv6",
            .area = "network",
            .name = "IPv6 under the same policy",
            .why = "Every interface has an IPv6 address reachable from the network; IPv6 must " ++
                "not be a way around the IPv4 rules.",
            .how = "IPv6 is off (disable_ipv6 reads 1, or the kernel has none), or its " ++
                "policy-routing rules (RTM_GETRULE, AF_INET6) drop arriving traffic before " ++
                "delivering it and refuse locally sent traffic no rule allows",
            .result = if (v6_off or (rules6.inbound_dropped and rules6.outbound_refused))
                .pass
            else
                .fail,
            .detail = if (v6_off)
                "IPv6 off"
            else
                try p.gpa.print("arriving: {s}; sent: {s}", .{
                    if (rules6.inbound_dropped) "dropped unless declared" else "delivered",
                    if (rules6.outbound_refused) "refused unless declared" else "routed",
                }),
        });
    }

    fn absentNamed(
        p: *Posture,
        id: []const u8,
        area: []const u8,
        name: []const u8,
        why: []const u8,
        names: []const []const u8,
    ) !void {
        try p.absent(id, name, why, names);
        p.checks.items[p.checks.items.len - 1].area = area;
    }

    // --- helpers -------------------------------------------------------------

    /// A setting the kernel lets rise but never fall: it must read locked,
    /// and as root, writing the unlocked value must be refused.
    fn oneWay(
        p: *Posture,
        id: []const u8,
        name: []const u8,
        why: []const u8,
        key: []const u8,
        locked: []const u8,
        unlocked: []const u8,
    ) !void {
        const path = try p.gpa.print("/proc/sys/{s}", .{key});
        const value = trim(p.read(path));
        const is_locked = std.mem.eql(u8, value, locked);
        const lowered = is_locked and p.root and !p.refused(path, unlocked);
        try p.add(.{
            .id = id,
            .area = "kernel",
            .name = name,
            .why = why,
            .how = if (p.root)
                try p.gpa.print(
                    "{s} is {s}, and writing {s} is refused",
                    .{ dotted(p.gpa, key), locked, unlocked },
                )
            else
                try p.gpa.print("{s} is {s}", .{ dotted(p.gpa, key), locked }),
            .result = if (is_locked and !lowered) .pass else .fail,
            .detail = if (is_locked) "" else try p.gpa.print(
                "{s} is {s}",
                .{ dotted(p.gpa, key), if (value.len > 0) value else "absent" },
            ),
        });
    }

    /// Settings that must hold these values. A * in a key stands for every
    /// entry in its directory, such as every interface, all and default
    /// among them; a directory that is not there has none to fail.
    fn sysctls(
        p: *Posture,
        id: []const u8,
        area: []const u8,
        name: []const u8,
        why: []const u8,
        want: []const [2][]const u8,
    ) !void {
        var how: std.ArrayList(u8) = .empty;
        var bad: std.ArrayList(u8) = .empty;
        for (want, 0..) |kv, i| {
            if (i > 0) try how.appendSlice(p.gpa, ", ");
            try how.print(p.gpa, "{s} = {s}", .{ dotted(p.gpa, kv[0]), kv[1] });
            for (try p.expand(kv[0])) |key| {
                const value = p.sysctl(key);
                if (!std.mem.eql(
                    u8,
                    value,
                    kv[1],
                )) try bad.print(
                    p.gpa,
                    "{s}{s} is {s}",
                    .{
                        if (bad.items.len > 0) ", " else "",
                        dotted(p.gpa, key),
                        if (value.len > 0) value else "absent",
                    },
                );
            }
        }
        try p.add(.{
            .id = id,
            .area = area,
            .name = name,
            .why = why,
            .how = how.items,
            .result = if (bad.items.len == 0) .pass else .fail,
            .detail = bad.items,
        });
    }

    /// key, or where it has a /*/, the key for each entry in that directory
    /// of /proc/sys, in order.
    fn expand(p: *Posture, key: []const u8) ![]const []const u8 {
        const star = std.mem.indexOf(u8, key, "/*/") orelse return p.gpa.dupe([]const u8, &.{key});
        var d = Dir.cwd().openDir(
            p.io,
            try p.gpa.print("/proc/sys/{s}", .{key[0..star]}),
            .{ .iterate = true },
        ) catch return &.{};
        defer d.close(p.io);
        var keys: std.ArrayList([]const u8) = .empty;
        var it = d.iterate();
        while (it.next(p.io) catch null) |e| try keys.append(
            p.gpa,
            try p.gpa.print("{s}/{s}{s}", .{ key[0..star], e.name, key[star + 2 ..] }),
        );
        std.mem.sort([]const u8, keys.items, {}, lessString);
        return keys.items;
    }

    /// A setting's value, without its newline.
    fn sysctl(p: *Posture, key: []const u8) []const u8 {
        return trim(p.read(p.gpa.print("/proc/sys/{s}", .{key}) catch return ""));
    }

    /// path, read to its end, or "". Not Dir.readFileAlloc, which reads
    /// only as much as stat reports: procfs reports 0.
    fn read(p: *Posture, path: []const u8) []const u8 {
        var f = Dir.cwd().openFile(p.io, path, .{}) catch return "";
        defer f.close(p.io);
        var buf: [4096]u8 = undefined;
        var r = f.readerStreaming(p.io, &buf);
        return r.interface.allocRemaining(p.gpa, .limited(16 << 20)) catch "";
    }

    /// Whether writing value to path fails.
    fn refused(p: *Posture, path: []const u8, value: []const u8) bool {
        Dir.cwd().writeFile(p.io, .{ .sub_path = path, .data = value }) catch return true;
        return false;
    }

    fn isElf(p: *Posture, path: []const u8) bool {
        var f = Dir.cwd().openFile(p.io, path, .{}) catch return false;
        defer f.close(p.io);
        var magic: [4]u8 = undefined;
        const n = f.readPositionalAll(p.io, &magic, 0) catch return false;
        return n == 4 and std.mem.eql(u8, &magic, "\x7fELF");
    }

    /// How many processes have a command line starting with prefix, and how
    /// many of those run as root.
    fn workerUids(p: *Posture, prefix: []const u8) !struct { found: usize, root: usize } {
        var found: usize = 0;
        var root: usize = 0;
        var d = Dir.cwd().openDir(
            p.io,
            "/proc",
            .{ .iterate = true },
        ) catch return .{ .found = 0, .root = 0 };
        defer d.close(p.io);
        var it = d.iterate();
        while (it.next(p.io) catch null) |e| {
            _ = std.fmt.parseInt(u32, e.name, 10) catch continue;
            const cmd = p.read(try p.gpa.print("/proc/{s}/cmdline", .{e.name}));
            if (!std.mem.startsWith(u8, cmd, prefix)) continue;
            found += 1;
            const status = p.read(try p.gpa.print("/proc/{s}/status", .{e.name}));
            if (uidOf(status) == 0) root += 1;
        }
        return .{ .found = found, .root = root };
    }

    /// Files on the root filesystem with setuid or setgid, as a list. It
    /// does not cross into other filesystems (/proc, /data and the like).
    fn findSetid(p: *Posture) ![]const u8 {
        var found: std.ArrayList(u8) = .empty;
        const root = statx(p.gpa, "/") orelse return "cannot stat /";
        try p.walk("/", root, .setid, &found, 0);
        return found.items;
    }

    /// The files under dir, on top's filesystem, that find looks for,
    /// added to found.
    fn walk(
        p: *Posture,
        dir: []const u8,
        top: linux.Statx,
        find: Find,
        found: *std.ArrayList(u8),
        depth: usize,
    ) !void {
        if (depth > 40) return;
        var d = Dir.cwd().openDir(p.io, dir, .{ .iterate = true }) catch return;
        defer d.close(p.io);
        var it = d.iterate();
        while (it.next(p.io) catch null) |e| {
            const path = try p.gpa.print(
                "{s}{s}{s}",
                .{ dir, if (dir.len > 1) "/" else "", e.name },
            );
            const st = statx(p.gpa, path) orelse continue;
            if (st.dev_major != top.dev_major or st.dev_minor != top.dev_minor) continue;
            if (isFound(
                find,
                st.mode,
            )) try found.print(p.gpa, "{s}{s}", .{ if (found.items.len > 0) ", " else "", path });
            if (st.mode & linux.S.IFMT == linux.S.IFDIR) try p.walk(
                path,
                top,
                find,
                found,
                depth + 1,
            );
        }
    }

    /// Where everyone may write, a directory must be sticky; outside the
    /// temporary directories, no file may be writable by everyone.
    fn worldWritable(p: *Posture) !struct { found: []const u8, tried: []const u8 } {
        var found: std.ArrayList(u8) = .empty;
        var tried: std.ArrayList(u8) = .empty;
        for ([_][]const u8{
            "/run",
            "/tmp",
            "/var/tmp",
            "/dev/shm",
            "/dev/mqueue",
            "/data",
        }) |dir| {
            const top = statx(p.gpa, dir) orelse continue;
            if (top.mode & linux.S.IFMT != linux.S.IFDIR) continue;
            try tried.print(p.gpa, "{s}{s}", .{ if (tried.items.len > 0) ", " else "", dir });
            const temporary = std.mem.eql(u8, dir, "/tmp") or std.mem.eql(u8, dir, "/var/tmp") or
                std.mem.eql(u8, dir, "/dev/shm");
            const find: Find = if (temporary) .open_dirs else .open;
            if (isFound(
                .open_dirs,
                top.mode,
            )) try found.print(p.gpa, "{s}{s}", .{ if (found.items.len > 0) ", " else "", dir });
            try p.walk(dir, top, find, &found, 0);
        }
        return .{ .found = found.items, .tried = tried.items };
    }

    /// Who could change the account files, wherever their links lead:
    /// each must be root's and writable by no one else, in a directory
    /// that is the same, and the shadow files readable by root's group at
    /// most.
    fn accountFiles(p: *Posture) ![]const u8 {
        var loose: std.ArrayList(u8) = .empty;
        for ([_][]const u8{ "/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow" }) |path| {
            const real = p.realPath(path) orelse continue;
            const st = statx(p.gpa, real) orelse continue;
            const dir = std.fs.path.dirname(real) orelse "/";
            const sep = if (loose.items.len > 0) ", " else "";
            if (st.uid != 0 or st.mode & 0o022 != 0) {
                try loose.print(p.gpa, "{s}{s} is not root's alone", .{ sep, real });
            } else if (std.mem.endsWith(u8, path, "shadow") and st.mode & 0o004 != 0) {
                try loose.print(p.gpa, "{s}{s} is readable by everyone", .{ sep, real });
            } else if (statx(p.gpa, dir)) |d| if (d.uid != 0 or d.mode & 0o022 != 0) {
                try loose.print(
                    p.gpa,
                    "{s}{s}, which holds {s}, is not root's alone",
                    .{ sep, dir, std.fs.path.basename(real) },
                );
            };
        }
        return loose.items;
    }

    /// The real path of path, every link followed, or null if it is not there.
    fn realPath(p: *Posture, path: []const u8) ?[]const u8 {
        const z = p.gpa.printSentinel("{s}", .{path}, 0) catch return null;
        const rc = linux.open(z, .{ .PATH = true, .CLOEXEC = true }, 0);
        if (linux.errno(rc) != .SUCCESS) return null;
        const fd: i32 = @intCast(rc);
        defer _ = linux.close(fd);
        const link = p.gpa.printSentinel(
            "/proc/self/fd/{d}",
            .{fd},
            0,
        ) catch return null;
        var buf: [4096]u8 = undefined;
        const n = linux.readlink(link, &buf, buf.len);
        if (linux.errno(n) != .SUCCESS) return null;
        return p.gpa.dupe(u8, buf[0..n]) catch null;
    }
};

/// What a walk looks for: setuid and setgid programs; anything anyone may
/// write, but a sticky directory; or only directories anyone may write that
/// are not sticky.
const Find = enum { setid, open, open_dirs };

fn isFound(find: Find, mode: u16) bool {
    const kind = mode & linux.S.IFMT;
    const open_dir = kind == linux.S.IFDIR and mode & linux.S.IWOTH != 0 and
        mode & linux.S.ISVTX == 0;
    return switch (find) {
        .setid => kind == linux.S.IFREG and mode & (linux.S.ISUID | linux.S.ISGID) != 0,
        .open => open_dir or (kind == linux.S.IFREG and mode & linux.S.IWOTH != 0),
        .open_dirs => open_dir,
    };
}

// --- text ----------------------------------------------------------------------

/// The report as people read it: a mark for each check, by area, and what
/// was found where a check did not pass. Details are cut to fit cols, the
/// terminal's width, when there is one.
fn printText(w: *Io.Writer, r: Report, cols: ?usize) !void {
    try w.print(
        "{s}, Linux {s}, on {s} ({s})\n",
        .{ r.os, r.kernel, r.host, if (r.root) "root" else "not root: some checks are limited" },
    );
    if (r.allow.len > 0) {
        try w.writeAll("Its form allows:");
        for (r.allow) |a| try w.print(" {s}", .{a});
        try w.writeByte('\n');
    }
    var width: usize = 0;
    for (r.checks) |c| width = @max(width, c.name.len);
    // Two spaces, a mark two columns wide, a space, the name padded to
    // width, two spaces, then the detail.
    const room = if (cols) |n| n -| (width + 7) else std.math.maxInt(usize);
    var area: []const u8 = "";
    for (r.checks) |c| {
        if (!std.mem.eql(u8, c.area, area)) {
            area = c.area;
            try w.print("\n{c}{s}\n", .{ std.ascii.toUpper(area[0]), area[1..] });
        }
        try w.print("  {s} {s}", .{ c.result.mark(), c.name });
        if (c.result != .pass and c.detail.len > 0) {
            const f = fit(c.detail, room);
            try w.splatByteAll(' ', width - c.name.len + 2);
            try w.writeAll(c.detail[0..f.len]);
            if (f.more > 0) try w.print(", +{d} more", .{f.more});
        }
        try w.writeByte('\n');
    }
    try w.print("\n{s} {d} passed   {s} {d} failed   {s} {d} skipped\n", .{
        Result.pass.mark(), r.summary.pass, Result.fail.mark(), r.summary.fail,
        Result.skip.mark(), r.summary.skip,
    });
}

/// One line: the ids that failed, sorted and between commas (none: fail=
/// and a space), the counts, then the whole report as JSON. A harness can
/// match the start and parse the rest.
fn printLine(gpa: Allocator, w: *Io.Writer, r: Report) !void {
    var failed: std.ArrayList([]const u8) = .empty;
    for (r.checks) |c| if (c.result == .fail) try failed.append(gpa, c.id);
    std.mem.sort([]const u8, failed.items, {}, lessString);
    try w.writeAll("posture: fail=");
    for (failed.items, 0..) |id, i| {
        if (i > 0) try w.writeByte(',');
        try w.writeAll(id);
    }
    try w.print(" pass={d} skip={d} ", .{ r.summary.pass, r.summary.skip });
    try std.json.Stringify.value(r, .{}, w);
    try w.writeByte('\n');
}

/// How much of detail, items between ", ", fits in max bytes: whole items,
/// with room left to say how many more there are. The first item is kept
/// even when it alone is too long.
fn fit(detail: []const u8, max: usize) struct { len: usize, more: usize } {
    if (detail.len <= max) return .{ .len = detail.len, .more = 0 };
    const items = std.mem.count(u8, detail, ", ") + 1;
    var len: usize = 0;
    var shown: usize = 0;
    var it = std.mem.splitSequence(u8, detail, ", ");
    while (it.next()) |item| : (shown += 1) {
        const end = if (shown == 0) item.len else len + 2 + item.len;
        if (shown > 0 and end + std.fmt.count(", +{d} more", .{items - shown - 1}) > max) break;
        len = end;
    }
    return .{ .len = len, .more = items - shown };
}

/// stdout's width in columns, or null when it is not a terminal.
fn columns() ?usize {
    var ws: std.posix.winsize = undefined;
    const rc = linux.ioctl(Io.File.stdout().handle, linux.T.IOCGWINSZ, @intFromPtr(&ws));
    if (linux.errno(rc) != .SUCCESS or ws.col == 0) return null;
    return ws.col;
}

// --- pure functions, tested below ----------------------------------------------

/// PRETTY_NAME in an os-release file, unquoted, or "Linux", its default.
fn prettyName(text: []const u8) []const u8 {
    var it = std.mem.tokenizeScalar(u8, text, '\n');
    while (it.next()) |line| {
        if (!std.mem.startsWith(u8, line, "PRETTY_NAME=")) continue;
        const name = std.mem.trim(u8, line["PRETTY_NAME=".len..], "\"' \r");
        if (name.len > 0) return name;
    }
    return "Linux";
}

/// The level in /sys/kernel/security/lockdown: "none [integrity] confidentiality".
fn lockdownLevel(text: []const u8) []const u8 {
    const a = std.mem.findScalar(u8, text, '[') orelse return "unavailable";
    const b = std.mem.findScalarPos(u8, text, a, ']') orelse return "unavailable";
    return text[a + 1 .. b];
}

fn isLocked(level: []const u8) bool {
    return std.mem.eql(u8, level, "integrity") or std.mem.eql(u8, level, "confidentiality");
}

/// Whether the mount at point (the last there, which is the one that shows)
/// has option among its options.
fn hasOption(mounts: []const u8, point: []const u8, option: []const u8) bool {
    var found = false;
    var it = std.mem.tokenizeScalar(u8, mounts, '\n');
    while (it.next()) |line| {
        const m = parseMount(line) orelse continue;
        if (!std.mem.eql(u8, m.dir, point)) continue;
        found = false;
        var o = std.mem.tokenizeScalar(u8, m.opts, ',');
        while (o.next()) |x| found = found or std.mem.eql(u8, x, option);
    }
    return found;
}

fn mountType(mounts: []const u8, point: []const u8) ?[]const u8 {
    var found: ?[]const u8 = null;
    var it = std.mem.tokenizeScalar(u8, mounts, '\n');
    while (it.next()) |line| {
        const m = parseMount(line) orelse continue;
        if (std.mem.eql(u8, m.dir, point)) found = m.kind;
    }
    return found;
}

/// The words of want not among the words of have, ", " between them.
fn missingArgs(gpa: Allocator, want: []const u8, have: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var w = std.mem.tokenizeAny(u8, want, " \n");
    next: while (w.next()) |arg| {
        var h = std.mem.tokenizeAny(u8, have, " \n");
        while (h.next()) |x| if (std.mem.eql(u8, x, arg)) continue :next;
        try out.print(gpa, "{s}{s}", .{ if (out.items.len > 0) ", " else "", arg });
    }
    return out.items;
}

/// Whether /proc/filesystems lists name: "nodev\tdebugfs", "\text4".
fn hasFilesystem(text: []const u8, name: []const u8) bool {
    var it = std.mem.tokenizeScalar(u8, text, '\n');
    while (it.next()) |line| {
        const tab = std.mem.findScalarLast(u8, line, '\t') orelse continue;
        if (std.mem.eql(u8, line[tab + 1 ..], name)) return true;
    }
    return false;
}

/// Kernel code few machines use, and exploits keep finding bugs in: by the
/// names /proc/modules, /proc/net/protocols (without "v6") and
/// /proc/filesystems give it.
const rare_features = [_][]const u8{
    "dccp",          "sctp",        "rds",         "tipc",      "n_hdlc",
    "ax25",          "netrom",      "x25",         "rose",      "decnet",
    "econet",        "af_802154",   "ipx",         "appletalk", "psnap",
    "p8022",         "p8023",       "can",         "atm",       "bluetooth",
    "firewire_core", "thunderbolt", "usb_storage", "cramfs",    "freevxfs",
    "jffs2",         "hfs",         "hfsplus",     "squashfs",  "udf",
    "cifs",          "ksmbd",       "gfs2",
};

/// The rare_features the running kernel has, as a list.
fn rareFeatures(
    gpa: Allocator,
    modules: []const u8,
    protocols: []const u8,
    filesystems: []const u8,
) ![]const u8 {
    var found: std.ArrayList(u8) = .empty;
    for (rare_features) |name| {
        if (hasFilesystem(filesystems, name) or firstWordIs(modules, name) or
            firstWordIs(protocols, name))
            try found.print(gpa, "{s}{s}", .{ if (found.items.len > 0) ", " else "", name });
    }
    return found.items;
}

/// Whether a line of text starts with the word name, in any case, or with
/// name and "v6": "sctp 475136 0 - Live", "SCTPv6    1272 ...".
fn firstWordIs(text: []const u8, name: []const u8) bool {
    var it = std.mem.tokenizeScalar(u8, text, '\n');
    while (it.next()) |line| {
        var word = line[0 .. std.mem.indexOfAny(u8, line, " \t") orelse line.len];
        if (std.ascii.endsWithIgnoreCase(word, "v6")) word = word[0 .. word.len - 2];
        if (std.ascii.eqlIgnoreCase(word, name)) return true;
    }
    return false;
}

/// Whether the kernel's mem auto-init line says what (heap alloc, heap
/// free) is on; null if it does not say.
fn heapInit(line: []const u8, what: []const u8) ?bool {
    const i = std.mem.indexOf(u8, line, what) orelse return null;
    const rest = line[i + what.len ..];
    if (std.mem.startsWith(u8, rest, ":on")) return true;
    if (std.mem.startsWith(u8, rest, ":off")) return false;
    return null;
}

/// The switches in names the command line does not turn on, as a list. A
/// switch is on bare, or set to what the kernel reads as true (1, y, on);
/// the last setting wins, as in the kernel.
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
        if (!on) try out.print(gpa, "{s}{s}", .{ if (out.items.len > 0) ", " else "", name });
    }
    return out.items;
}

/// The hard limit on a /proc/PID/limits "Max core file size" line, or null.
fn hardCoreLimit(limits: []const u8) ?[]const u8 {
    const label = "Max core file size";
    var it = std.mem.tokenizeScalar(u8, limits, '\n');
    while (it.next()) |line| {
        if (!std.mem.startsWith(u8, line, label)) continue;
        var f = std.mem.tokenizeAny(u8, line[label.len..], " \t");
        _ = f.next() orelse return null; // soft
        return f.next();
    }
    return null;
}

/// What sshd -T must report, by its names: keys only, no host-based trust,
/// and no forwarding, tunnels or user environment.
const ssh_settings = [_][2][]const u8{
    .{
        "passwordauthentication",
        "no",
    },
    .{ "kbdinteractiveauthentication", "no" },
    .{ "permitemptypasswords", "no" },
    .{
        "hostbasedauthentication",
        "no",
    },
    .{ "ignorerhosts", "yes" },
    .{ "strictmodes", "yes" },
    .{
        "permituserenvironment",
        "no",
    },
    .{ "x11forwarding", "no" },
    .{ "allowagentforwarding", "no" },
    .{
        "allowtcpforwarding",
        "no",
    },
    .{ "allowstreamlocalforwarding", "no" },
    .{ "gatewayports", "no" },
    .{ "permittunnel", "no" },
};

fn sshSettingsText() []const u8 {
    comptime var s: []const u8 = "";
    inline for (ssh_settings, 0..) |kv, i| s = s ++ (if (i > 0) ", " else "") ++ kv[0] ++ " " ++
        kv[1];
    return s;
}

/// A setting's value in sshd -T's output, "key value" a line, or null.
/// key's value in sshd -T's output, whose names are lowercase in some
/// OpenSSH releases and CamelCase in others (10.x: StrictModes yes).
fn sshValue(settings: []const u8, key: []const u8) ?[]const u8 {
    var it = std.mem.tokenizeScalar(u8, settings, '\n');
    while (it.next()) |line| {
        if (line.len > key.len and std.ascii.startsWithIgnoreCase(line, key) and
            line[key.len] == ' ') return trim(line[key.len + 1 ..]);
    }
    return null;
}

/// The settings in want that sshd -T reports otherwise, as a list.
fn sshMismatches(gpa: Allocator, settings: []const u8, want: []const [2][]const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (want) |kv| {
        // An sshd built without X11 (Wolfi's) lists no x11forwarding, and
        // cannot forward X11 at all.
        if (std.mem.eql(u8, kv[0], "x11forwarding") and sshValue(settings, kv[0]) == null) continue;
        const v = sshValue(settings, kv[0]) orelse "absent";
        if (!std.mem.eql(
            u8,
            v,
            kv[1],
        )) try out.print(gpa, "{s}{s} is {s}", .{ if (out.items.len > 0) ", " else "", kv[0], v });
    }
    return out.items;
}

/// What makes an algorithm weak, by the sshd -T list it is in.
const ssh_weak = [_]struct { []const u8, []const []const u8 }{
    .{ "ciphers", &.{ "-cbc", "arcfour", "3des" } },
    .{ "macs", &.{ "md5", "sha1", "umac-64", "-96" } },
    .{ "kexalgorithms", &.{"sha1"} },
    .{ "hostkeyalgorithms", &.{ "ssh-rsa", "ssh-dss" } },
    .{ "pubkeyacceptedalgorithms", &.{ "ssh-rsa", "ssh-dss" } },
};

/// The weak algorithms sshd -T lists, each once.
fn weakSshCrypto(gpa: Allocator, settings: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (ssh_weak) |w| {
        var algs = std.mem.tokenizeScalar(u8, sshValue(settings, w[0]) orelse continue, ',');
        next: while (algs.next()) |alg| {
            for (w[1]) |needle| if (std.mem.indexOf(u8, alg, needle) != null) {
                var seen = std.mem.tokenizeSequence(u8, out.items, ", ");
                while (seen.next()) |s| if (std.mem.eql(u8, s, alg)) continue :next;
                try out.print(gpa, "{s}{s}", .{ if (out.items.len > 0) ", " else "", alg });
                continue :next;
            };
        }
    }
    return out.items;
}

/// Accounts other than root with uid 0 in passwd, and accounts with an
/// empty password in shadow, as a list.
fn accountProblems(gpa: Allocator, passwd: []const u8, shadow: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var lines = std.mem.tokenizeScalar(u8, passwd, '\n');
    while (lines.next()) |line| {
        var f = std.mem.splitScalar(u8, line, ':');
        const name = f.next() orelse continue;
        _ = f.next() orelse continue;
        const uid = f.next() orelse continue;
        if (std.mem.eql(u8, uid, "0") and
            !std.mem.eql(
                u8,
                name,
                "root",
            )) try out.print(
            gpa,
            "{s}{s} has uid 0",
            .{ if (out.items.len > 0) ", " else "", name },
        );
    }
    lines = std.mem.tokenizeScalar(u8, shadow, '\n');
    while (lines.next()) |line| {
        var f = std.mem.splitScalar(u8, line, ':');
        const name = f.next() orelse continue;
        const hash = f.next() orelse continue;
        if (hash.len == 0) try out.print(
            gpa,
            "{s}{s} has no password",
            .{ if (out.items.len > 0) ", " else "", name },
        );
    }
    return out.items;
}

/// names, between commas.
fn joined(comptime names: []const []const u8) []const u8 {
    comptime var s: []const u8 = "";
    inline for (names, 0..) |n, i| s = s ++ (if (i > 0) ", " else "") ++ n;
    return s;
}

const Mount = struct { dir: []const u8, kind: []const u8, opts: []const u8 };

fn parseMount(line: []const u8) ?Mount {
    var f = std.mem.tokenizeScalar(u8, line, ' ');
    _ = f.next() orelse return null;
    const dir = f.next() orelse return null;
    const kind = f.next() orelse return null;
    const opts = f.next() orelse return null;
    return .{ .dir = dir, .kind = kind, .opts = opts };
}

/// The mount points, but those in except, whose options lack option, each
/// once.
fn missingOption(
    gpa: Allocator,
    mounts: []const u8,
    option: []const u8,
    except: []const []const u8,
) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var it = std.mem.tokenizeScalar(u8, mounts, '\n');
    next: while (it.next()) |line| {
        const m = parseMount(line) orelse continue;
        for (except) |e| if (std.mem.eql(u8, m.dir, e)) continue :next;
        if (hasOption(line, m.dir, option)) continue;
        var seen = std.mem.tokenizeAny(u8, out.items, ", ");
        while (seen.next()) |d| if (std.mem.eql(u8, d, m.dir)) continue :next;
        try out.print(gpa, "{s}{s}", .{ if (out.items.len > 0) ", " else "", m.dir });
    }
    return out.items;
}

/// The local ports of listening sockets in /proc/net/tcp or tcp6, each
/// once, in order.
fn listenPorts(gpa: Allocator, text: []const u8, out: *std.ArrayList(u16)) !void {
    var lines = std.mem.tokenizeScalar(u8, text, '\n');
    _ = lines.next(); // the header
    while (lines.next()) |line| {
        var f = std.mem.tokenizeScalar(u8, line, ' ');
        _ = f.next() orelse continue; // sl
        const local = f.next() orelse continue;
        _ = f.next() orelse continue; // remote
        const state = f.next() orelse continue;
        if (!std.mem.eql(u8, state, "0A")) continue; // TCP_LISTEN
        const colon = std.mem.findScalarLast(u8, local, ':') orelse continue;
        const port = std.fmt.parseInt(u16, local[colon + 1 ..], 16) catch continue;
        if (std.mem.findScalar(u16, out.items, port) == null) try out.append(gpa, port);
    }
    std.mem.sort(u16, out.items, {}, std.sort.asc(u16));
}

/// The ports in a network policy's `listen tcp PORT` lines, one a line.
fn policyPorts(gpa: Allocator, policy: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var it = std.mem.tokenizeScalar(u8, policy, '\n');
    while (it.next()) |line| {
        if (std.mem.startsWith(
            u8,
            line,
            "listen tcp ",
        )) try out.print(gpa, "{s}\n", .{std.mem.trim(u8, line["listen tcp ".len..], " ")});
    }
    return out.items;
}

/// Whether /etc/werewolf/listen declares port: one a line, or 22 for sshd,
/// which the image declares by carrying it.
fn isDeclared(text: []const u8, port: u16) bool {
    var it = std.mem.tokenizeAny(u8, text, " \n");
    while (it.next()) |d| if ((std.fmt.parseInt(u16, d, 10) catch 0) == port) return true;
    return false;
}

/// The real uid on a /proc/PID/status Uid: line.
const cap_sys_rawio = 17;

/// The capabilities kernel-bounding-set wants gone from PID 1's bounding
/// set, and the allowance that keeps each, if any.
const bounded_caps = [_]struct { name: []const u8, n: u6, allow: []const u8 = "" }{
    .{ .name = "CAP_SYS_MODULE", .n = 16 },
    .{ .name = "CAP_SYS_RAWIO", .n = cap_sys_rawio },
    .{ .name = "CAP_SYS_PTRACE", .n = 19 },
    .{ .name = "CAP_MKNOD", .n = 27 },
    .{ .name = "CAP_PERFMON", .n = 38 },
    .{ .name = "CAP_BPF", .n = 39 },
    .{ .name = "CAP_NET_ADMIN", .n = 12, .allow = "netadmin" },
    .{ .name = "CAP_NET_RAW", .n = 13, .allow = "packet" },
};

/// What kernel-helpers wants gone from the helpers' bounding set.
const helper_denied = [_]struct { name: []const u8, n: u6 }{
    .{ .name = "CAP_NET_ADMIN", .n = 12 },
    .{ .name = "CAP_NET_RAW", .n = 13 },
    .{ .name = "CAP_SYS_MODULE", .n = 16 },
    .{ .name = "CAP_SYS_RAWIO", .n = 17 },
    .{ .name = "CAP_SYS_PTRACE", .n = 19 },
    .{ .name = "CAP_SYS_ADMIN", .n = 21 },
    .{ .name = "CAP_PERFMON", .n = 38 },
    .{ .name = "CAP_BPF", .n = 39 },
};

/// kernel.usermodehelper.bset, "LOW\tHIGH", as one set, or null.
fn helperCaps(text: []const u8) ?u64 {
    var it = std.mem.tokenizeAny(u8, text, " \t\n");
    const low = std.fmt.parseInt(u32, it.next() orelse return null, 10) catch return null;
    const high = std.fmt.parseInt(u32, it.next() orelse return null, 10) catch return null;
    if (it.next() != null) return null;
    return @as(u64, high) << 32 | low;
}

/// Whether capability n is in a /proc/PID/status set, given in hex, or null
/// if the field is missing.
fn capBit(status: []const u8, field: []const u8, n: u6) ?bool {
    const hex = statusField(status, field) orelse return null;
    const set = std.fmt.parseInt(u64, hex, 16) catch return null;
    return set & (@as(u64, 1) << n) != 0;
}

/// A field's value on a /proc/PID/status line, "Name:\tvalue".
fn statusField(status: []const u8, name: []const u8) ?[]const u8 {
    var it = std.mem.tokenizeScalar(u8, status, '\n');
    while (it.next()) |line| {
        if (line.len > name.len and std.mem.startsWith(u8, line, name) and
            line[name.len] == ':') return std.mem.trim(u8, line[name.len + 1 ..], " \t");
    }
    return null;
}

fn uidOf(status: []const u8) ?u32 {
    var it = std.mem.tokenizeScalar(u8, status, '\n');
    while (it.next()) |line| {
        if (!std.mem.startsWith(u8, line, "Uid:")) continue;
        var f = std.mem.tokenizeAny(u8, line[4..], " \t");
        return std.fmt.parseInt(u32, f.next() orelse return null, 10) catch null;
    }
    return null;
}

/// kernel/yama/ptrace_scope as sysctl names it: kernel.yama.ptrace_scope.
fn dotted(gpa: Allocator, key: []const u8) []const u8 {
    const out = gpa.dupe(u8, key) catch return key;
    std.mem.replaceScalar(u8, out, '/', '.');
    return out;
}

// --- the leash probe --------------------------------------------------------------

const leash_bin = "/usr/lib/werewolf/leash";
const probe_name = "posture-probe";
const probe_dir = "/run/werewolf/" ++ probe_name;

/// What the probe tries, in its exit code's bits, each a thing that went
/// as it should not.
const probe_tries = [_][]const u8{
    "read a file it was not granted",
    "could not read /etc/passwd",
    "connected to a port it was not granted",
    "could not connect to the port it was granted",
    "could not write its own directory",
    "wrote to /tmp",
    "ran a program it was not granted",
};

/// posture --probe, as leashed by leashAttack: 128, and a bit for each of
/// probe_tries that went wrong. It makes only system calls.
fn probe() u8 {
    var bits: u8 = 0;
    if (opens("/run/werewolf/hostname")) bits |= 1 << 0;
    if (!opens("/etc/passwd")) bits |= 1 << 1;
    if (connectError(2) != .ACCES) bits |= 1 << 2;
    if (connectError(1) == .ACCES) bits |= 1 << 3;
    if (!creates("/run/svc/" ++ probe_name ++ "/x")) bits |= 1 << 4;
    if (creates("/tmp/." ++ probe_name)) bits |= 1 << 5;
    if (runs("/usr/bin/sv")) bits |= 1 << 6;
    return 0x80 | bits;
}

fn opens(path: [:0]const u8) bool {
    const fd = linux.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(fd) != .SUCCESS) return false;
    _ = linux.close(@intCast(fd));
    return true;
}

fn creates(path: [:0]const u8) bool {
    const fd = linux.open(
        path,
        .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .CLOEXEC = true },
        0o600,
    );
    if (linux.errno(fd) != .SUCCESS) return false;
    _ = linux.close(@intCast(fd));
    _ = linux.unlink(path);
    return true;
}

/// The error a TCP connect to port on 127.0.0.1 gets: fence lets loopback
/// pass, so a refusal there is the leash's.
fn connectError(port: u16) linux.E {
    const fd = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(fd) != .SUCCESS) return linux.errno(fd);
    defer _ = linux.close(@intCast(fd));
    var addr: linux.sockaddr.in = .{
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    return linux.errno(linux.connect(@intCast(fd), @ptrCast(&addr), @sizeOf(linux.sockaddr.in)));
}

/// Whether path starts: a child tries it, and says by its exit code.
fn runs(path: [:0]const u8) bool {
    const pid = linux.fork();
    if (linux.errno(pid) != .SUCCESS) return false;
    if (pid == 0) {
        const argv = [_:null]?[*:0]const u8{ path, null };
        const envp = [_:null]?[*:0]const u8{null};
        _ = linux.execve(path, &argv, &envp);
        linux.exit_group(42); // refused
    }
    var status: u32 = 0;
    if (linux.errno(linux.wait4(
        @intCast(pid),
        @ptrCast(&status),
        0,
        null,
    )) != .SUCCESS) return false;
    return !(linux.W.IFEXITED(status) and linux.W.EXITSTATUS(status) == 42);
}

/// Why a /proc/PID/status is not that of a process leash started, or null.
fn whyNotLeashed(status: []const u8) ?[]const u8 {
    var ids = std.mem.tokenizeAny(
        u8,
        statusField(status, "Uid") orelse return "shows no uid",
        " \t",
    );
    while (ids.next()) |id| if (std.mem.eql(u8, id, "0")) return "runs as root";
    const bind: u64 = 1 << linux.CAP.NET_BIND_SERVICE;
    for ([_][]const u8{ "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb" }) |key| {
        const v = std.fmt.parseInt(
            u64,
            statusField(status, key) orelse return "shows no capabilities",
            16,
        ) catch
            return "shows no capabilities";
        if (v & ~bind != 0) return "has capabilities";
    }
    if (!std.mem.eql(
        u8,
        statusField(status, "NoNewPrivs") orelse "",
        "1",
    )) return "may gain privileges";
    return null;
}

fn trim(s: []const u8) []const u8 {
    return std.mem.trim(u8, s, " \r\n");
}

fn exists(io: Io, path: []const u8) bool {
    Dir.cwd().access(io, path, .{}) catch return false;
    return true;
}

fn statx(gpa: Allocator, path: []const u8) ?linux.Statx {
    const z = gpa.printSentinel("{s}", .{path}, 0) catch return null;
    var st: linux.Statx = undefined;
    const rc = linux.statx(
        linux.AT.FDCWD,
        z,
        linux.AT.SYMLINK_NOFOLLOW,
        .{ .TYPE = true, .MODE = true, .UID = true },
        &st,
    );
    if (linux.errno(rc) != .SUCCESS) return null;
    return st;
}

fn lessString(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

fn nowSecs(io: Io) u64 {
    return @intCast(@max(0, @divFloor(Io.Timestamp.now(io, .real).nanoseconds, std.time.ns_per_s)));
}

fn rfc3339(gpa: Allocator, secs: u64) ![]const u8 {
    const es: std.time.epoch.EpochSeconds = .{ .secs = secs };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    return gpa.print("{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        yd.year,              md.month.numeric(),      md.day_index + 1,
        ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
    });
}

// --- tests -------------------------------------------------------------------

const testing = std.testing;

// --- fence probes ------------------------------------------------------------

/// A TCP port the policy does not declare, to try binding.
fn unusedPort(policy: []const u8) u16 {
    var port: u16 = 47321;
    while (isDeclared(policy, port)) port += 1;
    return port;
}

fn inet(addr: [4]u8, port: u16) linux.sockaddr.in {
    return .{ .port = std.mem.nativeToBig(u16, port), .addr = @bitCast(addr) };
}

/// bind() of a fresh TCP socket to `port` on every address: its errno. The
/// socket never listens, and is closed.
fn probeBind(port: u16) linux.E {
    const rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return linux.errno(rc);
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    const a = inet(.{ 0, 0, 0, 0 }, port);
    return linux.errno(linux.bind(fd, @ptrCast(&a), @sizeOf(linux.sockaddr.in)));
}

/// connect() of a UDP socket to 192.0.2.1:9: a route lookup, and no packet.
fn probeSend() linux.E {
    const rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return linux.errno(rc);
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    const a = inet(.{ 192, 0, 2, 1 }, 9);
    return linux.errno(linux.connect(fd, @ptrCast(&a), @sizeOf(linux.sockaddr.in)));
}

const Metadata = enum { refused, reached, absent };

/// A TCP connect() to 169.254.169.254:80, given a second: refused by
/// policy, reached (connected, or something answered), or absent.
fn probeMetadata() Metadata {
    const rc = linux.socket(
        linux.AF.INET,
        linux.SOCK.STREAM | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK,
        0,
    );
    if (linux.errno(rc) != .SUCCESS) return .absent;
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    const a = inet(.{ 169, 254, 169, 254 }, 80);
    switch (linux.errno(linux.connect(fd, @ptrCast(&a), @sizeOf(linux.sockaddr.in)))) {
        .ACCES, .PERM => return .refused,
        .SUCCESS => return .reached,
        .INPROGRESS => {},
        else => return .absent,
    }
    var fds = [1]linux.pollfd{.{ .fd = fd, .events = linux.POLL.OUT, .revents = 0 }};
    if (linux.poll(&fds, 1, 1000) != 1) return .absent;
    var err: i32 = 0;
    var len: linux.socklen_t = @sizeOf(i32);
    _ = linux.getsockopt(fd, linux.SOL.SOCKET, linux.SO.ERROR, @ptrCast(&err), &len);
    return if (err == 0 or err == @backingInt(linux.E.CONNREFUSED)) .reached else .absent;
}

fn errnoText(e: linux.E) []const u8 {
    return if (e == .SUCCESS) "allowed" else std.enums.tagName(linux.E, e) orelse "unknown";
}

/// A family's policy-routing rules, as the kernel lists them: RTM_GETRULE
/// messages, one after another. Listing them needs no privilege.
fn ruleDump(gpa: Allocator, family: u8) ![]const u8 {
    const rc = linux.socket(
        linux.AF.NETLINK,
        linux.SOCK.RAW | linux.SOCK.CLOEXEC,
        linux.NETLINK.ROUTE,
    );
    if (linux.errno(rc) != .SUCCESS) return error.NoNetlink;
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    var req: [28]u8 = @splat(0);
    std.mem.writeInt(u32, req[0..4], req.len, .little);
    std.mem.writeInt(u16, req[4..6], 34, .little); // RTM_GETRULE
    std.mem.writeInt(u16, req[6..8], 0x301, .little); // NLM_F_REQUEST | NLM_F_DUMP
    std.mem.writeInt(u32, req[8..12], 1, .little);
    req[16] = family;
    if (linux.errno(linux.sendto(
        fd,
        &req,
        req.len,
        0,
        null,
        0,
    )) != .SUCCESS) return error.NoNetlink;
    var out: std.ArrayList(u8) = .empty;
    var buf: [32 << 10]u8 align(4) = undefined;
    while (out.items.len < 1 << 20) {
        var fds = [1]linux.pollfd{.{ .fd = fd, .events = linux.POLL.IN, .revents = 0 }};
        if (linux.poll(&fds, 1, 1000) != 1) return error.NoReply;
        const n = linux.recvfrom(fd, &buf, buf.len, 0, null, null);
        if (linux.errno(n) != .SUCCESS) return error.NoReply;
        try out.appendSlice(gpa, buf[0..n]);
        if (dumpDone(buf[0..n])) return out.items;
    }
    return error.TooLong;
}

/// Whether a batch of netlink messages ends the dump.
fn dumpDone(batch: []const u8) bool {
    var off: usize = 0;
    while (off + 16 <= batch.len) {
        const len = std.mem.readInt(u32, batch[off..][0..4], .little);
        const kind = std.mem.readInt(u16, batch[off + 4 ..][0..2], .little);
        if (kind == 3 or kind == 2) return true; // NLMSG_DONE, NLMSG_ERROR
        if (len < 16) return true;
        off += std.mem.alignForward(usize, len, 4);
    }
    return false;
}

const RuleSummary = struct {
    /// A rule refuses whatever is sent here (from lo) that no earlier rule
    /// allowed: no selector but the interface, action prohibit.
    outbound_refused: bool = false,
    /// A rule drops whatever arrives that no earlier rule allowed, and no
    /// rule without selectors delivers to the local table before it.
    inbound_dropped: bool = false,
};

/// What a dump of policy-routing rules says about traffic in and out.
fn summarizeRules(dump: []const u8) RuleSummary {
    // Where arriving traffic is first dropped: all of it, or TCP and UDP
    // by name, as fence does so that ARP's lookup still finds the address
    // local; and where it is first delivered.
    var drop_at: ?u32 = null;
    var tcp_drop_at: ?u32 = null;
    var udp_drop_at: ?u32 = null;
    var local_at: ?u32 = null;
    var out_refused = false;
    var off: usize = 0;
    while (off + 28 <= dump.len) {
        const len = std.mem.readInt(u32, dump[off..][0..4], .little);
        if (len < 16 or off + len > dump.len) break;
        const msg = dump[off .. off + len];
        off += std.mem.alignForward(usize, len, 4);
        if (std.mem.readInt(u16, msg[4..6], .little) != 32 or msg.len < 28) continue; // RTM_NEWRULE
        var table: u32 = msg[16 + 4];
        const action = msg[16 + 7];
        var priority: u32 = 0;
        var from_lo = false;
        var iif = false;
        var selective = false;
        var proto: ?u8 = null;
        var a: usize = 28;
        while (a + 4 <= msg.len) {
            const alen = std.mem.readInt(u16, msg[a..][0..2], .little);
            if (alen < 4 or a + alen > msg.len) break;
            const kind = std.mem.readInt(u16, msg[a + 2 ..][0..2], .little) & 0x3fff;
            const v = msg[a + 4 .. a + alen];
            switch (kind) {
                6 => if (v.len == 4) {
                    priority = std.mem.readInt(u32, v[0..4], .little);
                },
                15 => if (v.len == 4) {
                    table = std.mem.readInt(u32, v[0..4], .little);
                },
                3 => {
                    iif = true;
                    from_lo = std.mem.eql(u8, std.mem.sliceTo(v, 0), "lo");
                },
                22 => if (v.len == 1) {
                    proto = v[0];
                },
                1, 2, 10, 17, 20, 23, 24 => selective = true, // dst, src, fwmark, oif, uid, ports
                else => {},
            }
            a += std.mem.alignForward(usize, alen, 4);
        }
        if (selective or (iif and proto != null)) continue;
        if (action == 8 and from_lo) out_refused = true; // FR_ACT_PROHIBIT
        if (iif) continue;
        if (action == 6) { // FR_ACT_BLACKHOLE
            const at: *?u32 = if (proto == null)
                &drop_at
            else if (proto == 6)
                &tcp_drop_at
            else if (proto == 17)
                &udp_drop_at
            else
                continue;
            at.* = @min(at.* orelse priority, priority);
        }
        if (action == 1 and table == 255 and
            proto == null) local_at = @min(local_at orelse priority, priority); // to local
    }
    const before = struct {
        fn f(drop: ?u32, local: ?u32) bool {
            const d = drop orelse return false;
            return local == null or d < local.?;
        }
    }.f;
    const dropped = before(
        drop_at,
        local_at,
    ) or (before(tcp_drop_at, local_at) and before(udp_drop_at, local_at));
    return .{ .outbound_refused = out_refused, .inbound_dropped = dropped };
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

const test_mounts =
    \\/dev/root / ext4 rw,relatime 0 0
    \\proc /proc proc rw,nosuid,nodev,noexec,relatime,hidepid=invisible 0 0
    \\dev /dev devtmpfs rw,nosuid,noexec,relatime 0 0
    \\tmpfs /tmp tmpfs rw,nosuid,nodev,noexec 0 0
    \\tmpfs /run tmpfs rw,nosuid,nodev 0 0
    \\/dev/vda1 /victim ext4 ro,nosuid,nodev,noexec 0 0
    \\/dev/vda1 /data ext4 rw,nosuid,nodev,noexec,noatime 0 0
    \\mqueue /dev/mqueue mqueue rw,nosuid,nodev,noexec 0 0
;

test hasOption {
    try testing.expect(hasOption(test_mounts, "/proc", "hidepid=invisible"));
    try testing.expect(hasOption(test_mounts, "/victim", "ro"));
    try testing.expect(!hasOption(test_mounts, "/", "ro"));
    try testing.expect(!hasOption(test_mounts, "/run", "noexec"));
    try testing.expectEqualStrings("ext4", mountType(test_mounts, "/data").?);
    try testing.expectEqual(null, mountType(test_mounts, "/nowhere"));
}

test missingOption {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectEqualStrings("/", try missingOption(a, test_mounts, "nosuid", &.{}));
    try testing.expectEqualStrings("/run", try missingOption(a, test_mounts, "noexec", &.{"/"}));
    try testing.expectEqualStrings(
        "",
        try missingOption(a, test_mounts, "nodev", &.{ "/", "/dev" }),
    );
}

test listenPorts {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var ports: std.ArrayList(u16) = .empty;
    const tcp =
        \\  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
        \\   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1
        \\   1: 0F05A8C0:0050 0105A8C0:C350 01 00000000:00000000 00:00000000 00000000   200        0 2 1
        \\   2: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 3 1
        \\   3: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4 1
    ;
    try listenPorts(arena.allocator(), tcp, &ports);
    try testing.expectEqualSlices(u16, &.{ 22, 80 }, ports.items);
    try testing.expect(isDeclared("80\n", 80));
    const policy = try policyPorts(
        arena.allocator(),
        "listen tcp 22\nlisten tcp 80\nmetadata 68\n",
    );
    try testing.expectEqualStrings("22\n80\n", policy);
    try testing.expect(isDeclared(policy, 80) and !isDeclared(policy, 68));
    try testing.expect(!isDeclared("80\n", 22));
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

test rareFeatures {
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
        try rareFeatures(a, modules, protocols, filesystems),
    );
    try testing.expectEqualStrings(
        "",
        try rareFeatures(
            a,
            "virtio_net 61440 0 - Live 0x0\n",
            "TCP 2432\nUDPv6 1472\n",
            "\text4\n",
        ),
    );
    // A name is a whole word: hfsplus is not hfs, can is not candle.
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
    // The last setting wins; a longer name is not the switch.
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

test sshMismatches {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const settings = "port 22\npasswordauthentication no\nallowtcpforwarding yes\npermittunnel " ++
        "no\nciphers chacha20-poly1305@openssh.com,aes256-cbc\nmacs hmac-sha2-256-etm@openssh.co" ++
        "m,umac-64-etm@openssh.com,hmac-sha1\nkexalgorithms curve25519-sha256,diffie-hellman-gro" ++
        "up14-sha1\nhostkeyalgorithms ssh-ed25519,ssh-rsa\npubkeyacceptedalgorithms " ++
        "ssh-ed25519,ssh-rsa,rsa-sha2-512\n";
    try testing.expectEqualStrings("no", sshValue(settings, "passwordauthentication").?);
    try testing.expectEqualStrings("yes", sshValue("Port 22\nStrictModes yes\n", "strictmodes").?);
    try testing.expectEqual(null, sshValue("StrictModesX yes\n", "strictmodes"));
    try testing.expectEqualStrings(
        "",
        try sshMismatches(
            a,
            "PermitTunnel no\n",
            &.{ .{ "x11forwarding", "no" }, .{ "permittunnel", "no" } },
        ),
    );
    try testing.expectEqualStrings(
        "x11forwarding is yes",
        try sshMismatches(a, "X11Forwarding yes\n", &.{.{ "x11forwarding", "no" }}),
    );
    try testing.expectEqual(null, sshValue(settings, "password"));
    try testing.expectEqualStrings(
        "allowtcpforwarding is yes, gatewayports is absent",
        try sshMismatches(
            a,
            settings,
            &.{
                .{ "passwordauthentication", "no" },
                .{ "allowtcpforwarding", "no" },
                .{ "permittunnel", "no" },
                .{ "gatewayports", "no" },
            },
        ),
    );
    try testing.expectEqualStrings(
        "aes256-cbc, umac-64-etm@openssh.com, hmac-sha1, diffie-hellman-group14-sha1, ssh-rsa",
        try weakSshCrypto(a, settings),
    );
    try testing.expectEqualStrings(
        "",
        try weakSshCrypto(
            a,
            "ciphers aes256-gcm@openssh.com\nmacs hmac-sha2-512-etm@openssh.com\nkexalgorithms " ++
                "mlkem768x25519-sha256\nhostkeyalgorithms ssh-ed25519,rsa-sha2-256\n",
        ),
    );
}

test accountProblems {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const passwd = "root:x:0:0:root:/root:/sbin/nologin\ntoor:x:0:0::/:/bin/sh\nnobody:x:65534:6" ++
        "5534::/:/sbin/nologin\n";
    const shadow = "root:*:19000::::::\ntoor::19000::::::\nnobody:!:19000::::::\n";
    try testing.expectEqualStrings(
        "toor has uid 0, toor has no password",
        try accountProblems(a, passwd, shadow),
    );
    try testing.expectEqualStrings(
        "",
        try accountProblems(a, "root:x:0:0::/:/x\n", "root:!::::::::\n"),
    );
}

test isFound {
    const S = linux.S;
    try testing.expect(isFound(.setid, S.IFREG | S.ISUID | 0o755));
    try testing.expect(!isFound(.setid, S.IFDIR | S.ISGID | 0o755));
    try testing.expect(isFound(.open, S.IFDIR | 0o777));
    try testing.expect(!isFound(.open, S.IFDIR | S.ISVTX | 0o777)); // /tmp
    try testing.expect(isFound(.open, S.IFREG | 0o666));
    try testing.expect(!isFound(.open, S.IFLNK | 0o777));
    try testing.expect(!isFound(.open_dirs, S.IFREG | 0o666));
    try testing.expect(isFound(.open_dirs, S.IFDIR | 0o773));
}

test helperCaps {
    try testing.expectEqual(1 << 22, helperCaps("4194304\t0\n").?);
    try testing.expectEqual((1 << 41) - 1, helperCaps("4294967295\t511").?);
    try testing.expectEqual(null, helperCaps(""));
    try testing.expectEqual(null, helperCaps("1"));
    try testing.expectEqual(null, helperCaps("1 2 3"));
    try testing.expectEqual(null, helperCaps("x 0"));
}

test capBit {
    const status = "CapEff:\t000001ffffffffff\nCapBnd:\t000001fffe7cfdff\n";
    try testing.expect(capBit(status, "CapEff", 17).?);
    try testing.expect(!capBit(status, "CapBnd", 16).?);
    try testing.expect(capBit(status, "CapBnd", 12).?);
    try testing.expectEqual(null, capBit(status, "CapPrm", 0));
}

test statusField {
    const status = "Name:\trunit\nSeccomp:\t2\nSeccomp_filters:\t1\n";
    try testing.expectEqualStrings("2", statusField(status, "Seccomp").?);
    try testing.expectEqualStrings("1", statusField(status, "Seccomp_filters").?);
    try testing.expectEqual(null, statusField(status, "NoNewPrivs"));
}

test uidOf {
    try testing.expectEqual(200, uidOf("Name:\tnginx\nUid:\t200\t200\t200\t200\nGid:\t200\n").?);
    try testing.expectEqual(null, uidOf("Name:\tx\n"));
}

test dotted {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    try testing.expectEqualStrings(
        "kernel.yama.ptrace_scope",
        dotted(arena.allocator(), "kernel/yama/ptrace_scope"),
    );
}

/// A netlink rule message for the tests: priority, action, table, and the
/// iif name and selectors given.
fn testRule(
    buf: []u8,
    priority: u32,
    action: u8,
    table: u8,
    iif: ?[]const u8,
    proto: ?u8,
) []const u8 {
    @memset(buf, 0);
    var n: usize = 28;
    buf[16] = linux.AF.INET;
    buf[16 + 4] = table;
    buf[16 + 7] = action;
    const put = struct {
        fn f(b: []u8, at: *usize, kind: u16, v: []const u8) void {
            std.mem.writeInt(u16, b[at.*..][0..2], @intCast(4 + v.len), .little);
            std.mem.writeInt(u16, b[at.* + 2 ..][0..2], kind, .little);
            @memcpy(b[at.* + 4 ..][0..v.len], v);
            at.* += std.mem.alignForward(usize, 4 + v.len, 4);
        }
    }.f;
    put(buf, &n, 6, std.mem.asBytes(&priority));
    if (iif) |name| put(buf, &n, 3, name);
    if (proto) |pr| put(buf, &n, 22, &.{pr});
    std.mem.writeInt(u32, buf[0..4], @intCast(n), .little);
    std.mem.writeInt(u16, buf[4..6], 32, .little);
    return buf[0..n];
}

test summarizeRules {
    var dump: std.ArrayList(u8) = .empty;
    defer dump.deinit(std.testing.allocator);
    var b: [64]u8 = undefined;
    // The kernel's own rules: local at 0, main, default. Nothing dropped.
    try dump.appendSlice(std.testing.allocator, testRule(&b, 0, 1, 255, null, null));
    try dump.appendSlice(std.testing.allocator, testRule(&b, 32766, 1, 254, null, null));
    try std.testing.expectEqual(RuleSummary{}, summarizeRules(dump.items));

    // fence's: local first only for lo, allowances with selectors, the
    // refusal from lo, ICMP in, the drops of TCP and UDP, then the local
    // rule moved after them.
    dump.clearRetainingCapacity();
    try dump.appendSlice(std.testing.allocator, testRule(&b, 10, 1, 255, "lo\x00", null));
    try dump.appendSlice(std.testing.allocator, testRule(&b, 200, 1, 254, "lo\x00", 6));
    try dump.appendSlice(std.testing.allocator, testRule(&b, 299, 8, 0, "lo\x00", null));
    try dump.appendSlice(std.testing.allocator, testRule(&b, 300, 1, 255, null, 1));
    try dump.appendSlice(std.testing.allocator, testRule(&b, 399, 6, 0, null, 6));
    const tcp_only = dump.items.len;
    try dump.appendSlice(std.testing.allocator, testRule(&b, 399, 6, 0, null, 17));
    try dump.appendSlice(std.testing.allocator, testRule(&b, 400, 1, 255, null, null));
    try std.testing.expectEqual(
        RuleSummary{ .outbound_refused = true, .inbound_dropped = true },
        summarizeRules(dump.items),
    );

    // TCP dropped and UDP not is not dropped.
    var half: std.ArrayList(u8) = .empty;
    defer half.deinit(std.testing.allocator);
    try half.appendSlice(std.testing.allocator, dump.items[0..tcp_only]);
    try half.appendSlice(std.testing.allocator, testRule(&b, 400, 1, 255, null, null));
    try std.testing.expect(!summarizeRules(half.items).inbound_dropped);

    // A drop of everything counts too.
    var all: std.ArrayList(u8) = .empty;
    defer all.deinit(std.testing.allocator);
    try all.appendSlice(std.testing.allocator, testRule(&b, 399, 6, 0, null, null));
    try all.appendSlice(std.testing.allocator, testRule(&b, 400, 1, 255, null, null));
    try std.testing.expect(summarizeRules(all.items).inbound_dropped);

    // A drop that comes after delivery to the local table drops nothing.
    var late: std.ArrayList(u8) = .empty;
    defer late.deinit(std.testing.allocator);
    try late.appendSlice(std.testing.allocator, testRule(&b, 0, 1, 255, null, null));
    try late.appendSlice(std.testing.allocator, testRule(&b, 399, 6, 0, null, null));
    try std.testing.expect(!summarizeRules(late.items).inbound_dropped);

    // Truncated input is not trusted past its end.
    try std.testing.expectEqual(RuleSummary{}, summarizeRules(dump.items[0..20]));
}

test unusedPort {
    try std.testing.expectEqual(47321, unusedPort(""));
    try std.testing.expectEqual(47322, unusedPort("listen tcp 47321\n"));
}

test printText {
    const checks = [_]Check{
        .{
            .id = "a",
            .area = "kernel",
            .name = "Kernel lockdown",
            .why = "",
            .how = "",
            .result = .pass,
            .detail = "integrity",
        },
        .{
            .id = "b",
            .area = "kernel",
            .name = "No SysRq",
            .why = "",
            .how = "",
            .result = .fail,
            .detail = "kernel.sysrq is 176",
        },
        .{
            .id = "c",
            .area = "processes",
            .name = "No setuid or setgid programs",
            .why = "",
            .how = "",
            .result = .fail,
            .detail = "/usr/bin/su, /usr/bin/sudo, /usr/bin/passwd, /usr/bin/mount",
        },
        .{
            .id = "d",
            .area = "network",
            .name = "Only declared ports open",
            .why = "",
            .how = "",
            .result = .skip,
            .detail = "listening: 22",
        },
    };
    const r: Report = .{
        .time = "",
        .os = "Wolfi",
        .host = "h",
        .kernel = "6.12.1",
        .root = true,
        .summary = .{ .pass = 1, .fail = 2, .skip = 1 },
        .checks = &checks,
    };
    var out: Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try printText(&out.writer, r, 60);
    try testing.expectEqualStrings(
        \\Wolfi, Linux 6.12.1, on h (root)
        \\
        \\Kernel
        \\  ✅ Kernel lockdown
        \\  ❌ No SysRq                      kernel.sysrq is 176
        \\
        \\Processes
        \\  ❌ No setuid or setgid programs  /usr/bin/su, +3 more
        \\
        \\Network
        \\  ⚠️ Only declared ports open      listening: 22
        \\
        \\✅ 1 passed   ❌ 2 failed   ⚠️ 1 skipped
        \\
    , out.written());

    // Not a terminal: nothing is cut.
    out.clearRetainingCapacity();
    try printText(&out.writer, r, null);
    try testing.expect(std.mem.indexOf(
        u8,
        out.written(),
        "/usr/bin/passwd, /usr/bin/mount\n",
    ) != null);
}

test whyNotLeashed {
    const ok = "Name:\tnginx\nUid:\t200\t200\t200\t200\nCapInh:\t0000000000000000\nCapPrm:\t0000" ++
        "000000000400\n" ++
        "CapEff:\t0000000000000400\nCapBnd:\t0000000000000400\nCapAmb:\t0000000000000400\nNoNewP" ++
        "rivs:\t1\n";
    try testing.expectEqual(null, whyNotLeashed(ok));
    try testing.expectEqualStrings("runs as root", whyNotLeashed("Uid:\t200\t0\t200\t200\n").?);
    const caps = "Uid:\t70\t70\t70\t70\nCapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapBnd:\t000001fffff" ++
        "fffff\nCapAmb:\t0\nNoNewPrivs:\t1\n";
    try testing.expectEqualStrings("has capabilities", whyNotLeashed(caps).?);
    const nnp = "Uid:\t70\t70\t70\t70\nCapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapBnd:\t0\nCapAmb:\t" ++
        "0\nNoNewPrivs:\t0\n";
    try testing.expectEqualStrings("may gain privileges", whyNotLeashed(nnp).?);
}

test printLine {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const checks = [_]Check{
        .{
            .id = "programs-shell",
            .area = "programs",
            .name = "No shell",
            .why = "",
            .how = "",
            .result = .fail,
        },
        .{
            .id = "kernel-lockdown",
            .area = "kernel",
            .name = "Kernel lockdown",
            .why = "",
            .how = "",
            .result = .pass,
        },
        .{
            .id = "kernel-io-uring",
            .area = "kernel",
            .name = "No io_uring",
            .why = "",
            .how = "",
            .result = .fail,
        },
    };
    const r: Report = .{
        .time = "t",
        .os = "o",
        .host = "h",
        .kernel = "k",
        .root = true,
        .summary = .{ .pass = 1, .fail = 2 },
        .checks = &checks,
    };
    var out: Io.Writer.Allocating = .init(arena.allocator());
    try printLine(arena.allocator(), &out.writer, r);
    const line = out.written();
    try testing.expect(std.mem.startsWith(
        u8,
        line,
        "posture: fail=kernel-io-uring,programs-shell pass=1 skip=0 {\"tool\":\"posture\",",
    ));
    try testing.expectEqual(1, std.mem.count(u8, line, "\n"));
    try testing.expect(std.mem.endsWith(u8, line, "}\n"));

    const clean: Report = .{
        .time = "t",
        .os = "o",
        .host = "h",
        .kernel = "k",
        .root = true,
        .summary = .{ .pass = 1 },
        .checks = checks[1..2],
    };
    out.clearRetainingCapacity();
    try printLine(arena.allocator(), &out.writer, clean);
    try testing.expect(std.mem.startsWith(u8, out.written(), "posture: fail= pass=1 skip=0 {"));
}

test serviceSettled {
    const now = 1_760_000_000;
    var st: [20]u8 = @splat(0);
    std.mem.writeInt(u64, st[0..8], (1 << 62) + 10 + now - 30, .big);
    st[17] = 'u';
    st[19] = 1;
    try testing.expect(serviceSettled(st, now)); // running 30 s
    try testing.expect(!serviceSettled(st, now - 28)); // running 2 s
    st[19] = 0;
    try testing.expect(!serviceSettled(st, now)); // down, wanted up: restarting
    st[17] = 'd';
    try testing.expect(serviceSettled(st, now)); // parked
    st[19] = 2;
    try testing.expect(!serviceSettled(st, now)); // finishing
}

test fit {
    const list = "/usr/bin/su, /usr/bin/sudo, /usr/bin/passwd";
    try testing.expectEqual(list.len, fit(list, list.len).len);
    try testing.expectEqual(0, fit(list, list.len).more);
    // "/usr/bin/su, /usr/bin/sudo, +1 more" is 35 bytes.
    try testing.expectEqualStrings("/usr/bin/su, /usr/bin/sudo", list[0..fit(list, 35).len]);
    try testing.expectEqual(1, fit(list, 35).more);
    try testing.expectEqualStrings("/usr/bin/su", list[0..fit(list, 34).len]);
    try testing.expectEqual(2, fit(list, 34).more);
    // The first item stays, however little room.
    try testing.expectEqual(11, fit(list, 0).len);
    try testing.expectEqual(2, fit(list, 0).more);
    try testing.expectEqual(13, fit("ran from /tmp", 3).len);
    try testing.expectEqual(0, fit("ran from /tmp", 3).more);
}

test prettyName {
    try testing.expectEqualStrings(
        "Ubuntu 24.04.1 LTS",
        prettyName("NAME=\"Ubuntu\"\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nID=ubuntu\n"),
    );
    try testing.expectEqualStrings("Wolfi", prettyName("ID=wolfi\nPRETTY_NAME=Wolfi\n"));
    try testing.expectEqualStrings("Linux", prettyName("PRETTY_NAME=\"\"\n"));
    try testing.expectEqualStrings("Linux", prettyName(""));
}
