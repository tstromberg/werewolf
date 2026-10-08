//! sandbox: how werewolf's programs give themselves up (docs/programs.md):
//! every descriptor closed but those they were handed, an account of their
//! own, a chroot, no capabilities or only those kept, limits, Landlock, and
//! a seccomp allowlist. One copy, so one place to audit. And how root hears
//! a child: what it says, within a limit and a deadline.

const std = @import("std");
const Allocator = std.mem.Allocator;
const linux = std.os.linux;

/// The system call that failed, and how.
pub var failed: []const u8 = "";
pub var failed_errno: linux.E = .SUCCESS;

pub fn sys(rc: usize, comptime what: []const u8) !usize {
    const err = linux.errno(rc);
    if (err == .SUCCESS) return rc;
    failed = what;
    failed_errno = err;
    return error.SystemCall;
}

/// Die with the parent, and not outlive it if it is already gone. dropTo
/// and keepOnly keep the tie, which the kernel would otherwise forget as
/// they change who the process is.
pub fn tieTo(parent: linux.pid_t) void {
    const tie: Tie = .{ .sig = @backingInt(linux.SIG.KILL), .parent = parent };
    tie.keep();
}

/// The parent-death signal, and the parent it is for. The kernel clears the
/// signal when a process's uid, gid or capabilities change, so a change of
/// them notes it before and sets it again after, and ends the process if
/// the parent died in between.
const Tie = struct {
    sig: u32,
    parent: linux.pid_t,

    fn note() Tie {
        var sig: i32 = 0;
        _ = linux.prctl(@backingInt(linux.PR.GET_PDEATHSIG), @intFromPtr(&sig), 0, 0, 0);
        return .{ .sig = @bitCast(sig), .parent = linux.getppid() };
    }

    fn keep(t: Tie) void {
        if (t.sig == 0) return;
        _ = linux.prctl(@backingInt(linux.PR.SET_PDEATHSIG), t.sig, 0, 0, 0);
        if (linux.getppid() != t.parent) linux.exit_group(1);
    }
};

/// Close every descriptor but those in keep, at most 8, with 0, 1 and 2 on
/// /dev/null: nothing of root's open files, its console included, goes
/// with a child.
pub fn closeAllBut(keep: []const i32) !void {
    var sorted: [8]i32 = undefined;
    if (keep.len > sorted.len) return error.TooManyKept;
    const null_fd: i32 = @intCast(try sys(
        linux.openat(linux.AT.FDCWD, "/dev/null", .{ .ACCMODE = .RDWR }, 0),
        "open /dev/null",
    ));
    // Where 0, 1 or 2 was closed, /dev/null opened as it already.
    for ([_]i32{ 0, 1, 2 }) |fd| if (fd != null_fd) {
        _ = try sys(linux.dup3(null_fd, fd, 0), "dup3");
    };
    const k = sorted[0..keep.len];
    @memcpy(k, keep);
    std.mem.sort(i32, k, {}, std.sort.asc(i32));
    var from: i32 = 3;
    for (k) |fd| {
        if (fd > from) _ = try sys(
            linux.close_range(from, fd - 1, .{ .UNSHARE = false, .CLOEXEC = false }),
            "close_range",
        );
        from = @max(from, fd + 1);
    }
    _ = try sys(
        linux.close_range(from, std.math.maxInt(i32), .{ .UNSHARE = false, .CLOEXEC = false }),
        "close_range",
    );
}

/// At most n of resource, hard and soft.
pub fn limit(resource: linux.rlimit_resource, n: u64) !void {
    const l: linux.rlimit = .{ .cur = n, .max = n };
    _ = try sys(linux.setrlimit(resource, &l), "setrlimit");
}

/// Become `id`, user and group, rooted at `root` if one is given, with no
/// capabilities left to anything that follows: the bounding set emptied,
/// and every set cleared after the change of uid, which alone would keep
/// them under a keepOnly's NO_SETUID_FIXUP. Then check root cannot be had
/// back.
pub fn dropTo(id: u32, root: ?[*:0]const u8) !void {
    const tie: Tie = .note();
    try bound(0);
    if (root) |r| _ = try sys(linux.chroot(r), "chroot");
    _ = try sys(linux.chdir("/"), "chdir /");
    _ = try sys(linux.setgroups(0, &[_]linux.gid_t{}), "setgroups");
    _ = try sys(linux.setresgid(id, id, id), "setresgid");
    _ = try sys(linux.setresuid(id, id, id), "setresuid");
    var hdr: CapHeader = .{};
    const none = [2]CapSets{ .{}, .{} };
    _ = try sys(linux.syscall2(.capset, @intFromPtr(&hdr), @intFromPtr(&none)), "capset");
    if (linux.errno(linux.setresuid(0, 0, 0)) == .SUCCESS) return error.StillRoot;
    tie.keep();
}

/// Keep only the capabilities in `keep`, a mask of CAP_ numbers below 32,
/// never to gain more: the bounding set emptied of the rest; NOROOT,
/// NO_SETUID_FIXUP and NO_CAP_AMBIENT_RAISE set and locked, and KEEP_CAPS
/// locked off (moot under NO_SETUID_FIXUP), so root's uid brings no others.
pub fn keepOnly(keep: u32) !void {
    const tie: Tie = .note();
    try bound(keep);
    _ = try sys(linux.prctl(@backingInt(linux.PR.SET_SECUREBITS), 0xef, 0, 0, 0), "securebits");
    var hdr: CapHeader = .{};
    const caps = [2]CapSets{ .{ .effective = keep, .permitted = keep }, .{} };
    _ = try sys(linux.syscall2(.capset, @intFromPtr(&hdr), @intFromPtr(&caps)), "capset");
    tie.keep();
}

/// The bounding set emptied of every capability not in keep, a mask of
/// those below 32. One the kernel does not know (EINVAL) is one it cannot
/// grant; any other failure is an error, not a set left whole.
fn bound(keep: u32) !void {
    for (0..64) |cap| {
        if (cap < 32 and keep & (@as(u32, 1) << @intCast(cap)) != 0) continue;
        const rc = linux.prctl(@backingInt(linux.PR.CAPBSET_DROP), cap, 0, 0, 0);
        if (linux.errno(rc) != .INVAL) _ = try sys(rc, "capbset drop");
    }
}

/// The kernel's struct __user_cap_header_struct: pid is an int, not the
/// usize std.os.linux declares, which would leave padding the kernel reads.
const CapHeader = extern struct {
    version: u32 = 0x20080522, // _LINUX_CAPABILITY_VERSION_3
    pid: i32 = 0,

    comptime {
        std.debug.assert(@sizeOf(CapHeader) == 8);
    }
};
const CapSets = extern struct { effective: u32 = 0, permitted: u32 = 0, inheritable: u32 = 0 };

/// Landlock's filesystem rights, from linux/landlock.h.
pub const execute: u64 = 0x1;
pub const write_file: u64 = 0x2;
pub const read_file: u64 = 0x4;
pub const read_dir: u64 = 0x8;
pub const remove_dir: u64 = 0x10;
pub const remove_file: u64 = 0x20;
pub const make_dir: u64 = 0x80;
pub const make_reg: u64 = 0x100;
/// Known from ABI 3; landlock drops it where the kernel does not know it.
pub const truncate: u64 = 0x4000;
/// Files only, beneath a directory: read, write, make, remove and truncate
/// them, and so replace one by renaming another over it.
pub const own_files: u64 = read_file | write_file | remove_file | make_reg | truncate;
/// Everything a directory's owner does: read, write, make and remove files
/// and directories, truncate. No devices, sockets, FIFOs, links or ioctls.
pub const own_dir: u64 = own_files | read_dir | remove_dir | make_dir;

/// Access to what fd names: beneath it, for a directory.
pub const Rule = struct { fd: i32, access: u64 };

/// Landlock: of the filesystem, only what `rules` allow; connect over TCP
/// only to `ports`, and bind none; reach no abstract socket and signal no
/// process outside. What the kernel's Landlock does not know yet goes
/// unrestricted: ports before ABI 4 (6.7), sockets and signals before ABI 6
/// (6.12). werewolf's own kernel knows all of it.
pub fn landlock(rules: []const Rule, ports: []const u16) !void {
    const abi = linux.syscall3(.landlock_create_ruleset, 0, 0, 1);
    _ = try sys(abi, "landlock version");
    const fs_all: u64 = if (abi >= 5)
        0xffff
    else if (abi >= 3)
        0x7fff
    else if (abi >= 2)
        0x3fff
    else
        0x1fff;
    // BIND_TCP and CONNECT_TCP; the scopes, abstract sockets and signals.
    const attr: [3]u64 = .{ fs_all, if (abi >= 4) 0x3 else 0, if (abi >= 6) 0x3 else 0 };
    const size: usize = if (abi >= 6) 24 else if (abi >= 4) 16 else 8;
    const ruleset = try sys(
        linux.syscall3(.landlock_create_ruleset, @intFromPtr(&attr), size, 0),
        "landlock ruleset",
    );
    for (rules) |r| {
        // LANDLOCK_RULE_PATH_BENEATH, of the rights this kernel knows.
        var beneath: [12]u8 = undefined;
        std.mem.writeInt(u64, beneath[0..8], r.access & fs_all, .little);
        std.mem.writeInt(i32, beneath[8..12], r.fd, .little);
        _ = try sys(
            linux.syscall4(.landlock_add_rule, ruleset, 1, @intFromPtr(&beneath), 0),
            "landlock rule",
        );
    }
    if (abi >= 4) for (ports) |port| {
        // LANDLOCK_RULE_NET_PORT: CONNECT_TCP.
        const rule: [2]u64 = .{ 0x2, port };
        _ = try sys(
            linux.syscall4(.landlock_add_rule, ruleset, 2, @intFromPtr(&rule), 0),
            "landlock port",
        );
    };
    _ = try sys(linux.prctl(@backingInt(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0), "no_new_privs");
    // Refusals audited, after an exec too (LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON,
    // ABI 7), for a program that runs another inside its domain.
    const log_new_exec: usize = if (abi >= 7) 1 << 1 else 0;
    _ = try sys(
        linux.syscall2(.landlock_restrict_self, ruleset, log_new_exec),
        "landlock restrict",
    );
    _ = linux.close(@intCast(ruleset));
}

const SockFilter = extern struct { code: u16, jt: u8 = 0, jf: u8 = 0, k: u32 = 0 };
const SockFprog = extern struct { len: u16, filter: [*]const SockFilter };
const BPF_LD_W_ABS = 0x20;
const BPF_JEQ_K = 0x15;
const BPF_RET_K = 0x06;

/// A seccomp filter that allows the calls named, some only with one
/// argument equal to a value, fails some with EPERM, and kills the process
/// for anything else, including a call made as another architecture.
pub const Filter = struct {
    prog: [max_insns]SockFilter = undefined,
    n: usize = 3,

    const max_insns = 200;
    /// Jump targets, until finish knows where they are.
    const to_allow = 0xff;
    const to_refuse = 0xfe;
    /// AUDIT_ARCH_X86_64 and AUDIT_ARCH_AARCH64, from linux/audit.h.
    const audit_arch: u32 = switch (@import("builtin").cpu.arch) {
        .x86_64 => 0xc000003e,
        .aarch64 => 0xc00000b7,
        else => @compileError("werewolf builds for x86_64 and aarch64"),
    };

    pub fn allow(f: *Filter, comptime name: []const u8) void {
        const n = nr(name) orelse return;
        f.prog[f.n] = .{ .code = BPF_JEQ_K, .jt = to_allow, .k = n };
        f.n += 1;
    }

    /// Fail the call with EPERM, as the kernel would without privilege, for
    /// a program that tries it and carries on.
    pub fn refuse(f: *Filter, comptime name: []const u8) void {
        const n = nr(name) orelse return;
        f.prog[f.n] = .{ .code = BPF_JEQ_K, .jt = to_refuse, .k = n };
        f.n += 1;
    }

    /// Allow the call when argument arg equals value, comparing its low 32
    /// bits alone: only for an argument the kernel reads as 32 bits (a
    /// descriptor, an ioctl's request, a socket's family), or a value with
    /// other high bits would pass.
    pub fn allowArg(f: *Filter, comptime name: []const u8, comptime arg: u3, value: u32) void {
        const n = nr(name) orelse return;
        f.prog[f.n] = .{ .code = BPF_JEQ_K, .jf = 3, .k = n };
        f.prog[f.n + 1] = .{ .code = BPF_LD_W_ABS, .k = 16 + 8 * @as(u32, arg) };
        f.prog[f.n + 2] = .{ .code = BPF_JEQ_K, .jt = to_allow, .k = value };
        f.prog[f.n + 3] = .{ .code = BPF_LD_W_ABS, .k = 0 };
        f.n += 4;
    }

    fn finish(f: *Filter) []const SockFilter {
        f.prog[0] = .{ .code = BPF_LD_W_ABS, .k = 4 };
        f.prog[1] = .{ .code = BPF_JEQ_K, .jf = @intCast(f.n - 2), .k = audit_arch };
        f.prog[2] = .{ .code = BPF_LD_W_ABS, .k = 0 };
        const kill = f.n;
        const allow_at = f.n + 1;
        const refuse_at = f.n + 2;
        f.prog[kill] = .{ .code = BPF_RET_K, .k = linux.SECCOMP.RET.KILL_PROCESS };
        f.prog[allow_at] = .{ .code = BPF_RET_K, .k = linux.SECCOMP.RET.ALLOW };
        f.prog[refuse_at] = .{
            .code = BPF_RET_K,
            .k = linux.SECCOMP.RET.ERRNO | @as(u32, @backingInt(linux.E.PERM)),
        };
        for (f.prog[3..kill], 3..) |*insn, i| {
            if (insn.code != BPF_JEQ_K) continue;
            if (insn.jt == to_allow) insn.jt = @intCast(allow_at - i - 1);
            if (insn.jt == to_refuse) insn.jt = @intCast(refuse_at - i - 1);
        }
        return f.prog[0 .. kill + 3];
    }

    pub fn install(f: *Filter) !void {
        const insns = f.finish();
        const prog: SockFprog = .{ .len = @intCast(insns.len), .filter = insns.ptr };
        _ = try sys(
            linux.prctl(@backingInt(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0),
            "no_new_privs",
        );
        _ = try sys(linux.seccomp(linux.SECCOMP.SET_MODE_FILTER, 0, &prog), "seccomp");
    }

    fn nr(comptime name: []const u8) ?u32 {
        return if (@hasField(linux.SYS, name))
            @intCast(@backingInt(@field(linux.SYS, name)))
        else
            null;
    }
};

// --- children ------------------------------------------------------------------

/// What a child said, and how it ended.
pub const Exit = struct { code: u8, out: []const u8 };

/// A child's error, as its status line: the error, or for a system call,
/// which and the kernel's reason.
pub fn whyNot(gpa: Allocator, err: anyerror) []const u8 {
    if (err != error.SystemCall) return @errorName(err);
    return gpa.print("{s}: {s}", .{ failed, errnoName(failed_errno) }) catch "SystemCall";
}

/// A child's last words, and its end.
pub fn say(out: i32, code: u8, status: []const u8, rest: []const u8) noreturn {
    for ([_][]const u8{ status, "\n", rest }) |data| {
        var off: usize = 0;
        while (off < data.len) {
            const n = linux.write(out, data[off..].ptr, data.len - off);
            if (linux.errno(n) != .SUCCESS) linux.exit_group(1);
            off += n;
        }
    }
    // Straight out: the runtime's cleanup would make calls the filter kills.
    linux.exit_group(code);
}

/// What child pid writes to in, and its exit code: at most max bytes,
/// within seconds. It is killed if it says more, or takes longer.
pub fn collect(gpa: Allocator, pid: linux.pid_t, in: i32, max: usize, seconds: i64) !Exit {
    var reaped = false;
    defer if (!reaped) {
        _ = linux.kill(pid, .KILL);
        var status: i32 = 0;
        while (linux.errno(linux.wait4(pid, &status, 0, null)) == .INTR) {}
    };
    // A byte past max, to tell a child that said max from one that said more.
    const buf = try gpa.alloc(u8, max + 1);
    const deadline = nowMs() + seconds * std.time.ms_per_s;
    var got: usize = 0;
    while (true) {
        const left = deadline - nowMs();
        if (left <= 0) return error.Timeout;
        var pfd = [1]linux.pollfd{.{ .fd = in, .events = linux.POLL.IN, .revents = 0 }};
        const ready = linux.poll(&pfd, 1, @intCast(@min(left, std.time.ms_per_s)));
        if (linux.errno(ready) == .INTR or ready == 0) continue;
        const n = linux.read(in, buf[got..].ptr, buf.len - got);
        switch (linux.errno(n)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return error.ReadFailed,
        }
        if (n == 0) break;
        got += n;
        if (got > max) return error.ChildSaidTooMuch;
    }
    // Its end of the pipe is closed: it has until the deadline to exit.
    while (nowMs() < deadline) {
        var status: i32 = 0;
        const rc = linux.wait4(pid, &status, linux.W.NOHANG, null);
        if (linux.errno(rc) == .INTR) continue;
        if (linux.errno(rc) != .SUCCESS) return error.WaitFailed;
        if (rc == 0) {
            const tick: linux.timespec = .{ .sec = 0, .nsec = 50 * std.time.ns_per_ms };
            _ = linux.nanosleep(&tick, null);
            continue;
        }
        reaped = true;
        const s: u32 = @bitCast(status);
        if (!linux.W.IFEXITED(s)) return error.ChildKilled;
        return .{ .code = linux.W.EXITSTATUS(s), .out = buf[0..got] };
    }
    return error.Timeout;
}

fn nowMs() i64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.BOOTTIME, &ts);
    return ts.sec * std.time.ms_per_s + @divFloor(ts.nsec, std.time.ns_per_ms);
}

pub fn errnoName(e: linux.E) []const u8 {
    return std.enums.tagName(linux.E, e) orelse "unknown";
}

test Filter {
    var f: Filter = .{};
    f.allow("read");
    f.allowArg("write", 0, 7);
    f.allow("this_call_does_not_exist");
    f.refuse("mount");
    const p = f.finish();
    // 0-2 the arch check and load; 3 read; 4-7 write with its argument and
    // the reload; 8 mount; 9 kill; 10 allow; 11 EPERM. Each jump lands where
    // it should.
    try std.testing.expectEqual(12, p.len);
    try std.testing.expectEqual(9, 1 + 1 + p[1].jf);
    try std.testing.expectEqual(10, 3 + 1 + p[3].jt);
    try std.testing.expectEqual(8, 4 + 1 + p[4].jf);
    try std.testing.expectEqual(@as(u32, 7), p[6].k);
    try std.testing.expectEqual(10, 6 + 1 + p[6].jt);
    try std.testing.expectEqual(11, 8 + 1 + p[8].jt);
    try std.testing.expectEqual(linux.SECCOMP.RET.KILL_PROCESS, p[9].k);
    try std.testing.expectEqual(linux.SECCOMP.RET.ALLOW, p[10].k);
    try std.testing.expectEqual(linux.SECCOMP.RET.ERRNO | 1, p[11].k);
}
