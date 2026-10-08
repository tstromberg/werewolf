//! sandbox: how werewolf's programs give themselves up (docs/programs.md):
//! every descriptor closed but those they were handed, an account of their
//! own, a chroot, no capabilities or only those kept, limits, Landlock, and
//! a seccomp allowlist. One copy, so one place to audit. And how root hears
//! a child: what it says, within a limit and a deadline.

const std = @import("std");
const seal = @import("seal");
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

// --- Landlock ------------------------------------------------------------------

/// Landlock's filesystem rights, from linux/landlock.h: one copy, for this
/// file, leash and fence. A kernel ignores none it is asked to handle, so
/// what one does not know is masked off (fsAll).
pub const execute: u64 = 0x1;
pub const write_file: u64 = 0x2;
pub const read_file: u64 = 0x4;
pub const read_dir: u64 = 0x8;
pub const remove_dir: u64 = 0x10;
pub const remove_file: u64 = 0x20;
pub const make_char: u64 = 0x40;
pub const make_dir: u64 = 0x80;
pub const make_reg: u64 = 0x100;
pub const make_sock: u64 = 0x200;
pub const make_fifo: u64 = 0x400;
pub const make_block: u64 = 0x800;
pub const make_sym: u64 = 0x1000;
/// Known from ABI 2.
pub const refer: u64 = 0x2000;
/// Known from ABI 3.
pub const truncate: u64 = 0x4000;
/// Known from ABI 5.
pub const ioctl_dev: u64 = 0x8000;
/// The rights a rule on a file, not a directory, may hold.
pub const file_rights: u64 = execute | write_file | read_file | truncate | ioctl_dev;
/// Files only, beneath a directory: read, write, make, remove and truncate
/// them, and so replace one by renaming another over it.
pub const own_files: u64 = read_file | write_file | remove_file | make_reg | truncate;
/// Everything a directory's owner does: read, write, make and remove files
/// and directories, truncate. No devices, sockets, FIFOs, links or ioctls.
pub const own_dir: u64 = own_files | read_dir | remove_dir | make_dir;

/// Landlock's network rights, known from ABI 4: binding and connecting a
/// TCP socket to a port.
pub const bind_tcp: u64 = 0x1;
pub const connect_tcp: u64 = 0x2;

/// Every filesystem right a kernel of Landlock ABI abi knows.
pub fn fsAll(abi: usize) u64 {
    return if (abi >= 5)
        0xffff
    else if (abi >= 3)
        0x7fff
    else if (abi >= 2)
        0x3fff
    else
        0x1fff;
}

/// A Landlock ruleset that handles every right this kernel knows, so what
/// no rule grants is refused: every filesystem right; from ABI 4, binding
/// and connecting TCP; from ABI 6, scoped, so no abstract UNIX socket of,
/// and no signal to, a process outside the domain.
pub const Ruleset = struct {
    fd: i32,
    abi: usize,

    pub fn init() !Ruleset {
        // LANDLOCK_CREATE_RULESET_VERSION
        const abi = try sys(linux.syscall3(.landlock_create_ruleset, 0, 0, 1), "landlock version");
        // struct landlock_ruleset_attr: handled_access_fs, handled_access_net,
        // scoped (LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET and _SIGNAL).
        const attr: [3]u64 = .{
            fsAll(abi),
            if (abi >= 4) bind_tcp | connect_tcp else 0,
            if (abi >= 6) 0x3 else 0,
        };
        const size: usize = if (abi >= 6) 24 else if (abi >= 4) 16 else 8;
        const fd = try sys(
            linux.syscall3(.landlock_create_ruleset, @intFromPtr(&attr), size, 0),
            "landlock ruleset",
        );
        return .{ .fd = @intCast(fd), .abi = abi };
    }

    /// access beneath what fd names, of the rights this kernel knows: on a
    /// directory, all of it; a file's rule may hold file_rights alone.
    pub fn add(r: Ruleset, fd: i32, access: u64) !void {
        // struct landlock_path_beneath_attr, packed.
        var beneath: [12]u8 = undefined;
        std.mem.writeInt(u64, beneath[0..8], access & fsAll(r.abi), .little);
        std.mem.writeInt(i32, beneath[8..12], fd, .little);
        _ = try sys(
            linux.syscall4(.landlock_add_rule, @intCast(r.fd), 1, @intFromPtr(&beneath), 0),
            "landlock rule",
        );
    }

    /// access, bind_tcp or connect_tcp, on TCP port p; ABI 4 and later.
    pub fn port(r: Ruleset, access: u64, p: u16) !void {
        const attr: [2]u64 = .{ access, p }; // struct landlock_net_port_attr
        _ = try sys(
            linux.syscall4(.landlock_add_rule, @intCast(r.fd), 2, @intFromPtr(&attr), 0),
            "landlock port",
        );
    }

    /// Enter the domain, for good, and close the ruleset. Every access it
    /// refuses is audited, after an exec too
    /// (LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON, ABI 7): without it the
    /// kernel says nothing of a domain's refusals once the program that
    /// made it has become another.
    pub fn restrict(r: Ruleset) !void {
        const log_new_exec: usize = if (r.abi >= 7) 1 << 1 else 0;
        _ = try sys(
            linux.syscall2(.landlock_restrict_self, @intCast(r.fd), log_new_exec),
            "landlock restrict",
        );
        _ = linux.close(r.fd);
    }
};

/// Access to what fd names: beneath it, for a directory.
pub const Rule = struct { fd: i32, access: u64 };

/// Landlock: of the filesystem, only what `rules` allow; connect over TCP
/// only to `ports`, and bind none; reach no abstract socket and signal no
/// process outside. What the kernel's Landlock does not know yet goes
/// unrestricted: ports before ABI 4 (6.7), sockets and signals before ABI 6
/// (6.12). werewolf's own kernel knows all of it.
pub fn landlock(rules: []const Rule, ports: []const u16) !void {
    const ruleset: Ruleset = try .init();
    for (rules) |r| try ruleset.add(r.fd, r.access);
    if (ruleset.abi >= 4) for (ports) |p| try ruleset.port(connect_tcp, p);
    _ = try sys(linux.prctl(@backingInt(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0), "no_new_privs");
    try ruleset.restrict();
}

const SockFprog = extern struct { len: u16, filter: [*]const seal.Filter };

/// A seccomp filter that allows the calls named, some only with one
/// argument equal to a value, fails some with EPERM, and kills the process
/// for anything else, including a call made as another architecture.
pub const Filter = struct {
    prog: [max_insns]seal.Filter = undefined,
    n: usize = 3,

    const max_insns = 200;
    /// Jump targets, until finish knows where they are.
    const to_allow = 0xff;
    const to_refuse = 0xfe;

    pub fn allow(f: *Filter, comptime name: []const u8) void {
        const n = nr(name) orelse return;
        f.prog[f.n] = .{ .code = seal.JEQ_K, .jt = to_allow, .k = n };
        f.n += 1;
    }

    /// Fail the call with EPERM, as the kernel would without privilege, for
    /// a program that tries it and carries on.
    pub fn refuse(f: *Filter, comptime name: []const u8) void {
        const n = nr(name) orelse return;
        f.prog[f.n] = .{ .code = seal.JEQ_K, .jt = to_refuse, .k = n };
        f.n += 1;
    }

    /// Allow the call when argument arg equals value, comparing its low 32
    /// bits alone: only for an argument the kernel reads as 32 bits (a
    /// descriptor, an ioctl's request, a socket's family), or a value with
    /// other high bits would pass.
    pub fn allowArg(f: *Filter, comptime name: []const u8, comptime arg: u3, value: u32) void {
        const n = nr(name) orelse return;
        f.prog[f.n] = .{ .code = seal.JEQ_K, .jf = 3, .k = n };
        f.prog[f.n + 1] = .{ .code = seal.LD_W_ABS, .k = 16 + 8 * @as(u32, arg) };
        f.prog[f.n + 2] = .{ .code = seal.JEQ_K, .jt = to_allow, .k = value };
        f.prog[f.n + 3] = .{ .code = seal.LD_W_ABS, .k = 0 };
        f.n += 4;
    }

    fn finish(f: *Filter) []const seal.Filter {
        f.prog[0] = .{ .code = seal.LD_W_ABS, .k = 4 };
        f.prog[1] = .{ .code = seal.JEQ_K, .jf = @intCast(f.n - 2), .k = seal.native_arch };
        f.prog[2] = .{ .code = seal.LD_W_ABS, .k = 0 };
        const kill = f.n;
        const allow_at = f.n + 1;
        const refuse_at = f.n + 2;
        f.prog[kill] = .{ .code = seal.RET_K, .k = linux.SECCOMP.RET.KILL_PROCESS };
        f.prog[allow_at] = .{ .code = seal.RET_K, .k = linux.SECCOMP.RET.ALLOW };
        f.prog[refuse_at] = .{
            .code = seal.RET_K,
            .k = linux.SECCOMP.RET.ERRNO | @as(u32, @backingInt(linux.E.PERM)),
        };
        for (f.prog[3..kill], 3..) |*insn, i| {
            if (insn.code != seal.JEQ_K) continue;
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
