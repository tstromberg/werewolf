//! sandbox: how the updater's children give themselves up, as werewolf's
//! programs do (docs/programs.md): every descriptor closed but those they
//! were handed, an account of their own, a chroot, no capabilities, limits,
//! Landlock, and a seccomp allowlist. The pieces are cloud/cloud.zig's.

const std = @import("std");
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

/// Die with the parent, and not outlive it if it is already gone.
pub fn tieTo(parent: linux.pid_t) void {
    _ = linux.prctl(@backingInt(linux.PR.SET_PDEATHSIG), @backingInt(linux.SIG.KILL), 0, 0, 0);
    if (linux.getppid() != parent) linux.exit_group(1);
}

/// Close every descriptor but those in keep, with 0, 1 and 2 on /dev/null:
/// nothing of root's open files, its console included, goes with a child.
pub fn closeAllBut(keep: []const i32) !void {
    const null_fd: i32 = @intCast(try sys(linux.openat(linux.AT.FDCWD, "/dev/null", .{ .ACCMODE = .RDWR }, 0), "open /dev/null"));
    for (0..3) |fd| _ = try sys(linux.dup3(null_fd, @intCast(fd), 0), "dup3");
    var sorted: [8]i32 = undefined;
    const k = sorted[0..keep.len];
    @memcpy(k, keep);
    std.mem.sort(i32, k, {}, std.sort.asc(i32));
    var from: i32 = 3;
    for (k) |fd| {
        if (fd > from) _ = try sys(linux.close_range(from, fd - 1, .{ .UNSHARE = false, .CLOEXEC = false }), "close_range");
        from = @max(from, fd + 1);
    }
    _ = try sys(linux.close_range(from, std.math.maxInt(i32), .{ .UNSHARE = false, .CLOEXEC = false }), "close_range");
}

/// At most n of resource, hard and soft.
pub fn limit(resource: linux.rlimit_resource, n: u64) !void {
    const l: linux.rlimit = .{ .cur = n, .max = n };
    _ = try sys(linux.setrlimit(resource, &l), "setrlimit");
}

/// Become `id`, user and group, rooted at `root` if one is given, with no
/// capabilities left to anything that follows, and check root cannot be had
/// back.
pub fn dropTo(id: u32, root: ?[*:0]const u8) !void {
    var cap: usize = 0;
    while (cap < 64) : (cap += 1) _ = linux.prctl(@backingInt(linux.PR.CAPBSET_DROP), cap, 0, 0, 0);
    if (root) |r| _ = try sys(linux.chroot(r), "chroot");
    _ = try sys(linux.chdir("/"), "chdir /");
    _ = try sys(linux.setgroups(0, &[_]linux.gid_t{}), "setgroups");
    _ = try sys(linux.setresgid(id, id, id), "setresgid");
    _ = try sys(linux.setresuid(id, id, id), "setresuid");
    if (linux.errno(linux.setresuid(0, 0, 0)) == .SUCCESS) return error.StillRoot;
}

/// Landlock's filesystem rights, from linux/landlock.h.
pub const execute: u64 = 0x1;
pub const write_file: u64 = 0x2;
pub const read_file: u64 = 0x4;
pub const read_dir: u64 = 0x8;
/// Everything a directory's owner does: read, write, make and remove files
/// and directories, truncate. No devices, sockets, FIFOs, links or ioctls.
pub const own_dir: u64 = write_file | read_file | read_dir | 0x10 | 0x20 | 0x80 | 0x100 | 0x4000;

/// Access to what fd names: beneath it, for a directory.
pub const Rule = struct { fd: i32, access: u64 };

/// Landlock: of the filesystem, only what `rules` allow; connect over TCP
/// only to `ports`, and bind none; reach no abstract socket and signal no
/// process outside.
pub fn landlock(rules: []const Rule, ports: []const u16) !void {
    const abi = linux.syscall3(.landlock_create_ruleset, 0, 0, 1);
    _ = try sys(abi, "landlock version");
    const fs_all: u64 = if (abi >= 5) 0xffff else if (abi >= 3) 0x7fff else if (abi >= 2) 0x3fff else 0x1fff;
    // BIND_TCP and CONNECT_TCP; the scopes, abstract sockets and signals.
    const attr: [3]u64 = .{ fs_all, if (abi >= 4) 0x3 else 0, if (abi >= 6) 0x3 else 0 };
    const size: usize = if (abi >= 6) 24 else if (abi >= 4) 16 else 8;
    const ruleset = try sys(linux.syscall3(.landlock_create_ruleset, @intFromPtr(&attr), size, 0), "landlock ruleset");
    for (rules) |r| {
        // LANDLOCK_RULE_PATH_BENEATH, of the rights this kernel knows.
        var beneath: [12]u8 = undefined;
        std.mem.writeInt(u64, beneath[0..8], r.access & fs_all, .little);
        std.mem.writeInt(i32, beneath[8..12], r.fd, .little);
        _ = try sys(linux.syscall4(.landlock_add_rule, ruleset, 1, @intFromPtr(&beneath), 0), "landlock rule");
    }
    if (abi >= 4) for (ports) |port| {
        // LANDLOCK_RULE_NET_PORT: CONNECT_TCP.
        const rule: [2]u64 = .{ 0x2, port };
        _ = try sys(linux.syscall4(.landlock_add_rule, ruleset, 2, @intFromPtr(&rule), 0), "landlock port");
    };
    _ = try sys(linux.prctl(@backingInt(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0), "no_new_privs");
    _ = try sys(linux.syscall2(.landlock_restrict_self, ruleset, 0), "landlock restrict");
    _ = linux.close(@intCast(ruleset));
}

const SockFilter = extern struct { code: u16, jt: u8 = 0, jf: u8 = 0, k: u32 = 0 };
const SockFprog = extern struct { len: u16, filter: [*]const SockFilter };
const BPF_LD_W_ABS = 0x20;
const BPF_JEQ_K = 0x15;
const BPF_RET_K = 0x06;

/// A seccomp filter that allows the calls named, some only with one
/// argument equal to a value, fails some with EPERM, and kills the process
/// for anything else, including a call made as another architecture. As in
/// dhcp/dhcp.zig.
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
        f.prog[refuse_at] = .{ .code = BPF_RET_K, .k = linux.SECCOMP.RET.ERRNO | @as(u32, @backingInt(linux.E.PERM)) };
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
        _ = try sys(linux.prctl(@backingInt(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0), "no_new_privs");
        _ = try sys(linux.seccomp(linux.SECCOMP.SET_MODE_FILTER, 0, &prog), "seccomp");
    }

    fn nr(comptime name: []const u8) ?u32 {
        return if (@hasField(linux.SYS, name)) @intCast(@backingInt(@field(linux.SYS, name))) else null;
    }
};

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
