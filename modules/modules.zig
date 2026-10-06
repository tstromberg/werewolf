//! modules: load the form's kernel modules, then close the loader for good.
//!
//!     modules   load each module /usr/lib/modules/RELEASE/werewolf.modules
//!               names, in its order, then set kernel.modules_disabled
//!
//! init runs it on a RAM root, and stage0 on a slot; the root a slot hands
//! over finds the loader closed, and it says so and does nothing.
//!
//! The kernel is the judge of a module, not this program: under lockdown it
//! loads only those signed with the key it was built with. So this program
//! fails closed around that:
//!
//! - It refuses to load anything unless the kernel will check signatures
//!   (lockdown at integrity or above, or module.sig_enforce), and then still
//!   closes the loader. A machine that boots without them loads no modules.
//! - Each module goes to the kernel as an open file (finit_module(2)), so
//!   the kernel reads and checks what is on disk, not a copy this program
//!   made. The build decompresses them, since Alpine's kernel cannot.
//! - Whatever happens, the loader is closed before it exits, and it reads
//!   kernel.modules_disabled back to say so: a module that fails does not
//!   leave the door open for another try, and a write the kernel ignored is
//!   not mistaken for one it took.
//!
//! And as paranoid as the rest of werewolf's programs (docs/programs.md):
//!
//! - The list is werewolf's own, checked strictly: paths under kernel/,
//!   ending in .ko, of plain characters, no . or .. parts, at most 256. One
//!   bad line and nothing is loaded.
//! - Every file is opened beneath the module directory with symlinks
//!   refused (openat2), all of them before it pledges.
//! - Then it pledges: no_new_privs, every capability dropped but
//!   CAP_SYS_MODULE, and a seccomp filter of finit_module, read, write,
//!   close and exit. Anything else kills it.
//! - No arguments, no environment; one line on the console for what it
//!   did, and one for each module the kernel refused, with the kernel's
//!   reason.
//!
//! There is no privilege separation: nothing it reads comes from outside
//! the image, and the one judgement that matters is the kernel's.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

const max_modules = 256;
const max_list = 64 << 10;

pub fn main() void {
    if (loaderClosed()) {
        say("modules: the loader is closed already\n", .{});
        linux.exit_group(0);
    }
    // One descriptor to close the loader, one to see that it did, both
    // opened now, before the pledge. A sysctl write lands only at offset 0,
    // so the write has its own; and the answer is the kernel's, read back,
    // not the write's return.
    const disabled = openPath(modules_disabled, O_WRONLY) catch |err| fail("cannot open kernel.modules_disabled", err);
    const verify = openPath(modules_disabled, O_RDONLY) catch |err| fail("cannot open kernel.modules_disabled", err);

    // Whatever load does, the loader closes after it.
    const result = load() catch |err| blk: {
        say("modules: {s}; loading none\n", .{describe(err)});
        break :blk null;
    };

    _ = linux.write(disabled, "1", 1);
    close(disabled);
    var state: [4]u8 = undefined;
    const got = linux.read(verify, &state, state.len);
    const closed = linux.errno(got) == .SUCCESS and got > 0 and state[0] == '1';
    const door = if (closed) "closed" else "STILL OPEN";
    if (result) |r| {
        say("modules: {d} of {d} loaded; the loader is {s}\n", .{ r.count - r.refused, r.count, door });
        linux.exit_group(if (r.refused == 0 and closed) 0 else 1);
    }
    say("modules: the loader is {s}\n", .{door});
    linux.exit_group(1);
}

const Result = struct { count: usize, refused: usize };

/// Check, read, open, pledge, load: everything but closing the loader.
fn load() !Result {
    if (!enforced()) return error.Unenforced;

    var uts: linux.utsname = undefined;
    _ = linux.uname(&uts);
    const release = std.mem.sliceTo(&uts.release, 0);
    var dir_buf: [128]u8 = undefined;
    const dir_len = (std.fmt.bufPrint(dir_buf[0 .. dir_buf.len - 1], "/usr/lib/modules/{s}", .{release}) catch return error.Release).len;
    dir_buf[dir_len] = 0;
    const dir = try openPath(dir_buf[0..dir_len :0], O_PATH);
    defer close(dir);

    var list: [max_list]u8 = undefined;
    const text = try readBeneath(dir, "werewolf.modules", &list);
    var paths: [max_modules][:0]const u8 = undefined;
    var names: [max_modules][256:0]u8 = undefined;
    const count = try parse(text, &names, &paths);

    var fds: [max_modules]i32 = undefined;
    for (paths[0..count], 0..) |p, i| {
        fds[i] = openBeneath(dir, p, O_RDONLY) catch |err| {
            say("modules: {s}: cannot open\n", .{p});
            return err;
        };
    }

    try pledge();

    var refused: usize = 0;
    for (fds[0..count], paths[0..count]) |fd, p| {
        const rc = linux.syscall3(.finit_module, @bitCast(@as(isize, fd)), @intFromPtr(""), 0);
        switch (linux.errno(rc)) {
            .SUCCESS, .EXIST => {}, // built in, or loaded already
            else => |e| {
                say("modules: {s}: refused by the kernel: {t}\n", .{ p, e });
                refused += 1;
            },
        }
        close(fd);
    }
    return .{ .count = count, .refused = refused };
}

fn describe(err: anyerror) []const u8 {
    return switch (err) {
        error.Unenforced => "refused: the kernel would load unsigned modules (no lockdown, no module.sig_enforce)",
        error.BadPath, error.TooMany => "refused: werewolf.modules is not a clean list",
        else => @errorName(err),
    };
}

const modules_disabled = "/proc/sys/kernel/modules_disabled";

fn loaderClosed() bool {
    var buf: [4]u8 = undefined;
    const s = readSmall(modules_disabled, &buf) orelse return false;
    return s.len > 0 and s[0] == '1';
}

/// Whether the kernel will refuse an unsigned module: lockdown at integrity
/// or confidentiality, or module.sig_enforce.
fn enforced() bool {
    var buf: [128]u8 = undefined;
    if (readSmall("/sys/kernel/security/lockdown", &buf)) |s| {
        if (std.mem.indexOf(u8, s, "[integrity]") != null or std.mem.indexOf(u8, s, "[confidentiality]") != null) return true;
    }
    if (readSmall("/sys/module/module/parameters/sig_enforce", &buf)) |s| {
        if (s.len > 0 and s[0] == 'Y') return true;
    }
    return false;
}

// --- the list --------------------------------------------------------------------

/// The lines of werewolf.modules, each a clean path to a .ko under kernel/.
/// Any other line, or too many, and the whole list is refused.
fn parse(text: []const u8, names: *[max_modules][256:0]u8, paths: *[max_modules][:0]const u8) !usize {
    var n: usize = 0;
    var lines = std.mem.tokenizeScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (n == max_modules) return error.TooMany;
        try checkPath(line);
        @memcpy(names[n][0..line.len], line);
        names[n][line.len] = 0;
        paths[n] = names[n][0..line.len :0];
        n += 1;
    }
    return n;
}

fn checkPath(p: []const u8) !void {
    if (p.len == 0 or p.len > 255) return error.BadPath;
    if (!std.mem.startsWith(u8, p, "kernel/") or !std.mem.endsWith(u8, p, ".ko")) return error.BadPath;
    for (p) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '/' and c != '_' and c != '-' and c != '.') return error.BadPath;
    }
    var parts = std.mem.splitScalar(u8, p, '/');
    while (parts.next()) |c| {
        if (c.len == 0 or std.mem.eql(u8, c, ".") or std.mem.eql(u8, c, "..")) return error.BadPath;
    }
}

// --- files -----------------------------------------------------------------------

const O_RDONLY = 0;
const O_WRONLY = 1;
const O_PATH = 0o10000000;
const O_CLOEXEC = 0o2000000;
const RESOLVE_NO_MAGICLINKS = 0x02;
const RESOLVE_NO_SYMLINKS = 0x04;
const RESOLVE_BENEATH = 0x08;
const OpenHow = extern struct { flags: u64, mode: u64, resolve: u64 };

fn openPath(path: [:0]const u8, flags: u64) !i32 {
    return openat2(linux.AT.FDCWD, path, flags, RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS);
}

fn openBeneath(dir: i32, path: [:0]const u8, flags: u64) !i32 {
    return openat2(dir, path, flags, RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS);
}

fn openat2(dir: i32, path: [:0]const u8, flags: u64, resolve: u64) !i32 {
    var how: OpenHow = .{ .flags = flags | O_CLOEXEC, .mode = 0, .resolve = resolve };
    const rc = linux.syscall4(.openat2, @bitCast(@as(isize, dir)), @intFromPtr(path.ptr), @intFromPtr(&how), @sizeOf(OpenHow));
    try sys(rc);
    return @intCast(rc);
}

/// Read a whole file, as a stream: procfs and sysfs report a size of 0.
fn readBeneath(dir: i32, path: [:0]const u8, buf: []u8) ![]const u8 {
    const fd = try openBeneath(dir, path, O_RDONLY);
    defer close(fd);
    return readAll(fd, buf);
}

fn readSmall(path: [:0]const u8, buf: []u8) ?[]const u8 {
    const fd = openPath(path, O_RDONLY) catch return null;
    defer close(fd);
    return readAll(fd, buf) catch null;
}

fn readAll(fd: i32, buf: []u8) ![]const u8 {
    var n: usize = 0;
    while (true) {
        if (n == buf.len) return error.TooLarge;
        const rc = linux.read(fd, buf[n..].ptr, buf.len - n);
        try sys(rc);
        if (rc == 0) return buf[0..n];
        n += rc;
    }
}

fn close(fd: i32) void {
    _ = linux.close(fd);
}

// --- pledge ----------------------------------------------------------------------

const PR_SET_NO_NEW_PRIVS = 38;
const CAP_SYS_MODULE = 16;
const LINUX_CAPABILITY_VERSION_3 = 0x20080522;
const SECCOMP_SET_MODE_FILTER = 1;
const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x80000000;

/// The kernel's __user_cap_header_struct, whose pid is an int; Zig 0.17's
/// cap_user_header_t has it as a usize (see mount/mount.zig).
const CapHeader = extern struct { version: u32, pid: i32 };
const CapData = extern struct { effective: u32, permitted: u32, inheritable: u32 };

const allowed_syscalls = [_]linux.SYS{ .finit_module, .read, .write, .close, .exit, .exit_group };

const audit_arch: u32 = switch (builtin.cpu.arch) {
    .aarch64 => 0xc00000b7,
    .x86_64 => 0xc000003e,
    else => @compileError("modules runs on aarch64 and x86_64"),
};

const Filter = extern struct { code: u16, jt: u8, jf: u8, k: u32 };
const LD_W_ABS = 0x20;
const JEQ_K = 0x15;
const JGE_K = 0x35;
const RET_K = 0x06;

const filter = blk: {
    const n = allowed_syscalls.len;
    var f: [5 + n + 1]Filter = undefined;
    f[0] = .{ .code = LD_W_ABS, .jt = 0, .jf = 0, .k = 4 }; // arch
    f[1] = .{ .code = JEQ_K, .jt = 1, .jf = 0, .k = audit_arch };
    f[2] = .{ .code = RET_K, .jt = 0, .jf = 0, .k = SECCOMP_RET_KILL_PROCESS };
    f[3] = .{ .code = LD_W_ABS, .jt = 0, .jf = 0, .k = 0 }; // nr
    f[4] = .{ .code = JGE_K, .jt = @intCast(n), .jf = 0, .k = 0x40000000 }; // x32
    for (allowed_syscalls, 0..) |s, j| f[5 + j] = .{ .code = JEQ_K, .jt = @intCast(n - j), .jf = 0, .k = @intCast(@backingInt(s)) };
    f[5 + n] = .{ .code = RET_K, .jt = 0, .jf = 0, .k = SECCOMP_RET_KILL_PROCESS };
    break :blk f ++ [_]Filter{.{ .code = RET_K, .jt = 0, .jf = 0, .k = SECCOMP_RET_ALLOW }};
};

fn pledge() !void {
    try sys(linux.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
    const header: CapHeader = .{ .version = LINUX_CAPABILITY_VERSION_3, .pid = 0 };
    const keep: u32 = 1 << CAP_SYS_MODULE;
    const data = [2]CapData{
        .{ .effective = keep, .permitted = keep, .inheritable = 0 },
        .{ .effective = 0, .permitted = 0, .inheritable = 0 },
    };
    try sys(linux.syscall2(.capset, @intFromPtr(&header), @intFromPtr(&data)));
    const prog = extern struct { len: u16, filter: [*]const Filter }{ .len = filter.len, .filter = &filter };
    try sys(linux.seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog));
}

// --- saying so -------------------------------------------------------------------

fn sys(rc: usize) !void {
    return switch (linux.errno(rc)) {
        .SUCCESS => {},
        .PERM => error.PermissionDenied,
        .ACCES => error.AccessDenied,
        .NOENT => error.NoSuchFileOrDirectory,
        .LOOP => error.SymlinkInPath,
        .XDEV => error.OutsideModuleDirectory,
        .INVAL => error.InvalidArgument,
        else => error.Failed,
    };
}

fn say(comptime format: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const line = std.fmt.bufPrint(&buf, format, args) catch "modules: (message too long)\n";
    _ = linux.write(2, line.ptr, line.len);
}

fn fail(what: []const u8, err: anyerror) noreturn {
    say("modules: {s}: {s}\n", .{ what, @errorName(err) });
    linux.exit_group(1);
}

// --- tests -----------------------------------------------------------------------

const testing = std.testing;

test "a clean list parses, in order" {
    var names: [max_modules][256:0]u8 = undefined;
    var paths: [max_modules][:0]const u8 = undefined;
    const n = try parse("kernel/drivers/block/virtio_blk.ko\nkernel/net/packet/af_packet.ko\n", &names, &paths);
    try testing.expectEqual(2, n);
    try testing.expectEqualStrings("kernel/drivers/block/virtio_blk.ko", paths[0]);
    try testing.expectEqualStrings("kernel/net/packet/af_packet.ko", paths[1]);
}

test "one bad line refuses the list" {
    var names: [max_modules][256:0]u8 = undefined;
    var paths: [max_modules][:0]const u8 = undefined;
    for ([_][]const u8{
        "kernel/drivers/x.ko\n/etc/x.ko\n",
        "kernel/../x.ko\n",
        "kernel/./x.ko\n",
        "kernel//x.ko\n",
        "kernel/drivers/x.ko.gz\n",
        "drivers/x.ko\n",
        "kernel/x y.ko\n",
        "kernel/x.ko\x00\n",
    }) |text| try testing.expectError(error.BadPath, parse(text, &names, &paths));
}

test "too many modules refuses the list" {
    var names: [max_modules][256:0]u8 = undefined;
    var paths: [max_modules][:0]const u8 = undefined;
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(testing.allocator);
    for (0..max_modules + 1) |_| try text.appendSlice(testing.allocator, "kernel/x.ko\n");
    try testing.expectError(error.TooMany, parse(text.items, &names, &paths));
}

test "the pledge's pieces are the kernel's" {
    try testing.expectEqual(8, @sizeOf(CapHeader));
    try testing.expectEqual(filter.len - 1, 5 + 0 + 1 + filter[5].jt);
    try testing.expectEqual(SECCOMP_RET_ALLOW, filter[filter.len - 1].k);
}
