//! seal-watch: answer for the machine seal what its promises do not allow.
//!
//! The seal (cmd/init), on PID 1, allows the system calls of the machine's
//! promises and hands the rest to this program through a seccomp listener
//! (SECCOMP_RET_USER_NOTIF), passed over a socket on stdin at boot. Each
//! service holds itself to its own pledge with a filter of its own that
//! refuses with ENOSYS, and the kernel takes ENOSYS over a listener, so
//! what reaches here is what a program running under the machine seal
//! alone, werewolf's own, makes outside the machine's promises; a leashed
//! service's refusals are not seen here. It answers each:
//!
//!     enforce   refused as if the kernel had no such call (ENOSYS); said
//!               once, with the promise that would allow it, and counted in
//!               /run/werewolf/seal/refused, which `seal` shows:
//!               seal-watch: {"event":"refused","call":"keyctl","promise":"never","pid":97}
//!     learn     allowed, and said once, with the program that made it, so
//!               make seal-learn can read what each form needs. A learning
//!               machine installs no per-service filters either, so every
//!               call reaches here:
//!               seal-watch:
//! {"event":"learned","call":"memfd_create","promise":"memfd","service":"app","exe":"/usr/bin/node"}
//!
//! What no promise brings (lib/seal.zig, never) is refused either way, and
//! so is what the seal refuses by its arguments (lib/seal.zig, refusal): a
//! socket family no promise names, kernel TLS, a watch queue, a CPU-time
//! timer. Those are answered as a kernel without the feature would answer,
//! and said with what was asked for:
//!               seal-watch:
//! {"event":"refused","call":"socket","promise":"never","why":"socket family","arg":38,"pid":97}
//! init decides to learn: only on a DEV=1 build, never released, booted
//! with werewolf.seal=learn.
//!
//! It is one process that answers every caller in turn, so it says each
//! call once, and past 512 refused counts the rest together, as other,
//! said once (learning, past 4096 it says no more): a flood of new calls
//! cannot hold the console, and with it every caller.
//!
//! init starts it before the seal, so it is not under it. Enforcing, it
//! becomes _seal, an account of its own that no service shares and so none
//! may signal, with no capabilities, under no_new_privs and a filter of its
//! own (lib/sandbox.zig) that allows the calls of its loop, ioctl only for
//! the listener's two, and kills it for anything else or another
//! architecture. Learning, it stays root, to read each caller's
//! /proc/PID/exe.

const std = @import("std");
const builtin = @import("builtin");
const seal = @import("seal");
const sandbox = @import("sandbox");
const linux = std.os.linux;

/// _seal, seal-watch's own account (forms/minimal.yaml).
const seal_id = 66;

pub fn main() void {
    var mode_buf: [8]u8 = undefined;
    const got = receiveListener(&mode_buf) orelse {
        say("no listener from init; unlisted calls are refused unsaid", .{});
        linux.exit_group(1);
    };
    _ = linux.close(0);
    const fd = got.fd;
    const learn = got.mode.len > 0 and got.mode[0] == 'l';
    // runit's stage 3 asks every process to stop; refusals still come until
    // the machine is down, so this one ignores the signals and waits for the
    // KILL that follows.
    const ignore: linux.Sigaction = .{
        .handler = .{ .handler = linux.SIG.IGN },
        .mask = linux.sigemptyset(),
        .flags = 0,
    };
    for ([_]linux.SIG{ .TERM, .HUP, .INT, .PIPE }) |sig| _ = linux.sigaction(sig, &ignore, null);
    const table = linux.open(
        seal.refused_path,
        .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true, .CLOEXEC = true, .NOFOLLOW = true },
        0o644,
    );
    if (linux.errno(table) != .SUCCESS)
        say("cannot write {s}: {s}", .{ seal.refused_path, @tagName(linux.errno(table)) });
    if (!learn) confine() catch {
        say("cannot confine itself: {s} {s}; unlisted calls are refused unsaid", .{
            sandbox.failed, sandbox.errnoName(sandbox.failed_errno),
        });
        linux.exit_group(1);
    };
    say("{{\"event\":\"start\",\"mode\":\"{s}\"}}", .{if (learn) "learn" else "enforce"});
    serve(fd, learn, if (linux.errno(table) == .SUCCESS) @intCast(table) else -1);
}

const Received = struct { fd: i32, mode: []const u8 };

/// The listener, sent by init over the socket on stdin (SCM_RIGHTS), with
/// one byte: l to learn, e to enforce.
fn receiveListener(mode_buf: *[8]u8) ?Received {
    var iov = [_]std.posix.iovec{.{ .base = mode_buf, .len = mode_buf.len }};
    var control: [cmsg_space]u8 align(8) = @splat(0);
    var msg: linux.msghdr = .{
        .name = null,
        .namelen = 0,
        .iov = &iov,
        .iovlen = 1,
        .control = &control,
        .controllen = control.len,
        .flags = 0,
    };
    const n = linux.recvmsg(0, &msg, linux.MSG.CMSG_CLOEXEC);
    if (linux.errno(n) != .SUCCESS or n == 0) return null;
    const e = builtin.cpu.arch.endian();
    if (msg.controllen < 20 or
        std.mem.readInt(i32, control[8..12], e) != linux.SOL.SOCKET or
        std.mem.readInt(i32, control[12..16], e) != scm_rights) return null;
    return .{ .fd = std.mem.readInt(i32, control[16..20], e), .mode = mode_buf[0..n] };
}

const scm_rights = 1;
/// struct cmsghdr (a size_t and two ints) and one int, aligned.
const cmsg_space = 24;

/// _seal, with no capabilities, now or ever (the bounding set emptied),
/// and a filter allowing only what serve and say call: ioctl only to hear
/// and answer the listener, not on the console it writes to.
fn confine() !void {
    try sandbox.dropTo(seal_id, null);
    var f: sandbox.Filter = .{};
    inline for (.{
        "write",      "pwrite64", "ftruncate",    "clock_gettime",
        "exit_group", "exit",     "rt_sigreturn",
    }) |name| f.allow(name);
    f.allowArg("ioctl", 1, notif_recv);
    f.allowArg("ioctl", 1, notif_send);
    try f.install();
}

/// struct seccomp_notif, and struct seccomp_notif_resp.
const Notif = extern struct {
    id: u64,
    pid: u32,
    flags: u32,
    nr: i32,
    arch: u32,
    ip: u64,
    args: [6]u64,
};
const Resp = extern struct { id: u64, val: i64, @"error": i32, flags: u32 };

/// _IOWR('!', 0, struct seccomp_notif) and _IOWR('!', 1, struct seccomp_notif_resp).
const notif_recv: u32 = 0xc0000000 | @as(u32, @sizeOf(Notif)) << 16 | 0x21 << 8 | 0;
const notif_send: u32 = 0xc0000000 | @as(u32, @sizeOf(Resp)) << 16 | 0x21 << 8 | 1;
const flag_continue: u32 = 1;

const max_rows = 512;
const max_learned = 4096;

/// One call refused this boot; never if no promise could allow it.
const Row = struct { nr: u32, count: u64, pid: u32, first: i64, never: bool = false };

fn serve(fd: i32, learn: bool, table: i32) noreturn {
    var rows: [max_rows]Row = undefined;
    var n_rows: usize = 0;
    // Every call past the rows, counted together.
    var other: Row = .{ .nr = 0, .count = 0, .pid = 0, .first = 0 };
    var learned: [max_learned]u64 = undefined;
    var n_learned: usize = 0;
    var buf: [64 << 10]u8 = undefined;
    while (true) {
        var req: Notif = std.mem.zeroes(Notif);
        const rc = linux.ioctl(fd, notif_recv, @intFromPtr(&req));
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .INTR, .NOENT => continue, // the caller died while waiting
            else => |e| {
                say("listener gone: {s}", .{@tagName(e)});
                linux.exit_group(1);
            },
        }
        const nr: u32 = @bitCast(req.nr);
        const why = seal.refusal(nr, req.args);
        const never = isNever(nr) or why != null;
        const allow = learn and !never;
        var exe_buf: [256]u8 = undefined;
        var cgroup_buf: [256]u8 = undefined;
        const exe = if (allow) exeOf(req.pid, &exe_buf) else "";
        const service = if (allow) serviceOf(req.pid, &cgroup_buf) else "";
        const resp: Resp = .{
            .id = req.id,
            .val = 0,
            .@"error" = if (allow) 0 else -@as(i32, @backingInt(if (why) |w| w.errno else .NOSYS)),
            .flags = if (allow) flag_continue else 0,
        };
        _ = linux.ioctl(fd, notif_send, @intFromPtr(&resp));
        if (allow) {
            const key = std.hash.Wyhash.hash(std.hash.Wyhash.hash(nr, exe), service);
            if (std.mem.findScalar(u64, learned[0..n_learned], key) != null) continue;
            if (n_learned == learned.len) continue;
            learned[n_learned] = key;
            n_learned += 1;
            say(
                "{{\"event\":\"learned\",\"call\":\"{s}\",\"promise\":\"{s}\"," ++
                    "\"service\":\"{s}\",\"exe\":\"{s}\"}}",
                .{ callName(nr), promiseName(nr), service, exe },
            );
            // Full: the rest are allowed, unsaid.
            if (n_learned == learned.len)
                say("{{\"event\":\"learning-full\",\"after\":{d}}}", .{max_learned});
            continue;
        }
        const row = for (rows[0..n_rows]) |*r| {
            if (r.nr == nr) break r;
        } else if (n_rows < max_rows) blk: {
            if (why) |w| say(
                "{{\"event\":\"refused\",\"call\":\"{s}\",\"promise\":\"never\"," ++
                    "\"why\":\"{s}\",\"arg\":{d},\"pid\":{d}}}",
                .{ callName(nr), w.what, w.arg, req.pid },
            ) else say(
                "{{\"event\":\"refused\",\"call\":\"{s}\",\"promise\":\"{s}\",\"pid\":{d}}}",
                .{ callName(nr), promiseName(nr), req.pid },
            );
            rows[n_rows] = .{
                .nr = nr,
                .count = 0,
                .pid = req.pid,
                .first = now(),
                .never = never,
            };
            n_rows += 1;
            break :blk &rows[n_rows - 1];
        } else blk: {
            if (other.count == 0) {
                say(
                    "{{\"event\":\"refused\",\"call\":\"other\",\"pid\":{d},\"after\":{d}}}",
                    .{ req.pid, max_rows },
                );
                other.first = now();
            }
            break :blk &other;
        };
        row.count += 1;
        row.pid = req.pid;
        if (table >= 0) {
            const text = tableText(&buf, rows[0..n_rows], other);
            _ = linux.pwrite(table, text.ptr, text.len, 0);
            _ = linux.ftruncate(table, @intCast(text.len));
        }
    }
}

fn now() i64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.REALTIME, &ts);
    return ts.sec;
}

/// The refused table: CALL COUNT LAST_PID FIRST_SECONDS PROMISE a line, and
/// other, every call past the rows, once there is one.
fn tableText(buf: []u8, rows: []const Row, other: Row) []const u8 {
    var out: std.Io.Writer = .fixed(buf);
    for (rows) |r| out.print("{s} {d} {d} {d} {s}\n", .{
        callName(r.nr), r.count, r.pid, r.first, if (r.never) "never" else promiseName(r.nr),
    }) catch break;
    if (other.count > 0) out.print("other {d} {d} {d} none\n", .{
        other.count, other.pid, other.first,
    }) catch {};
    return out.buffered();
}

fn isNever(nr: u32) bool {
    for (seal.never) |sys| if (@backingInt(sys) == nr) return true;
    return false;
}

/// The promise that would allow the call, or never, or none.
fn promiseName(nr: u32) []const u8 {
    if (isNever(nr)) return "never";
    var it = seal.promisesOf(nr).iterator();
    return if (it.next()) |p| @tagName(p) else "none";
}

/// The call's name on this architecture, or its number.
fn callName(nr: u32) []const u8 {
    for (std.enums.values(linux.SYS)) |sys| if (@backingInt(sys) == nr) return @tagName(sys);
    const S = struct {
        var buf: [16]u8 = undefined;
    };
    return std.mem.print(&S.buf, "{d}", .{nr}) catch "?";
}

/// /proc/PID/exe, as plain characters only, or "?" for a process gone.
fn exeOf(pid: u32, buf: *[256]u8) []const u8 {
    var path: [32]u8 = undefined;
    const p = std.mem.print(path[0 .. path.len - 1], "/proc/{d}/exe", .{pid}) catch return "?";
    path[p.len] = 0;
    const n = linux.readlink(@ptrCast(&path), buf, buf.len);
    if (linux.errno(n) != .SUCCESS) return "?";
    return plain(buf[0..n]);
}

/// The service pid runs as, from its cgroup, where leash puts each service
/// (/run/cgroup/svc/NAME); - for werewolf's own programs, or a process gone.
fn serviceOf(pid: u32, buf: *[256]u8) []const u8 {
    var path: [32]u8 = undefined;
    const p = std.mem.print(path[0 .. path.len - 1], "/proc/{d}/cgroup", .{pid}) catch return "-";
    path[p.len] = 0;
    const rc = linux.open(@ptrCast(&path), .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(rc) != .SUCCESS) return "-";
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    const n = linux.read(fd, buf, buf.len);
    if (linux.errno(n) != .SUCCESS) return "-";
    return cgroupService(buf[0..n]);
}

/// The service in /proc/PID/cgroup's cgroup2 line, 0::/svc/NAME, or -.
fn cgroupService(text: []u8) []const u8 {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        const prefix = "0::/svc/";
        if (!std.mem.startsWith(u8, line, prefix)) continue;
        const rest = line[prefix.len..];
        const name = rest[0 .. std.mem.findScalar(u8, rest, '/') orelse rest.len];
        if (name.len == 0) return "-";
        const at = @intFromPtr(name.ptr) - @intFromPtr(text.ptr);
        return plain(text[at..][0..name.len]);
    }
    return "-";
}

/// s, each character that is not plain printable ASCII, or would end a
/// JSON string, made ?.
fn plain(s: []u8) []const u8 {
    for (s) |*c| if (c.* < 0x20 or c.* == '"' or c.* == '\\' or c.* > 0x7e) {
        c.* = '?';
    };
    return s;
}

var line_buf: [512]u8 = undefined;

/// One line on the console.
fn say(comptime fmt: []const u8, args: anytype) void {
    const s = std.mem.print(&line_buf, "seal-watch: " ++ fmt ++ "\n", args) catch return;
    _ = linux.write(1, s.ptr, s.len);
}

const testing = std.testing;

test cgroupService {
    var a = "0::/svc/nginx\n".*;
    try testing.expectEqualStrings("nginx", cgroupService(&a));
    var b = "0::/svc/app/child\n".*;
    try testing.expectEqualStrings("app", cgroupService(&b));
    var c = "0::/\n".*;
    try testing.expectEqualStrings("-", cgroupService(&c));
    var d = "0::/svc/a\"b\n".*;
    try testing.expectEqualStrings("a?b", cgroupService(&d));
}

test callName {
    try testing.expectEqualStrings("read", callName(@intCast(@backingInt(linux.SYS.read))));
    try testing.expectEqualStrings("4000", callName(4000));
}

test promiseName {
    try testing.expectEqualStrings(
        "memfd",
        promiseName(@intCast(@backingInt(linux.SYS.memfd_create))),
    );
    try testing.expectEqualStrings("never", promiseName(@intCast(@backingInt(linux.SYS.bpf))));
    try testing.expectEqualStrings("none", promiseName(@intCast(@backingInt(linux.SYS.ptrace))));
}

test tableText {
    const rows = [_]Row{.{
        .nr = @intCast(@backingInt(linux.SYS.keyctl)),
        .count = 2,
        .pid = 97,
        .first = 1791335742,
    }};
    var buf: [256]u8 = undefined;
    const none: Row = .{ .nr = 0, .count = 0, .pid = 0, .first = 0 };
    try testing.expectEqualStrings(
        "keyctl 2 97 1791335742 never\n",
        tableText(&buf, &rows, none),
    );
    const past: Row = .{ .nr = 0, .count = 5, .pid = 98, .first = 1791335800 };
    try testing.expectEqualStrings(
        "keyctl 2 97 1791335742 never\nother 5 98 1791335800 none\n",
        tableText(&buf, &rows, past),
    );
    // A call some promise allows, refused for what it asked: never.
    const family = [_]Row{.{
        .nr = @intCast(@backingInt(linux.SYS.socket)),
        .count = 1,
        .pid = 97,
        .first = 1791335742,
        .never = true,
    }};
    try testing.expectEqualStrings(
        "socket 1 97 1791335742 never\n",
        tableText(&buf, &family, none),
    );
}

test "ioctl numbers" {
    // As the kernel's uapi header has them, for 64-bit architectures.
    try testing.expectEqual(@as(u32, 0xc0502100), notif_recv);
    try testing.expectEqual(@as(u32, 0xc0182101), notif_send);
}
