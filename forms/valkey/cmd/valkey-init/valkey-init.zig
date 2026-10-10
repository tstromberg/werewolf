//! valkey-init copies one dump.rdb from the import disk into Valkey's
//! data directory, once, before the server starts. A later start that
//! finds dump.rdb leaves it. On valkey-tcp it also writes override.conf:
//! port 6379, the password, and maxmemory. See forms/valkey/README.md.

const std = @import("std");
const linux = std.os.linux;
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

const svc_dir = "/data/svc/valkey";
const run_dir = "/run/svc/valkey";
const override_name = "override.conf";
const dump_name = "dump.rdb";
const import_dir = "/run/werewolf/import";
const import_failed = import_dir ++ "/import-failed";
/// max_mib is the largest --maxmemory, matching a service's memory line.
const max_mib: i64 = 1 << 20;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();
    try writeOverride(io, gpa, init.minimal.environ);
    var svc = try Dir.cwd().openDir(io, svc_dir, .{});
    defer svc.close(io);
    if (svc.access(io, dump_name, .{})) |_| {
        say(io, "keeping {s}/{s}", .{ svc_dir, dump_name });
        return;
    } else |_| {}
    if (importBlocked(io)) {
        say(io, "import disk did not mount; not starting an empty store", .{});
        return error.ImportFailed;
    }
    const src = import_dir ++ "/" ++ dump_name;
    if (Dir.cwd().access(io, src, .{})) |_| {} else |_| return;
    const st = Dir.cwd().statFile(io, src, .{ .follow_symlinks = false }) catch |err| {
        say(io, "{s}: {s}", .{ src, @errorName(err) });
        return err;
    };
    if (st.kind == .sym_link) {
        say(io, "{s} is a symlink; not importing", .{src});
        return error.Symlink;
    }
    if (st.kind != .file) return;
    try copyDump(io, svc, src);
    say(io, "imported {s}", .{src});
}

/// writeOverride replaces override.conf. It is the one place the default
/// user is named. The socket form's user has no password, and the image's
/// port 0 and 192mb stand. valkey-tcp (PORT=6379) sets the port, the
/// password and maxmemory; 0, or no MAXMEMORY, clears the image's 192mb.
fn writeOverride(io: Io, gpa: Allocator, environ: std.process.Environ) !void {
    const tcp = openPort(gpa, environ) catch |err| {
        say(io, "PORT is 6379, the one port this form may bind", .{});
        return err;
    };
    const mem = maxmemoryOf(gpa, environ) catch |err| {
        say(io, "maxmemory is 0 to {d} MiB", .{max_mib});
        return err;
    };
    const password = setting(gpa, environ, "VALKEY_PASSWORD");
    if (tcp and !passwordOk(password)) {
        say(io, "password must be 8 to 256 characters, with no space or #", .{});
        return error.BadPassword;
    }
    const text = try limitsText(gpa, tcp, mem, password);
    var dir = try Dir.cwd().openDir(io, run_dir, .{});
    defer dir.close(io);
    const tmp = ".override.conf.tmp";
    dir.deleteFile(io, tmp) catch {};
    {
        var f = try dir.createFile(io, tmp, .{
            .exclusive = true,
            .permissions = .fromMode(0o600),
        });
        defer f.close(io);
        try f.writeStreamingAll(io, text);
        try f.sync(io);
    }
    try Dir.rename(dir, tmp, dir, override_name, io);
    if (!tcp) return;
    if (mem == 0)
        say(io, "maxmemory off", .{})
    else
        say(io, "maxmemory {d}mb", .{mem});
}

fn openPort(gpa: Allocator, environ: std.process.Environ) !bool {
    const v = setting(gpa, environ, "PORT") orelse return false;
    const n = std.fmt.parseInt(u16, v, 10) catch return error.BadPort;
    if (n != 6379) return error.BadPort;
    return true;
}

fn maxmemoryOf(gpa: Allocator, environ: std.process.Environ) !i64 {
    const v = setting(gpa, environ, "MAXMEMORY") orelse return 0;
    const n = std.fmt.parseInt(i64, v, 10) catch return error.BadMemory;
    if (n < 0 or n > max_mib) return error.BadMemory;
    return n;
}

fn setting(gpa: Allocator, environ: std.process.Environ, key: []const u8) ?[]const u8 {
    const v = environ.getAlloc(gpa, key) catch return null;
    return if (v.len > 0) v else null;
}

fn passwordOk(password: ?[]const u8) bool {
    const p = password orelse return false;
    if (p.len < 8 or p.len > 256) return false;
    for (p) |c| if (c <= 0x20 or c >= 0x7f or c == '#') return false;
    return true;
}

/// limitsText is what override.conf holds. The user is named once: Valkey
/// refuses a second definition. A later maxmemory replaces the image's.
/// maxmemory 0 is Valkey's own way of having no cap.
fn limitsText(gpa: Allocator, tcp: bool, mem: i64, password: ?[]const u8) ![]u8 {
    if (!tcp) return gpa.dupe(u8, "user default on nopass ~* &* +@all -@admin\n");
    const pass = password orelse return error.BadPassword;
    if (mem == 0) return gpa.print(
        "bind 0.0.0.0\nport 6379\nmaxmemory 0\nuser default on >{s} ~* &* +@all -@admin\n",
        .{pass},
    );
    return gpa.print(
        "bind 0.0.0.0\nport 6379\nmaxmemory {d}mb\nuser default on >{s} ~* &* +@all -@admin\n",
        .{ mem, pass },
    );
}

fn importBlocked(io: Io) bool {
    return if (Dir.cwd().access(io, import_failed, .{})) |_| true else |_| false;
}

/// copyDump writes src to dump.rdb through a temporary name, so a torn
/// copy is never what the server loads.
fn copyDump(io: Io, svc: Dir, src: []const u8) !void {
    const tmp = ".dump.rdb.tmp";
    svc.deleteFile(io, tmp) catch {};
    {
        var in = try Dir.cwd().openFile(io, src, .{ .follow_symlinks = false });
        defer in.close(io);
        var out = try svc.createFile(io, tmp, .{
            .exclusive = true,
            .permissions = .fromMode(0o600),
        });
        defer out.close(io);
        var buf: [1 << 16]u8 = undefined;
        while (true) {
            const n = in.readStreaming(io, &.{&buf}) catch |err| switch (err) {
                error.EndOfStream => break,
                else => return err,
            };
            if (n == 0) break;
            try out.writeStreamingAll(io, buf[0..n]);
        }
        try out.sync(io);
    }
    try Dir.rename(svc, tmp, svc, dump_name, io);
    try syncSvc(io);
}

fn syncSvc(io: Io) !void {
    const rc = linux.open(svc_dir, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
    var e = linux.errno(rc);
    if (e == .SUCCESS) {
        e = linux.errno(linux.fsync(@intCast(rc)));
        _ = linux.close(@intCast(rc));
    }
    if (e == .SUCCESS) return;
    say(io, "syncing {s}: {s}", .{ svc_dir, @tagName(e) });
    return error.SyncFailed;
}

test "limits stay empty off the network and name the cap on it" {
    const gpa = std.testing.allocator;
    const quiet = try limitsText(gpa, false, 0, null);
    defer gpa.free(quiet);
    try std.testing.expectEqualStrings("user default on nopass ~* &* +@all -@admin\n", quiet);
    const off = try limitsText(gpa, true, 0, "werewolf-check-password");
    defer gpa.free(off);
    try std.testing.expectEqualStrings(
        "bind 0.0.0.0\nport 6379\nmaxmemory 0\nuser default on >werewolf-check-password ~* &* +@all -@admin\n",
        off,
    );
    const capped = try limitsText(gpa, true, 64, "werewolf-check-password");
    defer gpa.free(capped);
    try std.testing.expect(std.mem.indexOf(u8, capped, "maxmemory 64mb\n") != null);
    try std.testing.expect(!passwordOk("short"));
    try std.testing.expect(!passwordOk("has a space!!"));
    try std.testing.expect(!passwordOk("has#hash!!"));
    try std.testing.expect(passwordOk("werewolf-check-password"));
}

fn say(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const line = std.mem.print(&buf, "valkey-init: " ++ fmt ++ "\n", args) catch return;
    Io.File.stdout().writeStreamingAll(io, line) catch {};
}
