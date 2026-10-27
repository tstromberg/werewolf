//! people-persist's assertions inside one boot of
//! test/check-people-persist.zig, which names the boot in the hostname it
//! gives the machine: people-enroll and people-restore have both kept
//! accounts active, people-retire and people-conflict have them retired.
//! Enrollment gives each account a private file; every boot must find it as
//! it was, readable by its owner alone.
const std = @import("std");
const driver = @import("test-driver");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const linux = std.os.linux;
const mem = std.mem;

// The check's, test/check-people-persist.zig: these names collide under
// the people mapping, and the key is every account's.
const person = "u2guv05clv";
const collision = "udm5vojgxd";
const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGf9JfLCEyq5b4u2jFqCi6Q7BSQx5vLzPVRzCPkTaq2f";

const Account = struct { name: []const u8, uid: u32, source: []const u8 };
const kept = [_]Account{
    .{ .name = person, .uid = 982829894, .source = "p" },
    .{ .name = "lima", .uid = 1000, .source = "n" },
};
/// outsider is an identity no account has.
const outsider = 1001;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len == 5 and mem.eql(u8, args[1], "read")) return readAs(io, a, args[2..]);
    if (args.len != 4 or !mem.eql(u8, args[2], "people")) return error.Usage;
    const ctx = try driver.Run.load(io, a, args[3]);
    const suite = args[1];
    const boot = mem.trimEnd(u8, try driver.readKernel(io, a, "/proc/sys/kernel/hostname"), "\n");
    const active = mem.eql(u8, boot, "people-enroll") or mem.eql(u8, boot, "people-restore");
    if (!active and !mem.eql(u8, boot, "people-retire") and !mem.eql(u8, boot, "people-conflict"))
        return error.UnknownBoot;
    try ctx.result(io, suite, "accounts", try accounts(io, a, active));
    try ctx.result(io, suite, "collision-absent", try absent(io, a));
    if (mem.eql(u8, boot, "people-enroll")) try enroll(io, a);
    try ctx.result(io, suite, "ledger-private", try ledger(io, a));
    try ctx.result(io, suite, "admin-access", try admin(io, a, active));
    try ctx.result(io, suite, "files-private", try files(io, a, active));
}

/// Verdict is a case's: it holds while each check does, and says on the
/// console, which the stage keeps, why each that fails does not.
const Verdict = struct {
    ok: bool = true,

    fn check(v: *Verdict, holds: bool, comptime fmt: []const u8, args: anytype) void {
        if (holds) return;
        std.debug.print("people-persist: " ++ fmt ++ "\n", args);
        v.ok = false;
    }

    /// owned checks path's owners and mode.
    fn owned(v: *Verdict, a: Allocator, path: []const u8, uid: u32, gid: u32, mode: u32) !void {
        const m = try meta(a, path) orelse return v.check(false, "{s}: missing", .{path});
        v.check(
            m.uid == uid and m.gid == gid and m.mode == mode,
            "{s}: {d}:{d}:{o}, want {d}:{d}:{o}",
            .{ path, m.uid, m.gid, m.mode, uid, gid, mode },
        );
    }
};

/// Meta is what a check compares of a file: its identity, owners and mode.
const Meta = struct { inode: u64, uid: u32, gid: u32, mode: u32 };

/// meta is path's, or null if it does not exist.
fn meta(a: Allocator, path: []const u8) !?Meta {
    var info: linux.Statx = undefined;
    const rc = linux.statx(
        linux.AT.FDCWD,
        try a.dupeSentinel(u8, path, 0),
        linux.AT.SYMLINK_NOFOLLOW,
        .{ .INO = true, .MODE = true, .UID = true, .GID = true },
        &info,
    );
    return switch (linux.errno(rc)) {
        .SUCCESS => .{
            .inode = info.ino,
            .uid = info.uid,
            .gid = info.gid,
            .mode = info.mode & 0o7777,
        },
        .NOENT => null,
        else => error.FileMetadata,
    };
}

/// read is path's text, or nothing if there is no such file.
fn read(io: Io, a: Allocator, path: []const u8) ![]const u8 {
    return driver.system.read(io, a, path) catch |err| switch (err) {
        error.FileNotFound => "",
        else => err,
    };
}

/// line is whether text has a line that is want or, unless whole, begins with it.
fn line(text: []const u8, want: []const u8, whole: bool) bool {
    var lines = mem.splitScalar(u8, text, '\n');
    while (lines.next()) |l| if (if (whole) mem.eql(u8, l, want) else mem.startsWith(u8, l, want))
        return true;
    return false;
}

/// accounts are both kept accounts, active or retired, with their
/// reservations and homes: an account keeps its identity either way.
fn accounts(io: Io, a: Allocator, active: bool) !bool {
    const passwd = try read(io, a, "/etc/passwd");
    const shadow = try read(io, a, "/etc/shadow");
    const group = try read(io, a, "/etc/group");
    const identities = try read(io, a, "/data/.werewolf/identities");
    // init gives the active a shell when the image has one (cmd/init/config.zig).
    const mksh = try meta(a, "/bin/mksh") != null;
    var v: Verdict = .{};
    for (kept) |k| {
        const home = try a.print("/data/home/{s}", .{k.name});
        const shell = if (active and mksh) "/bin/mksh" else "/sbin/nologin";
        const entry = try a.print("{s}:x:{d}:{d}::{s}:{s}", .{ k.name, k.uid, k.uid, home, shell });
        v.check(line(passwd, entry, true), "passwd: no {s}", .{entry});
        const locked = try a.print("{s}:{s}:", .{ k.name, if (active) "*" else "!" });
        v.check(line(shadow, locked, false), "shadow: no {s}", .{locked});
        const member = try a.print("{s}:x:{d}:", .{ k.name, k.uid });
        v.check(line(group, member, true), "group: no {s}", .{member});
        const reserved = try a.print("{s} {s} {d} {d}", .{ k.source, k.name, k.uid, k.uid });
        v.check(line(identities, reserved, true), "identities: no {s}", .{reserved});
        try v.owned(a, home, k.uid, k.uid, 0o700);
        const keys = try a.print("/run/werewolf/keys/{s}", .{k.name});
        if (active) {
            try v.owned(a, keys, 0, k.uid, 0o640);
            v.check(mem.find(u8, try read(io, a, keys), key) != null, "{s}: no key", .{keys});
        } else v.check(try meta(a, keys) == null, "{s}: a retired account's keys", .{keys});
    }
    return v.ok;
}

/// absent is the colliding name, refused at every boot that asked for it.
fn absent(io: Io, a: Allocator) !bool {
    var v: Verdict = .{};
    v.check(!line(try read(io, a, "/etc/passwd"), collision ++ ":", false), "passwd: {s}", .{
        collision,
    });
    for ([_][]const u8{ "/data/home/" ++ collision, "/run/werewolf/keys/" ++ collision }) |path|
        v.check(try meta(a, path) == null, "{s} exists", .{path});
    return v.ok;
}

/// enroll gives each account a private file as its own, mode 0600, and
/// records it, and the reservation table, for every later boot to compare.
fn enroll(io: Io, a: Allocator) !void {
    for (kept) |k| {
        const private = try a.print("/data/home/{s}/private", .{k.name});
        try Io.Dir.cwd().writeFile(io, .{
            .sub_path = private,
            .data = try a.print("{s}-secret\n", .{k.name}),
            .flags = .{ .permissions = .fromMode(0o600) },
        });
        const path = try a.dupeSentinel(u8, private, 0);
        if (linux.errno(linux.chmod(path, 0o600)) != .SUCCESS) return error.Chmod;
        if (linux.errno(linux.chown(path, k.uid, k.uid)) != .SUCCESS) return error.Chown;
        try Io.Dir.cwd().writeFile(io, .{
            .sub_path = try a.print("/data/{s}.stat", .{k.name}),
            .data = try record(a, (try meta(a, private)).?),
        });
    }
    try Io.Dir.cwd().writeFile(io, .{
        .sub_path = "/data/identities.saved",
        .data = try read(io, a, "/data/.werewolf/identities"),
    });
}

fn record(a: Allocator, m: Meta) ![]const u8 {
    return a.print("{d}:{d}:{d}:{o}\n", .{ m.inode, m.uid, m.gid, m.mode });
}

/// ledger is the reservation table, root's alone and as enrollment left it:
/// its header and one line an account.
fn ledger(io: Io, a: Allocator) !bool {
    const table = try read(io, a, "/data/.werewolf/identities");
    var v: Verdict = .{};
    try v.owned(a, "/data/.werewolf", 0, 0, 0o700);
    try v.owned(a, "/data/.werewolf/identities", 0, 0, 0o600);
    const lines = mem.count(u8, table, "\n");
    v.check(lines == 3, "identities: {d} lines", .{lines});
    const saved = try read(io, a, "/data/identities.saved");
    v.check(mem.eql(u8, table, saved), "identities changed since enrollment", .{});
    return v.ok;
}

/// admin is root's access: the active person's key, and they are the
/// people list; with them retired, neither.
fn admin(io: Io, a: Allocator, active: bool) !bool {
    const root = try read(io, a, "/run/werewolf/keys/root");
    const people = try read(io, a, "/run/werewolf/people");
    var v: Verdict = .{};
    if (active) {
        v.check(mem.find(u8, root, "people-persist") != null, "root: no admin key", .{});
        v.check(line(people, person, true), "people: no {s}", .{person});
    } else v.check(root.len == 0 and people.len == 0, "retired, yet root keys {d} bytes, " ++
        "people {d}", .{ root.len, people.len });
    return v.ok;
}

/// files are the private files as enrollment recorded them: no one else can
/// read them, and their active owners can.
fn files(io: Io, a: Allocator, active: bool) !bool {
    const self = try std.process.executablePathAlloc(io, a);
    var v: Verdict = .{};
    for (kept) |k| {
        const private = try a.print("/data/home/{s}/private", .{k.name});
        const secret = try a.print("{s}-secret\n", .{k.name});
        const m = try meta(a, private) orelse {
            v.check(false, "{s}: missing", .{private});
            continue;
        };
        const now = try record(a, m);
        const then = try read(io, a, try a.print("/data/{s}.stat", .{k.name}));
        v.check(mem.eql(u8, now, then), "{s}: {s}, enrolled {s}", .{ private, now, then });
        v.check(mem.eql(u8, try read(io, a, private), secret), "{s} changed", .{private});
        // Mode 0600 gives a group nothing, so the outsider's groups do not matter.
        const refused = try readsAs(io, self, private, secret, outsider);
        v.check(refused == 3, "{s}: an outsider's read ended {d}", .{ private, refused });
        if (!active) continue;
        const own = try readsAs(io, self, private, secret, k.uid);
        v.check(own == 0, "{s}: its owner's read ended {d}", .{ private, own });
    }
    return v.ok;
}

/// readsAs is how this driver, reading path as uid, ends: 0 if it read
/// want, 3 if the read was refused.
fn readsAs(io: Io, self: []const u8, path: []const u8, want: []const u8, uid: u32) !u8 {
    var number: [10]u8 = undefined;
    var child = try std.process.spawn(io, .{
        .argv = &.{ self, "read", path, want, try std.mem.print(&number, "{d}", .{uid}) },
        .uid = uid,
        .gid = uid,
        .stdin = .ignore,
        .stdout = .ignore,
    });
    const term = try child.wait(io);
    return if (term == .exited) term.exited else error.ReaderKilled;
}

/// readAs is readsAs's child: PATH WANT UID, as UID alone.
fn readAs(io: Io, a: Allocator, args: []const []const u8) !void {
    const uid = try std.fmt.parseInt(u32, args[2], 10);
    const alone = linux.getuid() == uid and linux.geteuid() == uid and linux.getgid() == uid;
    if (!alone) std.process.exit(5);
    const text = driver.system.read(io, a, args[0]) catch |err| switch (err) {
        error.AccessDenied, error.PermissionDenied => std.process.exit(3),
        else => std.process.exit(4),
    };
    std.process.exit(if (mem.eql(u8, text, args[1])) 0 else 4);
}

test "a line is whole or begins one" {
    try std.testing.expect(line("a:x\nlima:x:1000:\n", "lima:x:1000:", true));
    try std.testing.expect(!line("lima:x:10001:\n", "lima:x:1000:", true));
    try std.testing.expect(line("root:*:1\nlima:!:2\n", "lima:!:", false));
    try std.testing.expect(!line("xlima:!:2\n", "lima:!:", false));
}
