//! Check real UNIX IDs and read Samba's database as its own unprivileged user.
const std = @import("std");
const driver = @import("test-driver");

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 4 or !std.mem.eql(u8, args[2], "identity")) return error.Usage;
    const ctx = try driver.Run.load(init.io, a, args[3]);
    const seed = std.mem.eql(u8, ctx.phase, "seed");
    const alice = try driver.system.account(init.io, a, "alice");
    const other = try driver.system.account(init.io, a, if (seed) "bob" else "carol");
    const database = try driver.system.read(init.io, a, "/run/svc/samba/private/smbpasswd");
    const retired = if (seed) true else locked: {
        // Retired people retain locked UNIX identities so ownership never moves.
        const bob = try driver.system.account(init.io, a, "bob");
        const passwd = try driver.system.read(init.io, a, "/run/werewolf/passwd");
        break :locked !containsUser(database, "bob") and personId(bob) and
            bob != alice and bob != other and retiredAccount(passwd, "bob", bob);
    };
    try ctx.result(init.io, args[1], if (seed)
        "samba-unix-users"
    else
        "samba-new-account", retired and personId(alice) and personId(other) and
        alice != other and
        hasUser(database, "alice", alice) and
        hasUser(database, if (seed) "bob" else "carol", other));
}

fn personId(uid: u32) bool {
    // lib/people.zig reserves [2^16, 2^30) for config-created people.
    return uid >= 1 << 16 and uid < 1 << 30;
}

fn retiredAccount(passwd: []const u8, name: []const u8, uid: u32) bool {
    var lines = std.mem.tokenizeAny(u8, passwd, "\r\n");
    while (lines.next()) |line| {
        var fields = std.mem.splitScalar(u8, line, ':');
        if (!std.mem.eql(u8, fields.next() orelse continue, name)) continue;
        _ = fields.next() orelse return false;
        const found = std.fmt.parseInt(u32, fields.next() orelse return false, 10) catch
            return false;
        const group = std.fmt.parseInt(u32, fields.next() orelse return false, 10) catch
            return false;
        _ = fields.next() orelse return false;
        _ = fields.next() orelse return false;
        return found == uid and group == uid and
            std.mem.eql(u8, fields.next() orelse return false, "/sbin/nologin") and
            fields.next() == null;
    }
    return false;
}

fn containsUser(database: []const u8, name: []const u8) bool {
    var lines = std.mem.tokenizeAny(u8, database, "\r\n");
    while (lines.next()) |line| {
        const colon = std.mem.findScalar(u8, line, ':') orelse continue;
        if (std.mem.eql(u8, line[0..colon], name)) return true;
    }
    return false;
}

fn hasUser(database: []const u8, name: []const u8, uid: u32) bool {
    var lines = std.mem.tokenizeAny(u8, database, "\r\n");
    while (lines.next()) |line| {
        var fields = std.mem.splitScalar(u8, line, ':');
        if (!std.mem.eql(u8, fields.next() orelse continue, name)) continue;
        const found = std.fmt.parseInt(u32, fields.next() orelse return false, 10) catch
            return false;
        return found == uid;
    }
    return false;
}

test "Samba's account IDs must match, without accepting a name suffix or stale ID" {
    const database = "malice:600000001:hash\nalice:600000002:hash\nbob:600000003:hash\n";
    try std.testing.expect(hasUser(database, "alice", 600000002));
    try std.testing.expect(hasUser(database, "bob", 600000003));
    try std.testing.expect(!hasUser(database, "alice", 600000001));
    try std.testing.expect(!hasUser("alice:broken:hash", "alice", 600000002));
    try std.testing.expect(containsUser(database, "bob"));
    try std.testing.expect(!containsUser(database, "carol"));
    try std.testing.expect(!containsUser("bobby:600000003:hash\n", "bob"));
}

test "retired Samba people keep the same locked UNIX identity" {
    try std.testing.expect(personId(432192699));
    try std.testing.expect(!personId((1 << 16) - 1));
    try std.testing.expect(!personId(1 << 30));
    const retired = "bob:x:600000003:600000003::/data/home/bob:/sbin/nologin\n";
    try std.testing.expect(retiredAccount(retired, "bob", 600000003));
    try std.testing.expect(!retiredAccount(retired, "bob", 600000004));
    try std.testing.expect(!retiredAccount(retired, "bobby", 600000003));
    try std.testing.expect(!retiredAccount(
        "bob:x:600000003:600000003::/data/home/bob:/bin/sh\n",
        "bob",
        600000003,
    ));
}
