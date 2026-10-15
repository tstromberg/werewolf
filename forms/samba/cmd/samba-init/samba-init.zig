//! samba-init writes Samba's configuration and its password file before
//! each start. Users come from /run/svc/samba/users, one `name:password`
//! line. Each gets a directory under /data/svc/samba/homes. Registration
//! requires an existing UNIX account; the share forces the samba service user.
//!
//! The password file is the classic smbpasswd format, under /run, rewritten
//! each start. Its NT hash is MD4 of the password in UTF-16LE. LANMAN is
//! disabled, so that field is unused.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

const data_dir = "/data/svc/samba";
const homes = data_dir ++ "/homes";
const run_dir = "/run/svc/samba";
const private_dir = run_dir ++ "/private";
const users_file = run_dir ++ "/users";
const conf_name = "smb.conf";
const passwd_name = "smbpasswd";

const User = struct { name: []const u8, password: []const u8 };

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();
    run(io, gpa) catch |err| {
        say(io, "{s}", .{@errorName(err)});
        std.process.exit(1);
    };
}

fn run(io: Io, gpa: Allocator) !void {
    const raw = Dir.cwd().readFileAlloc(io, users_file, gpa, .limited(1 << 16)) catch |err| {
        say(io, "{s}: {s}", .{ users_file, @errorName(err) });
        return err;
    };
    const users = try parseUsers(gpa, raw);
    if (users.len == 0) {
        say(io, "name at least one user, as name:password", .{});
        return error.NoUsers;
    }
    const accounts = try Dir.cwd().readFileAlloc(io, "/etc/passwd", gpa, .limited(1 << 20));
    const uids = try gpa.alloc(u32, users.len);
    for (users, uids) |user, *uid| {
        uid.* = accountUid(accounts, user.name) catch |err| {
            say(io, "{s}: a real non-root UNIX account is required", .{user.name});
            return err;
        };
    }
    // The password file and smbd's sockets live under /run: /data is noexec,
    // and the password file is rewritten from the config on every start.
    // The shares themselves stay on /data.
    for ([_][]const u8{
        data_dir,
        homes,
        private_dir,
        run_dir ++ "/lock",
        run_dir ++ "/state",
        run_dir ++ "/cache",
        run_dir ++ "/ncalrpc",
    }) |dir| {
        Dir.cwd().createDirPath(io, dir) catch |err| {
            say(io, "{s}: {s}", .{ dir, @errorName(err) });
            return err;
        };
    }
    var passwd: std.ArrayList(u8) = .empty;
    for (users, uids) |user, uid| {
        Dir.cwd().createDirPath(io, try gpa.print("{s}/{s}", .{ homes, user.name })) catch |err| {
            say(io, "{s}/{s}: {s}", .{ homes, user.name, @errorName(err) });
            return err;
        };
        const hash = ntHash(user.password);
        // smbd is not root, so it cannot become this uid. The share forces
        // the samba user, who owns the files.
        try passwd.print(
            gpa,
            "{s}:{d}:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX:{s}:[U          ]:LCT-00000001\n",
            .{ user.name, uid, hash },
        );
    }
    try writePrivate(io, passwd.items);
    const conf = try configText(gpa, users);
    try writeRun(io, conf_name, conf);
    say(io, "{d} user{s}", .{ users.len, if (users.len == 1) "" else "s" });
}

fn accountUid(passwd: []const u8, name: []const u8) !u32 {
    var found: ?u32 = null;
    var lines = std.mem.splitScalar(u8, passwd, '\n');
    while (lines.next()) |line| {
        var fields = std.mem.splitScalar(u8, line, ':');
        if (!std.mem.eql(u8, fields.next() orelse "", name)) continue;
        _ = fields.next() orelse return error.BadAccount;
        const uid = std.fmt.parseInt(
            u32,
            fields.next() orelse "",
            10,
        ) catch return error.BadAccount;
        if (uid == 0 or found != null) return error.BadAccount;
        found = uid;
    }
    return found orelse error.NoAccount;
}

fn parseUsers(gpa: Allocator, raw: []const u8) ![]User {
    var users: std.ArrayList(User) = .empty;
    errdefer users.deinit(gpa);
    var lines = std.mem.splitScalar(u8, raw, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const colon = std.mem.findScalar(u8, line, ':') orelse return error.BadUser;
        const name = line[0..colon];
        const password = line[colon + 1 ..];
        if (!nameOk(name) or !passwordOk(password)) return error.BadUser;
        for (users.items) |have| if (std.mem.eql(u8, have.name, name)) return error.BadUser;
        try users.append(gpa, .{ .name = name, .password = password });
    }
    return users.toOwnedSlice(gpa);
}

fn nameOk(name: []const u8) bool {
    if (name.len == 0 or name.len > 32) return false;
    for (name) |c| if (!std.ascii.isAlphanumeric(c) and c != '.' and c != '_' and
        c != '-') return false;
    return true;
}

fn passwordOk(password: []const u8) bool {
    if (password.len < 8 or password.len > 128) return false;
    for (password) |c| if (c < 0x20 or c >= 0x7f or c == ':') return false;
    return true;
}

fn configText(gpa: Allocator, users: []const User) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(gpa);
    // smbd exits when it cannot list interfaces. It has no netlink
    // socket, so the line names one address and it still binds every one.
    try buf.appendSlice(gpa,
        \\[global]
        \\server role = standalone server
        \\server min protocol = SMB3
        \\server smb encrypt = required
        \\server signing = mandatory
        \\disable netbios = yes
        \\smb ports = 445
        \\interfaces = 127.0.0.1/8
        \\bind interfaces only = no
        \\map to guest = Never
        \\restrict anonymous = 2
        \\null passwords = no
        \\unix password sync = no
        \\obey pam restrictions = no
        \\load printers = no
        \\printing = bsd
        \\printcap name = /dev/null
        \\disable spoolss = yes
        \\unix extensions = no
        \\wide links = no
        \\allow insecure wide links = no
        \\follow symlinks = no
        \\ntlm auth = ntlmv2-only
        \\lanman auth = no
        \\private dir = /run/svc/samba/private
        \\lock directory = /run/svc/samba/lock
        \\state directory = /run/svc/samba/state
        \\cache directory = /run/svc/samba/cache
        \\pid directory = /run/svc/samba
        \\ncalrpc dir = /run/svc/samba/ncalrpc
        \\passdb backend = smbpasswd
        \\smb passwd file = /run/svc/samba/private/smbpasswd
        \\log level = 1
        \\
    );
    for (users) |user| {
        try buf.print(gpa,
            \\
            \\[{s}]
            \\path = /data/svc/samba/homes/{s}
            \\valid users = {s}
            \\read only = no
            \\browseable = no
            \\guest ok = no
            \\force user = samba
            \\force group = samba
            \\create mask = 0600
            \\directory mask = 0700
            \\
        , .{ user.name, user.name, user.name });
    }
    return buf.toOwnedSlice(gpa);
}

fn writePrivate(io: Io, text: []const u8) !void {
    var dir = try Dir.cwd().openDir(io, private_dir, .{});
    defer dir.close(io);
    const tmp = ".smbpasswd.tmp";
    dir.deleteFile(io, tmp) catch {};
    {
        var f = try dir.createFile(
            io,
            tmp,
            .{ .exclusive = true, .permissions = .fromMode(0o600) },
        );
        defer f.close(io);
        try f.writeStreamingAll(io, text);
        try f.sync(io);
    }
    try Dir.rename(dir, tmp, dir, passwd_name, io);
}

fn writeRun(io: Io, name: []const u8, text: []const u8) !void {
    var dir = try Dir.cwd().openDir(io, run_dir, .{});
    defer dir.close(io);
    const tmp = ".smb.conf.tmp";
    dir.deleteFile(io, tmp) catch {};
    {
        var f = try dir.createFile(
            io,
            tmp,
            .{ .exclusive = true, .permissions = .fromMode(0o644) },
        );
        defer f.close(io);
        try f.writeStreamingAll(io, text);
        try f.sync(io);
    }
    try Dir.rename(dir, tmp, dir, name, io);
}

/// ntHash is Samba's NT hash: MD4 of the password's UTF-16LE bytes.
/// Passwords here are ASCII, so each byte is followed by a zero.
fn ntHash(password: []const u8) [32]u8 {
    var utf: [256]u8 = undefined;
    for (password, 0..) |c, i| {
        utf[i * 2] = c;
        utf[i * 2 + 1] = 0;
    }
    const dig = md4(utf[0 .. password.len * 2]);
    var hex: [32]u8 = undefined;
    const alphabet = "0123456789ABCDEF";
    for (dig, 0..) |b, i| {
        hex[i * 2] = alphabet[b >> 4];
        hex[i * 2 + 1] = alphabet[b & 0xf];
    }
    return hex;
}

fn md4(msg: []const u8) [16]u8 {
    // A password's UTF-16LE form fits, with padding, in two blocks.
    var storage: [512]u8 = undefined;
    const n = msg.len;
    @memcpy(storage[0..n], msg);
    storage[n] = 0x80;
    const padded_body = (n + 1 + 8 + 63) / 64 * 64;
    @memset(storage[n + 1 .. padded_body - 8], 0);
    const bits: u64 = @as(u64, n) * 8;
    std.mem.writeInt(u64, storage[padded_body - 8 ..][0..8], bits, .little);
    var a: u32 = 0x67452301;
    var b: u32 = 0xefcdab89;
    var c: u32 = 0x98badcfe;
    var d: u32 = 0x10325476;
    var off: usize = 0;
    while (off < padded_body) : (off += 64) {
        var x: [16]u32 = undefined;
        for (0..16) |i| x[i] = std.mem.readInt(u32, storage[off + i * 4 ..][0..4], .little);
        const aa = a;
        const bb = b;
        const cc = c;
        const dd = d;
        const r1 = [_]u5{ 3, 7, 11, 19 };
        inline for (0..16) |i| {
            const t = std.math.rotl(u32, a +% ((b & c) | (~b & d)) +% x[i], r1[i % 4]);
            a = d;
            d = c;
            c = b;
            b = t;
        }
        const r2 = [_]u5{ 3, 5, 9, 13 };
        const o2 = [_]usize{ 0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15 };
        inline for (0..16) |i| {
            const t = std.math.rotl(
                u32,
                a +% ((b & c) | (b & d) | (c & d)) +% x[o2[i]] +% 0x5a827999,
                r2[i % 4],
            );
            a = d;
            d = c;
            c = b;
            b = t;
        }
        const r3 = [_]u5{ 3, 9, 11, 15 };
        const o3 = [_]usize{ 0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15 };
        inline for (0..16) |i| {
            const t = std.math.rotl(u32, a +% (b ^ c ^ d) +% x[o3[i]] +% 0x6ed9eba1, r3[i % 4]);
            a = d;
            d = c;
            c = b;
            b = t;
        }
        a +%= aa;
        b +%= bb;
        c +%= cc;
        d +%= dd;
    }
    var out: [16]u8 = undefined;
    std.mem.writeInt(u32, out[0..4], a, .little);
    std.mem.writeInt(u32, out[4..8], b, .little);
    std.mem.writeInt(u32, out[8..12], c, .little);
    std.mem.writeInt(u32, out[12..16], d, .little);
    return out;
}

test "the NT hash of password is the one Samba publishes" {
    const gpa = std.testing.allocator;
    const hash = ntHash("password");
    try std.testing.expectEqualStrings("8846F7EAEE8FB117AD06BDD830B7586C", &hash);
    const users = try parseUsers(
        gpa,
        "alice:werewolf-check-password\nbob:werewolf-other-password\n",
    );
    defer gpa.free(users);
    try std.testing.expectEqual(@as(usize, 2), users.len);
    try std.testing.expectError(error.BadUser, parseUsers(gpa, "alice:short\n"));
    try std.testing.expectError(error.BadUser, parseUsers(gpa, "alice:pass:word1\n"));
    try std.testing.expectError(
        error.BadUser,
        parseUsers(gpa, "alice:werewolf-check-password\nalice:werewolf-other-password\n"),
    );
    const conf = try configText(gpa, users);
    defer gpa.free(conf);
    try std.testing.expect(std.mem.indexOf(u8, conf, "server smb encrypt = required\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, conf, "bind interfaces only = no\n") != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        conf,
        "smb passwd file = /run/svc/samba/private/smbpasswd\n",
    ) != null);
    try std.testing.expect(std.mem.indexOf(u8, conf, "valid users = alice\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, conf, "guest ok = no\n") != null);
}

test "SMB identities come from existing UNIX users, independent of password order" {
    const passwd = "root:x:0:0::/root:/bin/sh\nalice:x:1001:1001::/data/home/alice:/sbin/nologin" ++
        "\nbob:x:1002:1002::/data/home/bob:/sbin/nologin\n";
    try std.testing.expectEqual(@as(u32, 1002), try accountUid(passwd, "bob"));
    try std.testing.expectEqual(@as(u32, 1001), try accountUid(passwd, "alice"));
    try std.testing.expectError(error.NoAccount, accountUid(passwd, "carol"));
    try std.testing.expectError(error.BadAccount, accountUid(passwd, "root"));
    try std.testing.expectError(
        error.BadAccount,
        accountUid("alice:x:0:1001::/:/bin/sh\n", "alice"),
    );
    try std.testing.expectError(
        error.BadAccount,
        accountUid("alice:x:bad:1001::/:/bin/sh\n", "alice"),
    );
    try std.testing.expectError(
        error.BadAccount,
        accountUid(passwd ++ "alice:x:2001:2001::/:/bin/sh\n", "alice"),
    );
}

fn say(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const line = std.mem.print(&buf, "samba-init: " ++ fmt ++ "\n", args) catch return;
    Io.File.stdout().writeStreamingAll(io, line) catch {};
}
