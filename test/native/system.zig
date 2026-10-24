//! Concrete read-only Linux probes. An unreadable source never proves absence.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Json = std.json.Value;
const linux = std.os.linux;

pub fn object(_: Allocator) Json {
    return .{ .object = .empty };
}
pub fn text(value: []const u8) Json {
    return .{ .string = value };
}
pub fn number(value: anytype) Json {
    return .{ .integer = @intCast(value) };
}
pub fn read(io: Io, a: Allocator, path: []const u8) ![]const u8 {
    var input = try Io.Dir.cwd().openFile(io, path, .{});
    defer input.close(io);
    var buffer: [4096]u8 = undefined;
    var reader = input.readerStreaming(io, &buffer);
    return reader.interface.allocRemaining(a, .limited(1 << 20));
}

pub fn file(io: Io, a: Allocator, path: []const u8, want: Json) !Json {
    if (@import("builtin").os.tag != .linux) return error.LinuxOnly;
    var info: linux.Statx = undefined;
    const rc = linux.statx(
        linux.AT.FDCWD,
        try a.dupeSentinel(u8, path, 0),
        linux.AT.SYMLINK_NOFOLLOW,
        .{ .TYPE = true, .MODE = true, .UID = true, .GID = true, .SIZE = true },
        &info,
    );
    var result = object(a);
    if (want.object.contains("readable")) {
        const fd = linux.openat(
            linux.AT.FDCWD,
            try a.dupeSentinel(u8, path, 0),
            .{ .ACCMODE = .RDONLY, .NONBLOCK = true, .CLOEXEC = true },
            0,
        );
        const allowed = try readPermission(linux.errno(fd));
        if (allowed) _ = linux.close(@intCast(fd));
        try result.object.put(a, "readable", .{ .bool = allowed });
        // An inaccessible parent can hide metadata as well. It does not prove absence.
        if (linux.errno(rc) == .ACCES or linux.errno(rc) == .PERM) return result;
    }
    if (linux.errno(rc) == .NOENT) {
        try result.object.put(a, "exists", .{ .bool = false });
        return result;
    }
    if (linux.errno(rc) != .SUCCESS) return error.FileMetadata;
    if (!info.mask.TYPE or !info.mask.MODE or !info.mask.UID or !info.mask.GID or !info.mask.SIZE)
        return error.IncompleteFileMetadata;
    try result.object.put(a, "exists", .{ .bool = true });
    try result.object.put(a, "uid", number(info.uid));
    try result.object.put(a, "gid", number(info.gid));
    try result.object.put(a, "size", number(info.size));
    try result.object.put(a, "mode", text(try a.print("{o}", .{info.mode & 0o7777})));
    try result.object.put(a, "type", text(switch (info.mode & linux.S.IFMT) {
        linux.S.IFREG => "file",
        linux.S.IFDIR => "directory",
        linux.S.IFLNK => "symlink",
        linux.S.IFSOCK => "socket",
        else => "other",
    }));
    if (want.object.contains("body") or want.object.contains("json")) {
        const contents = try read(io, a, path);
        try result.object.put(a, "body", text(contents));
    }
    if (want.object.contains("link")) {
        var buffer: [4096]u8 = undefined;
        const link = try Io.Dir.cwd().readLink(io, path, &buffer);
        try result.object.put(a, "link", text(try a.dupe(u8, buffer[0..link])));
    }
    if (want.object.contains("entries")) {
        var dir = try Io.Dir.cwd().openDir(io, path, .{ .iterate = true });
        defer dir.close(io);
        var it = dir.iterate();
        var entries: std.json.Array = .init(a);
        while (try it.next(io)) |entry| {
            if (entries.items.len >= 4096) return error.TooManyEntries;
            try entries.append(text(try a.dupe(u8, entry.name)));
        }
        std.mem.sort(Json, entries.items, {}, struct {
            fn less(_: void, x: Json, y: Json) bool {
                return std.mem.order(u8, x.string, y.string) == .lt;
            }
        }.less);
        try result.object.put(a, "entries", .{ .array = entries });
    }
    return result;
}

fn readPermission(err: linux.E) !bool {
    return switch (err) {
        .SUCCESS => true,
        .ACCES, .PERM => false,
        .NOENT => error.FileNotFound,
        else => error.FileOpen,
    };
}

test "only permission errors prove a refused file read" {
    try std.testing.expect(try readPermission(.SUCCESS));
    try std.testing.expect(!try readPermission(.ACCES));
    try std.testing.expect(!try readPermission(.PERM));
    try std.testing.expectError(error.FileNotFound, readPermission(.NOENT));
    try std.testing.expectError(error.FileOpen, readPermission(.IO));
    try std.testing.expectError(error.FileOpen, readPermission(.LOOP));
}

pub fn account(io: Io, a: Allocator, name: []const u8) !u32 {
    return identity(io, a, name, false);
}

pub fn identity(io: Io, a: Allocator, name: []const u8, group: bool) !u32 {
    var lines = std.mem.splitScalar(
        u8,
        try read(io, a, if (group) "/etc/group" else "/etc/passwd"),
        '\n',
    );
    while (lines.next()) |line| {
        var fields = std.mem.splitScalar(u8, line, ':');
        if (!std.mem.eql(u8, fields.next() orelse continue, name)) continue;
        _ = fields.next();
        return std.fmt.parseInt(u32, fields.next() orelse return error.InvalidAccount, 10);
    }
    return error.UnknownAccount;
}

pub fn field(raw: []const u8, name: []const u8) ![]const u8 {
    var lines = std.mem.splitScalar(u8, raw, '\n');
    while (lines.next()) |line| {
        const colon = std.mem.findScalar(u8, line, ':') orelse continue;
        if (std.mem.eql(
            u8,
            line[0..colon],
            name,
        )) return std.mem.trim(u8, line[colon + 1 ..], " \t\r");
    }
    return error.MissingKernelField;
}

pub fn service(io: Io, a: Allocator, name: []const u8) !Json {
    const path = try a.print("/run/cgroup/svc/{s}", .{name});
    const pids = try read(io, a, try a.print("{s}/cgroup.procs", .{path}));
    var it = std.mem.tokenizeAny(u8, pids, " \r\n\t");
    var members: std.json.Array = .init(a);
    while (it.next()) |pid| {
        _ = try std.fmt.parseInt(u32, pid, 10);
        if (members.items.len == 4096) return error.TooManyProcesses;
        const status = try read(io, a, try a.print("/proc/{s}/status", .{pid}));
        var member = object(a);
        try member.object.put(a, "pid", number(try std.fmt.parseInt(u32, pid, 10)));
        var uids: std.json.Array = .init(a);
        var ids = std.mem.tokenizeAny(u8, try field(status, "Uid"), " \t");
        while (ids.next()) |id| try uids.append(number(try std.fmt.parseInt(u32, id, 10)));
        if (uids.items.len != 4) return error.InvalidProcessIdentity;
        try member.object.put(a, "uids", .{ .array = uids });
        var groups: std.json.Array = .init(a);
        var gs = std.mem.tokenizeAny(u8, try field(status, "Groups"), " \t");
        while (gs.next()) |group| try groups.append(number(try std.fmt.parseInt(u32, group, 10)));
        try member.object.put(a, "groups", .{ .array = groups });
        try member.object.put(
            a,
            "capabilities",
            number(try std.fmt.parseInt(u64, try field(status, "CapEff"), 16)),
        );
        try member.object.put(
            a,
            "bounding_capabilities",
            number(try std.fmt.parseInt(u64, try field(status, "CapBnd"), 16)),
        );
        try member.object.put(
            a,
            "no_new_privileges",
            .{ .bool = (try std.fmt.parseInt(u8, try field(status, "NoNewPrivs"), 10)) == 1 },
        );
        const seccomp = try std.fmt.parseInt(u8, try field(status, "Seccomp"), 10);
        if (seccomp > 2) return error.InvalidSeccomp;
        try member.object.put(
            a,
            "seccomp",
            text(([_][]const u8{ "none", "strict", "filter" })[seccomp]),
        );
        try members.append(member);
    }
    if (members.items.len == 0) return error.ServiceNotRunning;
    // A changing process set is not a complete observation. Read-only await may retry it.
    if (!std.mem.eql(
        u8,
        pids,
        try read(io, a, try a.print("{s}/cgroup.procs", .{path})),
    )) return error.ProcessSetChanged;
    var result = object(a);
    try result.object.put(a, "members", .{ .array = members });
    try result.object.put(a, "processes", number(members.items.len));
    try result.object.put(
        a,
        "pids_max",
        text(std.mem.trim(u8, try read(io, a, try a.print("{s}/pids.max", .{path})), " \n")),
    );
    return result;
}

pub fn mount(io: Io, a: Allocator, path: []const u8) !Json {
    return mountTable(a, try read(io, a, "/proc/mounts"), path);
}

fn mountTable(a: Allocator, raw: []const u8, path: []const u8) !Json {
    var found: ?Json = null;
    var lines = std.mem.splitScalar(u8, raw, '\n');
    while (lines.next()) |line| {
        var words = std.mem.tokenizeScalar(u8, line, ' ');
        const source = words.next() orelse continue;
        const target = words.next() orelse return error.MountTable;
        if (!std.mem.eql(u8, try mountField(a, target), path)) continue;
        if (found != null) return error.AmbiguousMount;
        var result = object(a);
        try result.object.put(a, "source", text(try mountField(a, source)));
        try result.object.put(a, "type", text(words.next() orelse return error.MountTable));
        var flags: std.json.Array = .init(a);
        var options = std.mem.splitScalar(u8, words.next() orelse return error.MountTable, ',');
        while (options.next()) |option| try flags.append(text(option));
        try result.object.put(a, "flags", .{ .array = flags });
        found = result;
    }
    return found orelse error.MountNotFound;
}

pub fn listeners(io: Io, a: Allocator, protocol: []const u8) !Json {
    var entries: std.json.Array = .init(a);
    for ([_][]const u8{ "tcp", "tcp6", "udp", "udp6" }) |table| {
        if (!std.mem.eql(u8, protocol, "all") and
            !std.mem.startsWith(u8, table, protocol)) continue;
        const contents = read(io, a, try a.print("/proc/net/{s}", .{table})) catch |err| {
            if (err != error.FileNotFound or !std.mem.endsWith(u8, table, "6")) return err;
            if (@import("builtin").os.tag != .linux) return error.LinuxOnly;
            const fd = linux.socket(linux.AF.INET6, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
            if (linux.errno(fd) == .SUCCESS) {
                _ = linux.close(@intCast(fd));
                return error.MissingIpv6Table;
            }
            if (linux.errno(fd) != .AFNOSUPPORT) return error.MissingIpv6Table;
            continue;
        };
        var lines = std.mem.splitScalar(u8, contents, '\n');
        const header = lines.next() orelse return error.NetworkTable;
        if (std.mem.find(u8, header, "local_address") == null) return error.NetworkTable;
        while (lines.next()) |line| {
            if (std.mem.trim(u8, line, " ").len == 0) continue;
            var fields = std.mem.tokenizeAny(u8, line, " \t");
            _ = fields.next();
            const local = fields.next() orelse return error.NetworkTable;
            _ = fields.next() orelse return error.NetworkTable;
            const state = fields.next() orelse return error.NetworkTable;
            if (!std.mem.eql(u8, state, if (table[0] == 't') "0A" else "07")) continue;
            const colon = std.mem.findScalar(u8, local, ':') orelse return error.NetworkTable;
            const hex = local[0..colon];
            var entry = object(a);
            try entry.object.put(a, "protocol", text(if (table[0] == 't') "tcp" else "udp"));
            try entry.object.put(
                a,
                "port",
                number(try std.fmt.parseInt(u16, local[colon + 1 ..], 16)),
            );
            var bytes: [16]u8 = undefined;
            if (hex.len != 8 and hex.len != 32) return error.NetworkTable;
            for (0..hex.len / 8) |i| {
                const word = try std.fmt.parseInt(u32, hex[i * 8 ..][0..8], 16);
                std.mem.writeInt(
                    u32,
                    bytes[i * 4 ..][0..4],
                    word,
                    @import("builtin").cpu.arch.endian(),
                );
            }
            const address = if (hex.len == 8)
                try a.print("{d}.{d}.{d}.{d}", .{ bytes[0], bytes[1], bytes[2], bytes[3] })
            else
                try a.print("{x}:{x}:{x}:{x}:{x}:{x}:{x}:{x}", .{
                    std.mem.readInt(
                        u16,
                        bytes[0..2],
                        .big,
                    ),
                    std.mem.readInt(u16, bytes[2..4], .big),
                    std.mem.readInt(
                        u16,
                        bytes[4..6],
                        .big,
                    ),
                    std.mem.readInt(u16, bytes[6..8], .big),
                    std.mem.readInt(
                        u16,
                        bytes[8..10],
                        .big,
                    ),
                    std.mem.readInt(u16, bytes[10..12], .big),
                    std.mem.readInt(
                        u16,
                        bytes[12..14],
                        .big,
                    ),
                    std.mem.readInt(u16, bytes[14..16], .big),
                });
            try entry.object.put(a, "address", text(address));
            try entries.append(entry);
        }
    }
    return .{ .array = entries };
}

fn mountField(a: Allocator, raw: []const u8) ![]const u8 {
    var decoded: std.ArrayList(u8) = .empty;
    errdefer decoded.deinit(a);
    var i: usize = 0;
    while (i < raw.len) : (i += 1) {
        if (raw[i] != '\\') {
            try decoded.append(a, raw[i]);
            continue;
        }
        if (raw.len - i < 4) return error.MountTable;
        const code = raw[i + 1 ..][0..3];
        if (!std.mem.eql(u8, code, "040") and !std.mem.eql(u8, code, "011") and
            !std.mem.eql(u8, code, "012") and
            !std.mem.eql(u8, code, "134")) return error.MountTable;
        try decoded.append(a, try std.fmt.parseInt(u8, code, 8));
        i += 3;
    }
    return decoded.toOwnedSlice(a);
}

test "mount fields decode kernel escapes and reject malformed ones" {
    const a = std.testing.allocator;
    const decoded = try mountField(a, "/a\\040b\\134c");
    defer a.free(decoded);
    try std.testing.expectEqualStrings("/a b\\c", decoded);
    try std.testing.expectError(error.MountTable, mountField(a, "\\07"));
}

test "mount probes refuse stacked targets instead of inspecting a hidden mount" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const line = "/dev/a /data ext4 rw,nosuid,nodev,noexec 0 0\n";
    const result = try mountTable(a, line, "/data");
    try std.testing.expectEqualStrings("ext4", result.object.get("type").?.string);
    const stacked = line ++ "tmpfs /data tmpfs rw 0 0\n";
    try std.testing.expectError(error.AmbiguousMount, mountTable(a, stacked, "/data"));
    try std.testing.expectError(error.MountNotFound, mountTable(a, line, "/missing"));
}

/// Explicit fence connect rules for a process UID, including rules for all users.
/// Resolver grants (dns lines) are separate from these declarations.
pub fn connectRules(a: Allocator, raw: []const u8, uid: u32) !Json {
    var rules: std.ArrayList([]const u8) = .empty;
    var lines = std.mem.splitScalar(u8, raw, '\n');
    while (lines.next()) |line| {
        var words = std.mem.tokenizeAny(u8, line, " \t");
        if (!std.mem.eql(u8, words.next() orelse continue, "connect")) continue;
        const who = words.next() orelse return error.NetworkPolicy;
        const all = std.mem.eql(u8, who, "all");
        const owner = if (all) 0 else try std.fmt.parseInt(u32, who, 10);
        const protocol = words.next() orelse return error.NetworkPolicy;
        const icmp = std.mem.eql(u8, protocol, "icmp");
        const tcp = std.mem.eql(u8, protocol, "tcp");
        if (!icmp and !tcp and !std.mem.eql(u8, protocol, "udp")) return error.NetworkPolicy;
        const port = if (icmp) "" else words.next() orelse return error.NetworkPolicy;
        const any = std.mem.eql(u8, port, "any");
        if (any) {
            if (!tcp or all) return error.NetworkPolicy;
        } else if (!icmp and (try std.fmt.parseInt(u16, port, 10)) == 0) return error.NetworkPolicy;
        const scope = words.next();
        if (scope) |s| {
            if (icmp or any) return error.NetworkPolicy;
            if (std.mem.eql(u8, s, "lan")) {
                if (tcp or all) return error.NetworkPolicy;
            } else if (std.mem.eql(u8, s, "loopback")) {
                if (!tcp) return error.NetworkPolicy;
            } else if (!std.mem.eql(u8, s, "public")) return error.NetworkPolicy;
        }
        if (words.next() != null) return error.NetworkPolicy;
        if (!all and owner != uid) continue;
        const rule = if (icmp) "icmp" else try a.print("{s}/{s}{s}{s}", .{
            protocol, port, if (scope == null) "" else " ", scope orelse "",
        });
        try rules.append(a, rule);
    }
    std.mem.sort([]const u8, rules.items, {}, struct {
        fn less(_: void, x: []const u8, y: []const u8) bool {
            return std.mem.lessThan(u8, x, y);
        }
    }.less);
    var result: std.json.Array = .init(a);
    for (rules.items) |rule| try result.append(text(rule));
    return .{ .array = result };
}

test "connect rules match whole UIDs and include global grants without losing scopes" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const raw = "connect 1234 tcp 80\nconnect 123 tcp 443 public\nconnect 123 udp 5353 lan\n" ++
        "connect all udp 53\nconnect 123 icmp\nconnect 123 tcp any\ndns 123\nlisten tcp 80\n";
    const got = try connectRules(a, raw, 123);
    const want = [_][]const u8{ "icmp", "tcp/443 public", "tcp/any", "udp/53", "udp/5353 lan" };
    try std.testing.expectEqual(want.len, got.array.items.len);
    for (want, got.array.items) |expected, actual| try std.testing.expectEqualStrings(
        expected,
        actual.string,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        (try connectRules(a, "connect 1234 tcp 80", 123)).array.items.len,
    );
    for ([_][]const u8{
        "connect",                        "connect 123",
        "connect 123 tcp",                "connect 123 tcp 0",
        "connect 123 udp 65536",          "connect 123 tcp 80 typo",
        "connect 123 tcp 80 public junk", "connect all tcp any",
        "connect 123 udp any",            "connect 123 icmp public",
        "connect 123 tcp 80 lan",         "connect all udp 53 lan",
        "connect 123 sctp 80",
    }) |bad| {
        if (connectRules(a, bad, 123)) |_| return error.MalformedPolicyAccepted else |_| {}
    }
}
