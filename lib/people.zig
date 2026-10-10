//! people turns the config's users file into accounts: what init does at
//! boot, and cloud-metadata again as the metadata server's config changes
//! (docs/forms.md, People). It touches no file: it reads the account files
//! and the users file as text and returns the text to write, so init and
//! cloud-metadata make the same accounts, and a test needs no machine.
//!
//! The users file is one key a line, `NAME [admin] TYPE KEY [COMMENT]`
//! (lib/form.zig peopleFile). A person gets uid and gid userId(name), home
//! /data/home/NAME, the shell given, and a password of "*", which sshd
//! takes a key for where "!" would refuse one. An admin's keys are root's
//! too. The people made before, named in `made`, are taken out first, so a
//! person the config no longer names loses the account and its keys; any
//! other account stays. A line that is not one, or a name or id an account
//! has, is refused with a line of why, and the rest are made.
const std = @import("std");
const Allocator = std.mem.Allocator;
const mem = std.mem;

/// Person is one of the users file's people.
pub const Person = struct { name: []const u8, keys: []const []const u8, admin: bool };

/// Files are the account files as they are, and the names of the people
/// made from the users file before, one a line (none at boot).
pub const Files = struct {
    passwd: []const u8,
    group: []const u8,
    shadow: []const u8,
    made: []const u8 = "",
};

/// Keys is a person's keys file: its name, and its lines.
pub const Keys = struct { name: []const u8, text: []const u8 };

/// Change is what apply asks for: the account files as they become, the
/// names made (the next apply's `made`), each person's keys file, the
/// admins' keys to add to root's, the names that went, and why any line
/// was refused.
pub const Change = struct {
    passwd: []const u8,
    group: []const u8,
    shadow: []const u8,
    made: []const u8,
    keys: []const Keys,
    root_keys: []const u8,
    removed: []const []const u8,
    refused: []const []const u8,
};

/// userId returns a person's uid and gid: an FNV-1a hash of the name, in
/// 1000 to 60000, the same on every machine, so a home on /data keeps its
/// owner from one image to the next.
pub fn userId(name: []const u8) u32 {
    return 1000 + std.hash.Fnv1a_32.hash(name) % 59000;
}

/// parse reads the users file. A line that is not one goes to refused.
pub fn parse(
    gpa: Allocator,
    text: []const u8,
    refused: *std.ArrayList([]const u8),
) Allocator.Error![]const Person {
    var out: std.ArrayList(Person) = .empty;
    var lines = mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        var words = mem.tokenizeAny(u8, line, " \t");
        const name = words.next() orelse continue;
        var rest = words.rest();
        const admin = mem.startsWith(u8, rest, "admin ");
        if (admin) rest = mem.trimStart(u8, rest["admin ".len..], " \t");
        if (rest.len == 0 or !isName(name) or mem.findAny(u8, line, "\r\x00") != null) {
            try refused.append(gpa, try gpa.print(
                "'{s}': not NAME [admin] TYPE KEY [COMMENT]",
                .{shown(line)},
            ));
            continue;
        }
        const person = for (out.items) |*p| {
            if (mem.eql(u8, p.name, name)) break p;
        } else blk: {
            try out.append(gpa, .{ .name = name, .keys = &.{}, .admin = false });
            break :blk &out.items[out.items.len - 1];
        };
        var keys = try gpa.alloc([]const u8, person.keys.len + 1);
        @memcpy(keys[0..person.keys.len], person.keys);
        keys[person.keys.len] = rest;
        person.keys = keys;
        if (admin) person.admin = true;
    }
    return out.items;
}

/// apply works out the accounts the users file asks for, from the files as
/// they are. shell is each person's: ash where busybox gives one.
pub fn apply(
    gpa: Allocator,
    files: Files,
    text: []const u8,
    shell: []const u8,
) Allocator.Error!Change {
    var refused: std.ArrayList([]const u8) = .empty;
    const people = try parse(gpa, text, &refused);

    // The people made before go first; what the config names comes back
    // below, and what it no longer names does not.
    var before: std.ArrayList([]const u8) = .empty;
    var it = mem.tokenizeScalar(u8, files.made, '\n');
    while (it.next()) |n| try before.append(gpa, n);
    var passwd = try without(gpa, files.passwd, before.items);
    var group = try without(gpa, files.group, before.items);
    var shadow = try without(gpa, files.shadow, before.items);

    var made: std.ArrayList(u8) = .empty;
    var keys: std.ArrayList(Keys) = .empty;
    var root_keys: std.ArrayList(u8) = .empty;
    for (people) |p| {
        const id = try gpa.print("{d}", .{userId(p.name)});
        if (mem.eql(u8, p.name, "root") or hasEntry(passwd.items, p.name) or
            hasEntry(group.items, p.name) or idInUse(passwd.items, id) or idInUse(group.items, id))
        {
            try refused.append(gpa, try gpa.print(
                "'{s}': a name or uid {s} an account has",
                .{ p.name, id },
            ));
            continue;
        }
        try passwd.print(
            gpa,
            "{s}:x:{s}:{s}::/data/home/{s}:{s}\n",
            .{ p.name, id, id, p.name, shell },
        );
        try group.print(gpa, "{s}:x:{s}:\n", .{ p.name, id });
        try shadow.print(gpa, "{s}:*:0:0:99999:7:::\n", .{p.name});
        try made.print(gpa, "{s}\n", .{p.name});
        var text_: std.ArrayList(u8) = .empty;
        for (p.keys) |k| {
            try text_.print(gpa, "{s}\n", .{k});
            if (p.admin) try root_keys.print(gpa, "{s}\n", .{k});
        }
        try keys.append(gpa, .{ .name = p.name, .text = text_.items });
    }
    var removed: std.ArrayList([]const u8) = .empty;
    for (before.items) |b| {
        const kept = for (keys.items) |k| {
            if (mem.eql(u8, k.name, b)) break true;
        } else false;
        if (!kept) try removed.append(gpa, b);
    }
    return .{
        .passwd = passwd.items,
        .group = group.items,
        .shadow = shadow.items,
        .made = made.items,
        .keys = keys.items,
        .root_keys = root_keys.items,
        .removed = removed.items,
        .refused = refused.items,
    };
}

/// without returns the account file less the lines of the names given.
fn without(
    gpa: Allocator,
    file: []const u8,
    names: []const []const u8,
) Allocator.Error!std.ArrayList(u8) {
    var out: std.ArrayList(u8) = .empty;
    var lines = mem.splitScalar(u8, file, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const name = line[0 .. mem.findScalar(u8, line, ':') orelse line.len];
        const drop = for (names) |n| {
            if (mem.eql(u8, n, name)) break true;
        } else false;
        if (!drop) try out.print(gpa, "{s}\n", .{line});
    }
    return out;
}

/// isName reports whether s is a person's name: a-z, 0-9 and -, starting
/// with a letter, at most 32, as lib/form.zig takes one and sshd allows.
pub fn isName(s: []const u8) bool {
    if (s.len == 0 or s.len > 32 or !std.ascii.isLower(s[0])) return false;
    for (s) |c| if (!std.ascii.isLower(c) and !std.ascii.isDigit(c) and c != '-') return false;
    return true;
}

fn hasEntry(file: []const u8, name: []const u8) bool {
    var lines = mem.splitScalar(u8, file, '\n');
    while (lines.next()) |line| if (line.len > name.len and line[name.len] == ':' and
        mem.eql(u8, line[0..name.len], name)) return true;
    return false;
}

fn idInUse(file: []const u8, id: []const u8) bool {
    var lines = mem.splitScalar(u8, file, '\n');
    while (lines.next()) |line| {
        var fields = mem.splitScalar(u8, line, ':');
        _ = fields.next();
        _ = fields.next();
        if (mem.eql(u8, fields.next() orelse "", id)) return true;
    }
    return false;
}

/// shown returns s cut to what a log line can hold, control characters
/// and all beyond 48 bytes left out.
fn shown(s: []const u8) []const u8 {
    const n = @min(s.len, 48);
    for (s[0..n], 0..) |c, i| if (c < ' ' or c == 0x7f) return s[0..i];
    return s[0..n];
}

const testing = std.testing;

test "apply: accounts for the people named, admins' keys root's, the gone removed" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const gpa = a.allocator();
    const base: Files = .{
        .passwd = "root:x:0:0::/root:/bin/sh\nnginx:x:384260303:384260303::/var/empty:/sbin/nolo" ++
            "gin\n",
        .group = "root:x:0:\nnginx:x:384260303:\n",
        .shadow = "root:!:::::::\nnginx:!:::::::\n",
    };
    const k1 = "sk-ssh-ed25519@openssh.com AAAA1 tom@yubikey";
    const k2 = "sk-ssh-ed25519@openssh.com AAAA2 tom@spare";
    const k3 = "sk-ssh-ed25519@openssh.com AAAA3 ann";
    const c = try apply(gpa, base, "tom admin " ++ k1 ++ "\ntom " ++ k2 ++ "\nann " ++ k3 ++
        "\nroot " ++ k3 ++ "\nBad x\nnginx " ++ k3 ++ "\n\n", "/bin/ash");
    const tom = userId("tom");
    try testing.expect(tom >= 1000 and tom < 60000);
    try testing.expectEqualStrings(try gpa.print(
        "root:x:0:0::/root:/bin/sh\nnginx:x:384260303:384260303::/var/empty:/sbin/nologin\n" ++
            "tom:x:{d}:{d}::/data/home/tom:/bin/ash\nann:x:{d}:{d}::/data/home/ann:/bin/ash\n",
        .{ tom, tom, userId("ann"), userId("ann") },
    ), c.passwd);
    try testing.expectEqualStrings("tom\nann\n", c.made);
    try testing.expectEqual(2, c.keys.len);
    try testing.expectEqualStrings(k1 ++ "\n" ++ k2 ++ "\n", c.keys[0].text);
    try testing.expectEqualStrings(k1 ++ "\n" ++ k2 ++ "\n", c.root_keys);
    try testing.expect(mem.find(u8, c.shadow, "tom:*:") != null);
    try testing.expectEqual(3, c.refused.len);
    try testing.expectEqual(0, c.removed.len);

    // Applied again with ann gone and a new person: ann's lines go, and
    // tom's are made afresh, so an edited key takes.
    const again = try apply(gpa, .{
        .passwd = c.passwd,
        .group = c.group,
        .shadow = c.shadow,
        .made = c.made,
    }, "tom " ++ k2 ++ "\nbob " ++ k3 ++ "\n", "/sbin/nologin");
    try testing.expectEqualStrings("tom\nbob\n", again.made);
    try testing.expectEqual(1, again.removed.len);
    try testing.expectEqualStrings("ann", again.removed[0]);
    try testing.expect(mem.find(u8, again.passwd, "ann:") == null);
    try testing.expect(mem.find(u8, again.passwd, "bob:x:") != null);
    try testing.expectEqualStrings("", again.root_keys);
    try testing.expectEqualStrings(k2 ++ "\n", again.keys[0].text);
    try testing.expectEqual(0, again.refused.len);
}
