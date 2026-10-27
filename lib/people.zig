//! people turns the config's users file and durable identity table into
//! accounts at boot and during metadata polling (docs/forms.md, People).
//!
//! The users file names an account alone, or one SSH key per line as
//! `NAME [admin] TYPE KEY [COMMENT]`
//! (lib/form.zig peopleFile). A person gets uid and gid userId(name), home
//! /data/home/NAME, the shell given, and a password of "*", which sshd
//! takes a key for where "!" would refuse one. An admin's keys are root's
//! too. A person the config no longer names keeps locked account entries
//! and loses its keys; any other account stays. Malformed lines and names
//! or IDs that conflict with an account are refused with a reason.
const std = @import("std");
const Allocator = std.mem.Allocator;
const mem = std.mem;
const linux = std.os.linux;

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
pub const Keys = struct { name: []const u8, text: []const u8, id: u32 = 0 };

/// verify_path holds the key types a machine's sshd must see verified, one
/// a line, from form.yaml's sshd: verify-required-keys (lib/sshd.zig).
pub const verify_path = "/usr/share/werewolf/sshd-verify-required";

/// verified returns a keys file's text with `verify-required` before each
/// key whose type policy names (verify_path's contents): sshd then takes
/// that key's signature only if its authenticator verified the person.
/// A line that starts with anything else, an option included, stays.
pub fn verified(gpa: Allocator, text: []const u8, policy: []const u8) ![]const u8 {
    if (mem.trim(u8, policy, " \t\n").len == 0) return text;
    var out: std.ArrayList(u8) = .empty;
    var lines = mem.splitScalar(u8, text, '\n');
    var first = true;
    while (lines.next()) |line| {
        if (!first) try out.append(gpa, '\n');
        first = false;
        var words = mem.tokenizeAny(u8, line, " \t");
        const kind = words.next() orelse "";
        var types = mem.tokenizeAny(u8, policy, " \t\n");
        while (types.next()) |t| if (mem.eql(u8, t, kind)) {
            try out.appendSlice(gpa, "verify-required ");
            break;
        };
        try out.appendSlice(gpa, line);
    }
    return out.items;
}

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
    identities: []const Identity = &.{},
    nocloud_name: []const u8 = "",
};

pub const Source = enum { people, nocloud };
pub const Identity = struct { source: Source, name: []const u8, id: u32 };
pub const NoCloud = struct { name: []const u8, id: u32, keys: []const u8 };

/// ids are the uid ranges, first and last, people's accounts take: NoCloud's
/// logins, then userId's. A form's `:people` network grant is these
/// (lib/compose.zig net), so the build refuses any other account in them.
pub const ids = [_][2]u32{ .{ 500, 60000 }, .{ 1 << 16, (1 << 30) - 1 } };

/// userId returns a person's uid and gid in [2^16, 2^30), ids[1]. The fixed
/// FNV-1a mapping is stable across machines; the durable identity table still
/// checks every collision before this ID can own a file.
pub fn userId(name: []const u8) u32 {
    const span: u64 = ids[1][1] + 1 - ids[1][0];
    return ids[1][0] + @as(u32, @intCast((@as(u64, std.hash.Fnv1a_32.hash(name)) * span) >> 32));
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
        const admin = mem.eql(u8, rest, "admin") or mem.startsWith(u8, rest, "admin ");
        if (admin) rest = mem.trimStart(u8, rest["admin".len..], " \t");
        if ((admin and rest.len == 0) or !isName(name) or
            (rest.len > 0 and !validKey(rest)) or mem.findAny(u8, line, "\r\x00") != null)
        {
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
        if (rest.len == 0) continue;
        var keys = try gpa.alloc([]const u8, person.keys.len + 1);
        @memcpy(keys[0..person.keys.len], person.keys);
        keys[person.keys.len] = rest;
        person.keys = keys;
        if (admin) person.admin = true;
    }
    return out.items;
}

/// applyReserved derives account files from the durable identity table. At
/// boot it also accepts one NoCloud request; polling leaves that account as it
/// is and changes only people. The caller persists new identities before it
/// publishes any of these files or changes a home.
pub fn applyReserved(
    gpa: Allocator,
    files: Files,
    identities: []const Identity,
    text: []const u8,
    shell: []const u8,
    nocloud: ?NoCloud,
    boot: bool,
) !Change {
    var refused: std.ArrayList([]const u8) = .empty;
    const wanted = try parse(gpa, text, &refused);
    var old: std.ArrayList([]const u8) = .empty;
    var it = mem.tokenizeScalar(u8, files.made, '\n');
    while (it.next()) |name| try old.append(gpa, name);
    // Remove only the accounts that this publisher owns. NoCloud and image
    // accounts stay in place during metadata polling.
    var owned: std.ArrayList([]const u8) = .empty;
    try owned.appendSlice(gpa, old.items);
    for (identities) |r| {
        if (boot and (hasEntry(files.passwd, r.name) or hasEntry(files.group, r.name) or
            hasEntry(files.shadow, r.name) or
            (try idInUseNumber(gpa, files.passwd, r.id)) or
            (try idInUseNumber(gpa, files.group, r.id)))) return error.AccountConflict;
        if (r.source != .people) continue;
        try owned.append(gpa, r.name);
    }
    var passwd = try without(gpa, files.passwd, owned.items);
    var group = try without(gpa, files.group, owned.items);
    var shadow = try without(gpa, files.shadow, owned.items);
    var records: std.ArrayList(Identity) = .empty;
    try records.appendSlice(gpa, identities);
    var keys: std.ArrayList(Keys) = .empty;
    var active_nocloud: []const u8 = "";

    if (boot) {
        if (nocloud) |nc| {
            if (validNoCloudName(nc.name) and nc.id >= ids[0][0] and nc.id <= ids[0][1] and
                !conflicts(records.items, .nocloud, nc.name, nc.id) and
                !hasEntry(passwd.items, nc.name) and !hasEntry(group.items, nc.name) and
                !hasEntry(shadow.items, nc.name) and
                !(try idInUseNumber(gpa, passwd.items, nc.id)) and
                !(try idInUseNumber(gpa, group.items, nc.id)))
            {
                try ensureRecord(gpa, &records, .nocloud, nc.name, nc.id);
                try appendAccount(gpa, &passwd, &group, &shadow, nc.name, nc.id, shell, false);
                try keys.append(gpa, .{ .name = nc.name, .text = nc.keys, .id = nc.id });
                active_nocloud = nc.name;
            } else try refused.append(gpa, "NoCloud name or UID is already reserved");
        }
        for (records.items) |r| {
            if (r.source != .nocloud or mem.eql(u8, r.name, active_nocloud)) continue;
            try appendAccount(gpa, &passwd, &group, &shadow, r.name, r.id, "/sbin/nologin", true);
        }
    }

    var made: std.ArrayList(u8) = .empty;
    var administrators: std.ArrayList([]const u8) = .empty;
    var root_keys: std.ArrayList(u8) = .empty;
    for (wanted) |p| {
        const id = userId(p.name);
        if (mem.eql(u8, p.name, "root") or mem.eql(u8, p.name, "wheel") or
            conflicts(records.items, .people, p.name, id) or
            hasEntry(passwd.items, p.name) or hasEntry(group.items, p.name) or
            hasEntry(shadow.items, p.name) or
            (try idInUseNumber(gpa, passwd.items, id)) or
            (try idInUseNumber(gpa, group.items, id)))
        {
            try refused.append(
                gpa,
                try gpa.print("'{s}': name or UID is already reserved", .{p.name}),
            );
            continue;
        }
        try ensureRecord(gpa, &records, .people, p.name, id);
        try appendAccount(gpa, &passwd, &group, &shadow, p.name, id, shell, false);
        try made.print(gpa, "{s}\n", .{p.name});
        if (p.admin) try administrators.append(gpa, p.name);
        var key_text: std.ArrayList(u8) = .empty;
        for (p.keys) |k| {
            try key_text.print(gpa, "{s}\n", .{k});
            if (p.admin) try root_keys.print(gpa, "{s}\n", .{k});
        }
        try keys.append(gpa, .{ .name = p.name, .text = key_text.items, .id = id });
    }
    for (records.items) |r| {
        if (r.source != .people or hasLine(made.items, r.name)) continue;
        try appendAccount(gpa, &passwd, &group, &shadow, r.name, r.id, "/sbin/nologin", true);
    }
    var removed: std.ArrayList([]const u8) = .empty;
    // A previous attempt may already have replaced `made` before key
    // removal failed. Sweep every retired reservation on every retry.
    for (records.items) |r| if (r.source == .people and !hasLine(made.items, r.name)) {
        try removed.append(gpa, r.name);
    };
    group = try adminGroup(gpa, group.items, administrators.items);
    return .{
        .passwd = passwd.items,
        .group = group.items,
        .shadow = shadow.items,
        .made = made.items,
        .keys = keys.items,
        .root_keys = root_keys.items,
        .removed = removed.items,
        .refused = refused.items,
        .identities = records.items,
        .nocloud_name = active_nocloud,
    };
}

fn adminGroup(gpa: Allocator, text: []const u8, members: []const []const u8) !std.ArrayList(u8) {
    var gid = userId("wheel");
    var lines = mem.tokenizeScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (!mem.startsWith(u8, line, "wheel:")) continue;
        var fields = mem.splitScalar(u8, line, ':');
        _ = fields.next();
        _ = fields.next();
        gid = std.fmt.parseInt(
            u32,
            fields.next() orelse return error.AccountConflict,
            10,
        ) catch return error.AccountConflict;
    }
    var out = try without(gpa, text, &.{"wheel"});
    if (try idInUseNumber(gpa, out.items, gid)) return error.AccountConflict;
    try out.print(gpa, "wheel:x:{d}:{s}\n", .{ gid, try mem.join(gpa, ",", members) });
    return out;
}

/// Consult current account files, not a session's possibly stale groups.
pub fn administrator(passwd: []const u8, group: []const u8, uid: u32) bool {
    var name: ?[]const u8 = null;
    var lines = mem.tokenizeScalar(u8, passwd, '\n');
    while (lines.next()) |line| {
        var fields = mem.splitScalar(u8, line, ':');
        const user = fields.next() orelse continue;
        _ = fields.next();
        const id = std.fmt.parseInt(u32, fields.next() orelse continue, 10) catch continue;
        if (id == uid) {
            name = user;
            break;
        }
    }
    const wanted = name orelse return false;
    lines = mem.tokenizeScalar(u8, group, '\n');
    while (lines.next()) |line| {
        if (!mem.startsWith(u8, line, "wheel:")) continue;
        var fields = mem.splitScalar(u8, line, ':');
        for (0..3) |_| _ = fields.next() orelse return false;
        var members = mem.splitScalar(u8, fields.next() orelse return false, ',');
        while (members.next()) |member| if (mem.eql(u8, member, wanted)) return true;
    }
    return false;
}

test "wheel membership follows accepted admin declarations and revocation" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const first = try applyReserved(
        gpa,
        .{ .passwd = "root:x:0:0:root:/root:/bin/sh\n", .group = "root:x:0:\n", .shadow = "" },
        &.{},
        "alice admin ssh-ed25519 AAAA\nbob ssh-ed25519 BBBB\n",
        "/bin/mksh",
        null,
        true,
    );
    try std.testing.expect(administrator(first.passwd, first.group, userId("alice")));
    try std.testing.expect(!administrator(first.passwd, first.group, userId("bob")));
    const next = try applyReserved(
        gpa,
        .{
            .passwd = first.passwd,
            .group = first.group,
            .shadow = first.shadow,
            .made = first.made,
        },
        first.identities,
        "alice ssh-ed25519 AAAA\nbob ssh-ed25519 BBBB\n",
        "/bin/mksh",
        null,
        false,
    );
    try std.testing.expect(!administrator(next.passwd, next.group, userId("alice")));
    try std.testing.expectEqualStrings("", next.root_keys);
}

fn hasLine(lines: []const u8, name: []const u8) bool {
    var it = mem.tokenizeScalar(u8, lines, '\n');
    while (it.next()) |line| if (mem.eql(u8, line, name)) return true;
    return false;
}

fn validNoCloudName(name: []const u8) bool {
    if (name.len == 0 or name.len > 32 or
        (!std.ascii.isLower(name[0]) and name[0] != '_')) return false;
    for (name[1..]) |c| if (!std.ascii.isLower(c) and !std.ascii.isDigit(c) and
        c != '_' and c != '-') return false;
    return true;
}

fn conflicts(records: []const Identity, source: Source, name: []const u8, id: u32) bool {
    for (records) |r| {
        if (mem.eql(u8, r.name, name) or r.id == id) {
            if (r.source != source or !mem.eql(u8, r.name, name) or r.id != id) return true;
        }
    }
    return false;
}

fn ensureRecord(
    gpa: Allocator,
    records: *std.ArrayList(Identity),
    source: Source,
    name: []const u8,
    id: u32,
) Allocator.Error!void {
    for (records.items) |r| if (r.source == source and mem.eql(u8, r.name, name) and
        r.id == id) return;
    try records.append(gpa, .{ .source = source, .name = name, .id = id });
}

fn idInUseNumber(gpa: Allocator, file: []const u8, id: u32) Allocator.Error!bool {
    return idInUse(file, try gpa.print("{d}", .{id}));
}

fn appendAccount(
    gpa: Allocator,
    passwd: *std.ArrayList(u8),
    group: *std.ArrayList(u8),
    shadow: *std.ArrayList(u8),
    name: []const u8,
    id: u32,
    shell: []const u8,
    locked: bool,
) Allocator.Error!void {
    try passwd.print(gpa, "{s}:x:{d}:{d}::/data/home/{s}:{s}\n", .{ name, id, id, name, shell });
    try group.print(gpa, "{s}:x:{d}:\n", .{ name, id });
    try shadow.print(gpa, "{s}:{s}:0:0:99999:7:::\n", .{ name, if (locked) "!" else "*" });
}

/// Refuse to publish an account over a retained home owned by another ID.
/// O_PATH inspects a mode 0700 home without giving the publisher file access.
/// The caller holds a root-owned /data/home directory descriptor.
pub fn checkHomes(home_fd: i32, keys: []const Keys) !void {
    for (keys) |k| {
        const name = try std.heap.page_allocator.dupeSentinel(u8, k.name, 0);
        defer std.heap.page_allocator.free(name);
        const rc = linux.openat(home_fd, name, .{
            .PATH = true,
            .DIRECTORY = true,
            .NOFOLLOW = true,
            .CLOEXEC = true,
        }, 0);
        if (linux.errno(rc) == .NOENT) continue;
        if (linux.errno(rc) != .SUCCESS) return error.HomeOwner;
        const fd: i32 = @intCast(rc);
        defer _ = linux.close(fd);
        var st: linux.Statx = undefined;
        if (linux.errno(linux.statx(fd, "", linux.AT.EMPTY_PATH, .{
            .TYPE = true,
            .UID = true,
            .GID = true,
        }, &st)) != .SUCCESS or st.mode & linux.S.IFMT != linux.S.IFDIR or
            st.uid != k.id or st.gid != k.id) return error.HomeOwner;
    }
}

/// Create homes only after the reservation is durable. A retained home was
/// checked before publication and is checked again before any ownership change.
pub fn ensureHomes(home_fd: i32, keys: []const Keys) !void {
    for (keys) |k| {
        const name = try std.heap.page_allocator.dupeSentinel(u8, k.name, 0);
        defer std.heap.page_allocator.free(name);
        const made = linux.mkdirat(home_fd, name, 0o700);
        const created = linux.errno(made) == .SUCCESS;
        if (!created and linux.errno(made) != .EXIST) return error.HomeCreationFailed;
        const rc = linux.openat(home_fd, name, .{
            .ACCMODE = .RDONLY,
            .PATH = !created,
            .DIRECTORY = true,
            .NOFOLLOW = true,
            .CLOEXEC = true,
        }, 0);
        if (linux.errno(rc) != .SUCCESS) return error.HomeCreationFailed;
        const fd: i32 = @intCast(rc);
        defer _ = linux.close(fd);
        var st: linux.Statx = undefined;
        if (linux.errno(linux.statx(fd, "", linux.AT.EMPTY_PATH, .{
            .TYPE = true,
            .UID = true,
            .GID = true,
        }, &st)) != .SUCCESS or st.mode & linux.S.IFMT != linux.S.IFDIR)
            return error.HomeOwner;
        if (created) {
            if (st.uid != 0 or st.gid != 0 or
                linux.errno(linux.fchmod(fd, 0o700)) != .SUCCESS or
                linux.errno(linux.fchown(fd, k.id, k.id)) != .SUCCESS)
                return error.HomeOwner;
        } else if (st.uid != k.id or st.gid != k.id) return error.HomeOwner;
    }
}

pub fn openHomeDir(data_fd: i32) !i32 {
    const made = linux.mkdirat(data_fd, "home", 0o755);
    if (linux.errno(made) != .SUCCESS and linux.errno(made) != .EXIST)
        return error.HomeDirectory;
    const rc = linux.openat(data_fd, "home", .{
        .ACCMODE = .RDONLY,
        .DIRECTORY = true,
        .NOFOLLOW = true,
        .CLOEXEC = true,
    }, 0);
    if (linux.errno(rc) != .SUCCESS) return error.HomeDirectory;
    const fd: i32 = @intCast(rc);
    errdefer _ = linux.close(fd);
    var st: linux.Statx = undefined;
    if (linux.errno(linux.statx(fd, "", linux.AT.EMPTY_PATH, .{
        .TYPE = true,
        .MODE = true,
        .UID = true,
        .GID = true,
    }, &st)) != .SUCCESS or st.uid != 0 or st.gid != 0 or
        st.mode & linux.S.IFMT != linux.S.IFDIR or st.mode & 0o777 != 0o755)
        return error.HomeDirectory;
    return fd;
}

const max_ledger = 256 << 10;
const max_identities = 4096;

/// openLedgerDir accepts only the root-owned private directory on /data.
/// The caller opens /data itself without following a link.
pub fn openLedgerDir(data_fd: i32) !i32 {
    var parent: linux.Statx = undefined;
    if (linux.errno(linux.statx(data_fd, "", linux.AT.EMPTY_PATH, .{
        .TYPE = true,
        .MODE = true,
        .UID = true,
        .GID = true,
    }, &parent)) != .SUCCESS or parent.uid != 0 or parent.gid != 0 or
        parent.mode & linux.S.IFMT != linux.S.IFDIR or parent.mode & 0o022 != 0)
        return error.DataDirectory;
    const made = linux.mkdirat(data_fd, ".werewolf", 0o700);
    if (linux.errno(made) != .SUCCESS and linux.errno(made) != .EXIST)
        return error.LedgerDirectory;
    const rc = linux.openat(data_fd, ".werewolf", .{
        .ACCMODE = .RDONLY,
        .DIRECTORY = true,
        .NOFOLLOW = true,
        .CLOEXEC = true,
    }, 0);
    if (linux.errno(rc) != .SUCCESS) return error.LedgerDirectory;
    const fd: i32 = @intCast(rc);
    errdefer _ = linux.close(fd);
    var st: linux.Statx = undefined;
    if (linux.errno(linux.statx(fd, "", linux.AT.EMPTY_PATH, .{
        .TYPE = true,
        .MODE = true,
        .UID = true,
        .GID = true,
    }, &st)) != .SUCCESS or st.uid != 0 or st.gid != 0 or
        st.mode & linux.S.IFMT != linux.S.IFDIR or st.mode & 0o777 != 0o700)
        return error.LedgerDirectory;
    return fd;
}

/// freshData refuses enrollment over old data when no identity table exists.
/// A new filesystem's empty lost+found and a crashed table temp are harmless.
pub fn freshData(data_fd: i32) !bool {
    if (linux.errno(linux.lseek(data_fd, 0, linux.SEEK.SET)) != .SUCCESS)
        return error.ReadDirectory;
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = linux.getdents64(data_fd, &buf, buf.len);
        if (linux.errno(n) != .SUCCESS) return error.ReadDirectory;
        if (n == 0) return true;
        var off: usize = 0;
        while (off < n) {
            if (off + 19 > n) return error.ReadDirectory;
            const size = mem.readInt(u16, buf[off + 16 ..][0..2], .little);
            if (size < 20 or off + size > n) return error.ReadDirectory;
            const raw = buf[off + 19 .. off + size];
            const end = mem.indexOfScalar(u8, raw, 0) orelse return error.ReadDirectory;
            const name = raw[0..end];
            if (!mem.eql(u8, name, ".") and !mem.eql(u8, name, "..")) {
                if (mem.eql(u8, name, "lost+found") or mem.eql(u8, name, ".werewolf") or
                    mem.eql(u8, name, "home"))
                {
                    const z: [*:0]const u8 = if (mem.eql(u8, name, "lost+found"))
                        "lost+found"
                    else if (mem.eql(u8, name, "home"))
                        "home"
                    else
                        ".werewolf";
                    const sub = linux.openat(data_fd, z, .{
                        .ACCMODE = .RDONLY,
                        .DIRECTORY = true,
                        .NOFOLLOW = true,
                        .CLOEXEC = true,
                    }, 0);
                    if (linux.errno(sub) != .SUCCESS) return false;
                    const sub_fd: i32 = @intCast(sub);
                    defer _ = linux.close(sub_fd);
                    if (!(try emptyDir(sub_fd, mem.eql(u8, name, ".werewolf")))) return false;
                } else return false;
            }
            off += size;
        }
    }
}

fn emptyDir(fd: i32, allow_temp: bool) !bool {
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = linux.getdents64(fd, &buf, buf.len);
        if (linux.errno(n) != .SUCCESS) return error.ReadDirectory;
        if (n == 0) return true;
        var off: usize = 0;
        while (off < n) {
            if (off + 19 > n) return error.ReadDirectory;
            const size = mem.readInt(u16, buf[off + 16 ..][0..2], .little);
            if (size < 20 or off + size > n) return error.ReadDirectory;
            const raw = buf[off + 19 .. off + size];
            const end = mem.indexOfScalar(u8, raw, 0) orelse return error.ReadDirectory;
            const name = raw[0..end];
            if (!mem.eql(u8, name, ".") and !mem.eql(u8, name, "..") and
                !(allow_temp and mem.eql(u8, name, "identities.new"))) return false;
            off += size;
        }
    }
}

pub fn loadLedger(gpa: Allocator, dir: i32) ![]const Identity {
    const rc = linux.openat(dir, "identities", .{
        .ACCMODE = .RDONLY,
        .NOFOLLOW = true,
        .CLOEXEC = true,
        .NONBLOCK = true,
    }, 0);
    if (linux.errno(rc) == .NOENT) return error.NoLedger;
    if (linux.errno(rc) != .SUCCESS) return error.BadLedger;
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    var st: linux.Statx = undefined;
    if (linux.errno(linux.statx(fd, "", linux.AT.EMPTY_PATH, .{
        .TYPE = true,
        .MODE = true,
        .UID = true,
        .GID = true,
        .SIZE = true,
        .NLINK = true,
    }, &st)) != .SUCCESS or st.uid != 0 or st.gid != 0 or
        st.mode & linux.S.IFMT != linux.S.IFREG or st.mode & 0o777 != 0o600 or
        st.nlink != 1 or st.size > max_ledger) return error.BadLedger;
    const buf = try gpa.alloc(u8, @intCast(st.size));
    var off: usize = 0;
    while (off < buf.len) {
        const n = linux.read(fd, buf[off..].ptr, buf.len - off);
        if (linux.errno(n) == .INTR) continue;
        if (linux.errno(n) != .SUCCESS or n == 0) return error.BadLedger;
        off += n;
    }
    return parseLedger(gpa, buf);
}

pub fn parseLedger(gpa: Allocator, data: []const u8) ![]const Identity {
    if (!mem.startsWith(u8, data, "werewolf-identities 1\n") or data.len > max_ledger)
        return error.BadLedger;
    if (data[data.len - 1] != '\n') return error.BadLedger;
    var out: std.ArrayList(Identity) = .empty;
    var lines = mem.splitScalar(u8, data["werewolf-identities 1\n".len..], '\n');
    while (lines.next()) |line| {
        if (line.len == 0) {
            if (lines.next() != null) return error.BadLedger;
            break;
        }
        var fields = mem.splitScalar(u8, line, ' ');
        const tag = fields.next() orelse return error.BadLedger;
        const name = fields.next() orelse return error.BadLedger;
        const uid_text = fields.next() orelse return error.BadLedger;
        const gid_text = fields.next() orelse return error.BadLedger;
        if (fields.next() != null) return error.BadLedger;
        const source: Source = if (mem.eql(u8, tag, "p"))
            .people
        else if (mem.eql(u8, tag, "n"))
            .nocloud
        else
            return error.BadLedger;
        const uid = std.fmt.parseInt(u32, uid_text, 10) catch return error.BadLedger;
        const gid = std.fmt.parseInt(u32, gid_text, 10) catch return error.BadLedger;
        if (mem.eql(u8, name, "root") or uid != gid or
            (source == .people and (!isName(name) or uid != userId(name))) or
            (source == .nocloud and (!validNoCloudName(name) or uid < ids[0][0] or
                uid > ids[0][1])))
            return error.BadLedger;
        for (out.items) |r| if (mem.eql(u8, r.name, name) or r.id == uid) return error.BadLedger;
        if (out.items.len == max_identities) return error.BadLedger;
        try out.append(gpa, .{ .source = source, .name = name, .id = uid });
    }
    return out.items;
}

pub fn commitLedger(gpa: Allocator, dir: i32, identities: []const Identity) !void {
    if (identities.len > max_identities) return error.LedgerFull;
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(gpa, "werewolf-identities 1\n");
    for (identities) |r| try out.print(gpa, "{s} {s} {d} {d}\n", .{
        if (r.source == .people) @as([]const u8, "p") else "n", r.name, r.id, r.id,
    });
    if (out.items.len > max_ledger) return error.LedgerFull;
    _ = linux.unlinkat(dir, "identities.new", 0);
    const rc = linux.openat(dir, "identities.new", .{
        .ACCMODE = .WRONLY,
        .CREAT = true,
        .EXCL = true,
        .NOFOLLOW = true,
        .CLOEXEC = true,
    }, 0o600);
    if (linux.errno(rc) != .SUCCESS) return error.LedgerWrite;
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    var off: usize = 0;
    while (off < out.items.len) {
        const n = linux.write(fd, out.items[off..].ptr, out.items.len - off);
        if (linux.errno(n) == .INTR) continue;
        if (linux.errno(n) != .SUCCESS or n == 0) return error.LedgerWrite;
        off += n;
    }
    if (linux.errno(linux.fsync(fd)) != .SUCCESS or
        linux.errno(linux.renameat(dir, "identities.new", dir, "identities")) != .SUCCESS)
        return error.LedgerWrite;
    try syncLedger(dir);
}

/// Retry the durability barrier even when a previous rename made the new
/// rows visible. The table file was synced before that rename.
pub fn syncLedger(dir: i32) !void {
    if (linux.errno(linux.fsync(dir)) != .SUCCESS) return error.LedgerWrite;
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

const key_types = [_][]const u8{
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "ssh-rsa",
};

fn validKey(s: []const u8) bool {
    var words = mem.tokenizeAny(u8, s, " \t");
    const kind = words.next() orelse return false;
    const body = words.next() orelse return false;
    const known = for (key_types) |t| {
        if (mem.eql(u8, t, kind)) break true;
    } else false;
    if (!known or body.len == 0 or body.len > 16 << 10) return false;
    for (body) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '+' and c != '/' and c != '=') return false;
    }
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

test "keyless people have stable real accounts, no SSH keys or admin rights" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const gpa = a.allocator();
    const base: Files = .{
        .passwd = "root:x:0:0::/root:/bin/sh\n",
        .group = "root:x:0:\n",
        .shadow = "root:!:::::::\n",
    };
    const first = try applyReserved(gpa, base, &.{}, "alice\nbob\n", "/sbin/nologin", null, true);
    try testing.expectEqual(2, first.keys.len);
    try testing.expectEqualStrings("", first.keys[0].text);
    try testing.expectEqualStrings("", first.root_keys);
    try testing.expect(mem.indexOf(
        u8,
        first.passwd,
        try gpa.print("alice:x:{d}:{d}:", .{ userId("alice"), userId("alice") }),
    ) != null);
    const next = try applyReserved(
        gpa,
        .{
            .passwd = first.passwd,
            .group = first.group,
            .shadow = first.shadow,
            .made = first.made,
        },
        first.identities,
        "carol\nalice\nalice admin\nroot\n",
        "/sbin/nologin",
        null,
        false,
    );
    try testing.expectEqual(2, next.keys.len);
    try testing.expectEqual(2, next.refused.len);
    try testing.expectEqualStrings("", next.root_keys);
    try testing.expectEqualStrings("bob", next.removed[0]);
    try testing.expect(mem.indexOf(
        u8,
        next.passwd,
        try gpa.print("alice:x:{d}:{d}:", .{ userId("alice"), userId("alice") }),
    ) != null);
}

test "reserved accounts keep admin keys and lock absent people" {
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
    const c = try applyReserved(gpa, base, &.{}, "tom admin " ++ k1 ++ "\ntom " ++ k2 ++ "\nann " ++
        k3 ++
        "\nroot " ++ k3 ++ "\nBad x\nnginx " ++ k3 ++
        "\ntom command=\"/bin/sh\" ssh-ed25519 AAAA1\ntom ssh-ed25519 " ++
        "not-base64!\n\n", "/bin/ash", null, true);
    const tom = userId("tom");
    try testing.expect(tom >= 1 << 16 and tom < 1 << 30);
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
    try testing.expectEqual(5, c.refused.len);
    try testing.expectEqual(0, c.removed.len);

    // Applied again with ann gone and a new person: ann's lines go, and
    // tom's are made afresh, so an edited key takes.
    const again = try applyReserved(gpa, .{
        .passwd = c.passwd,
        .group = c.group,
        .shadow = c.shadow,
        .made = c.made,
    }, c.identities, "tom " ++ k2 ++ "\nbob " ++ k3 ++ "\n", "/sbin/nologin", null, false);
    try testing.expectEqualStrings("tom\nbob\n", again.made);
    try testing.expectEqual(1, again.removed.len);
    try testing.expectEqualStrings("ann", again.removed[0]);
    try testing.expect(mem.find(u8, again.passwd, "ann:x:") != null);
    try testing.expect(mem.find(u8, again.shadow, "ann:!:") != null);
    try testing.expect(mem.find(u8, again.passwd, "bob:x:") != null);
    try testing.expectEqualStrings("", again.root_keys);
    try testing.expectEqualStrings(k2 ++ "\n", again.keys[0].text);
    try testing.expectEqual(0, again.refused.len);
}

test "retired people keep their names and IDs through removal, collision, and return" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const base: Files = .{
        .passwd = "root:x:0:0::/root:/bin/sh\n",
        .group = "root:x:0:\n",
        .shadow = "root:!:::::::\n",
    };
    try testing.expectEqual(userId("u2guv05clv"), userId("udm5vojgxd"));
    try testing.expect(userId("alice") != userId("audit-2ola31"));
    const first = try applyReserved(
        gpa,
        base,
        &.{},
        "u2guv05clv ssh-ed25519 AAAA admin-key\n",
        "/bin/ash",
        null,
        true,
    );
    try testing.expectEqual(1, first.identities.len);
    try testing.expect(mem.find(u8, first.shadow, "u2guv05clv:*:") != null);
    const retired = try applyReserved(gpa, .{
        .passwd = first.passwd,
        .group = first.group,
        .shadow = first.shadow,
        .made = first.made,
    }, first.identities, "", "/bin/ash", null, false);
    try testing.expectEqual(1, retired.identities.len);
    try testing.expectEqualStrings("u2guv05clv", retired.removed[0]);
    try testing.expect(mem.find(u8, retired.passwd, "u2guv05clv:x:") != null);
    try testing.expect(mem.find(u8, retired.passwd, ":/sbin/nologin\n") != null);
    try testing.expect(mem.find(u8, retired.shadow, "u2guv05clv:!:") != null);
    const retry = try applyReserved(gpa, .{
        .passwd = retired.passwd,
        .group = retired.group,
        .shadow = retired.shadow,
        .made = retired.made,
    }, retired.identities, "", "/bin/ash", null, false);
    try testing.expectEqual(1, retry.removed.len);
    try testing.expectEqualStrings("u2guv05clv", retry.removed[0]);
    const collision = try applyReserved(gpa, .{
        .passwd = retired.passwd,
        .group = retired.group,
        .shadow = retired.shadow,
        .made = retired.made,
    }, retired.identities, "udm5vojgxd\n", "/bin/ash", null, false);
    try testing.expectEqual(1, collision.refused.len);
    try testing.expectEqualStrings("", collision.made);
    try testing.expect(mem.find(u8, collision.passwd, "udm5vojgxd:") == null);
    const returned = try applyReserved(gpa, .{
        .passwd = retired.passwd,
        .group = retired.group,
        .shadow = retired.shadow,
        .made = retired.made,
    }, retired.identities, "u2guv05clv\n", "/bin/ash", null, false);
    try testing.expectEqual(0, returned.refused.len);
    try testing.expectEqual(1, returned.identities.len);
    try testing.expect(mem.find(u8, returned.shadow, "u2guv05clv:*:") != null);
}

test "NoCloud cannot change a reserved name's UID or take a people name" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const base: Files = .{
        .passwd = "root:x:0:0::/root:/bin/sh\n",
        .group = "root:x:0:\n",
        .shadow = "root:!:::::::\n",
    };
    const first = try applyReserved(
        gpa,
        base,
        &.{},
        "",
        "/bin/mksh",
        .{ .name = "lima", .id = 1000, .keys = "" },
        true,
    );
    try testing.expectEqualStrings("lima", first.nocloud_name);
    try testing.expect(mem.find(
        u8,
        first.passwd,
        "lima:x:1000:1000::/data/home/lima:/bin/mksh\n",
    ) != null);
    const changed = try applyReserved(
        gpa,
        base,
        first.identities,
        "",
        "/bin/ash",
        .{ .name = "lima", .id = 1001, .keys = "" },
        true,
    );
    try testing.expectEqual(1, changed.refused.len);
    try testing.expectEqualStrings("", changed.nocloud_name);
    try testing.expect(mem.find(u8, changed.shadow, "lima:!:") != null);
    try testing.expect(mem.find(u8, changed.passwd, "lima:x:1000:1000:") != null);
    const returned = try applyReserved(
        gpa,
        base,
        first.identities,
        "",
        "/bin/ash",
        .{ .name = "lima", .id = 1000, .keys = "" },
        true,
    );
    try testing.expectEqualStrings("lima", returned.nocloud_name);
    try testing.expectEqual(0, returned.refused.len);
    const reused = try applyReserved(gpa, base, first.identities, "lima\n", "/bin/ash", null, true);
    try testing.expectEqual(1, reused.refused.len);
    try testing.expectEqualStrings("", reused.made);
}

test "identity table rejects duplicate names, IDs, and damaged rows" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const alice = try gpa.print("p alice {d} {d}\n", .{ userId("alice"), userId("alice") });
    const good = try std.mem.concat(gpa, u8, &.{ "werewolf-identities 1\n", alice });
    try testing.expectEqual(1, (try parseLedger(gpa, good)).len);
    try testing.expectError(
        error.BadLedger,
        parseLedger(gpa, try std.mem.concat(gpa, u8, &.{ good, alice })),
    );
    try testing.expectError(
        error.BadLedger,
        parseLedger(gpa, "werewolf-identities 1\nn lima 1000 1001\n"),
    );
    try testing.expectError(error.BadLedger, parseLedger(gpa, "werewolf-identities 2\n"));
    try testing.expectError(
        error.BadLedger,
        parseLedger(gpa, "werewolf-identities 1\np alice 1 1\n"),
    );
    try testing.expectError(
        error.BadLedger,
        parseLedger(gpa, "werewolf-identities 1\nn root 1000 1000\n"),
    );
    try testing.expectError(
        error.BadLedger,
        parseLedger(gpa, "werewolf-identities 1\nn lima 1000 1000"),
    );
    try testing.expectError(
        error.BadLedger,
        parseLedger(gpa, "werewolf-identities 1\n\nn lima 1000 1000\n"),
    );
}

test "boot refuses a reserved identity that collides with an image account" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const id = userId("alice");
    const records = [_]Identity{.{ .source = .people, .name = "alice", .id = id }};
    const base: Files = .{
        .passwd = try gpa.print(
            "root:x:0:0::/root:/bin/sh\nservice:x:{d}:{d}::/:/sbin/nologin\n",
            .{ id, id },
        ),
        .group = try gpa.print("root:x:0:\nservice:x:{d}:\n", .{id}),
        .shadow = "root:!:::::::\nservice:!:::::::\n",
    };
    try testing.expectError(
        error.AccountConflict,
        applyReserved(gpa, base, &records, "", "/bin/ash", null, true),
    );
}

test verified {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const ed = "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29t tom@yubikey";
    const p256 = "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNh tom@mac";
    const text = ed ++ "\n" ++ p256 ++ "\n";
    const policy = "sk-ssh-ed25519@openssh.com\n";
    const once = try verified(gpa, text, policy);
    try std.testing.expectEqualStrings("verify-required " ++ ed ++ "\n" ++ p256 ++ "\n", once);
    // Root's file gains admins' keys after the image's: each pass is the same.
    try std.testing.expectEqualStrings(once, try verified(gpa, once, policy));
    try std.testing.expectEqualStrings(text, try verified(gpa, text, ""));
    try std.testing.expectEqualStrings("", try verified(gpa, "", policy));
    // A type is matched whole, never as a prefix of the line.
    try std.testing.expectEqualStrings(
        "sk-ssh-ed25519@openssh.comX AAAA\n",
        try verified(gpa, "sk-ssh-ed25519@openssh.comX AAAA\n", policy),
    );
}
