//! The data-transfer/1 archive contract. This module never mounts storage,
//! starts a program, installs into /data, or derives authority from an archive.
//! A caller supplies image policy and, optionally, a private staging sink.
const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const File = Io.File;
const Allocator = std.mem.Allocator;
const mem = std.mem;
const Sha256 = std.crypto.hash.sha2.Sha256;
pub const zstd = @import("data-transfer-zstd.zig");
pub const install = @import("data-transfer-install.zig");
pub const metadata = @import("data-transfer-metadata.zig");
pub const protocol = @import("data-transfer-protocol.zig");
pub const images = @import("data-transfer-image.zig");
pub const supervision = @import("data-transfer-supervision.zig");

pub const format = "werewolf-data/1";
pub const limits = struct {
    pub const manifest = 32 << 20;
    pub const entries = 100_000;
    pub const path = 4096;
    pub const depth = 128;
    pub const file_bytes: u64 = 1 << 44;
    pub const total_bytes: u64 = 1 << 48;
    pub const pax = 8192;
};

/// These are machine authority or filesystem bookkeeping, never application
/// input. The installer enforces these independently of the manifest's claims.
pub const exclusions = [_][]const u8{
    ".werewolf",      "lost+found",      "svc/sshd", "svc/sshd-dev",
    "svc/autoupdate", "svc/unwound-age",
};

pub const Identity = struct { name: []const u8, id: u32 };
pub const Arch = enum { aarch64, x86_64 };
pub const Kind = enum { file, directory };
pub const DefaultAcl = struct { user: u3, group: u3, other: u3 };
pub const Entry = struct {
    path: []const u8,
    kind: Kind,
    size: u64,
    mode: u32,
    mtime_ns: i64,
    owner: []const u8,
    group: []const u8,
    default_acl: ?DefaultAcl = null,
};
pub const Manifest = struct {
    format: []const u8 = format,
    image: []const u8,
    arch: Arch,
    service: ?[]const u8 = null,
    clean: bool = true,
    excluded: []const []const u8 = &exclusions,
    entries: []const Entry,
};
pub const Policy = struct {
    image: []const u8,
    arch: Arch,
    services: []const []const u8,
    users: []const Identity,
    groups: []const Identity,

    pub fn serviceAllowed(p: Policy, name: []const u8) bool {
        if (!validName(name)) return false;
        for (exclusions) |path| {
            if (mem.startsWith(u8, path, "svc/") and mem.eql(u8, path[4..], name)) return false;
        }
        for (p.services) |s| if (mem.eql(u8, s, name)) return true;
        return false;
    }
};
/// Trusted launcher control; this record is never read from an archive.
pub const WorkerRequest = struct {
    version: u8 = 1,
    policy: Policy,
    service: ?[]const u8 = null,
    target: []const u8,
};

pub const Owner = struct { uid: u32, gid: u32, default_acl: ?DefaultAcl = null };
/// Ownership is obtained from the already-open inode, not its pathname. The
/// Linux helper also uses this callback to reject xattrs it cannot preserve.
pub const Ownership = struct {
    context: ?*anyopaque = null,
    get: *const fn (?*anyopaque, File) anyerror!Owner,
};
pub const Result = struct { manifest: Manifest, sha256: [64]u8, bytes: u64 };
pub const Sink = struct {
    context: *anyopaque,
    begin: *const fn (*anyopaque, Entry) anyerror!void,
    write: *const fn (*anyopaque, []const u8) anyerror!void,
    end: *const fn (*anyopaque, Entry) anyerror!void,
};

pub fn validName(name: []const u8) bool {
    if (name.len == 0 or name.len > 64 or !std.ascii.isAlphanumeric(name[0])) return false;
    for (name) |c| if (!std.ascii.isAlphanumeric(c) and c != '-' and c != '_') return false;
    return true;
}

pub fn validIdentity(name: []const u8) bool {
    if (name.len == 0 or name.len > 31) return false;
    for (name) |c| if (!std.ascii.isAlphanumeric(c) and c != '_' and c != '-') return false;
    return true;
}

pub fn validPath(path: []const u8) bool {
    if (path.len == 0 or path.len > limits.path or
        !std.unicode.utf8ValidateSlice(path)) return false;
    var parts = mem.splitScalar(u8, path, '/');
    var depth: usize = 0;
    while (parts.next()) |p| {
        depth += 1;
        if (p.len == 0 or p.len > 255 or mem.eql(u8, p, ".") or mem.eql(u8, p, "..")) return false;
        for (p) |c| if (std.ascii.isControl(c) or c == '\\') return false;
    }
    return depth <= limits.depth;
}

pub fn excluded(path: []const u8) bool {
    for (exclusions) |p| if (beneath(path, p)) return true;
    return false;
}

pub fn beneath(path: []const u8, root: []const u8) bool {
    return mem.eql(u8, path, root) or
        (path.len > root.len and mem.startsWith(u8, path, root) and path[root.len] == '/');
}

pub fn selected(path: []const u8, service: ?[]const u8) bool {
    const s = service orelse return true;
    return mem.startsWith(u8, path, "svc/") and beneath(path[4..], s);
}

/// Logs are archive evidence, never destination application state.
pub fn importSelected(path: []const u8, service: ?[]const u8) bool {
    return !beneath(path, "log") and selected(path, service);
}

pub fn identityByName(ids: []const Identity, name: []const u8) !u32 {
    for (ids) |id| if (mem.eql(u8, id.name, name)) return id.id;
    return error.TransferOwner;
}

fn identityById(ids: []const Identity, id: u32) ![]const u8 {
    for (ids) |item| if (item.id == id) return item.name;
    return error.TransferOwner;
}

fn hashId(value: []const u8) bool {
    if (value.len != 64) return false;
    for (value) |c| if (!std.ascii.isDigit(c) and (c < 'a' or c > 'f')) return false;
    return true;
}

/// Validate all inventory and source scope before any staging callback runs.
pub fn check(a: Allocator, m: Manifest, policy: Policy, service: ?[]const u8) !void {
    if (!mem.eql(u8, m.format, format) or !m.clean or
        !hashId(m.image)) return error.TransferManifest;
    if (!mem.eql(u8, m.image, policy.image) or m.arch != policy.arch) return error.TransferImage;
    if (m.entries.len > limits.entries or
        m.excluded.len != exclusions.len) return error.TransferLimit;
    for (m.excluded, exclusions) |given, required|
        if (!mem.eql(u8, given, required)) return error.TransferExclusions;
    if (m.service) |s| if (!policy.serviceAllowed(s)) return error.TransferService;
    if (service) |s| {
        if (!policy.serviceAllowed(s)) return error.TransferService;
        if (m.service) |source| if (!mem.eql(u8, source, s)) return error.TransferService;
    }
    var seen: std.StringHashMapUnmanaged(Kind) = .empty;
    defer seen.deinit(a);
    var total: u64 = 0;
    var found = service == null;
    for (m.entries) |entry| {
        if (!validPath(entry.path) or excluded(entry.path) or !selected(entry.path, m.service))
            return error.TransferPath;
        if ((mem.eql(u8, entry.path, "svc") or mem.eql(u8, entry.path, "home") or
            (service != null and selected(entry.path, service) and
                mem.count(u8, entry.path, "/") == 1)) and entry.kind != .directory)
            return error.TransferFileType;
        if (entry.mode & ~@as(u32, 0o3777) != 0 or
            (entry.kind == .file and entry.mode & 0o7000 != 0)) return error.TransferMetadata;
        if (entry.default_acl != null and entry.kind != .directory) return error.TransferMetadata;
        if (entry.size > limits.file_bytes or (entry.kind == .directory and entry.size != 0))
            return error.TransferLimit;
        total = std.math.add(u64, total, entry.size) catch return error.TransferLimit;
        if (total > limits.total_bytes) return error.TransferLimit;
        for ([_][]const u8{ entry.owner, entry.group }) |name|
            if (!validIdentity(name)) return error.TransferOwner;
        if (importSelected(entry.path, service)) {
            _ = try identityByName(policy.users, entry.owner);
            _ = try identityByName(policy.groups, entry.group);
        }
        if (std.fs.path.dirname(entry.path)) |parent| {
            const implicit = m.service != null and mem.eql(u8, parent, "svc");
            if (!implicit and seen.get(parent) != .directory) return error.TransferParent;
        }
        const result = try seen.getOrPut(a, entry.path);
        if (result.found_existing) return error.TransferDuplicate;
        result.value_ptr.* = entry.kind;
        if (selected(entry.path, service)) found = true;
    }
    if (!found) return error.TransferService;
    if (m.service) |s| {
        var buf: [68]u8 = undefined;
        const root = try std.mem.print(&buf, "svc/{s}", .{s});
        if (seen.get(root) != .directory) return error.TransferService;
    }
}

pub fn scan(
    io: Io,
    a: Allocator,
    root: Dir,
    policy: Policy,
    service: ?[]const u8,
    owners: Ownership,
) !Manifest {
    if (service) |s| if (!policy.serviceAllowed(s)) return error.TransferService;
    var list: std.ArrayList(Entry) = .empty;
    errdefer list.deinit(a);
    if (service) |s| {
        var services = try root.openDir(io, "svc", .{ .follow_symlinks = false });
        defer services.close(io);
        try scanEntry(io, a, services, s, try a.print("svc/{s}", .{s}), policy, owners, &list, 0);
    } else try scanTree(io, a, root, "", policy, owners, &list, 0);
    const m: Manifest = .{
        .image = policy.image,
        .arch = policy.arch,
        .service = service,
        .entries = list.items,
    };
    try check(a, m, policy, service);
    return m;
}

fn scanTree(
    io: Io,
    a: Allocator,
    dir: Dir,
    prefix: []const u8,
    p: Policy,
    o: Ownership,
    list: *std.ArrayList(Entry),
    depth: usize,
) anyerror!void {
    if (depth > limits.depth) return error.TransferLimit;
    const before = try dir.stat(io);
    var names: std.ArrayList([]const u8) = .empty;
    defer {
        for (names.items) |n| a.free(n);
        names.deinit(a);
    }
    var it = dir.iterate();
    while (try it.next(io)) |e| {
        if (names.items.len + list.items.len >= limits.entries) return error.TransferLimit;
        try names.append(a, try a.dupe(u8, e.name));
    }
    mem.sort([]const u8, names.items, {}, struct {
        fn less(_: void, x: []const u8, y: []const u8) bool {
            return mem.lessThan(u8, x, y);
        }
    }.less);
    for (names.items) |name| {
        const path = if (prefix.len == 0)
            try a.dupe(u8, name)
        else
            try a.print("{s}/{s}", .{ prefix, name });
        if (excluded(path)) {
            a.free(path);
            continue;
        }
        try scanEntry(io, a, dir, name, path, p, o, list, depth);
    }
    if (!unchanged(before, try dir.stat(io))) return error.TransferChanged;
}

fn scanEntry(
    io: Io,
    a: Allocator,
    dir: Dir,
    name: []const u8,
    path: []const u8,
    p: Policy,
    o: Ownership,
    list: *std.ArrayList(Entry),
    depth: usize,
) !void {
    if (!validPath(path) or list.items.len >= limits.entries) return error.TransferLimit;
    const st = try dir.statFile(io, name, .{ .follow_symlinks = false });
    if (st.kind == .directory) {
        var child = try dir.openDir(io, name, .{ .iterate = true, .follow_symlinks = false });
        defer child.close(io);
        const pinned = try child.stat(io);
        if (!unchanged(st, pinned)) return error.TransferChanged;
        const owner = try o.get(
            o.context,
            .{ .handle = child.handle, .flags = .{ .nonblocking = false } },
        );
        try list.append(a, try entryFor(path, pinned, owner, p));
        try scanTree(io, a, child, path, p, o, list, depth + 1);
    } else {
        const f = try openRegular(io, dir, name);
        defer f.close(io);
        const pinned = try f.stat(io);
        if (!unchanged(st, pinned)) return error.TransferChanged;
        try list.append(a, try entryFor(path, pinned, try o.get(o.context, f), p));
    }
}

fn entryFor(path: []const u8, st: File.Stat, owner: Owner, p: Policy) !Entry {
    const ns = std.math.cast(i64, st.mtime.nanoseconds) orelse return error.TransferMetadata;
    return .{
        .path = path,
        .kind = if (st.kind == .directory) .directory else .file,
        .size = if (st.kind == .directory) 0 else st.size,
        .mode = st.permissions.toMode() & 0o7777,
        .mtime_ns = ns,
        .owner = try identityById(p.users, owner.uid),
        .group = try identityById(p.groups, owner.gid),
        .default_acl = owner.default_acl,
    };
}

pub fn openRegular(io: Io, dir: Dir, name: []const u8) !File {
    if (mem.findScalar(u8, name, '/') != null) return error.TransferPath;
    const fd = try std.posix.openat(dir.handle, name, .{
        .ACCMODE = .RDONLY,
        .NOFOLLOW = true,
        .NONBLOCK = true,
        .CLOEXEC = true,
    }, 0);
    const f: File = .{ .handle = fd, .flags = .{ .nonblocking = true } };
    errdefer f.close(io);
    const st = try f.stat(io);
    if (st.kind != .file or st.nlink != 1 or st.permissions.toMode() & 0o6000 != 0)
        return error.TransferFileType;
    return f;
}

/// Opens every intermediate directory without following links, never openat
/// with an untrusted multi-component pathname.
pub fn parentDir(io: Io, root: Dir, path: []const u8) !Dir {
    if (!validPath(path)) return error.TransferPath;
    var current = try root.openDir(io, ".", .{});
    errdefer current.close(io);
    var parts = mem.splitScalar(u8, std.fs.path.dirname(path) orelse return current, '/');
    while (parts.next()) |part| {
        const next = try current.openDir(io, part, .{ .follow_symlinks = false });
        current.close(io);
        current = next;
    }
    return current;
}

fn unchanged(a: File.Stat, b: File.Stat) bool {
    return a.inode == b.inode and a.kind == b.kind and a.size == b.size and
        a.permissions.toMode() == b.permissions.toMode() and a.nlink == b.nlink and
        a.mtime.nanoseconds == b.mtime.nanoseconds and a.ctime.nanoseconds == b.ctime.nanoseconds;
}

const Output = struct {
    writer: *Io.Writer,
    hash: Sha256 = .init(.{}),
    fn put(o: *Output, bytes: []const u8) !void {
        try o.writer.writeAll(bytes);
        o.hash.update(bytes);
    }
    fn pad(o: *Output, size: u64) !void {
        const zeros: [512]u8 = @splat(0);
        try o.put(zeros[0..padding(size)]);
    }
    fn record(o: *Output, name: []const u8, data: []const u8) !void {
        try o.put(&try header(name, '0', data.len, 0o600, "root", "root"));
        try o.put(data);
        try o.pad(data.len);
    }
};

fn padding(size: u64) usize {
    return @intCast((512 - size % 512) % 512);
}

fn octal(buf: []u8, value: u64) !void {
    @memset(buf, '0');
    buf[buf.len - 1] = 0;
    var n = value;
    var i = buf.len - 1;
    while (n != 0) {
        if (i == 0) return error.TransferLimit;
        i -= 1;
        buf[i] = @intCast('0' + n % 8);
        n /= 8;
    }
}

fn header(
    name: []const u8,
    kind: u8,
    size: u64,
    mode: u32,
    owner: []const u8,
    group: []const u8,
) ![512]u8 {
    if (name.len > 100 or owner.len > 31 or group.len > 31) return error.TransferLimit;
    var h: [512]u8 = @splat(0);
    @memcpy(h[0..name.len], name);
    try octal(h[100..108], mode);
    try octal(h[108..116], 0);
    try octal(h[116..124], 0);
    try octal(h[124..136], size);
    try octal(h[136..148], 0);
    @memset(h[148..156], ' ');
    h[156] = kind;
    @memcpy(h[257..265], "ustar\x0000");
    @memcpy(h[265..][0..owner.len], owner);
    @memcpy(h[297..][0..group.len], group);
    var sum: u64 = 0;
    for (h) |c| sum += c;
    try octal(h[148..156], sum);
    return h;
}

fn paxRecord(a: Allocator, key: []const u8, value: []const u8) ![]const u8 {
    var n = key.len + value.len + 4;
    while (true) {
        const line = try a.print("{d} {s}={s}\n", .{ n, key, value });
        if (line.len == n) return line;
        n = line.len;
        a.free(line);
    }
}

fn pax(a: Allocator, e: Entry) ![]const u8 {
    const path = try a.print("data/{s}", .{e.path});
    defer a.free(path);
    const size = try a.print("{d}", .{e.size});
    defer a.free(size);
    const ns: i128 = e.mtime_ns;
    const abs = @abs(ns);
    const time = try a.print(
        "{s}{d}.{d:0>9}",
        .{ if (ns < 0) "-" else "", abs / 1_000_000_000, abs % 1_000_000_000 },
    );
    defer a.free(time);
    const p = try paxRecord(a, "path", path);
    defer a.free(p);
    const s = try paxRecord(a, "size", size);
    defer a.free(s);
    const t = try paxRecord(a, "mtime", time);
    defer a.free(t);
    return mem.concat(a, u8, &.{ p, s, t });
}

/// Produces uncompressed tar; the caller connects its writer to pinned Zstd.
/// Reader ownership and source metadata are rechecked during emission.
pub fn emit(
    io: Io,
    a: Allocator,
    root: Dir,
    m: Manifest,
    p: Policy,
    owners: Ownership,
    writer: *Io.Writer,
) ![64]u8 {
    try check(a, m, p, m.service);
    const json = try std.json.Stringify.valueAlloc(a, m, .{});
    defer a.free(json);
    if (json.len > limits.manifest) return error.TransferLimit;
    var out: Output = .{ .writer = writer };
    try out.record("manifest.json", json);
    for (m.entries) |e| {
        var parent = try parentDir(io, root, e.path);
        defer parent.close(io);
        const base = std.fs.path.basename(e.path);
        var sub: ?Dir = null;
        const file: File = if (e.kind == .file) try openRegular(io, parent, base) else blk: {
            sub = try parent.openDir(io, base, .{ .iterate = true, .follow_symlinks = false });
            break :blk .{ .handle = sub.?.handle, .flags = .{ .nonblocking = false } };
        };
        defer file.close(io);
        const st = try file.stat(io);
        const actual = try entryFor(e.path, st, try owners.get(owners.context, file), p);
        if (beneath(e.path, "log")) {
            var snapshot = actual;
            snapshot.size = e.size;
            snapshot.mtime_ns = e.mtime_ns;
            if (actual.size < e.size or !entryEqual(e, snapshot)) return error.TransferChanged;
        } else if (!entryEqual(e, actual)) return error.TransferChanged;
        const extended = try pax(a, e);
        defer a.free(extended);
        if (extended.len > limits.pax) return error.TransferLimit;
        try out.put(&try header("PaxHeaders/entry", 'x', extended.len, 0o600, "root", "root"));
        try out.put(extended);
        try out.pad(extended.len);
        try out.put(&try header(
            "entry",
            if (e.kind == .file) '0' else '5',
            0,
            e.mode,
            e.owner,
            e.group,
        ));
        var offset: u64 = 0;
        var buffer: [64 << 10]u8 = undefined;
        while (offset < e.size) {
            const n = try file.readPositional(
                io,
                &.{buffer[0..@min(buffer.len, e.size - offset)]},
                offset,
            );
            if (n == 0) return error.TransferChanged;
            try out.put(buffer[0..n]);
            offset += n;
        }
        const after = try file.stat(io);
        if (beneath(e.path, "log")) {
            if (after.inode != st.inode or after.kind != st.kind or
                (e.kind == .file and (after.nlink != 1 or after.size < e.size)))
                return error.TransferChanged;
        } else if (!unchanged(st, after)) return error.TransferChanged;
        try out.pad(e.size);
    }
    const digest = std.fmt.bytesToHex(out.hash.finalResult(), .lower);
    const complete = try std.json.Stringify.valueAlloc(a, .{ .sha256 = &digest }, .{});
    defer a.free(complete);
    try out.record("complete.json", complete);
    const zeros: [1024]u8 = @splat(0);
    try writer.writeAll(&zeros);
    return digest;
}

fn entryEqual(a: Entry, b: Entry) bool {
    return a.kind == b.kind and a.size == b.size and a.mode == b.mode and
        a.mtime_ns == b.mtime_ns and
        mem.eql(u8, a.path, b.path) and mem.eql(u8, a.owner, b.owner) and
        mem.eql(u8, a.group, b.group) and
        std.meta.eql(a.default_acl, b.default_acl);
}

const Input = struct {
    reader: *Io.Reader,
    hash: Sha256 = .init(.{}),
    checksum: ?*std.hash.XxHash64 = null,
    fn take(i: *Input, buf: []u8) !void {
        try i.reader.readSliceAll(buf);
        i.hash.update(buf);
        if (i.checksum) |c| c.update(buf);
    }
    fn pad(i: *Input, size: u64) !void {
        var buf: [512]u8 = undefined;
        const bytes = buf[0..padding(size)];
        try i.take(bytes);
        if (!allZero(bytes)) return error.TransferHeader;
    }
    fn body(i: *Input, a: Allocator, size: u64, max: usize) ![]u8 {
        if (size > max) return error.TransferLimit;
        const data = try a.alloc(u8, @intCast(size));
        errdefer a.free(data);
        try i.take(data);
        try i.pad(size);
        return data;
    }
};

fn allZero(b: []const u8) bool {
    for (b) |c| if (c != 0) return false;
    return true;
}
fn number(b: []const u8) !u64 {
    if (b[b.len - 1] != 0) return error.TransferHeader;
    var n: u64 = 0;
    for (b[0 .. b.len - 1]) |c| {
        if (c < '0' or c > '7') return error.TransferHeader;
        n = std.math.mul(u64, n, 8) catch return error.TransferHeader;
        n = std.math.add(u64, n, c - '0') catch return error.TransferHeader;
    }
    return n;
}

/// Match the exact header dialect we emit. Reject unused fields rather than
/// accepting alternate extraction semantics (links, prefixes or numeric owners).
fn matchHeader(
    h: [512]u8,
    name: []const u8,
    kind: u8,
    size: u64,
    mode: u32,
    owner: []const u8,
    group: []const u8,
) !void {
    if (!mem.eql(
        u8,
        &h,
        &try header(name, kind, size, mode, owner, group),
    )) return error.TransferHeader;
}

/// The sink must be private, disposable staging. Completion of callbacks is
/// deliberately not authorization to publish: the final digest/EOF can still fail.
pub fn validate(
    a: Allocator,
    reader: *Io.Reader,
    p: Policy,
    service: ?[]const u8,
    sink: ?Sink,
) !Result {
    return validateChecksummed(a, reader, p, service, sink, null);
}

/// Routing information only. The caller must still validate the complete
/// archive against independently approved image and ownership policy.
pub fn manifest(a: Allocator, reader: *Io.Reader) !Manifest {
    var in: Input = .{ .reader = reader };
    var h: [512]u8 = undefined;
    try in.take(&h);
    const size = try number(h[124..136]);
    try matchHeader(h, "manifest.json", '0', size, 0o600, "root", "root");
    const json = try in.body(a, size, limits.manifest);
    defer a.free(json);
    const m = try std.json.parseFromSliceLeaky(Manifest, a, json, .{ .allocate = .alloc_always });
    if (!mem.eql(u8, m.format, format) or m.image.len != 64 or
        m.entries.len > limits.entries) return error.TransferManifest;
    for (m.image) |c| if (!std.ascii.isDigit(c) and (c < 'a' or c > 'f'))
        return error.TransferImage;
    return m;
}

/// Internal hook: the frame checksum covers all tar bytes, including completion.
pub fn validateChecksummed(
    a: Allocator,
    reader: *Io.Reader,
    p: Policy,
    service: ?[]const u8,
    sink: ?Sink,
    checksum: ?*std.hash.XxHash64,
) !Result {
    var in: Input = .{ .reader = reader, .checksum = checksum };
    var h: [512]u8 = undefined;
    try in.take(&h);
    const size = try number(h[124..136]);
    try matchHeader(h, "manifest.json", '0', size, 0o600, "root", "root");
    const json = try in.body(a, size, limits.manifest);
    defer a.free(json);
    const m = try std.json.parseFromSliceLeaky(Manifest, a, json, .{ .allocate = .alloc_always });
    try check(a, m, p, service);
    const scope = service orelse m.service;
    var total: u64 = 0;
    for (m.entries) |e| {
        const extended = try pax(a, e);
        defer a.free(extended);
        try in.take(&h);
        try matchHeader(h, "PaxHeaders/entry", 'x', extended.len, 0o600, "root", "root");
        const given = try in.body(a, extended.len, limits.pax);
        defer a.free(given);
        if (!mem.eql(u8, given, extended)) return error.TransferMetadata;
        try in.take(&h);
        try matchHeader(h, "entry", if (e.kind == .file) '0' else '5', 0, e.mode, e.owner, e.group);
        const dest = if (importSelected(e.path, scope)) sink else null;
        if (dest) |s| try s.begin(s.context, e);
        var remaining = e.size;
        var buf: [64 << 10]u8 = undefined;
        while (remaining > 0) {
            const part = buf[0..@min(buf.len, remaining)];
            try in.take(part);
            if (dest) |s| try s.write(s.context, part);
            remaining -= part.len;
        }
        try in.pad(e.size);
        if (dest) |s| try s.end(s.context, e);
        total += e.size;
    }
    const digest = std.fmt.bytesToHex(in.hash.finalResult(), .lower);
    try reader.readSliceAll(&h);
    if (checksum) |c| c.update(&h);
    const complete_size = try number(h[124..136]);
    try matchHeader(h, "complete.json", '0', complete_size, 0o600, "root", "root");
    const complete = try in.body(a, complete_size, 1024);
    defer a.free(complete);
    const record = try std.json.parseFromSliceLeaky(
        struct { sha256: []const u8 },
        a,
        complete,
        .{},
    );
    if (!mem.eql(u8, record.sha256, &digest)) return error.TransferChecksum;
    var end: [1024]u8 = undefined;
    try reader.readSliceAll(&end);
    if (checksum) |c| c.update(&end);
    if (!allZero(&end)) return error.TransferHeader;
    if (reader.takeByte()) |_|
        return error.TransferTrailing
    else |err| if (err != error.EndOfStream)
        return err;
    return .{ .manifest = m, .sha256 = digest, .bytes = total };
}

const test_image = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const test_policy: Policy = .{
    .image = test_image,
    .arch = .aarch64,
    .services = &.{ "plex", "plex-media", "postgres" },
    .users = &.{.{ .name = "root", .id = 0 }},
    .groups = &.{.{ .name = "root", .id = 0 }},
};
fn testOwner(_: ?*anyopaque, _: File) !Owner {
    return .{ .uid = 0, .gid = 0 };
}

test "paths and service scopes have one interpretation" {
    const t = std.testing;
    for ([_][]const u8{ "", "/a", "a/", "a//b", "a/../b", "./a", "a\\b", "a\nb" }) |p|
        try t.expect(!validPath(p));
    try t.expect(validPath("svc/plex/Library/Application Support/.database"));
    try t.expect(selected("svc/plex/a", "plex"));
    try t.expect(!selected("svc/plex-media/a", "plex"));
    try t.expect(!test_policy.serviceAllowed("sshd"));
    try t.expect(!test_policy.serviceAllowed("../plex"));
    try t.expect(excluded(".werewolf/identities"));
    try t.expect(excluded("svc/sshd/host-key"));
    try t.expect(!excluded("svc/sshd-other/data"));
    try t.expect(validIdentity("_private"));
}

test "inventory cannot authorize machine state, unknown owners or ambiguous paths" {
    const t = std.testing;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const directory: Entry = .{
        .path = "svc",
        .kind = .directory,
        .size = 0,
        .mode = 0o755,
        .mtime_ns = 0,
        .owner = "root",
        .group = "root",
    };
    var entry = directory;
    var m: Manifest = .{ .image = test_image, .arch = .aarch64, .entries = &.{directory} };
    try check(a, m, test_policy, null);
    m.entries = &.{ directory, directory };
    try t.expectError(error.TransferDuplicate, check(a, m, test_policy, null));
    entry.path = "svc/plex/data";
    m.entries = &.{ directory, entry };
    try t.expectError(error.TransferParent, check(a, m, test_policy, null));
    entry.path = "svc/sshd";
    m.entries = &.{ directory, entry };
    try t.expectError(error.TransferPath, check(a, m, test_policy, null));
    entry.path = "/outside";
    m.entries = &.{entry};
    try t.expectError(error.TransferPath, check(a, m, test_policy, null));
    entry = directory;
    entry.owner = "undeclared";
    m.entries = &.{entry};
    try t.expectError(error.TransferOwner, check(a, m, test_policy, null));
    entry = directory;
    entry.mode = 0o2750;
    m.entries = &.{entry};
    try check(a, m, test_policy, null);
    entry.mode = 0o2770;
    m.entries = &.{entry};
    try check(a, m, test_policy, null);
    entry.mode = 0o4755;
    m.entries = &.{entry};
    try t.expectError(error.TransferMetadata, check(a, m, test_policy, null));
    for ([_]u32{ 0o4755, 0o2755, 0o1755 }) |bad_file_mode| {
        var file_entry = directory;
        file_entry.path = "svc/plex";
        var sub = file_entry;
        sub.path = "svc/plex/bin";
        sub.kind = .file;
        sub.mode = bad_file_mode;
        m.entries = &.{ directory, file_entry, sub };
        try t.expectError(error.TransferMetadata, check(a, m, test_policy, null));
    }
    m.entries = &.{directory};
    m.excluded = &.{};
    try t.expectError(error.TransferLimit, check(a, m, test_policy, null));
    m.excluded = &exclusions;
    m.image = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    try t.expectError(error.TransferImage, check(a, m, test_policy, null));
    m.image = test_image;
    try t.expectError(error.TransferService, check(a, m, test_policy, "postgres"));
}

test "service selection needs no destination authority for discarded owners" {
    const t = std.testing;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const directory: Entry = .{
        .path = "svc",
        .kind = .directory,
        .size = 0,
        .mode = 0o755,
        .mtime_ns = 0,
        .owner = "root",
        .group = "root",
    };
    var entries = [_]Entry{ directory, directory, directory };
    entries[1].path = "svc/plex";
    entries[2].path = "foreign";
    entries[2].owner = "remote-user";
    const m: Manifest = .{ .image = test_image, .arch = .aarch64, .entries = &entries };
    try t.expectError(error.TransferOwner, check(arena.allocator(), m, test_policy, null));
    try check(arena.allocator(), m, test_policy, "plex");
    entries[1].owner = "remote-user";
    try t.expectError(error.TransferOwner, check(arena.allocator(), m, test_policy, "plex"));
    entries[1].owner = "root";
    entries[2].path = "../foreign";
    try t.expectError(error.TransferPath, check(arena.allocator(), m, test_policy, "plex"));
}

test "real tree archive round trip validates all selected and unselected bytes" {
    const t = std.testing;
    const io = t.io;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var tmp = t.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "svc/plex/nested");
    try tmp.dir.createDirPath(io, "svc/plex-media");
    try tmp.dir.createDirPath(io, "svc/sshd");
    try tmp.dir.createDirPath(io, "log");
    try tmp.dir.writeFile(io, .{ .sub_path = "svc/plex/nested/.db", .data = "database" });
    try tmp.dir.writeFile(io, .{ .sub_path = "svc/plex-media/movie", .data = "media-sentinel" });
    try tmp.dir.writeFile(io, .{ .sub_path = "svc/sshd/host-key", .data = "never export" });
    try tmp.dir.writeFile(io, .{ .sub_path = "log/current", .data = "native audit trail" });
    const owners: Ownership = .{ .get = testOwner };
    const m = try scan(io, a, tmp.dir, test_policy, null, owners);
    for (m.entries) |e| try t.expect(!excluded(e.path));
    // Active audit writers may append after inventory. Export the bounded
    // prefix that was measured, without weakening application consistency.
    try tmp.dir.writeFile(
        io,
        .{ .sub_path = "log/current", .data = "native audit trail appended" },
    );
    var out: Io.Writer.Allocating = .init(a);
    const digest = try emit(io, a, tmp.dir, m, test_policy, owners, &out.writer);
    var input: Io.Reader = .fixed(out.written());
    const checked = try validate(a, &input, test_policy, "plex", null);
    try t.expectEqualStrings(&digest, &checked.sha256);
    try t.expectEqual(@as(u64, 40), checked.bytes);
    const offset = mem.find(u8, out.written(), "native audit trail").?;
    out.written()[offset] ^= 1;
    input = .fixed(out.written());
    try t.expectError(error.TransferChecksum, validate(a, &input, test_policy, "plex", null));
}

test "all truncation points and trailing bytes fail closed" {
    const t = std.testing;
    const io = t.io;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var tmp = t.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = ".empty", .data = "" });
    const owners: Ownership = .{ .get = testOwner };
    const m = try scan(io, a, tmp.dir, test_policy, null, owners);
    var out: Io.Writer.Allocating = .init(a);
    _ = try emit(io, a, tmp.dir, m, test_policy, owners, &out.writer);
    for (0..out.written().len) |n| {
        var scratch = std.heap.ArenaAllocator.init(t.allocator);
        defer scratch.deinit();
        var input: Io.Reader = .fixed(out.written()[0..n]);
        if (validate(scratch.allocator(), &input, test_policy, null, null)) |_|
            return error.AcceptedTruncation
        else |_| {}
    }
    try out.writer.writeByte(0);
    var input: Io.Reader = .fixed(out.written());
    try t.expectError(error.TransferTrailing, validate(a, &input, test_policy, null, null));
}

test "single-service source excludes companions and refuses widening" {
    const t = std.testing;
    const io = t.io;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var tmp = t.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "svc/plex");
    try tmp.dir.createDirPath(io, "svc/plex-media");
    try tmp.dir.writeFile(io, .{ .sub_path = "svc/plex/db", .data = "state" });
    try tmp.dir.writeFile(io, .{ .sub_path = "svc/plex-media/movie", .data = "media" });
    const owners: Ownership = .{ .get = testOwner };
    const m = try scan(io, a, tmp.dir, test_policy, "plex", owners);
    try t.expectEqual(@as(usize, 2), m.entries.len);
    var out: Io.Writer.Allocating = .init(a);
    _ = try emit(io, a, tmp.dir, m, test_policy, owners, &out.writer);
    var input: Io.Reader = .fixed(out.written());
    _ = try validate(a, &input, test_policy, null, null);
    input = .fixed(out.written());
    try t.expectError(error.TransferService, validate(a, &input, test_policy, "plex-media", null));
    try tmp.dir.symLink(io, "/etc/passwd", "svc/plex/escape", .{});
    if (scan(io, a, tmp.dir, test_policy, "plex", owners)) |_| return error.FollowedLink else |_| {}
}

test {
    _ = zstd;
    _ = install;
    _ = metadata;
    _ = protocol;
    _ = images;
    _ = supervision;
}
