//! Crash-safe publication from an archive into a stopped machine's data volume.
//! Archive bytes reach private staging only. Machine identity is provisioned by
//! the caller before this code runs, never from the manifest.
const std = @import("std");
const data = @import("data-transfer.zig");
const Io = std.Io;
const Dir = Io.Dir;
const File = Io.File;
const Allocator = std.mem.Allocator;
const mem = std.mem;

pub const state_path = ".werewolf/transfer";
pub const pending_path = "/data/" ++ state_path ++ "/pending.json";

/// Called by init before accounts or applications. An unreadable or linked
/// state path is an error, never evidence that an interrupted import completed.
pub fn blocked(io: Io, root: Dir) !bool {
    var parent = data.parentDir(io, root, state_path ++ "/pending.json") catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    defer parent.close(io);
    _ = parent.statFile(
        io,
        "pending.json",
        .{ .follow_symlinks = false },
    ) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    return true;
}
pub const Boundary = enum { pending, before_move, after_move, recorded, complete };
pub const Options = struct {
    target: []const u8,
    service: ?[]const u8 = null,
    /// Test-only fault injection at durable transaction boundaries. Callbacks
    /// are supplied by compiled code, never an archive or an external request.
    context: ?*anyopaque = null,
    boundary: ?*const fn (?*anyopaque, Boundary) anyerror!void = null,

    fn hit(o: Options, b: Boundary) !void {
        if (o.boundary) |f| try f(o.context, b);
    }
};
const Unit = struct {
    path: []const u8,
    entry: ?data.Entry = null,
    inode: ?u64 = null,
    installed: bool = false,
    sequence: u64 = 0,
    entry: ?data.Entry = null,
};
const Receipt = struct {
    version: u8 = 2,
    archive: []const u8,
    service: ?[]const u8,
    target: []const u8,
    image: []const u8,
    units: []const []const u8,
    parent_inode: ?u64 = null,
    parent_mtime_ns: ?i64 = null,
};

pub fn apply(
    io: Io,
    a: Allocator,
    input: *Io.Reader,
    target: Dir,
    p: data.Policy,
    o: Options,
) !data.Result {
    return applyInner(io, a, input, target, p, o, true);
}

fn applyInner(
    io: Io,
    a: Allocator,
    input: *Io.Reader,
    target: Dir,
    p: data.Policy,
    o: Options,
    compressed: bool,
) !data.Result {
    var session = try Session.init(io, target);
    defer session.deinit(io);
    var staging: Staging = .{ .io = io, .allocator = a, .root = session.stage };
    defer staging.close();
    const result = if (compressed)
        try data.zstd.validate(a, input, p, o.service, staging.sink())
    else
        try data.validate(a, input, p, o.service, staging.sink());
    try session.publish(io, a, result, p, o);
    return result;
}

/// Only this private directory is passed to the unprivileged decoder. The
/// destination, machine state, lock and publication authority stay here.
pub const Session = struct {
    target: Dir,
    machine: Dir,
    state: Dir,
    lock: File,
    stage: Dir,

    pub fn init(io: Io, target: Dir) !Session {
        var machine = try privateDir(io, target, ".werewolf");
        errdefer machine.close(io);
        var state = try privateDir(io, machine, "transfer");
        errdefer state.close(io);
        const fd = try std.posix.openat(state.handle, "lock", .{
            .ACCMODE = .RDWR,
            .CREAT = true,
            .NOFOLLOW = true,
            .NONBLOCK = true,
            .CLOEXEC = true,
        }, 0o600);
        const lock: File = .{ .handle = fd, .flags = .{ .nonblocking = true } };
        errdefer lock.close(io);
        const st = try lock.stat(io);
        if (st.kind != .file or st.nlink != 1) return error.TransferState;
        try lock.lock(io, .exclusive);
        try cleanIncoming(io, state);
        try state.createDir(io, "incoming", .fromMode(0o700));
        const stage = try state.openDir(
            io,
            "incoming",
            .{ .iterate = true, .follow_symlinks = false },
        );
        return .{
            .target = target,
            .machine = machine,
            .state = state,
            .lock = lock,
            .stage = stage,
        };
    }

    pub fn deinit(s: *Session, io: Io) void {
        s.stage.close(io);
        cleanIncoming(io, s.state) catch {};
        s.lock.close(io);
        s.state.close(io);
        s.machine.close(io);
    }

    /// Validate the decoder's bounded inventory and its actual staging tree
    /// independently before applying ownership or publishing a directory.
    pub fn publish(
        s: *Session,
        io: Io,
        a: Allocator,
        result: data.Result,
        p: data.Policy,
        o: Options,
    ) !void {
        var phase: []const u8 = "validation";
        errdefer std.debug.print("data-transfer publication: {s}\n", .{phase});
        if (o.target.len == 0 or o.target.len > 256) return error.TransferTarget;
        try data.check(a, result.manifest, p, o.service);
        const target = s.target;
        const machine = s.machine;
        const state = s.state;
        const stage = s.stage;
        const old = try readReceipt(io, a, state);
        const scope = o.service orelse result.manifest.service;
        phase = "staging inventory";
        try verifyStage(io, a, stage, result.manifest, scope);
        var staging: Staging = .{ .io = io, .allocator = a, .root = stage };
        phase = "staging metadata";
        try staging.metadata(result.manifest, p, scope);
        // These containers are staging scaffolding, never publication units.
        // Reclaim them after the decoder exits so moving their children needs
        // no DAC write override. Destination metadata is restored separately.
        if (@import("builtin").os.tag == .linux and std.os.linux.geteuid() == 0) {
            for ([_][]const u8{ "svc", "home" }) |name| {
                var container = stage.openDir(
                    io,
                    name,
                    .{ .iterate = true, .follow_symlinks = false },
                ) catch |err| {
                    if (err == error.FileNotFound) continue;
                    return err;
                };
                defer container.close(io);
                const file: File = .{
                    .handle = container.handle,
                    .flags = .{ .nonblocking = false },
                };
                try file.setOwner(io, 0, 0);
                try file.setPermissions(io, .fromMode(0o700));
            }
        }
        var units: std.ArrayList(Unit) = .empty;
        defer units.deinit(a);
        for (result.manifest.entries) |e| {
            if (data.importSelected(e.path, scope) and
                isUnit(e.path)) try units.append(a, .{ .path = e.path, .entry = e });
        }
        const paths = try a.alloc([]const u8, units.items.len);
        defer a.free(paths);
        for (units.items, paths) |unit, *path| path.* = unit.path;
        var receipt: Receipt = .{
            .archive = &result.sha256,
            .service = scope,
            .target = o.target,
            .image = p.image,
            .units = paths,
        };
        if (scope != null) {
            const st = target.statFile(io, "svc", .{ .follow_symlinks = false }) catch |err| blk: {
                if (err != error.FileNotFound) return err;
                break :blk null;
            };
            if (st) |parent| {
                if (parent.kind != .directory) return error.TransferConflict;
                receipt.parent_inode = parent.inode;
                receipt.parent_mtime_ns = std.math.cast(
                    i64,
                    parent.mtime.nanoseconds,
                ) orelse return error.TransferMetadata;
            }
        }
        if (old) |previous| {
            if (!mem.eql(u8, previous.archive, &result.sha256) or
                !sameScope(previous.service, scope) or !mem.eql(u8, previous.target, o.target) or
                !mem.eql(u8, previous.image, p.image) or previous.units.len != receipt.units.len)
                return error.TransferPending;
            for (receipt.units, previous.units) |next, prior| {
                if (!mem.eql(u8, next, prior)) return error.TransferState;
            }
            receipt.parent_inode = previous.parent_inode;
            receipt.parent_mtime_ns = previous.parent_mtime_ns;
            // A crash may happen after the rename but before its receipt update.
            // The pre-rename inode, recorded durably, identifies that exact move.
        }
        phase = "progress records";
        const progress = try Progress.open(io, state, units.items, old != null);
        defer progress.file.close(io);
        if (old != null) {
            for (units.items) |*unit| if (unit.inode) |inode| {
                var parent = try data.parentDir(io, target, unit.path);
                defer parent.close(io);
                const st = parent.statFile(
                    io,
                    std.fs.path.basename(unit.path),
                    .{ .follow_symlinks = false },
                ) catch |err| {
                    if (err == error.FileNotFound and !unit.installed) continue;
                    return error.TransferState;
                };
                if (st.inode != inode) {
                    if (!unit.installed and st.kind == .directory and
                        try empty(io, parent, std.fs.path.basename(unit.path)))
                    {
                        unit.inode = null;
                        continue;
                    }
                    return error.TransferConflict;
                }
                if (st.kind != .file and st.kind != .directory) return error.TransferConflict;
                unit.installed = true;
            };
        }
        phase = "destination preflight";
        try preflight(io, a, target, scope, units.items);
        // No application directory changes before this durable boot barrier.
        if (old == null) try writeReceipt(io, a, state, receipt);
        try syncDir(io, machine);
        try syncDir(io, target);
        try o.hit(.pending);
        phase = "directory publication";
        for (units.items, 0..) |*unit, index| {
            if (unit.installed) {
                if (unit.entry.?.kind == .directory) try applyMetadata(io, target, unit.entry.?, p);
                continue;
            }
            try ensureContainer(io, target, unit.path);
            var from = try data.parentDir(io, stage, unit.path);
            defer from.close(io);
            var to = try data.parentDir(io, target, unit.path);
            defer to.close(io);
            const base = std.fs.path.basename(unit.path);
            if (@import("builtin").os.tag == .linux and std.os.linux.geteuid() == 0 and
                unit.entry.?.kind == .directory)
            {
                // Moving a directory across parents requires write access to
                // that directory itself. Keep it private until final metadata
                // is restored; a pending receipt fences every crash boundary.
                var moving = try from.openDir(
                    io,
                    base,
                    .{ .iterate = true, .follow_symlinks = false },
                );
                defer moving.close(io);
                const file: File = .{ .handle = moving.handle, .flags = .{ .nonblocking = false } };
                try file.setOwner(io, 0, 0);
                try file.setPermissions(io, .fromMode(0o700));
            }
            const st = try from.statFile(io, base, .{ .follow_symlinks = false });
            unit.inode = st.inode;
            try progress.record(io, index, unit);
            try o.hit(.before_move);
            // Only an empty, preflighted scaffold directory may be removed.
            to.deleteDir(
                io,
                base,
            ) catch |err| if (err != error.FileNotFound) return error.TransferConflict;
            try from.renamePreserve(base, to, base, io);
            if (unit.entry.?.kind == .directory) try applyMetadata(io, target, unit.entry.?, p);
            try syncDir(io, from);
            try syncDir(io, to);
            try o.hit(.after_move);
            unit.installed = true;
            try progress.record(io, index, unit);
            try o.hit(.recorded);
        }
        // Full import also restores the svc/home container metadata. A service
        // import must never change its shared parent's modes, owner or timestamps.
        if (scope == null) for (result.manifest.entries) |e| {
            if (isContainer(e.path)) {
                target.createDir(
                    io,
                    e.path,
                    .fromMode(0o755),
                ) catch |err| if (err != error.PathAlreadyExists) return err;
                try applyMetadata(io, target, e, p);
            }
        };
        phase = "container metadata";
        if (receipt.parent_inode) |inode| {
            var parent = try target.openDir(
                io,
                "svc",
                .{ .iterate = true, .follow_symlinks = false },
            );
            defer parent.close(io);
            if ((try parent.stat(io)).inode != inode) return error.TransferConflict;
            const f: File = .{ .handle = parent.handle, .flags = .{ .nonblocking = false } };
            try f.setTimestamps(
                io,
                .{
                    .modify_timestamp = .{
                        .new = .{
                            .nanoseconds = receipt.parent_mtime_ns orelse
                                return error.TransferState,
                        },
                    },
                },
            );
            try f.sync(io);
        }
        try syncDir(io, target);
        try o.hit(.complete);
        try state.rename("pending.json", state, "complete.json", io);
        try syncDir(io, state);
    }
};

fn cleanIncoming(io: Io, state: Dir) !void {
    if (@import("builtin").os.tag == .linux and std.os.linux.geteuid() == 0) {
        var incoming = state.openDir(
            io,
            "incoming",
            .{ .iterate = true, .follow_symlinks = false },
        ) catch |err| {
            if (err == error.FileNotFound) return;
            return err;
        };
        defer incoming.close(io);
        try reclaimStaging(io, incoming, 0);
    }
    state.deleteTree(io, "incoming") catch |err| if (err != error.FileNotFound) return err;
}

fn reclaimStaging(io: Io, dir: Dir, depth: usize) !void {
    if (depth > data.limits.depth) return error.TransferLimit;
    const file: File = .{ .handle = dir.handle, .flags = .{ .nonblocking = false } };
    try file.setOwner(io, 0, 0);
    try file.setPermissions(io, .fromMode(0o700));
    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        const st = try dir.statFile(io, entry.name, .{ .follow_symlinks = false });
        if (st.kind != .directory) continue;
        var child = try dir.openDir(io, entry.name, .{ .iterate = true, .follow_symlinks = false });
        defer child.close(io);
        try reclaimStaging(io, child, depth + 1);
    }
}

// The immutable pending receipt is written once. Each unit has two fixed
// records: an interrupted write leaves its previous durable record intact.
// Publication therefore writes O(1) metadata per unit, not O(all units).
const Progress = struct {
    file: File,
    const record_size = 56;
    const unit_size = record_size * 2;

    fn open(io: Io, state: Dir, units: []Unit, resume_pending: bool) !Progress {
        if (!resume_pending) {
            state.deleteFile(
                io,
                "progress-part",
            ) catch |err| if (err != error.FileNotFound) return err;
            const f = try state.createFile(
                io,
                "progress-part",
                .{ .exclusive = true, .permissions = .fromMode(0o600) },
            );
            defer f.close(io);
            try f.setLength(io, units.len * unit_size);
            try f.sync(io);
            try state.rename("progress-part", state, "progress", io);
            try syncDir(io, state);
        }
        const fd = try std.posix.openat(
            state.handle,
            "progress",
            .{ .ACCMODE = .RDWR, .NOFOLLOW = true, .NONBLOCK = true, .CLOEXEC = true },
            0,
        );
        const f: File = .{ .handle = fd, .flags = .{ .nonblocking = true } };
        errdefer f.close(io);
        const st = try f.stat(io);
        if (st.kind != .file or st.nlink != 1 or
            st.size != units.len * unit_size) return error.TransferState;
        for (units, 0..) |*unit, index| {
            var bytes: [unit_size]u8 = undefined;
            if (try f.readPositionalAll(
                io,
                &bytes,
                index * unit_size,
            ) != bytes.len) return error.TransferState;
            const first = Progress.decode(bytes[0..record_size], index);
            const second = Progress.decode(bytes[record_size..], index);
            const chosen = if (first) |one| if (second) |two|
                (if (one.sequence >= two.sequence) one else two)
            else
                one else second orelse return error.TransferState;
            unit.inode = chosen.inode;
            unit.installed = chosen.installed;
            unit.sequence = chosen.sequence;
        }
        return .{ .file = f };
    }

    fn digest(bytes: []const u8, index: usize) [32]u8 {
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        var number: [8]u8 = undefined;
        mem.writeInt(u64, &number, index, .little);
        h.update(&number);
        h.update(bytes);
        return h.finalResult();
    }

    fn decode(bytes: *const [record_size]u8, index: usize) ?Unit {
        if (mem.allEqual(u8, bytes, 0)) return .{ .path = "" };
        if (!mem.eql(u8, bytes[24..], &digest(bytes[0..24], index)) or
            bytes[16] > 1 or !mem.allEqual(u8, bytes[17..24], 0)) return null;
        const inode = mem.readInt(u64, bytes[8..16], .little);
        const sequence = mem.readInt(u64, bytes[0..8], .little);
        if (inode == 0 or sequence == 0) return null;
        return .{ .path = "", .inode = inode, .installed = bytes[16] == 1, .sequence = sequence };
    }

    fn record(p: Progress, io: Io, index: usize, unit: *Unit) !void {
        const inode = unit.inode orelse return error.TransferState;
        unit.sequence = std.math.add(u64, unit.sequence, 1) catch return error.TransferState;
        var bytes: [record_size]u8 = @splat(0);
        mem.writeInt(u64, bytes[0..8], unit.sequence, .little);
        mem.writeInt(u64, bytes[8..16], inode, .little);
        bytes[16] = @intFromBool(unit.installed);
        bytes[24..].* = digest(bytes[0..24], index);
        try p.file.writePositionalAll(
            io,
            &bytes,
            index * unit_size + (unit.sequence % 2) * record_size,
        );
        try p.file.sync(io);
    }
};

fn sameScope(x: ?[]const u8, y: ?[]const u8) bool {
    if (x == null or y == null) return x == null and y == null;
    return mem.eql(u8, x.?, y.?);
}
fn isContainer(path: []const u8) bool {
    return mem.eql(u8, path, "svc") or mem.eql(u8, path, "home");
}
fn isUnit(path: []const u8) bool {
    if (isContainer(path)) return false;
    const parent = std.fs.path.dirname(path) orelse return true;
    return isContainer(parent);
}

fn privateDir(io: Io, parent: Dir, name: []const u8) !Dir {
    parent.createDir(
        io,
        name,
        .fromMode(0o700),
    ) catch |err| if (err != error.PathAlreadyExists) return err;
    const dir = try parent.openDir(io, name, .{ .iterate = true, .follow_symlinks = false });
    errdefer dir.close(io);
    const owner = try currentOwner(
        null,
        .{ .handle = dir.handle, .flags = .{ .nonblocking = false } },
    );
    const me = if (@import("builtin").os.tag == .linux) std.os.linux.geteuid() else std.c.geteuid();
    if ((try dir.stat(io)).permissions.toMode() & 0o7777 != 0o700 or owner.uid != me)
        return error.TransferState;
    return dir;
}

pub fn openMachine(io: Io, root: Dir) !Dir {
    return privateDir(io, root, ".werewolf");
}

/// The volume keeps its receipt identity across online/offline recovery and
/// host moves. Archives exclude this private machine state.
pub fn targetIdentity(io: Io, root: Dir) ![64]u8 {
    var machine = try openMachine(io, root);
    defer machine.close(io);
    const file = data.openRegular(io, machine, "transfer-id") catch |err| blk: {
        if (err != error.FileNotFound) return err;
        const created = try machine.createFile(
            io,
            "transfer-id",
            .{ .read = true, .exclusive = true, .permissions = .fromMode(0o600) },
        );
        errdefer created.close(io);
        var random: [32]u8 = undefined;
        try io.randomSecure(&random);
        try created.writeStreamingAll(io, &std.fmt.bytesToHex(random, .lower));
        try created.sync(io);
        try syncDir(io, machine);
        break :blk created;
    };
    defer file.close(io);
    const st = try file.stat(io);
    if (st.size != 64 or st.nlink != 1) return error.TransferTarget;
    var bytes: [64]u8 = undefined;
    if (try file.readPositionalAll(io, &bytes, 0) != 64) return error.TransferTarget;
    for (bytes) |c| if (!std.ascii.isHex(c)) return error.TransferTarget;
    return bytes;
}

pub fn syncDir(io: Io, dir: Dir) !void {
    var opened = try dir.openDir(io, ".", .{ .iterate = true });
    defer opened.close(io);
    try (File{ .handle = opened.handle, .flags = .{ .nonblocking = false } }).sync(io);
}

fn readReceipt(io: Io, a: Allocator, state: Dir) !?Receipt {
    const file = data.openRegular(io, state, "pending.json") catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer file.close(io);
    var buf: [4096]u8 = undefined;
    var reader = file.readerStreaming(io, &buf);
    const json = try reader.interface.allocRemaining(a, .limited(data.limits.manifest));
    const r = try std.json.parseFromSliceLeaky(Receipt, a, json, .{});
    if (r.version != 2 or r.archive.len != 64 or
        r.units.len > data.limits.entries) return error.TransferState;
    return r;
}

fn writeReceipt(io: Io, a: Allocator, state: Dir, receipt: Receipt) !void {
    const json = try std.json.Stringify.valueAlloc(a, receipt, .{});
    defer a.free(json);
    state.deleteFile(io, "receipt-part") catch |err| if (err != error.FileNotFound) return err;
    const f = try state.createFile(
        io,
        "receipt-part",
        .{ .exclusive = true, .permissions = .fromMode(0o600) },
    );
    defer f.close(io);
    try f.writeStreamingAll(io, json);
    try f.sync(io);
    try state.rename("receipt-part", state, "pending.json", io);
    try syncDir(io, state);
}

fn empty(io: Io, parent: Dir, name: []const u8) !bool {
    var d = parent.openDir(
        io,
        name,
        .{ .iterate = true, .follow_symlinks = false },
    ) catch |err| switch (err) {
        error.FileNotFound => return true,
        else => return error.TransferConflict,
    };
    defer d.close(io);
    var it = d.iterate();
    return try it.next(io) == null;
}

fn preflight(io: Io, a: Allocator, target: Dir, scope: ?[]const u8, units: []const Unit) !void {
    if (scope) |service| {
        const path = try a.print("svc/{s}", .{service});
        defer a.free(path);
        if (done(units, path)) return;
        var svc = target.openDir(
            io,
            "svc",
            .{ .iterate = true, .follow_symlinks = false },
        ) catch |err| {
            if (err == error.FileNotFound) return;
            return err;
        };
        defer svc.close(io);
        if (!try empty(io, svc, service)) return error.TransferConflict;
        return;
    }
    var installed: std.StringHashMapUnmanaged(void) = .empty;
    defer installed.deinit(a);
    for (units) |unit| if (unit.installed) {
        try installed.put(a, unit.path, {});
    };
    try emptyTree(io, a, target, "", &installed);
}

fn done(units: []const Unit, path: []const u8) bool {
    for (units) |u| if (mem.eql(u8, u.path, path) and u.installed) return true;
    return false;
}

fn emptyTree(
    io: Io,
    a: Allocator,
    dir: Dir,
    prefix: []const u8,
    installed: *const std.StringHashMapUnmanaged(void),
) anyerror!void {
    var it = dir.iterate();
    while (try it.next(io)) |e| {
        const path = if (prefix.len == 0)
            try a.dupe(u8, e.name)
        else
            try a.print("{s}/{s}", .{ prefix, e.name });
        defer a.free(path);
        if (data.excluded(path) or data.beneath(path, "log") or installed.contains(path)) continue;
        const st = try dir.statFile(io, e.name, .{ .follow_symlinks = false });
        if (st.kind != .directory) return error.TransferConflict;
        var sub = try dir.openDir(io, e.name, .{ .iterate = true, .follow_symlinks = false });
        defer sub.close(io);
        try emptyTree(io, a, sub, path, installed);
        // A nested scaffold cannot be removed by one non-replacing rename.
        // Refuse it rather than introducing recursive deletion into import.
        if (!isContainer(path)) {
            var children = sub.iterate();
            if (try children.next(io) != null) return error.TransferConflict;
        }
    }
}

fn ensureContainer(io: Io, target: Dir, path: []const u8) !void {
    if (std.fs.path.dirname(path)) |parent| {
        if (!isContainer(parent)) return error.TransferPath;
        target.createDir(
            io,
            parent,
            .fromMode(0o755),
        ) catch |err| if (err != error.PathAlreadyExists) return err;
    }
}

pub fn decode(
    io: Io,
    a: Allocator,
    input: *Io.Reader,
    stage: Dir,
    p: data.Policy,
    scope: ?[]const u8,
) !data.Result {
    var staging: Staging = .{ .io = io, .allocator = a, .root = stage };
    defer staging.close();
    return data.zstd.validate(a, input, p, scope, staging.sink());
}

fn verifyStage(io: Io, a: Allocator, stage: Dir, m: data.Manifest, scope: ?[]const u8) !void {
    var expected: std.StringHashMapUnmanaged(data.Entry) = .empty;
    defer expected.deinit(a);
    for (m.entries) |entry| {
        if (data.importSelected(entry.path, scope)) try expected.put(a, entry.path, entry);
    }
    // A selected service archive has an implicit, private svc container.
    var seen: usize = 0;
    var walker = try stage.walk(a);
    defer walker.deinit();
    while (try walker.next(io)) |item| {
        if (scope != null and mem.eql(u8, item.path, "svc")) {
            if (item.kind != .directory) return error.TransferFileType;
            continue;
        }
        const entry = expected.get(item.path) orelse return error.TransferStaging;
        var parent = try data.parentDir(io, stage, entry.path);
        defer parent.close(io);
        const st = try parent.statFile(
            io,
            std.fs.path.basename(entry.path),
            .{ .follow_symlinks = false },
        );
        if (entry.kind == .directory) {
            if (st.kind != .directory) return error.TransferFileType;
        } else if (st.kind != .file or st.nlink != 1 or
            st.size != entry.size) return error.TransferFileType;
        if (@import("builtin").os.tag == .linux) {
            const file: File = if (entry.kind == .file)
                try data.openRegular(io, parent, std.fs.path.basename(entry.path))
            else
                .{
                    .handle = (try parent.openDir(
                        io,
                        std.fs.path.basename(entry.path),
                        .{ .iterate = true, .follow_symlinks = false },
                    )).handle,
                    .flags = .{ .nonblocking = false },
                };
            defer file.close(io);
            _ = try data.metadata.owner(null, file);
        }
        seen += 1;
    }
    if (seen != expected.count()) return error.TransferStaging;
}

const Staging = struct {
    io: Io,
    allocator: Allocator,
    root: Dir,
    file: ?File = null,
    fn close(s: *Staging) void {
        if (s.file) |f| f.close(s.io);
        s.file = null;
    }
    fn sink(s: *Staging) data.Sink {
        return .{ .context = s, .begin = begin, .write = write, .end = end };
    }
    fn begin(context: *anyopaque, e: data.Entry) !void {
        const s: *Staging = @ptrCast(@alignCast(context));
        if (s.file != null) return error.TransferState;
        // Only the optional service container is implicit; all other parents
        // were declared and created by earlier validated inventory entries.
        if (mem.startsWith(u8, e.path, "svc/"))
            s.root.createDir(
                s.io,
                "svc",
                .fromMode(0o700),
            ) catch |err| if (err != error.PathAlreadyExists) return err;
        var parent = try data.parentDir(s.io, s.root, e.path);
        defer parent.close(s.io);
        const base = std.fs.path.basename(e.path);
        if (e.kind == .directory) {
            try parent.createDir(s.io, base, .fromMode(0o700));
        } else s.file = try parent.createFile(
            s.io,
            base,
            .{ .exclusive = true, .permissions = .fromMode(0o600) },
        );
    }
    fn write(context: *anyopaque, bytes: []const u8) !void {
        const s: *Staging = @ptrCast(@alignCast(context));
        const f = s.file orelse return error.TransferState;
        try f.writeStreamingAll(s.io, bytes);
    }
    fn end(context: *anyopaque, _: data.Entry) !void {
        const s: *Staging = @ptrCast(@alignCast(context));
        if (s.file) |f| {
            try f.sync(s.io);
            f.close(s.io);
            s.file = null;
        }
    }
    fn metadata(
        s: *Staging,
        manifest: data.Manifest,
        policy: data.Policy,
        scope: ?[]const u8,
    ) !void {
        // Children first: applying a readonly directory mode cannot prevent
        // subsequent creation, and directory timestamps are restored last.
        var i = manifest.entries.len;
        while (i > 0) {
            i -= 1;
            const e = manifest.entries[i];
            if (data.importSelected(e.path, scope)) try applyMetadata(s.io, s.root, e, policy);
        }
        try syncDir(s.io, s.root);
    }
};

fn applyMetadata(io: Io, root: Dir, e: data.Entry, p: data.Policy) !void {
    var phase: []const u8 = "open";
    errdefer std.debug.print("data-transfer metadata: {s}\n", .{phase});
    var parent = try data.parentDir(io, root, e.path);
    defer parent.close(io);
    const base = std.fs.path.basename(e.path);
    const file: File = if (e.kind == .file) blk: {
        const fd = try std.posix.openat(
            parent.handle,
            base,
            .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .NONBLOCK = true, .CLOEXEC = true },
            0,
        );
        break :blk .{ .handle = fd, .flags = .{ .nonblocking = true } };
    } else blk: {
        const dir = try parent.openDir(io, base, .{ .iterate = true, .follow_symlinks = false });
        break :blk .{ .handle = dir.handle, .flags = .{ .nonblocking = false } };
    };
    defer file.close(io);
    const st = try file.stat(io);
    if ((e.kind == .file and (st.kind != .file or st.nlink != 1)) or
        (e.kind == .directory and st.kind != .directory)) return error.TransferFileType;
    const uid = try data.identityByName(p.users, e.owner);
    const gid = try data.identityByName(p.groups, e.group);
    try file.setOwner(io, uid, gid);
    if (@import("builtin").os.tag == .linux and e.kind == .directory and e.mode & 0o2000 != 0 and
        std.os.linux.geteuid() == 0)
    {
        const linux = std.os.linux;
        const old_gid = linux.getegid();
        const unchanged = std.math.maxInt(linux.gid_t);
        if (linux.errno(linux.setresgid(unchanged, gid, unchanged)) != .SUCCESS)
            return error.TransferMetadata;
        const result = file.setPermissions(io, .fromMode(@intCast(e.mode)));
        if (linux.errno(linux.setresgid(unchanged, old_gid, unchanged)) != .SUCCESS)
            return error.TransferMetadata;
        try result;
    } else try file.setPermissions(io, .fromMode(@intCast(e.mode)));
    phase = "ACL";
    if (e.kind == .directory and e.default_acl == null) try data.metadata.clearDefault(file);
    if (e.default_acl) |acl| try data.metadata.setDefault(file, acl);
    phase = "timestamp";
    try file.setTimestamps(io, .{ .modify_timestamp = .{ .new = .{ .nanoseconds = e.mtime_ns } } });
    phase = "sync";
    if ((try file.stat(io)).permissions.toMode() & 0o7777 != e.mode) return error.TransferMetadata;
    try file.sync(io);
}

fn currentOwner(_: ?*anyopaque, f: File) !data.Owner {
    if (@import("builtin").os.tag == .linux) {
        const linux = std.os.linux;
        var st: linux.Statx = undefined;
        if (linux.errno(linux.statx(
            f.handle,
            "",
            linux.AT.EMPTY_PATH,
            .{ .UID = true, .GID = true },
            &st,
        )) != .SUCCESS)
            return error.TransferOwner;
        return .{ .uid = st.uid, .gid = st.gid };
    } else {
        var st: std.c.Stat = undefined;
        if (std.c.fstat(f.handle, &st) != 0) return error.TransferOwner;
        return .{ .uid = st.uid, .gid = st.gid };
    }
}

test "empty svc and home containers publish and recover from a pending import" {
    const t = std.testing;
    const io = t.io;
    for ([_][]const u8{ "svc", "home" }) |name| {
        var arena = std.heap.ArenaAllocator.init(t.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        var tmp = t.tmpDir(.{});
        defer tmp.cleanup();
        try tmp.dir.createDir(io, "source", .fromMode(0o700));
        try tmp.dir.createDir(io, "target", .fromMode(0o700));
        var source = try tmp.dir.openDir(io, "source", .{ .iterate = true });
        defer source.close(io);
        var target = try tmp.dir.openDir(io, "target", .{ .iterate = true });
        defer target.close(io);
        try source.createDir(io, name, .fromMode(0o750));
        const owner = try currentOwner(
            null,
            .{ .handle = source.handle, .flags = .{ .nonblocking = false } },
        );
        const policy: data.Policy = .{
            .image = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            .arch = .aarch64,
            .services = &.{},
            .users = &.{.{ .name = "test", .id = owner.uid }},
            .groups = &.{.{ .name = "test", .id = owner.gid }},
        };
        const owners: data.Ownership = .{ .get = currentOwner };
        const manifest = try data.scan(io, a, source, policy, null, owners);
        var archive: Io.Writer.Allocating = .init(a);
        _ = try data.emit(io, a, source, manifest, policy, owners, &archive.writer);
        var input: Io.Reader = .fixed(archive.written());
        try t.expectError(error.SimulatedCrash, applyInner(io, a, &input, target, policy, .{
            .target = "empty-test",
            .boundary = struct {
                fn hit(_: ?*anyopaque, b: Boundary) !void {
                    if (b == .pending) return error.SimulatedCrash;
                }
            }.hit,
        }, false));
        try t.expect(try blocked(io, target));
        input = .fixed(archive.written());
        _ = try applyInner(io, a, &input, target, policy, .{ .target = "empty-test" }, false);
        try t.expect(!try blocked(io, target));
        const st = try target.statFile(io, name, .{});
        try t.expectEqual(File.Kind.directory, st.kind);
        try t.expectEqual(manifest.entries[0].mode, st.permissions.toMode() & 0o7777);
        try t.expectEqual(@as(i96, manifest.entries[0].mtime_ns), st.mtime.nanoseconds);
    }
}

test "progress uses fixed records and survives a torn latest write" {
    const t = std.testing;
    const io = t.io;
    var tmp = t.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const units = try t.allocator.alloc(Unit, 4096);
    defer t.allocator.free(units);
    @memset(units, .{ .path = "" });
    const progress = try Progress.open(io, tmp.dir, units, false);
    defer progress.file.close(io);
    units[0].inode = 123;
    try progress.record(io, 0, &units[0]);
    units[0].installed = true;
    try progress.record(io, 0, &units[0]);
    try t.expectEqual(@as(u64, 4096 * Progress.unit_size), (try progress.file.stat(io)).size);
    try progress.file.writePositionalAll(io, "\xff", 0);
    try progress.file.sync(io);
    const resumed = try Progress.open(io, tmp.dir, units, true);
    defer resumed.file.close(io);
    try t.expectEqual(@as(?u64, 123), units[0].inode);
    try t.expect(!units[0].installed);
    try t.expectEqual(@as(u64, 1), units[0].sequence);
    try t.expect(units[4095].inode == null);
}

test "publisher refuses decoder files absent from its checked inventory" {
    const t = std.testing;
    const io = t.io;
    var tmp = t.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "undeclared", .data = "no" });
    const m: data.Manifest = .{
        .image = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        .arch = .aarch64,
        .entries = &.{},
    };
    try t.expectError(error.TransferStaging, verifyStage(io, t.allocator, tmp.dir, m, null));
}

test "service import recovers every publication boundary without changing companions" {
    for (std.meta.tags(Boundary)) |fault| {
        const t = std.testing;
        const io = t.io;
        var arena = std.heap.ArenaAllocator.init(t.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        var tmp = t.tmpDir(.{});
        defer tmp.cleanup();
        try tmp.dir.createDir(io, "source", .fromMode(0o700));
        try tmp.dir.createDir(io, "target", .fromMode(0o700));
        var source = try tmp.dir.openDir(io, "source", .{ .iterate = true });
        defer source.close(io);
        var target = try tmp.dir.openDir(io, "target", .{ .iterate = true });
        defer target.close(io);
        try source.createDirPath(io, "svc/plex");
        try source.createDirPath(io, "svc/plex-media");
        try source.writeFile(
            io,
            .{
                .sub_path = "svc/plex/db",
                .data = "database",
                .flags = .{ .permissions = .fromMode(0o640) },
            },
        );
        try source.writeFile(io, .{ .sub_path = "svc/plex-media/movie", .data = "source media" });
        try target.createDirPath(io, "svc/plex-media");
        try target.createDirPath(io, "svc/plex");
        try target.writeFile(
            io,
            .{ .sub_path = "svc/plex-media/movie", .data = "keep destination media" },
        );
        const parent_before = try target.statFile(io, "svc", .{});
        const owner = try currentOwner(
            null,
            .{ .handle = source.handle, .flags = .{ .nonblocking = false } },
        );
        const policy: data.Policy = .{
            .image = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            .arch = .aarch64,
            .services = &.{ "plex", "plex-media" },
            .users = &.{.{ .name = "test", .id = owner.uid }},
            .groups = &.{.{ .name = "test", .id = owner.gid }},
        };
        const owners: data.Ownership = .{ .get = currentOwner };
        const manifest = try data.scan(io, a, source, policy, null, owners);
        var archive: Io.Writer.Allocating = .init(a);
        _ = try data.emit(io, a, source, manifest, policy, owners, &archive.writer);
        var reader: Io.Reader = .fixed(archive.written());
        const crash = struct {
            fn hit(context: ?*anyopaque, b: Boundary) !void {
                const at: *const Boundary = @ptrCast(@alignCast(context.?));
                if (b == at.*) return error.SimulatedCrash;
            }
        }.hit;
        try t.expectError(
            error.SimulatedCrash,
            applyInner(
                io,
                a,
                &reader,
                target,
                policy,
                .{
                    .target = "destination",
                    .service = "plex",
                    .boundary = crash,
                    .context = @constCast(&fault),
                },
                false,
            ),
        );
        try t.expect(try blocked(io, target));
        reader = .fixed(archive.written());
        try t.expectError(
            error.TransferPending,
            applyInner(
                io,
                a,
                &reader,
                target,
                policy,
                .{ .target = "other", .service = "plex" },
                false,
            ),
        );
        reader = .fixed(archive.written());
        _ = try applyInner(
            io,
            a,
            &reader,
            target,
            policy,
            .{ .target = "destination", .service = "plex" },
            false,
        );
        try t.expect(!try blocked(io, target));
        try t.expectEqual(
            parent_before.mtime.nanoseconds,
            (try target.statFile(io, "svc", .{})).mtime.nanoseconds,
        );
        try t.expectEqualStrings(
            "database",
            try target.readFileAlloc(io, "svc/plex/db", a, .limited(1024)),
        );
        try t.expectEqualStrings(
            "keep destination media",
            try target.readFileAlloc(io, "svc/plex-media/movie", a, .limited(1024)),
        );
        const before = try source.statFile(io, "svc/plex/db", .{});
        const after = try target.statFile(io, "svc/plex/db", .{});
        try t.expectEqual(
            before.permissions.toMode() & 0o7777,
            after.permissions.toMode() & 0o7777,
        );
        try t.expectEqual(before.mtime.nanoseconds, after.mtime.nanoseconds);
        try t.expectError(
            error.FileNotFound,
            target.access(io, state_path ++ "/pending.json", .{}),
        );
        reader = .fixed(archive.written());
        try t.expectError(
            error.TransferConflict,
            applyInner(
                io,
                a,
                &reader,
                target,
                policy,
                .{ .target = "destination", .service = "plex" },
                false,
            ),
        );
    }
}

test "full compressed import preserves data and machine exclusions and rejects overwrite" {
    const t = std.testing;
    const io = t.io;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "source", .fromMode(0o700));
    try tmp.dir.createDir(io, "target", .fromMode(0o700));
    var source = try tmp.dir.openDir(io, "source", .{ .iterate = true });
    defer source.close(io);
    var target = try tmp.dir.openDir(io, "target", .{ .iterate = true });
    defer target.close(io);
    try source.createDirPath(io, "svc/postgres");
    try source.setFilePermissions(
        io,
        "svc/postgres",
        .fromMode(0o2750),
        .{ .follow_symlinks = false },
    );
    try source.createDirPath(io, "home/person/empty");
    try source.createDirPath(io, ".werewolf");
    try source.createDirPath(io, "log");
    try source.writeFile(io, .{ .sub_path = "log/current", .data = "source audit trail" });
    try source.writeFile(io, .{ .sub_path = ".werewolf/identities", .data = "source authority" });
    try source.writeFile(io, .{ .sub_path = "notes", .data = "outside service directories" });
    try source.writeFile(io, .{ .sub_path = "svc/postgres/data", .data = "cluster" });
    try source.writeFile(io, .{ .sub_path = "home/person/.empty", .data = "" });
    try target.createDir(io, ".werewolf", .fromMode(0o700));
    try target.createDir(io, "log", .fromMode(0o700));
    try target.writeFile(io, .{ .sub_path = "log/current", .data = "destination audit trail" });
    try target.writeFile(
        io,
        .{ .sub_path = ".werewolf/identities", .data = "destination authority" },
    );
    const owner = try currentOwner(
        null,
        .{ .handle = source.handle, .flags = .{ .nonblocking = false } },
    );
    const policy: data.Policy = .{
        .image = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        .arch = .aarch64,
        .services = &.{"postgres"},
        .users = &.{.{ .name = "test", .id = owner.uid }},
        .groups = &.{.{ .name = "test", .id = owner.gid }},
    };
    const owners: data.Ownership = .{ .get = currentOwner };
    const manifest = try data.scan(io, a, source, policy, null, owners);
    var tar: Io.Writer.Allocating = .init(a);
    _ = try data.emit(io, a, source, manifest, policy, owners, &tar.writer);
    try t.expect(mem.find(u8, tar.written(), "source audit trail") != null);
    try tmp.dir.writeFile(io, .{ .sub_path = "archive.tar", .data = tar.written() });
    const path = try tmp.dir.realPathFileAlloc(io, "archive.tar", a);
    const compressed = try std.process.run(
        a,
        io,
        .{
            .argv = &.{ "zstd", "-1", "-q", "-c", "--", path },
            .stdout_limit = .limited(1 << 20),
            .stderr_limit = .limited(4096),
        },
    );
    try t.expect(compressed.term == .exited and compressed.term.exited == 0);
    var input: Io.Reader = .fixed(compressed.stdout);
    const result = try apply(io, a, &input, target, policy, .{ .target = "new-machine" });
    try t.expect(result.manifest.service == null);
    try t.expectEqualStrings(
        "destination authority",
        try target.readFileAlloc(io, ".werewolf/identities", a, .limited(1024)),
    );
    try t.expectEqualStrings(
        "destination audit trail",
        try target.readFileAlloc(io, "log/current", a, .limited(1024)),
    );
    try tmp.dir.createDir(io, "fresh", .fromMode(0o700));
    var fresh = try tmp.dir.openDir(io, "fresh", .{ .iterate = true });
    defer fresh.close(io);
    var fresh_input: Io.Reader = .fixed(compressed.stdout);
    _ = try apply(io, a, &fresh_input, fresh, policy, .{ .target = "fresh-machine" });
    try t.expectError(error.FileNotFound, fresh.access(io, "log", .{}));
    for (manifest.entries) |e| {
        if (data.beneath(e.path, "log")) continue;
        const st = try target.statFile(io, e.path, .{ .follow_symlinks = false });
        try t.expectEqual(e.mode, @as(u32, st.permissions.toMode() & 0o7777));
        try t.expectEqual(@as(i96, e.mtime_ns), st.mtime.nanoseconds);
        if (e.kind == .file) try t.expectEqualStrings(
            try source.readFileAlloc(io, e.path, a, .limited(1024)),
            try target.readFileAlloc(io, e.path, a, .limited(1024)),
        );
    }
    input = .fixed(compressed.stdout);
    try t.expectError(
        error.TransferConflict,
        apply(io, a, &input, target, policy, .{ .target = "new-machine" }),
    );
    try t.expectEqualStrings(
        "cluster",
        try target.readFileAlloc(io, "svc/postgres/data", a, .limited(1024)),
    );
}

test "boot barrier fails closed on linked machine state" {
    const t = std.testing;
    const io = t.io;
    var tmp = t.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try t.expect(!try blocked(io, tmp.dir));
    try tmp.dir.createDirPath(io, state_path);
    try t.expect(!try blocked(io, tmp.dir));
    try tmp.dir.symLink(io, "missing", state_path ++ "/pending.json", .{});
    try t.expect(try blocked(io, tmp.dir));
    try tmp.dir.deleteFile(io, state_path ++ "/pending.json");
    try tmp.dir.deleteDir(io, state_path);
    try tmp.dir.symLink(io, "missing", state_path, .{ .is_directory = true });
    // A linked intermediate path must not look like an absent receipt.
    if (blocked(io, tmp.dir)) |_| return error.AcceptedLinkedState else |_| {}
}

test "receipt target identity is private, durable and refuses truncation" {
    const t = std.testing;
    var tmp = t.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const first = try targetIdentity(t.io, tmp.dir);
    try t.expectEqualStrings(&first, &try targetIdentity(t.io, tmp.dir));
    try tmp.dir.writeFile(t.io, .{ .sub_path = ".werewolf/transfer-id", .data = "torn" });
    try t.expectError(error.TransferTarget, targetIdentity(t.io, tmp.dir));
}
