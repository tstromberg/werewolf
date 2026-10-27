//! One archive import and export. Guest filesystems are only mounted by the
//! networkless storage appliance, never by the host running Howl.
const std = @import("std");
const howl = @import("howl.zig");
const secure = @import("local-secure.zig");
const images = @import("data-image.zig");
const helper = @import("data-helper.zig");
const data = @import("data-transfer");
const Io = std.Io;
const Dir = Io.Dir;
const A = std.mem.Allocator;
const mem = std.mem;

pub const Operation = enum { @"export", import };
const Options = struct {
    name: []const u8,
    archive: ?[]const u8 = null,
    service: ?[]const u8 = null,
    output: ?[]const u8 = null,
    on: ?howl.Platform = null,
    key: ?[]const u8 = null,
    config: ?[]const u8 = null,
    identity: ?[]const u8 = null,
};

fn parse(op: Operation, args: []const []const u8) !Options {
    if (args.len == 0 or !howl.isMachineName(args[0])) return error.TransferArguments;
    var o: Options = .{ .name = args[0] };
    var i: usize = 1;
    if (op == .import) {
        if (args.len < 2 or mem.startsWith(u8, args[1], "-")) return error.TransferArguments;
        o.archive = args[1];
        i = 2;
    }
    while (i < args.len) : (i += 2) {
        if (i + 1 >= args.len) return error.TransferArguments;
        const flag = args[i];
        const value = args[i + 1];
        if (value.len == 0) return error.TransferArguments;
        if (mem.eql(u8, flag, "--service") and o.service == null) {
            if (!data.validName(value)) return error.TransferArguments;
            o.service = value;
        } else if (op == .@"export" and mem.eql(u8, flag, "--output") and o.output == null) {
            o.output = value;
        } else if (op == .@"export" and mem.eql(u8, flag, "--identity") and o.identity == null) {
            o.identity = value;
        } else if (mem.eql(u8, flag, "--on") and o.on == null) {
            o.on = std.meta.stringToEnum(howl.Platform, value) orelse return error.TransferArguments;
        } else if (mem.eql(u8, flag, "--data-key") and o.key == null) {
            o.key = value;
        } else if (op == .import and mem.eql(u8, flag, "--config") and o.config == null) {
            o.config = value;
        } else return error.TransferArguments;
    }
    return o;
}

pub fn command(io: Io, a: A, op: Operation, args: []const []const u8, why: *howl.Why) !void {
    const o = parse(op, args) catch return why.refuse(
        "howl export NAME [--service NAME] [--output FILE] [--data-key FILE]; " ++
            "howl import NAME ARCHIVE [--service NAME] [--on qemu|lima] [--config DIR] [--data-key FILE]",
        .{},
    );
    const cwd = try std.process.currentPathAlloc(io, a);
    const at = try std.fs.path.resolveAlloc(a, &.{ cwd, try howl.machineDir(a, o.name) });
    try Dir.cwd().createDirPath(io, at);
    try Dir.cwd().setFilePermissions(io, at, .fromMode(0o700), .{});
    const lock = try Dir.cwd().createFile(io, try a.print("{s}/secure.lock", .{at}), .{
        .truncate = false,
        .permissions = .fromMode(0o600),
    });
    defer lock.close(io);
    try lock.lock(io, .exclusive);
    defer lock.unlock(io);
    var nonce: [12]u8 = undefined;
    try io.randomSecure(&nonce);
    const suffix = std.fmt.bytesToHex(nonce, .lower);
    const destination = if (op == .@"export") try std.fs.path.resolveAlloc(a, &.{ cwd, o.output orelse
        try a.print("{s}-export-{d}-{s}.tar.zst", .{ o.name, @divTrunc(Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s), suffix }) }) else null;
    const work = try a.print("{s}/.werewolf-transfer-{s}", .{
        if (destination) |path| std.fs.path.dirname(path).? else at, suffix,
    });
    try Dir.cwd().createDir(io, work, .fromMode(0o700));
    defer Dir.cwd().deleteTree(io, work) catch {};
    const file = try a.print("{s}/authority/profile.json", .{at});
    const saved = Dir.cwd().readFileAlloc(io, file, a, .limited(256 << 10)) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
    var profile: secure.Profile = undefined;
    var record: images.Record = undefined;
    var image: []const u8 = undefined;
    var users: []const u8 = "";
    if (saved) |text| {
        profile = try secure.parseProfile(a, text);
        if (o.on) |on| if (on != profile.provider) return error.TransferProvider;
        if (op == .@"export" and try machineRunning(io, a, o.name, at, profile.provider, why)) {
            const approved = try @import("data-ssh.zig").capture(io, a, o.name, at, profile.provider, o.service, o.identity, work, why);
            try publish(io, a, work, destination.?, approved, o.service);
            return;
        }
        try requireStopped(io, a, o.name, at, profile.provider, why);
        record = try images.approve(io, a, profile, false, why);
        image = try a.dupe(u8, &std.fmt.bytesToHex(record.verity.root, .lower));
        if (o.config != null) return why.refuse("existing destinations retain their configuration; omit --config", .{});
    } else {
        if (op != .import) return why.refuse("{s}: no enrolled machine", .{o.name});
        // Hints are used solely as a key in the owner's approved image cache.
        const hint = try archiveHint(io, a, o.archive.?);
        image = hint.image;
        record = images.read(io, a, image) catch |err| switch (err) {
            error.FileNotFound => return why.refuse("matching image {s} is unavailable; provision a stopped destination with that approved image first", .{image}),
            else => return err,
        };
        const on = o.on orelse howl.engine(io, a, null).on;
        if (on != .qemu and on != .lima) return error.TransferProvider;
        const definition = record.profile.configuration orelse return error.MissingBootConfiguration;
        const previous = @import("boot-config.zig").current;
        @import("boot-config.zig").current = definition;
        defer @import("boot-config.zig").current = previous;
        const iface = try howl.formInterface(io, a, record.profile.spec.form, why);
        const entries = try howl.gather(io, a, iface, .{
            .form = record.profile.spec.form,
            .name = o.name,
            .on = on,
            .config = o.config,
            .add_current_user = .no,
        }, why);
        for (entries) |entry| if (mem.eql(u8, entry.path, "users")) {
            users = entry.data;
        };
        // The helper validates with approved destination identities before
        // publishing any data. Provisioning does not start applications.
        profile = try secure.transferTarget(io, a, o.name, on, record, try howl.writeTar(a, entries), why);
    }
    const guest = try images.guest(io, a, image, record, why);
    const disk = try storage(io, a, o.name, at, profile.provider);
    try requireUnused(io, a, disk);
    if (op == .import) {
        const info = try std.process.run(a, io, .{
            .argv = &.{ "qemu-img", "info", "--output=json", disk },
            .stdout_limit = .limited(64 << 10),
            .stderr_limit = .limited(4096),
        });
        if (!info.term.success()) return error.TransferStorageState;
        const description = try std.json.parseFromSliceLeaky(struct {
            format: []const u8,
            @"backing-filename": ?[]const u8 = null,
        }, a, info.stdout, .{ .ignore_unknown_fields = true });
        if (!mem.eql(u8, description.format, "raw") or description.@"backing-filename" != null)
            return why.refuse("destination storage must be a standalone raw disk", .{});
    }
    const source = if (op == .@"export") blk: {
        const before = try Dir.cwd().statFile(io, disk, .{});
        const copy = try a.print("{s}/source.raw", .{work});
        try howl.run(io, why, &.{ "qemu-img", "convert", "-O", "raw", disk, copy });
        try requireStopped(io, a, o.name, at, profile.provider, why);
        try requireUnused(io, a, disk);
        const after = try Dir.cwd().statFile(io, disk, .{});
        if (before.size != after.size or !std.meta.eql(before.mtime, after.mtime))
            return error.TransferSourceChanged;
        break :blk copy;
    } else disk;
    const control = try helper.controlDisk(io, a, work, .{
        .operation = @tagName(op),
        .layout = "boot",
        .image = image,
        .verity = record.verity,
        .arch = @tagName(profile.spec.arch),
        .service = o.service,
        .target = at,
        .initialize = op == .import,
        .users = users,
    }, o.archive, o.key, why);
    const policy = try helper.run(io, a, guest, .{ .data = source, .control = control, .writable = op == .import }, work);
    if (destination) |path| try publish(io, a, work, path, policy, o.service) else howl.say(io, "{s}: import complete; destination remains stopped", .{o.name});
}

fn publish(io: Io, a: A, work: []const u8, path: []const u8, policy: data.Policy, service: ?[]const u8) !void {
    const archive = try a.print("{s}/archive.tar.zst", .{work});
    const input = try Dir.cwd().openFile(io, archive, .{});
    defer input.close(io);
    var buffer: [64 << 10]u8 = undefined;
    var reader = input.readerStreaming(io, &buffer);
    _ = try data.zstd.validate(a, &reader.interface, policy, service, null);
    try input.sync(io);
    try Dir.cwd().renamePreserve(archive, .cwd(), path, io);
    var parent = try Dir.cwd().openDir(io, std.fs.path.dirname(path).?, .{});
    defer parent.close(io);
    try data.install.syncDir(io, parent);
    try Io.File.stdout().writeStreamingAll(io, try a.print("{s}\n", .{path}));
}

/// A missing or stale PID file is not evidence that storage is unused. Howl's
/// lifecycle lock excludes its own launchers; this also catches external QEMU
/// instances holding the disk without that PID file. Uncertain probes fail.
fn requireUnused(io: Io, a: A, disk: []const u8) !void {
    const result = try std.process.run(a, io, .{
        .argv = &.{ "lsof", "-Fpcfn", "--", disk },
        .stdout_limit = .limited(64 << 10),
        .stderr_limit = .limited(4096),
    });
    if (result.term != .exited or result.term.exited != 1 or
        result.stdout.len != 0 or result.stderr.len != 0)
        return error.TransferStorageInUse;
}

fn archiveHint(io: Io, a: A, path: []const u8) !data.Manifest {
    const file = try Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    if ((try file.stat(io)).kind != .file) return error.TransferFileType;
    var buf: [64 << 10]u8 = undefined;
    var reader = file.readerStreaming(io, &buf);
    return data.zstd.manifest(a, &reader.interface);
}

fn machineRunning(io: Io, a: A, name: []const u8, at: []const u8, on: howl.Platform, why: *howl.Why) !bool {
    return switch (on) {
        .lima => try @import("lima.zig").running(io, a, name),
        .qemu => blk: {
            const text = Dir.cwd().readFileAlloc(io, try a.print("{s}/qemu.pid", .{at}), a, .limited(64)) catch |err| switch (err) {
                error.FileNotFound => break :blk false,
                else => return err,
            };
            const pid = try std.fmt.parseInt(std.posix.pid_t, mem.trim(u8, text, " \r\n"), 10);
            if (pid <= 1) return error.TransferMachineState;
            std.posix.kill(pid, @fromBackingInt(0)) catch |err| switch (err) {
                error.ProcessNotFound => break :blk false,
                else => return err,
            };
            break :blk true;
        },
        else => return why.refuse("data transfer for {t} has not passed its provider tests", .{on}),
    };
}

fn requireStopped(io: Io, a: A, name: []const u8, at: []const u8, on: howl.Platform, why: *howl.Why) !void {
    if (try machineRunning(io, a, name, at, on, why)) return why.refuse("{s}: data transfer requires cleanly stopped applications; the offline path refuses running storage", .{name});
}

fn storage(io: Io, a: A, name: []const u8, at: []const u8, on: howl.Platform) ![]const u8 {
    return switch (on) {
        .qemu => a.print("{s}/disk.img", .{at}),
        .lima => a.print("{s}/disk", .{try @import("lima.zig").dir(io, a, name) orelse return error.MissingLimaInstance}),
        else => error.TransferProvider,
    };
}

test "one archive syntax rejects legacy inputs and scope escalation" {
    const t = std.testing;
    const o = try parse(.import, &.{ "target", "backup.tar.zst", "--service", "plex" });
    try t.expectEqualStrings("plex", o.service.?);
    try t.expectError(error.TransferArguments, parse(.import, &.{ "target", "--retry", "abc" }));
    try t.expectError(error.TransferArguments, parse(.@"export", &.{ "source", "--service", "../plex" }));
    try t.expectError(error.TransferArguments, parse(.@"export", &.{ "source", "--service", "plex", "--service", "postgres" }));
    try t.expectError(error.TransferArguments, parse(.import, &.{ "target", "backup", "--output", "elsewhere" }));
}
