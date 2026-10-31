//! One archive import and export. Guest filesystems are only mounted by the
//! networkless storage appliance, never by the host running Howl.
const std = @import("std");
const howl = @import("howl.zig");
const cloud = @import("data-cloud.zig");
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
    host: ?[]const u8 = null,
    port: ?u16 = null,
    form: ?[]const u8 = null,
    version: ?[]const u8 = null,
    disk: ?[]const u8 = null,
    size: ?[]const u8 = null,
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
        } else if (mem.eql(u8, flag, "--identity") and o.identity == null) {
            o.identity = value;
        } else if (mem.eql(u8, flag, "--host") and o.host == null) {
            for (value) |c| if (!std.ascii.isAlphanumeric(c) and
                mem.findScalar(u8, ".-:[]%", c) == null)
                return error.TransferArguments;
            if (value[0] == '-') return error.TransferArguments;
            o.host = value;
        } else if (mem.eql(u8, flag, "--port") and o.port == null) {
            o.port = std.fmt.parseUnsigned(u16, value, 10) catch return error.TransferArguments;
            if (o.port.? == 0) return error.TransferArguments;
        } else if (mem.eql(u8, flag, "--on") and o.on == null) {
            o.on = std.meta.stringToEnum(
                howl.Platform,
                value,
            ) orelse return error.TransferArguments;
        } else if (mem.eql(u8, flag, "--data-key") and o.key == null) {
            o.key = value;
        } else if (mem.eql(u8, flag, "--disk") and o.disk == null) {
            o.disk = value;
        } else if (op == .import and mem.eql(u8, flag, "--size") and o.size == null) {
            o.size = value;
        } else if (op == .import and mem.eql(u8, flag, "--config") and o.config == null) {
            o.config = value;
        } else if (op == .import and mem.eql(u8, flag, "--with") and o.form == null) {
            if (!@import("form").isName(value)) return error.TransferArguments;
            o.form = value;
        } else if (op == .import and mem.eql(u8, flag, "--version") and o.version == null) {
            o.version = value;
        } else return error.TransferArguments;
    }
    if (o.port != null and o.host == null) return error.TransferArguments;
    if (o.version != null and o.form == null) return error.TransferArguments;
    return o;
}

pub fn command(io: Io, a: A, op: Operation, args: []const []const u8, why: *howl.Why) !void {
    const o = parse(op, args) catch return why.refuse(
        "howl export NAME [--service NAME] [--output FILE] [--disk RAW] [--data-key FILE]; " ++
            "howl import NAME ARCHIVE [--service NAME] [--on TARGET] [--config DIR] [--disk " ++
            "RAW] [--data-key FILE]",
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
    const destination = if (op == .@"export")
        try std.fs.path.resolveAlloc(a, &.{ cwd, o.output orelse
            try a.print(
                "{s}-export-{d}-{s}.tar.zst",
                .{
                    o.name,
                    @divTrunc(Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s),
                    suffix,
                },
            ) })
    else
        null;
    const work = try a.print("{s}/.werewolf-transfer-{s}", .{
        if (destination) |path| std.fs.path.dirname(path).? else at, suffix,
    });
    try Dir.cwd().createDir(io, work, .fromMode(0o700));
    defer Dir.cwd().deleteTree(io, work) catch {};
    if (o.host) |host| {
        if (o.disk != null) return error.TransferArguments;
        if (op == .import) {
            if (o.config != null or o.form != null or o.key != null) return error.TransferArguments;
            try @import("data-ssh.zig").restore(
                io,
                a,
                o.name,
                at,
                o.on orelse .qemu,
                o.service,
                o.identity,
                .{ .host = host, .port = o.port orelse 22 },
                o.archive.?,
                why,
            );
            return;
        }
        const approved = try @import("data-ssh.zig").capture(
            io,
            a,
            o.name,
            at,
            o.on orelse .qemu,
            o.service,
            o.identity,
            .{ .host = host, .port = o.port orelse 22 },
            work,
            why,
        );
        try publish(io, a, work, destination.?, approved, o.service);
        return;
    }
    const file = try a.print("{s}/authority/profile.json", .{at});
    const saved = Dir.cwd().readFileAlloc(
        io,
        file,
        a,
        .limited(256 << 10),
    ) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
    var profile: secure.Profile = undefined;
    var record: images.Record = undefined;
    var image: []const u8 = undefined;
    var users: []const u8 = "";
    if (saved) |text| {
        if (o.form != null) return why.refuse(
            "existing destinations retain their approved image; omit --with",
            .{},
        );
        profile = try secure.parseProfile(a, text);
        if (o.size != null) return why.refuse(
            "existing destinations retain their size; omit --size",
            .{},
        );
        if (o.on) |on| if (on != profile.provider) return error.TransferProvider;
        if (profile.cloud_staged) {
            if (profile.cloud != null) return error.TransferAwaitingStart;
        } else if (try machineRunning(io, a, o.name, at, profile.provider, why)) {
            if (o.disk != null) return error.TransferStorageInUse;
            if (op == .import) {
                if (o.config != null or o.key != null) return error.TransferArguments;
                try @import("data-ssh.zig").restore(
                    io,
                    a,
                    o.name,
                    at,
                    profile.provider,
                    o.service,
                    o.identity,
                    null,
                    o.archive.?,
                    why,
                );
                return;
            }
            const approved = try @import("data-ssh.zig").capture(
                io,
                a,
                o.name,
                at,
                profile.provider,
                o.service,
                o.identity,
                null,
                work,
                why,
            );
            try publish(io, a, work, destination.?, approved, o.service);
            return;
        }
        if (op == .import and try machineRunning(io, a, o.name, at, profile.provider, why)) {
            if (o.disk != null or o.key != null) return error.TransferArguments;
            try @import("data-ssh.zig").restore(
                io,
                a,
                o.name,
                at,
                profile.provider,
                o.service,
                o.identity,
                o.archive.?,
                why,
            );
            return;
        }
        try requireStopped(io, a, o.name, at, profile.provider, why);
        record = if (profile.data_image) |approved_image|
            try images.read(io, a, approved_image)
        else
            try images.approve(io, a, profile, false, why);
        image = try a.dupe(u8, &std.fmt.bytesToHex(record.verity.root, .lower));
        if (o.config != null) return why.refuse(
            "existing destinations retain their configuration; omit --config",
            .{},
        );
    } else {
        if (o.disk != null) return error.TransferArguments;
        if (op != .import) return why.refuse("{s}: no enrolled machine", .{o.name});
        // Hints are used solely as a key in the owner's approved image cache.
        const hint = try archiveHint(io, a, o.archive.?);
        image = hint.image;
        const on = o.on orelse howl.engine(io, a, null).on;
        if (on != .qemu and on != .lima and on != .bhyve and
            !cloud.supported(on)) return error.TransferProvider;
        const arch = std.meta.stringToEnum(howl.Arch, @tagName(hint.arch)).?;
        if (arch != howl.hostArch()) return error.TransferArchitecture;
        record = if (o.form) |form_name|
            try images.published(io, a, form_name, on, arch, o.version, image, why)
        else
            images.findByVerity(io, a, image, why) catch |err| switch (err) {
                error.FileNotFound => return why.refuse(
                    "matching image {s} is unavailable; select its approved published release " ++
                        "with --with FORM --version SERIAL",
                    .{image},
                ),
                else => return err,
            };
        const definition = record.profile.configuration orelse
            return error.MissingBootConfiguration;
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
        profile = if (cloud.supported(on))
            try @import("data-cloud-target.zig").prepare(
                io,
                a,
                at,
                on,
                o.size,
                record,
                try howl.writeTar(a, entries),
                why,
            )
        else
            try secure.transferTarget(
                io,
                a,
                o.name,
                on,
                record,
                try howl.writeTar(a, entries),
                why,
            );
    }
    const remote = !profile.cloud_staged and (cloud.supported(profile.provider));
    if (op == .import and remote and
        o.disk == null) return why.refuse(
        "offline cloud import requires a new machine name; use --disk RAW for manual staging on " ++
            "an existing VM",
        .{},
    );
    if (o.disk != null and !remote) return error.TransferArguments;
    const context = if (remote)
        try @import("data-cloud.zig").load(io, a, at, profile.provider)
    else
        null;
    const disk = if (o.disk) |path|
        try std.fs.path.resolveAlloc(a, &.{ cwd, path })
    else if (context) |c|
        try @import("data-cloud-disk.zig").copy(io, a, o.name, c, profile.spec.arch, work, why)
    else
        try storage(io, a, o.name, at, profile.provider);
    const cache_key = record.profile.data_image orelse image;
    const guest = try images.guest(io, a, cache_key, record, why);
    try requireUnused(io, a, disk);
    // Storage adapters provide raw disks. Never sniff guest-controlled bytes:
    // a forged qcow2 header could otherwise name a host backing file.
    const source = if (op == .@"export" and !profile.cloud_staged and (!remote or
        o.disk != null))
    blk: {
        const before = try Dir.cwd().statFile(io, disk, .{});
        const copy = try a.print("{s}/source.raw", .{work});
        try howl.run(io, why, &.{ "qemu-img", "convert", "-f", "raw", "-O", "raw", disk, copy });
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
        .replay_journal_on_copy = op == .@"export" and !profile.cloud_staged,
        .nocloud = if (profile.provider == .lima and op == .import)
            try @import("lima.zig").dataIdentity(io, a, o.name)
        else
            @as(?@import("people").NoCloud, null),
    }, o.archive, o.key, why);
    const policy = try helper.run(
        io,
        a,
        guest,
        .{
            .data = source,
            .control = control,
            .writable = op == .import or (op == .@"export" and !profile.cloud_staged),
            .guard = lock,
        },
        work,
    );
    if (op == .import and
        profile.cloud_staged) try images.replaceRecord(
        io,
        a,
        try a.print("{s}/authority/import-ready", .{at}),
        profile.data_image orelse image,
    );
    if (op == .import and o.disk != null) {
        howl.say(
            io,
            "{s}: staged disk import complete; publish {s} with the provider CLI; VM storage " ++
                "was not changed",
            .{ o.name, disk },
        );
        return;
    }
    if (destination) |path|
        try publish(io, a, work, path, policy, o.service)
    else
        howl.say(io, "{s}: import complete; destination remains stopped", .{o.name});
}

fn copyRaw(io: Io, source: []const u8, destination: []const u8, why: *howl.Why) !void {
    try howl.run(
        io,
        why,
        &.{ "qemu-img", "convert", "-f", "raw", "-O", "raw", source, destination },
    );
}

test "raw transport copies a forged qcow2 header instead of following its host backing path" {
    const t = std.testing;
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    const at = try tmp.dir.realPathFileAlloc(t.io, ".", a);
    var secret: [4096]u8 = @splat(0);
    @memcpy(secret[0..11], "host secret");
    try tmp.dir.writeFile(t.io, .{ .sub_path = "private.raw", .data = &secret });
    const forged = try a.print("{s}/forged.qcow2", .{at});
    const create = std.process.run(
        a,
        t.io,
        .{ .argv = &.{
            "qemu-img",
            "create",
            "-f",
            "qcow2",
            "-F",
            "raw",
            "-b",
            try a.print("{s}/private.raw", .{at}),
            forged,
        } },
    ) catch |err| switch (err) {
        error.FileNotFound => return error.SkipZigTest,
        else => return err,
    };
    try t.expect(create.term.success());
    const expected = try tmp.dir.readFileAlloc(t.io, "forged.qcow2", a, .limited(4 << 20));
    var why: howl.Why = .{};
    try copyRaw(t.io, forged, try a.print("{s}/copy.raw", .{at}), &why);
    const copied = try tmp.dir.readFileAlloc(t.io, "copy.raw", a, .limited(4 << 20));
    // QEMU rounds a raw image's final sector up to 512 bytes.
    try t.expect(copied.len >= expected.len and copied.len < expected.len + 512);
    try t.expectEqualSlices(u8, expected, copied[0..expected.len]);
    try t.expect(std.mem.allEqual(u8, copied[expected.len..], 0));
    try t.expectEqualSlices(
        u8,
        &secret,
        try tmp.dir.readFileAlloc(t.io, "private.raw", a, .limited(8192)),
    );
}

fn publish(
    io: Io,
    a: A,
    work: []const u8,
    path: []const u8,
    policy: data.Policy,
    service: ?[]const u8,
) !void {
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
    if (!std.fs.path.isAbsolute(disk)) return error.TransferPath;
    if (@import("builtin").os.tag == .freebsd) {
        const root = try @import("bhyve.zig").asRoot(io);
        const result = try std.process.run(a, io, .{
            .argv = try mem.concat(a, []const u8, &.{ root, &.{ "/usr/bin/fstat", "-n", disk } }),
            .stdout_limit = .limited(64 << 10),
            .stderr_limit = .limited(4096),
        });
        if (!result.term.success() or result.stderr.len != 0) return error.TransferStorageInUse;
        try unusedFreebsd(result.stdout);
        return;
    }
    // Linux lsof stats every mount, including unrelated private/FUSE mounts.
    // An inode probe avoids those warnings. Root is required to inspect every
    // process; an unprivileged scan cannot establish that the disk is unused.
    const args: []const []const u8 = if (@import("builtin").os.tag == .linux)
        try mem.concat(
            a,
            []const u8,
            &.{ try @import("firecracker.zig").asRoot(io, a), &.{ "/usr/bin/fuser", "-I", disk } },
        )
    else
        &.{ "lsof", "-Fpcfn", "--", disk };
    const result = try std.process.run(a, io, .{
        .argv = args,
        .stdout_limit = .limited(64 << 10),
        .stderr_limit = .limited(4096),
    });
    if (result.term != .exited or result.term.exited != 1 or
        result.stdout.len != 0 or result.stderr.len != 0)
        return error.TransferStorageInUse;
}

fn unusedFreebsd(output: []const u8) !void {
    const end = mem.findScalar(u8, output, '\n') orelse return error.TransferStorageInUse;
    var columns = mem.tokenizeAny(u8, output[0..end], " \t\r");
    for ([_][]const u8{
        "USER",
        "CMD",
        "PID",
        "FD",
        "DEV",
        "INUM",
        "MODE",
        "SZ|DV",
        "R/W",
        "NAME",
    }) |expected|
        if (!mem.eql(
            u8,
            columns.next() orelse return error.TransferStorageInUse,
            expected,
        )) return error.TransferStorageInUse;
    if (columns.next() != null or mem.trim(u8, output[end + 1 ..], " \t\r\n").len != 0)
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

fn machineRunning(
    io: Io,
    a: A,
    name: []const u8,
    at: []const u8,
    on: howl.Platform,
    why: *howl.Why,
) !bool {
    return switch (on) {
        .lima => try @import("lima.zig").running(io, a, name),
        .aws,
        .gcp,
        .azure,
        => (try @import("data-cloud.zig").state(
            io,
            a,
            name,
            try @import("data-cloud.zig").load(io, a, at, on),
        )).running,
        .bhyve => if (@import("builtin").os.tag == .freebsd)
            try @import("bhyve.zig").supervised(io, a, at) or
                try @import("bhyve.zig").exists(io, a, name)
        else
            error.TransferProvider,
        .qemu, .firecracker => blk: {
            if (on == .firecracker) {
                if (@import("builtin").os.tag != .linux) return error.TransferProvider;
                if (try @import("firecracker.zig").supervised(io, a, at)) break :blk true;
            }
            const text = Dir.cwd().readFileAlloc(
                io,
                try a.print("{s}/{s}.pid", .{ at, if (on == .qemu) "qemu" else "firecracker" }),
                a,
                .limited(64),
            ) catch |err| switch (err) {
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

fn requireStopped(
    io: Io,
    a: A,
    name: []const u8,
    at: []const u8,
    on: howl.Platform,
    why: *howl.Why,
) !void {
    if (try machineRunning(
        io,
        a,
        name,
        at,
        on,
        why,
    )) return why.refuse(
        "{s}: data transfer requires cleanly stopped applications; the offline path refuses " ++
            "running storage",
        .{name},
    );
}

fn storage(io: Io, a: A, name: []const u8, at: []const u8, on: howl.Platform) ![]const u8 {
    return switch (on) {
        .qemu, .bhyve, .firecracker, .aws, .gcp, .azure => a.print("{s}/disk.img", .{at}),
        .lima => @import("lima.zig").storageDisk(
            io,
            a,
            try @import("lima.zig").dir(io, a, name) orelse return error.MissingLimaInstance,
        ),
        else => error.TransferProvider,
    };
}

test "one archive syntax rejects legacy inputs and scope escalation" {
    const t = std.testing;
    const o = try parse(.import, &.{ "target", "backup.tar.zst", "--service", "plex" });
    try t.expectEqualStrings("plex", o.service.?);
    try t.expectError(error.TransferArguments, parse(.import, &.{ "target", "--retry", "abc" }));
    try t.expectError(
        error.TransferArguments,
        parse(.@"export", &.{ "source", "--service", "../plex" }),
    );
    try t.expectError(
        error.TransferArguments,
        parse(.@"export", &.{ "source", "--service", "plex", "--service", "postgres" }),
    );
    try t.expectError(
        error.TransferArguments,
        parse(.import, &.{ "target", "backup", "--output", "elsewhere" }),
    );
    const remote = try parse(
        .@"export",
        &.{ "remote", "--host", "backup.example", "--port", "2222" },
    );
    try t.expectEqual(@as(u16, 2222), remote.port.?);
    try t.expectError(error.TransferArguments, parse(.@"export", &.{ "remote", "--port", "2222" }));
    try t.expectError(
        error.TransferArguments,
        parse(.@"export", &.{ "remote", "--host", "-oProxyCommand=sh" }),
    );
    try t.expectError(
        error.TransferArguments,
        parse(.@"export", &.{ "remote", "--host", "backup.example", "--port", "0" }),
    );
    try t.expectError(
        error.TransferArguments,
        parse(.import, &.{ "target", "backup", "--version", "20261027T000000Z" }),
    );
    try t.expectError(
        error.TransferArguments,
        parse(.import, &.{ "target", "backup", "--with", "../untrusted" }),
    );
}

test "FreeBSD file-use probe requires a complete header and no open files" {
    const header = "USER     CMD          PID   FD  DEV    INUM       MODE SZ|DV R/W NAME\n";
    try unusedFreebsd(header);
    for ([_][]const u8{
        "",
        "USER CMD",
        "USER CMD\n",
        header ++ "root bhyve 123 5 ...\n",
        header ++ "unexpected output\n",
    }) |output|
        try std.testing.expectError(error.TransferStorageInUse, unusedFreebsd(output));
}

test "Linux root inode probe distinguishes held and unused storage" {
    if (@import("builtin").os.tag != .linux or !howl.isRoot()) return error.SkipZigTest;
    const t = std.testing;
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    const held = try tmp.dir.createFile(t.io, "disk.raw", .{});
    var open = true;
    defer if (open) held.close(t.io);
    const path = try tmp.dir.realPathFileAlloc(t.io, "disk.raw", a);
    try t.expectError(error.TransferStorageInUse, requireUnused(t.io, a, path));
    held.close(t.io);
    open = false;
    try requireUnused(t.io, a, path);
}
