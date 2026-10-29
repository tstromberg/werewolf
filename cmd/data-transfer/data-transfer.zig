//! Private transfer workers. A launcher supplies a bounded policy and an
//! already-open data directory by descriptor number. No argument is a path.
//! The read worker emits tar to its inherited compressor pipe; installation
//! consumes the compressed archive. This executable has no setuid/file caps.
const std = @import("std");
const data = @import("data-transfer");
const sandbox = @import("sandbox");
const seal = @import("seal");
const linux = std.os.linux;
const Io = std.Io;
const Dir = Io.Dir;
const File = Io.File;
const Allocator = std.mem.Allocator;

pub const reader_id: u32 = 78;
pub const Request = data.WorkerRequest;

pub fn main(init: std.process.Init) void {
    var threaded: Io.Threaded = .init_single_threaded;
    threaded.allocator = init.arena.allocator();
    defer threaded.deinit();
    var synchronous = init;
    synchronous.io = threaded.io();
    run(synchronous) catch |err| {
        // Archive content and source names never reach diagnostics.
        var buf: [256]u8 = undefined;
        var out = File.stderr().writerStreaming(init.io, &buf);
        out.interface.print("data-transfer: {s}\n", .{@errorName(err)}) catch {};
        out.interface.flush() catch {};
        std.process.exit(1);
    };
}

fn run(init: std.process.Init) !void {
    sandbox.tieTo(linux.getppid());
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len < 4 or args.len > 5) return error.TransferInvocation;
    const mode = std.meta.stringToEnum(enum { read, install, decode, @"install-session", @"decode-session" }, args[1]) orelse
        return error.TransferInvocation;
    if ((mode == .@"install-session") != (args.len == 5)) return error.TransferInvocation;
    const control_fd = try descriptor(args[2]);
    const root_fd = try descriptor(args[3]);
    if (control_fd == root_fd) return error.TransferInvocation;
    const guard_fd = if (args.len == 5) try descriptor(args[4]) else root_fd;
    if (args.len == 5 and (guard_fd == control_fd or guard_fd == root_fd)) return error.TransferInvocation;
    const control: File = .{ .handle = control_fd, .flags = .{ .nonblocking = false } };
    var buf: [4096]u8 = undefined;
    var reader = control.reader(init.io, &buf);
    const bytes = try reader.interface.allocRemaining(a, .limited(1 << 20));
    const request = try parse(a, bytes);
    const root: Dir = .{ .handle = root_fd };
    if ((try root.stat(init.io)).kind != .directory) return error.TransferInvocation;
    switch (mode) {
        .read => {
            control.close(init.io);
            const confined_root = try @import("data-read").confine(
                init.io,
                root,
                request.service,
                .{},
            );
            const owners: data.Ownership = .{ .get = data.metadata.owner };
            const manifest = try data.scan(
                init.io,
                a,
                confined_root,
                request.policy,
                request.service,
                owners,
            );
            var output_buffer: [64 << 10]u8 = undefined;
            var output = File.stdout().writerStreaming(init.io, &output_buffer);
            _ = try data.emit(
                init.io,
                a,
                confined_root,
                manifest,
                request.policy,
                owners,
                &output.interface,
            );
            try output.interface.flush();
        },
        .install, .@"install-session" => {
            const session_mode = mode == .@"install-session";
            var session = try data.install.Session.init(init.io, root);
            defer session.deinit(init.io);
            try (File{
                .handle = session.stage.handle,
                .flags = .{ .nonblocking = false },
            }).setOwner(init.io, reader_id, reader_id);
            session.state.deleteFile(
                init.io,
                "decoded",
            ) catch |err| if (err != error.FileNotFound) return err;
            const decoded = try session.state.createFile(
                init.io,
                "decoded",
                .{ .read = true, .exclusive = true, .permissions = .fromMode(0o600) },
            );
            defer decoded.close(init.io);
            defer session.state.deleteFile(init.io, "decoded") catch {};
            var env: std.process.Environ.Map = .init(a);
            var child = try std.process.spawn(init.io, .{
                .argv = &.{
                    "/usr/lib/werewolf/data-transfer",
                    "decode",
                    try a.print("{d}", .{control.handle}),
                    try a.print("{d}", .{session.stage.handle}),
                },
                .environ_map = &env,
                .stdin = .{ .file = File.stdin() },
                .stdout = .pipe,
                .stderr = .inherit,
                .inherit_files = &.{control},
                .inherit_dirs = &.{session.stage},
            });
            defer child.kill(init.io);
            const pipe = child.stdout.?;
            child.stdout = null;
            defer pipe.close(init.io);
            control.close(init.io);
            try sandbox.closeExcept(&.{
                root.handle,
                session.machine.handle,
                session.state.handle,
                session.lock.handle,
                session.stage.handle,
                decoded.handle,
                pipe.handle,
            });
            try sandbox.keepOnly(
                (1 << linux.CAP.CHOWN) | (1 << linux.CAP.DAC_OVERRIDE) | (1 << linux.CAP.FOWNER),
            );
            try sandbox.landlock(
                &.{.{ .fd = root.handle, .access = sandbox.own_dir | sandbox.refer }},
                &.{},
            );
            var filter: [seal.max_filter]seal.Filter = undefined;
            _ = try seal.install(
                seal.buildFilter(&filter, .initMany(&.{ .stdio, .rpath, .wpath, .proc }), true),
                false,
            );
            // The decoder never receives a machine-state file descriptor.
            // Drain its pipe with a hard byte limit before parsing records.
            var transfer_buffer: [64 << 10]u8 = undefined;
            var count: usize = 0;
            while (true) {
                const n = pipe.readStreaming(
                    init.io,
                    &.{&transfer_buffer},
                ) catch |err| switch (err) {
                    error.EndOfStream => break,
                    else => return err,
                };
                if (n == 0) break;
                if (n > data.limits.manifest - count) return error.TransferLimit;
                try decoded.writeStreamingAll(init.io, transfer_buffer[0..n]);
                count += n;
            }
            const status = try child.wait(init.io);
            if (!status.success()) return error.TransferDecode;
            try (File{ .handle = session.stage.handle, .flags = .{ .nonblocking = false } }).setOwner(init.io, 0, 0);
            var input_buffer: [4096]u8 = undefined;
            var input = decoded.reader(init.io, &input_buffer);
            const result = try data.protocol.read(
                a,
                &input.interface,
                request.policy,
                request.service,
            );
            try session.publish(
                init.io,
                a,
                result,
                request.policy,
                .{ .target = request.target, .service = request.service },
            );
        },
        .decode, .@"decode-session" => {
            control.close(init.io);
            try confineDecoderMode(root, mode == .@"decode-session");
            var input_buffer: [64 << 10]u8 = undefined;
            var input = File.stdin().readerStreaming(init.io, &input_buffer);
            const result = try data.install.decode(
                init.io,
                a,
                &input.interface,
                root,
                request.policy,
                request.service,
            );
            var output_buffer: [4096]u8 = undefined;
            var output = File.stdout().writerStreaming(init.io, &output_buffer);
            try data.protocol.write(&output.interface, result);
        },
    }
}

fn descriptor(text: []const u8) !i32 {
    if (text.len == 0 or text.len > 6) return error.TransferInvocation;
    const fd = std.fmt.parseUnsigned(u20, text, 10) catch return error.TransferInvocation;
    if (fd < 3) return error.TransferInvocation;
    return @intCast(fd);
}

pub fn parse(a: Allocator, bytes: []const u8) !Request {
    if (bytes.len > 1 << 20) return error.TransferLimit;
    const r = try std.json.parseFromSliceLeaky(Request, a, bytes, .{});
    if (r.version != 1 or r.target.len == 0 or r.target.len > 256 or
        r.policy.services.len > 4096 or r.policy.users.len > 8192 or r.policy.groups.len > 8192)
        return error.TransferInvocation;
    if (r.service) |s| if (!r.policy.serviceAllowed(s)) return error.TransferService;
    for (r.policy.services) |name| if (!data.validName(name)) return error.TransferService;
    for ([_][]const data.Identity{ r.policy.users, r.policy.groups }) |identities| {
        var names: std.StringHashMapUnmanaged(void) = .empty;
        defer names.deinit(a);
        var ids: std.AutoHashMapUnmanaged(u32, void) = .empty;
        defer ids.deinit(a);
        for (identities) |id| {
            if (!data.validIdentity(id.name)) return error.TransferOwner;
            const name = try names.getOrPut(a, id.name);
            const number = try ids.getOrPut(a, id.id);
            if (name.found_existing or number.found_existing) return error.TransferOwner;
        }
    }
    // check also validates image, architecture and exclusions without reading data.
    try data.check(
        a,
        .{ .image = r.policy.image, .arch = r.policy.arch, .entries = &.{} },
        r.policy,
        null,
    );
    return r;
}

fn confineDecoderMode(root: Dir, session: bool) !void {
    try sandbox.closeExcept(&.{root.handle});
    try sandbox.limit(.FSIZE, data.limits.file_bytes);
    try sandbox.limit(.AS, 1 << 30);
    try sandbox.dropTo(reader_id, null);
    try sandbox.landlock(
        &.{.{ .fd = root.handle, .access = sandbox.own_dir | sandbox.refer }},
        &.{},
    );
    try @import("data-read").restrictPathMetadata();
    var filter: [seal.max_filter]seal.Filter = undefined;
    _ = try seal.install(
        seal.buildFilter(&filter, .initMany(&.{ .stdio, .rpath, .wpath }), true),
        false,
    );
}

test "worker control policy cannot hide duplicate identities or widen scope" {
    const t = std.testing;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var r: Request = .{
        .target = "destination",
        .policy = .{
            .image = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            .arch = .aarch64,
            .services = &.{"plex"},
            .users = &.{.{ .name = "root", .id = 0 }},
            .groups = &.{.{ .name = "root", .id = 0 }},
        },
    };
    _ = try parse(a, try std.json.Stringify.valueAlloc(a, r, .{}));
    r.service = "../sshd";
    try t.expectError(
        error.TransferService,
        parse(a, try std.json.Stringify.valueAlloc(a, r, .{})),
    );
    r.service = "plex";
    r.policy.users = &.{ .{ .name = "root", .id = 0 }, .{ .name = "other", .id = 0 } };
    try t.expectError(error.TransferOwner, parse(a, try std.json.Stringify.valueAlloc(a, r, .{})));
}

test "Linux decoder and readers enforce filesystem, capability, network and exec boundaries" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    if (linux.geteuid() != 0) return error.SkipZigTest;
    const t = std.testing;
    const io = t.io;
    var tmp = t.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "svc/plex");
    try tmp.dir.createDirPath(io, "svc/plex-media");
    try tmp.dir.createDirPath(io, ".werewolf");
    try tmp.dir.createDirPath(io, "log");
    try tmp.dir.createDir(io, "stage", .fromMode(0o700));
    for ([_][]const u8{
        "svc/plex/content",
        "svc/plex-media/secret",
        ".werewolf/secret",
        "log/secret",
        "public",
    }) |path|
        try tmp.dir.writeFile(
            io,
            .{ .sub_path = path, .data = "x", .flags = .{ .permissions = .fromMode(0o666) } },
        );
    var stage = try tmp.dir.openDir(io, "stage", .{ .iterate = true });
    defer stage.close(io);
    try (File{
        .handle = stage.handle,
        .flags = .{ .nonblocking = false },
    }).setOwner(io, reader_id, reader_id);
    for (0..5) |mode| {
        const pid = try sandbox.sys(linux.fork(), "fork boundary test");
        if (pid == 0) {
            boundaryProbe(io, tmp.dir, stage, mode) catch linux.exit_group(1);
            linux.exit_group(0);
        }
        var status: i32 = 0;
        _ = try sandbox.sys(linux.waitpid(@intCast(pid), &status, 0), "wait boundary test");
        try t.expectEqual(@as(i32, 0), status);
    }
}

fn boundaryProbe(io: Io, root: Dir, stage: Dir, mode: usize) !void {
    if (mode == 4) {
        var done: std.atomic.Value(bool) = .init(false);
        const thread = try std.Thread.spawn(.{}, struct {
            fn run(stop: *std.atomic.Value(bool)) void {
                while (!stop.load(.acquire)) {
                    const delay: linux.timespec = .{ .sec = 0, .nsec = 1_000_000 };
                    _ = linux.nanosleep(&delay, null);
                }
            }
        }.run, .{&done});
        defer {
            done.store(true, .release);
            thread.join();
        }
        if (@import("data-read").confine(io, root, null, .{})) |_|
            return error.PrivilegedThreadAccepted
        else |err| if (err != error.TransferReaderThreads) return err;
        if (linux.geteuid() != 0) return error.Boundary;
        return;
    }
    if (mode == 3) try sandbox.inheritedCapabilities((1 << linux.CAP.DAC_READ_SEARCH) |
        (1 << linux.CAP.SETUID) | (1 << linux.CAP.SETGID));
    const view = if (mode == 0 or mode == 5) blk: {
        if (mode == 5) try sandbox.inheritedCapabilities((1 << linux.CAP.SETUID) | (1 << linux.CAP.SETGID));
        try confineDecoderMode(stage, mode == 5);
        break :blk stage;
    } else try @import("data-read").confine(
        io,
        root,
        if (mode == 1) "plex" else null,
        .{ .session = mode == 3 },
    );
    var header: extern struct { version: u32 = 0x20080522, pid: i32 = 0 } = .{};
    var caps: [2]extern struct { effective: u32, permitted: u32, inheritable: u32 } = undefined;
    _ = try sandbox.sys(
        linux.syscall2(.capget, @intFromPtr(&header), @intFromPtr(&caps)),
        "capget boundary test",
    );
    const permitted: u32 = if (mode == 0) 0 else 1 << linux.CAP.DAC_READ_SEARCH;
    if (linux.geteuid() != reader_id or caps[0].effective != permitted or
        caps[0].permitted != permitted or
        caps[0].inheritable != 0 or caps[1].effective != 0 or
        caps[1].permitted != 0) return error.Boundary;
    if (mode == 0) {
        const fd = try sandbox.sys(
            linux.openat(view.handle, "allowed", .{ .ACCMODE = .RDWR, .CREAT = true }, 0o600),
            "stage write",
        );
        _ = try sandbox.sys(linux.write(@intCast(fd), "x", 1), "stage write");
        _ = linux.close(@intCast(fd));
        try denied(linux.openat(view.handle, "../public", .{ .ACCMODE = .RDWR }, 0));
    } else {
        const fd = try sandbox.sys(
            linux.openat(view.handle, "svc/plex/content", .{ .ACCMODE = .RDONLY }, 0),
            "source read",
        );
        _ = linux.close(@intCast(fd));
        try denied(linux.openat(view.handle, "svc/plex/content", .{ .ACCMODE = .RDWR }, 0));
        try denied(linux.openat(view.handle, ".werewolf/secret", .{ .ACCMODE = .RDONLY }, 0));
        try denied(linux.openat(view.handle, "log/secret", .{ .ACCMODE = .RDONLY }, 0));
        if (mode == 1) try denied(linux.openat(
            view.handle,
            "svc/plex-media/secret",
            .{ .ACCMODE = .RDONLY },
            0,
        ));
    }
    try denied(linux.socket(linux.AF.INET, linux.SOCK.STREAM, 0));
    var bytes: [128]u8 = undefined;
    try denied(linux.getxattr("/outside-stage", "user.secret", &bytes, bytes.len));
    try denied(linux.readlinkat(view.handle, "../outside-stage", &bytes, bytes.len));
    const argv: [1:null]?[*:0]const u8 = .{null};
    try denied(linux.execve("/no-execution", &argv, &argv));
}

fn denied(rc: usize) !void {
    switch (linux.errno(rc)) {
        .ACCES, .PERM, .NOSYS => {},
        else => return error.Boundary,
    }
}

test "SSH publisher installs scoped bytes without SETPCAP or DAC_OVERRIDE" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    if (linux.geteuid() != 0) return error.SkipZigTest;
    const t = std.testing;
    const io = t.io;
    const a = t.allocator;
    var tmp = t.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "source/svc/plex");
    try tmp.dir.createDirPath(io, "target/svc/plex-media");
    var source = try tmp.dir.openDir(io, "source", .{ .iterate = true });
    defer source.close(io);
    var target = try tmp.dir.openDir(io, "target", .{ .iterate = true });
    defer target.close(io);
    try source.writeFile(io, .{ .sub_path = "svc/plex/db", .data = "database", .flags = .{ .permissions = .fromMode(0o600) } });
    var app = try source.openDir(io, "svc/plex", .{ .iterate = true });
    defer app.close(io);
    const app_file: File = .{ .handle = app.handle, .flags = .{ .nonblocking = false } };
    try app_file.setOwner(io, 123, 123);
    try app_file.setPermissions(io, .fromMode(0o2750));
    try target.writeFile(io, .{ .sub_path = "svc/plex-media/movie", .data = "keep" });
    const policy: data.Policy = .{
        .image = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        .arch = .aarch64,
        .services = &.{"plex"},
        .users = &.{ .{ .name = "root", .id = 0 }, .{ .name = "plex", .id = 123 } },
        .groups = &.{ .{ .name = "root", .id = 0 }, .{ .name = "plex", .id = 123 } },
    };
    var arena: std.heap.ArenaAllocator = .init(a);
    defer arena.deinit();
    const alloc = arena.allocator();
    const owners: data.Ownership = .{ .get = data.metadata.owner };
    const manifest = try data.scan(io, alloc, source, policy, "plex", owners);
    var tar: Io.Writer.Allocating = .init(alloc);
    _ = try data.emit(io, alloc, source, manifest, policy, owners, &tar.writer);
    // One raw Zstandard block keeps this test independent of external tools.
    if (tar.written().len > 128 << 10) return error.TransferLimit;
    var frame: [12]u8 = .{ 0x28, 0xb5, 0x2f, 0xfd, 0xa0, 0, 0, 0, 0, 0, 0, 0 };
    std.mem.writeInt(u32, frame[5..9], @intCast(tar.written().len), .little);
    std.mem.writeInt(u24, frame[9..12], (@as(u24, @intCast(tar.written().len)) << 3) | 1, .little);
    const archive = try tmp.dir.createFile(io, "archive", .{ .read = true });
    defer archive.close(io);
    try archive.writeStreamingAll(io, &frame);
    try archive.writeStreamingAll(io, tar.written());
    _ = try sandbox.sys(@intCast(linux.lseek(archive.handle, 0, 0)), "rewind archive");
    try tmp.dir.writeFile(io, .{ .sub_path = "policy", .data = try std.json.Stringify.valueAlloc(alloc, Request{ .target = "online:/data", .policy = policy, .service = "plex" }, .{}) });
    const control = try tmp.dir.openFile(io, "policy", .{});
    defer control.close(io);
    const guard = try tmp.dir.createFile(io, "guard", .{});
    defer guard.close(io);
    const argv = [_:null]?[*:0]const u8{
        "/usr/lib/werewolf/data-transfer",                    "install-session",
        try alloc.printSentinel("{d}", .{control.handle}, 0), try alloc.printSentinel("{d}", .{target.handle}, 0),
        try alloc.printSentinel("{d}", .{guard.handle}, 0),
    };
    for (0..2) |attempt| {
        _ = try sandbox.sys(@intCast(linux.lseek(archive.handle, 0, 0)), "rewind archive retry");
        const pid = try sandbox.sys(linux.fork(), "fork SSH publisher test");
        if (pid == 0) {
            for ([_]u32{ linux.CAP.SETPCAP, linux.CAP.DAC_OVERRIDE }) |cap|
                if (linux.errno(linux.prctl(@backingInt(linux.PR.CAPBSET_DROP), cap, 0, 0, 0)) != .SUCCESS) linux.exit_group(126);
            for ([_]i32{ control.handle, target.handle, guard.handle }) |fd|
                _ = linux.fcntl(fd, linux.F.SETFD, 0);
            _ = linux.dup2(archive.handle, 0);
            const env = [_:null]?[*:0]const u8{};
            _ = linux.execve(argv[0].?, &argv, &env);
            linux.exit_group(127);
        }
        var status: i32 = 0;
        _ = try sandbox.sys(linux.waitpid(@intCast(pid), &status, 0), "wait SSH publisher test");
        if (attempt == 0) try t.expectEqual(@as(i32, 0), status) else try t.expect(status != 0);
        try t.expectError(error.FileNotFound, target.access(io, data.install.state_path ++ "/incoming", .{}));
    }
    try t.expectEqualStrings("database", try target.readFileAlloc(io, "svc/plex/db", alloc, .limited(32)));
    try t.expectEqual(@as(u32, 0o2750), @as(u32, (try target.statFile(io, "svc/plex", .{})).permissions.toMode() & 0o7777));
    try t.expectEqualStrings("keep", try target.readFileAlloc(io, "svc/plex-media/movie", alloc, .limited(32)));
    try t.expect(!try data.install.blocked(io, target));
}
