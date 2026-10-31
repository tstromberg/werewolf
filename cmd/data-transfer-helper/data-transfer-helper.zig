//! PID 1 of the disposable, networkless storage helper. Devices have fixed
//! roles: vda is detached source/destination storage, vdb is the owner's
//! private control/transfer disk, vdc is the authenticated source image.
//! No application or code from those disks is ever executed.
const std = @import("std");
const data = @import("data-transfer");
const people = @import("people");
const linux = std.os.linux;
const Io = std.Io;
const Dir = Io.Dir;
const File = Io.File;
const Allocator = std.mem.Allocator;
const mem = std.mem;
var status_port: ?File = null;

pub const Config = struct {
    version: u8 = 1,
    operation: enum { inspect, @"export", import },
    layout: enum { volume, boot },
    image: []const u8,
    verity: @import("verity").Params,
    arch: data.Arch,
    service: ?[]const u8 = null,
    target: []const u8,
    initialize: bool = false,
    users: []const u8 = "",
    nocloud: ?people.NoCloud = null,
    replay_journal_on_copy: bool = false,
};

pub fn main(init: std.process.Init) noreturn {
    const io = init.io;
    const a = init.arena.allocator();
    setup() catch |err| finish(io, err);
    status_port = outputPort(io, a, "werewolf.transfer.status") catch |err| finish(io, err);
    run(io, a) catch |err| finish(io, err);
    _ = linux.sync();
    if (linux.errno(linux.umount2("/volume", 0)) != .SUCCESS)
        finish(io, error.TransferHelperUnmount);
    finish(io, null);
}

fn setup() !void {
    if (linux.getpid() != 1) return error.TransferHelperPid;
    for ([_][:0]const u8{
        "/dev",
        "/proc",
        "/sys",
        "/run",
        "/tmp",
        "/volume",
        "/control",
        "/image",
    }) |p| {
        const rc = linux.mkdir(p, 0o700);
        if (linux.errno(rc) != .SUCCESS and
            linux.errno(rc) != .EXIST) return error.TransferHelperMount;
    }
    try mount("devtmpfs", "/dev", "devtmpfs", linux.MS.NOSUID, null);
    const console = linux.open("/dev/console", .{ .ACCMODE = .RDWR }, 0);
    if (linux.errno(console) != .SUCCESS) return error.TransferHelperConsole;
    for (0..3) |fd| _ = linux.dup2(@intCast(console), @intCast(fd));
    if (console > 2) _ = linux.close(@intCast(console));
    try mount("proc", "/proc", "proc", linux.MS.NOSUID | linux.MS.NODEV | linux.MS.NOEXEC, null);
    try mount("sysfs", "/sys", "sysfs", linux.MS.NOSUID | linux.MS.NODEV | linux.MS.NOEXEC, null);
    // The control disk never replays a journal or accepts uncommitted requests.
    try mount(
        "/dev/vdb",
        "/control",
        "ext4",
        linux.MS.RDONLY | linux.MS.NOSUID | linux.MS.NODEV | linux.MS.NOEXEC,
        "noload",
    );
}

fn run(io: Io, a: Allocator) !void {
    const bytes = try read(io, a, "/control/request.json", 1 << 20);
    const c = try std.json.parseFromSliceLeaky(Config, a, bytes, .{});
    if (c.version != 1 or c.target.len == 0 or c.target.len > 256 or c.users.len > 1 << 18 or
        (c.replay_journal_on_copy and c.operation != .@"export"))
        return error.TransferControl;
    const native_arch: data.Arch = switch (@import("builtin").cpu.arch) {
        .aarch64 => .aarch64,
        .x86_64 => .x86_64,
        else => return error.TransferArchitecture,
    };
    if (c.arch != native_arch) return error.TransferArchitecture;
    if (!mem.eql(
        u8,
        c.image,
        &std.fmt.bytesToHex(c.verity.root, .lower),
    )) return error.TransferImage;
    const approved_image = try Dir.cwd().openFile(io, "/dev/vdc", .{});
    defer approved_image.close(io);
    try @import("verity").verify(a, io, approved_image, c.verity);
    try mount(
        "/dev/vdc",
        "/image",
        "erofs",
        linux.MS.RDONLY | linux.MS.NOSUID | linux.MS.NODEV | linux.MS.NOEXEC,
        null,
    );
    if (c.operation == .import) {
        var image_dir = try Dir.cwd().openDir(io, "/image", .{});
        defer image_dir.close(io);
        try data.images.requireBarrier(io, image_dir);
    }
    const device: [:0]const u8 = if (c.layout == .boot) "/dev/vda2" else "/dev/vda";
    const source = try unlock(io, a, device, c.operation != .import and !c.replay_journal_on_copy);
    if (c.operation != .import) cleanExt4(io, source) catch |err| {
        if (err != error.TransferUnclean or !c.replay_journal_on_copy) return err;
        // Only the owner's detached private copy is writable. A read-only
        // mount permits the kernel to replay its journal, then we unmount and
        // demand clean metadata before the ordinary noload reader mount.
        try mount(
            source,
            "/volume",
            "ext4",
            linux.MS.RDONLY | linux.MS.NOSUID | linux.MS.NODEV | linux.MS.NOEXEC,
            null,
        );
        if (linux.errno(linux.umount2(
            "/volume",
            0,
        )) != .SUCCESS) return error.TransferHelperUnmount;
        try cleanExt4(io, source);
        try File.stderr().writeStreamingAll(
            io,
            "replayed filesystem journal on private export copy\n",
        );
    };
    try mount(source, "/volume", "ext4", linux.MS.NOSUID | linux.MS.NODEV | linux.MS.NOEXEC |
        linux.MS.NOATIME | 256 |
        @as(
            u32,
            if (c.operation == .import) 0 else linux.MS.RDONLY,
        ), if (c.operation == .import) null else "noload");
    errdefer {
        _ = linux.sync();
        _ = linux.umount2("/volume", 0);
    }
    const path: []const u8 = if (c.layout == .boot) "/volume/data" else "/volume";
    if (c.operation == .import and
        c.initialize) Dir.cwd().createDir(io, path, .fromMode(0o755)) catch |err|
        if (err != error.PathAlreadyExists) return err;
    var root = try Dir.cwd().openDir(io, path, .{ .iterate = true, .follow_symlinks = false });
    defer root.close(io);
    var initialize = false;
    if (c.layout == .boot) {
        // Every installed fallback must enforce the same barrier and image
        // identity. Refuse mixed slots rather than guessing firmware's choice.
        var slots = try Dir.cwd().openDir(
            io,
            "/volume/slot",
            .{ .iterate = true, .follow_symlinks = false },
        );
        defer slots.close(io);
        var it = slots.iterate();
        var count: usize = 0;
        while (try it.next(io)) |entry| {
            if (!mem.eql(u8, entry.name, "a") and
                !mem.eql(u8, entry.name, "b")) return error.TransferImage;
            var slot = try slots.openDir(io, entry.name, .{ .follow_symlinks = false });
            defer slot.close(io);
            const file = try data.openRegular(io, slot, "root.erofs");
            defer file.close(io);
            try @import("verity").verify(a, io, file, c.verity);
            count += 1;
        }
        if (count == 0) return error.TransferImage;
    } else data.images.requireRecorded(io, root, c.image) catch |err| {
        if (err != error.TransferImageUnrecorded or c.operation != .import or
            !c.initialize or !try people.freshData(root.handle)) return err;
        initialize = true;
    };
    if (c.layout == .boot and c.operation == .import and c.initialize) {
        data.images.requireRecorded(io, root, c.image) catch |err| {
            if (err != error.TransferImageUnrecorded or
                !try people.freshData(root.handle)) return err;
            initialize = true;
        };
    }
    // A verified boot slot alone does not prove this directory was the
    // running image's /data. Require init's independent data-volume record.
    if (c.operation != .import) try data.images.requireRecorded(io, root, c.image);
    var image_dir = try Dir.cwd().openDir(io, "/image", .{});
    defer image_dir.close(io);
    const policy = try @import("data-source").catalog(
        io,
        a,
        image_dir,
        root,
        .{ .image = c.image, .arch = c.arch, .users = c.users, .nocloud = c.nocloud },
        initialize,
    );
    if (initialize) try data.images.record(io, root, c.image);
    if (c.service) |s| if (!policy.serviceAllowed(s)) return error.TransferService;
    // A dedicated private port avoids interleaving kernel log output with the
    // bounded protocol. It carries public identity metadata, never keys/data.
    const text = try std.json.Stringify.valueAlloc(a, policy, .{});
    try status_port.?.writeStreamingAll(
        io,
        try a.print("werewolf-transfer-policy: {s}\n", .{text}),
    );
    switch (c.operation) {
        .inspect => {},
        .@"export" => {
            if (c.service == null or
                mem.eql(
                    u8,
                    c.service.?,
                    "postgres",
                )) try @import("data-source").cleanPostgres(io, a, root, false);
            try archive(
                io,
                a,
                root,
                .{ .policy = policy, .service = c.service, .target = c.target },
            );
        },
        .import => {
            const archive_file = try Dir.cwd().openFile(io, "/control/archive.tar.zst", .{});
            defer archive_file.close(io);
            const target = try data.install.targetIdentity(io, root);
            const request: data.WorkerRequest = .{
                .policy = policy,
                .service = c.service,
                .target = &target,
            };
            try Dir.cwd().writeFile(
                io,
                .{
                    .sub_path = "/run/worker.json",
                    .data = try std.json.Stringify.valueAlloc(a, request, .{}),
                    .flags = .{ .permissions = .fromMode(0o600) },
                },
            );
            const control = try Dir.cwd().openFile(io, "/run/worker.json", .{});
            defer control.close(io);
            var env: std.process.Environ.Map = .init(a);
            var child = try std.process.spawn(io, .{
                .argv = &.{
                    "/usr/lib/werewolf/data-transfer",
                    "install",
                    try a.print("{d}", .{control.handle}),
                    try a.print("{d}", .{root.handle}),
                },
                .environ_map = &env,
                .stdin = .{ .file = archive_file },
                .stdout = .ignore,
                .stderr = .inherit,
                .inherit_files = &.{control},
                .inherit_dirs = &.{root},
            });
            defer child.kill(io);
            const status = try child.wait(io);
            if (status != .exited or status.exited != 0) return error.TransferInstall;
        },
    }
}

fn mount(
    device: [*:0]const u8,
    point: [*:0]const u8,
    kind: [*:0]const u8,
    flags: u32,
    options: ?[*:0]const u8,
) !void {
    if (linux.errno(linux.mount(
        device,
        point,
        kind,
        flags,
        if (options) |p| @intFromPtr(p) else 0,
    )) != .SUCCESS)
        return error.TransferHelperMount;
}

fn read(io: Io, a: Allocator, path: []const u8, limit: usize) ![]const u8 {
    return Dir.cwd().readFileAlloc(io, path, a, .limited(limit));
}

fn unlock(io: Io, a: Allocator, path: [:0]const u8, readonly: bool) ![:0]const u8 {
    const file = try Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    var magic: [6]u8 = undefined;
    if (try file.readPositionalAll(io, &magic, 0) != magic.len) return error.TransferDevice;
    if (!mem.eql(u8, &magic, "LUKS\xba\xbe")) return path;
    var env: std.process.Environ.Map = .init(a);
    try env.put("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
    const argv: []const []const u8 = if (readonly)
        &.{
            "/usr/sbin/cryptsetup",
            "open",
            "--readonly",
            "--batch-mode",
            "--key-file",
            "/control/key",
            path,
            "transfer",
        }
    else
        &.{
            "/usr/sbin/cryptsetup",
            "open",
            "--batch-mode",
            "--key-file",
            "/control/key",
            path,
            "transfer",
        };
    var child = try std.process.spawn(
        io,
        .{
            .argv = argv,
            .environ_map = &env,
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = .ignore,
        },
    );
    defer child.kill(io);
    const term = try child.wait(io);
    if (term != .exited or term.exited != 0) return error.TransferKey;
    return "/dev/mapper/transfer";
}

fn cleanExt4(io: Io, path: []const u8) !void {
    const file = try Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    var super: [1024]u8 = undefined;
    if (try file.readPositionalAll(io, &super, 1024) != super.len) return error.TransferFilesystem;
    if (mem.readInt(u16, super[0x38..0x3a], .little) != 0xef53) return error.TransferFilesystem;
    if (mem.readInt(u16, super[0x3a..0x3c], .little) & 2 != 0) return error.TransferFilesystem;
    if (mem.readInt(u16, super[0x3a..0x3c], .little) & 3 != 1 or
        mem.readInt(u32, super[0x60..0x64], .little) & 4 != 0) return error.TransferUnclean;
}

fn archive(io: Io, a: Allocator, root: Dir, request: data.WorkerRequest) !void {
    try Dir.cwd().writeFile(
        io,
        .{
            .sub_path = "/run/worker.json",
            .data = try std.json.Stringify.valueAlloc(a, request, .{}),
            .flags = .{ .permissions = .fromMode(0o600) },
        },
    );
    const control = try Dir.cwd().openFile(io, "/run/worker.json", .{});
    defer control.close(io);
    const output = try outputPort(io, a, "werewolf.transfer");
    defer output.close(io);
    var env: std.process.Environ.Map = .init(a);
    var compressor = try std.process.spawn(io, .{
        .argv = &.{ "/usr/lib/werewolf/data-transfer-tool", "compress" },
        .environ_map = &env,
        .stdin = .pipe,
        .stdout = .{ .file = output },
        .stderr = .inherit,
    });
    defer compressor.kill(io);
    const pipe = compressor.stdin.?;
    compressor.stdin = null;
    var child = std.process.spawn(io, .{
        .argv = &.{
            "/usr/lib/werewolf/data-transfer",
            "read",
            try a.print("{d}", .{control.handle}),
            try a.print("{d}", .{root.handle}),
        },
        .environ_map = &env,
        .stdin = .ignore,
        .stdout = .{ .file = pipe },
        .stderr = .inherit,
        .inherit_files = &.{control},
        .inherit_dirs = &.{root},
    }) catch |err| {
        pipe.close(io);
        return err;
    };
    pipe.close(io);
    defer child.kill(io);
    const status = try child.wait(io);
    const compression = try compressor.wait(io);
    if (status != .exited or status.exited != 0) return error.TransferRead;
    if (compression != .exited or compression.exited != 0) return error.TransferCompression;
}

fn outputPort(io: Io, a: Allocator, wanted: []const u8) !File {
    // The virtio device index depends on the block devices enumerated before
    // it. Resolve the fixed channel name in trusted sysfs, not a guessed index.
    var ports = try Dir.cwd().openDir(io, "/sys/class/virtio-ports", .{ .iterate = true });
    defer ports.close(io);
    var chosen: ?[]const u8 = null;
    var it = ports.iterate();
    while (try it.next(io)) |entry| {
        if (!mem.startsWith(u8, entry.name, "vport") or
            entry.name.len > 32) return error.TransferPort;
        for (entry.name[5..]) |c| if (!std.ascii.isDigit(c) and c != 'p') return error.TransferPort;
        const name = try ports.readFileAlloc(
            io,
            try a.print("{s}/name", .{entry.name}),
            a,
            .limited(128),
        );
        if (!mem.eql(u8, mem.trim(u8, name, "\n"), wanted)) continue;
        if (chosen != null) return error.TransferPort;
        chosen = try a.dupe(u8, entry.name);
    }
    return Dir.cwd().openFile(
        io,
        try a.print("/dev/{s}", .{chosen orelse return error.TransferPort}),
        .{ .mode = .write_only },
    );
}

fn finish(io: Io, err: ?anyerror) noreturn {
    var buf: [256]u8 = undefined;
    var out = (status_port orelse File.stdout()).writerStreaming(io, &buf);
    if (err) |e|
        out.interface.print("werewolf-transfer-error: {s}\n", .{@errorName(e)}) catch {}
    else
        out.interface.writeAll("werewolf-transfer-complete\n") catch {};
    out.interface.flush() catch {};
    _ = linux.sync();
    _ = linux.reboot(.MAGIC1, .MAGIC2, .POWER_OFF, null);
    while (true) _ = linux.pause();
}
