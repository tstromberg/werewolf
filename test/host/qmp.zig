//! qmp drives a QEMU monitor for host-side tests, and makes a disk fail its
//! writes with blkdebug, without editing an image or stopping a service.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const json = std.json;

const max_reply = 1 << 20;

/// command runs one QMP operation on the monitor at path and returns its
/// "return". arguments is any value json can write, or null.
pub fn command(
    io: Io,
    gpa: Allocator,
    path: []const u8,
    operation: []const u8,
    arguments: anytype,
) !json.Value {
    const address = try Io.net.UnixAddress.init(path);
    const stream = try address.connect(io);
    defer stream.close(io);
    var in_buf: [max_reply]u8 = undefined;
    var out_buf: [4096]u8 = undefined;
    var reader = stream.reader(io, &in_buf);
    var writer = stream.writer(io, &out_buf);
    const greeting = try reply(gpa, &reader.interface);
    if (greeting != .object or !greeting.object.contains("QMP")) return error.MissingQmpGreeting;
    _ = try exchange(gpa, &reader.interface, &writer.interface, 1, "qmp_capabilities", null);
    return exchange(gpa, &reader.interface, &writer.interface, 2, operation, arguments);
}

fn exchange(
    gpa: Allocator,
    r: *Io.Reader,
    w: *Io.Writer,
    id: u32,
    operation: []const u8,
    arguments: anytype,
) !json.Value {
    if (@TypeOf(arguments) == @TypeOf(null))
        try json.Stringify.value(.{ .execute = operation, .id = id }, .{}, w)
    else
        try json.Stringify.value(
            .{ .execute = operation, .id = id, .arguments = arguments },
            .{},
            w,
        );
    try w.writeByte('\n');
    try w.flush();
    while (true) {
        const response = try reply(gpa, r);
        if (response != .object) return error.BadQmpReply;
        const got = response.object.get("id") orelse continue; // An event.
        if (got != .integer or got.integer != id) continue;
        if (response.object.get("error")) |err| {
            std.log.err("QMP refused {s}: {f}", .{ operation, json.fmt(err, .{}) });
            return error.QmpRefused;
        }
        return response.object.get("return") orelse error.BadQmpReply;
    }
}

fn reply(gpa: Allocator, r: *Io.Reader) !json.Value {
    const line = r.takeDelimiterInclusive('\n') catch |err| switch (err) {
        error.StreamTooLong => return error.OversizedQmpReply,
        else => |e| return e,
    };
    return json.parseFromSliceLeaky(json.Value, gpa, line, .{});
}

/// StorageFault returns EIO for every write to one raw disk until restore.
pub const StorageFault = struct {
    monitor: []const u8,
    root: []const u8,
    file: []const u8,

    const filter = "werewolf-storage-fault";

    /// inject finds the raw node over disk and puts blkdebug beneath it.
    pub fn inject(io: Io, gpa: Allocator, monitor: []const u8, disk: []const u8) !StorageFault {
        const want = try Io.Dir.cwd().realPathFileAlloc(io, disk, gpa);
        const nodes = try command(io, gpa, monitor, "query-named-block-nodes", null);
        if (nodes != .array) return error.BadQmpReply;
        var found: ?StorageFault = null;
        for (nodes.array.items) |node| {
            if (node != .object) continue;
            const drv = node.object.get("drv") orelse continue;
            const file = node.object.get("file") orelse continue;
            if (drv != .string or !std.mem.eql(u8, drv.string, "raw") or file != .string) continue;
            const at = Io.Dir.cwd().realPathFileAlloc(io, file.string, gpa) catch continue;
            if (!std.mem.eql(u8, at, want)) continue;
            if (found != null) return error.AmbiguousBootDisk;
            const name = node.object.get("node-name") orelse return error.BadQmpReply;
            const children = node.object.get("children") orelse return error.BadQmpReply;
            if (name != .string or children != .array) return error.BadQmpReply;
            var child: ?[]const u8 = null;
            for (children.array.items) |c| {
                if (c != .object) continue;
                const role = c.object.get("child") orelse continue;
                const child_name = c.object.get("node-name") orelse continue;
                if (role != .string or child_name != .string or
                    !std.mem.eql(u8, role.string, "file")) continue;
                if (child != null) return error.AmbiguousBootDisk;
                child = child_name.string;
            }
            found = .{
                .monitor = monitor,
                .root = name.string,
                .file = child orelse return error.AmbiguousBootDisk,
            };
        }
        const fault = found orelse return error.NoBootDisk;
        const Inject = struct {
            event: []const u8,
            iotype: []const u8,
            errno: u8,
            once: bool,
            immediately: bool,
        };
        _ = try command(io, gpa, monitor, "blockdev-add", .{
            .driver = "blkdebug",
            .image = fault.file,
            .@"node-name" = filter,
            .@"inject-error" = [_]Inject{.{
                .event = "write_aio",
                .iotype = "write",
                .errno = 5,
                .once = false,
                .immediately = true,
            }},
        });
        try fault.attach(io, gpa, filter);
        return fault;
    }

    pub fn restore(f: StorageFault, io: Io, gpa: Allocator) !void {
        try f.attach(io, gpa, f.file);
        _ = try command(io, gpa, f.monitor, "blockdev-del", .{ .@"node-name" = filter });
    }

    fn attach(f: StorageFault, io: Io, gpa: Allocator, child: []const u8) !void {
        const Node = struct { driver: []const u8, file: []const u8, @"node-name": []const u8 };
        _ = try command(io, gpa, f.monitor, "blockdev-reopen", .{
            .options = [_]Node{.{ .driver = "raw", .file = child, .@"node-name" = f.root }},
        });
    }
};

test "a storage fault fails writes with EIO and restore keeps the same disk" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realPathFileAlloc(io, ".", gpa);
    const disk = try gpa.print("{s}/disk.raw", .{dir});
    const monitor = try gpa.print("{s}/qmp", .{dir});
    try tmp.dir.writeFile(io, .{ .sub_path = "disk.raw", .data = &@as([1 << 20]u8, @splat(0)) });
    const log = try tmp.dir.createFile(io, "qemu.log", .{});
    defer log.close(io);
    const arch = @tagName(@import("builtin").cpu.arch);
    var qemu = try std.process.spawn(io, .{
        .argv = &.{
            try gpa.print(
                "qemu-system-{s}",
                .{arch},
            ),
            "-M",
            "none",
            "-display",
            "none",
            "-qmp",
            try gpa.print(
                "unix:{s},server=on,wait=off",
                .{monitor},
            ),
            "-drive",
            try gpa.print("file={s},format=raw,if=none,node-name=disk-root", .{disk}),
        },
        .stdin = .ignore,
        .stdout = .{ .file = log },
        .stderr = .{ .file = log },
    });
    defer qemu.kill(io);
    for (0..100) |_| {
        if (tmp.dir.access(io, "qmp", .{}))
            break
        else |_|
            try io.sleep(.fromMilliseconds(50), .awake);
    }
    const fault = try StorageFault.inject(io, gpa, monitor, disk);
    const Line = struct { @"command-line": []const u8 };
    _ = try command(
        io,
        gpa,
        monitor,
        "human-monitor-command",
        Line{ .@"command-line" = "qemu-io disk-root \"write -P 0x5a 0 512\"" },
    );
    try std.testing.expectEqualSlices(
        u8,
        &@as([512]u8, @splat(0)),
        (try tmp.dir.readFileAlloc(io, "disk.raw", gpa, .unlimited))[0..512],
    );
    _ = try command(
        io,
        gpa,
        monitor,
        "human-monitor-command",
        Line{ .@"command-line" = "qemu-io disk-root \"read -P 0x00 0 512\"" },
    );
    try fault.restore(io, gpa);
    _ = try command(
        io,
        gpa,
        monitor,
        "human-monitor-command",
        Line{ .@"command-line" = "qemu-io disk-root \"write -P 0xa5 0 512\"" },
    );
    try std.testing.expectEqualSlices(
        u8,
        &@as([512]u8, @splat(0xa5)),
        (try tmp.dir.readFileAlloc(io, "disk.raw", gpa, .unlimited))[0..512],
    );
    _ = try command(io, gpa, monitor, "quit", null);
    _ = try qemu.wait(io);
    const output = try tmp.dir.readFileAlloc(io, "qemu.log", gpa, .unlimited);
    try std.testing.expectEqual(1, std.mem.count(u8, output, "Input/output error"));
    try std.testing.expect(std.mem.find(u8, output, "read 512/512 bytes") != null);
}
