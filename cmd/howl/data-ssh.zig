//! Streaming, pinned SSH transfers. No guest installation, firewall change,
//! command interpreter or host filesystem extraction is involved.
const std = @import("std");
const howl = @import("howl.zig");
const cloud = @import("data-cloud.zig");
const data = @import("data-transfer");
const Io = std.Io;
const Dir = Io.Dir;
const A = std.mem.Allocator;
pub const Endpoint = struct { host: []const u8, port: u16 = 22 };

/// Send an archive over an authenticated, pinned connection. The guest's
/// confined decoder validates it against the destination's own policy.
pub fn restore(
    io: Io,
    a: A,
    name: []const u8,
    at: []const u8,
    on: howl.Platform,
    service: ?[]const u8,
    identity: ?[]const u8,
    archive: []const u8,
    why: *howl.Why,
) !void {
    const port = switch (on) {
        .qemu => @import("qemu.zig").record(
            io,
            a,
            at,
            "ssh",
        ) orelse return error.TransferSshAddress,
        .lima => @import("lima.zig").sshPort(io, a, name) orelse return error.TransferSshAddress,
        .aws, .gcp, .azure, .firecracker => "22",
        else => return error.TransferProvider,
    };
    if (try std.fmt.parseUnsigned(u16, port, 10) == 0) return error.TransferSshAddress;
    const host = if (cloud.supported(on))
        try cloud.address(io, a, name, try cloud.load(io, a, at, on))
    else if (on == .firecracker)
        (try @import("firecracker.zig").net(a, name)).guest
    else
        "127.0.0.1";
    if (!howl.isIp4(host)) return error.TransferSshAddress;
    const known = try a.print("{s}/known_hosts", .{at});
    const pin = try std.process.run(a, io, .{
        .argv = &.{ "ssh-keygen", "-F", name, "-f", known },
        .stdout_limit = .limited(64 << 10),
        .stderr_limit = .limited(4096),
    });
    if (!pin.term.success() or pin.stdout.len == 0) return why.refuse(
        "{s}: transfer requires an existing host key pin in {s}",
        .{ name, known },
    );
    var args: std.ArrayList([]const u8) = .empty;
    try args.appendSlice(a, &.{
        "ssh",
        "-F",
        "/dev/null",
        "-S",
        "none",
        "-T",
        "-a",
        "-p",
        port,
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "GlobalKnownHostsFile=/dev/null",
        "-o",
        try a.print("UserKnownHostsFile={s}", .{known}),
        "-o",
        try a.print("HostKeyAlias={s}", .{name}),
        "-o",
        "Compression=no",
        "-o",
        "ClearAllForwardings=yes",
        "-o",
        "ConnectTimeout=15",
        "-o",
        "ServerAliveInterval=30",
        "-o",
        "ServerAliveCountMax=3",
        "-o",
        "LogLevel=ERROR",
    });
    if (identity) |path| {
        try args.appendSlice(a, &.{ "-i", path, "-o", "IdentitiesOnly=yes" });
    } else if (howl.environ.get("HOME")) |home| {
        for (try @import("keys.zig").securityIdentities(
            io,
            a,
            try a.print("{s}/.ssh", .{home}),
        )) |path|
            try args.appendSlice(a, &.{ "-i", path });
    }
    try args.appendSlice(a, &.{ try a.print("root@{s}", .{host}), "import-v1" });
    if (service) |name_of_service| try args.append(a, name_of_service);
    const input = try Dir.cwd().openFile(io, archive, .{});
    defer input.close(io);
    if ((try input.stat(io)).kind != .file) return error.TransferFileType;
    var child = try std.process.spawn(io, .{
        .argv = args.items,
        .stdin = .{ .file = input },
        .stdout = .inherit,
        .stderr = .inherit,
    });
    defer child.kill(io);
    const Event = union(enum) {
        done: anyerror!std.process.Child.Term,
        deadline: Io.Cancelable!void,
    };
    var events: [2]Event = undefined;
    var select = Io.Select(Event).init(io, &events);
    defer select.cancelDiscard();
    try select.concurrent(.done, std.process.Child.wait, .{ &child, io });
    try select.concurrent(.deadline, Io.sleep, .{ io, Io.Duration.fromSeconds(12 * 3600), .awake });
    switch (try select.await()) {
        .done => |result| if (!(try result).success()) return error.TransferSshInstall,
        .deadline => return error.TransferTimeout,
    }
}

pub fn capture(
    io: Io,
    a: A,
    name: []const u8,
    at: []const u8,
    on: howl.Platform,
    service: ?[]const u8,
    identity: ?[]const u8,
    endpoint: ?Endpoint,
    operation: []const u8,
    why: *howl.Why,
) ![]const []const u8 {
    const port = if (endpoint) |e| try a.print("{d}", .{e.port}) else switch (on) {
        .qemu,
        .bhyve,
        => @import("qemu.zig").record(io, a, at, "ssh") orelse return error.TransferSshAddress,
        .lima => @import("lima.zig").sshPort(io, a, name) orelse return error.TransferSshAddress,
        .aws, .gcp, .azure => "22",
        .firecracker => "22",
        else => return error.TransferProvider,
    };
    if (try std.fmt.parseUnsigned(u16, port, 10) == 0) return error.TransferSshAddress;
    const host = if (endpoint) |e| e.host else if (cloud.supported(on))
        try @import("data-cloud.zig").address(
            io,
            a,
            name,
            try @import("data-cloud.zig").load(io, a, at, on),
        )
    else if (on == .firecracker)
        (try @import("firecracker.zig").net(a, name)).guest
    else if (on == .bhyve)
        @import("qemu.zig").record(io, a, at, "host") orelse "127.0.0.1"
    else
        "127.0.0.1";
    if (endpoint == null and !howl.isIp4(host)) return error.TransferSshAddress;
    const known = try a.print("{s}/known_hosts", .{at});
    const pin = try std.process.run(a, io, .{
        .argv = &.{ "ssh-keygen", "-F", name, "-f", known },
        .stdout_limit = .limited(64 << 10),
        .stderr_limit = .limited(4096),
    });
    if (!pin.term.success() or pin.stdout.len == 0) return why.refuse(
        "{s}: transfer requires an existing host key pin in {s}",
        .{ name, known },
    );
    var args: std.ArrayList([]const u8) = .empty;
    try args.appendSlice(
        a,
        &.{
            "ssh",
            "-F",
            "/dev/null",
            "-S",
            "none",
            "-T",
            "-a",
            "-p",
            port,
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            try a.print("UserKnownHostsFile={s}", .{known}),
            "-o",
            try a.print("HostKeyAlias={s}", .{name}),
            "-o",
            "Compression=no",
            "-o",
            "ClearAllForwardings=yes",
            "-o",
            "ConnectTimeout=15",
            "-o",
            "ServerAliveInterval=30",
            "-o",
            "ServerAliveCountMax=3",
            "-o",
            "LogLevel=ERROR",
        },
    );
    if (identity) |path| {
        try args.appendSlice(a, &.{ "-i", path, "-o", "IdentitiesOnly=yes" });
    } else if (howl.environ.get("HOME")) |home| {
        for (try @import("keys.zig").securityIdentities(
            io,
            a,
            try a.print("{s}/.ssh", .{home}),
        )) |path|
            try args.appendSlice(a, &.{ "-i", path });
    }
    try args.appendSlice(
        a,
        &.{ try a.print("root@{s}", .{host}), "export-v1" },
    );
    if (service) |name_of_service| try args.append(a, name_of_service);
    return args.toOwnedSlice(a);
}

pub fn restore(
    io: Io,
    a: A,
    name: []const u8,
    at: []const u8,
    on: howl.Platform,
    service: ?[]const u8,
    identity: ?[]const u8,
    endpoint: ?Endpoint,
    archive: []const u8,
    why: *howl.Why,
) !void {
    const args = try arguments(io, a, name, at, on, service, identity, endpoint, "import-v1", why);
    const input = try Dir.cwd().openFile(io, archive, .{});
    defer input.close(io);
    if ((try input.stat(io)).kind != .file) return error.TransferArguments;
    var child = try std.process.spawn(
        io,
        .{ .argv = args, .stdin = .{ .file = input }, .stdout = .pipe, .stderr = .inherit },
    );
    defer child.kill(io);
    const Event = union(enum) { installed: anyerror!void, deadline: Io.Cancelable!void };
    var events: [2]Event = undefined;
    var select = Io.Select(Event).init(io, &events);
    defer select.cancelDiscard();
    try select.concurrent(.installed, installed, .{ io, &child });
    try select.concurrent(.deadline, Io.sleep, .{ io, Io.Duration.fromSeconds(12 * 3600), .awake });
    switch (try select.await()) {
        .installed => |result| try result,
        .deadline => return error.TransferTimeout,
    }
    howl.say(io, "{s}: import complete; applications remain stopped", .{name});
}

fn installed(io: Io, child: *std.process.Child) !void {
    const pipe = child.stdout.?;
    child.stdout = null;
    defer pipe.close(io);
    var buffer: [128]u8 = undefined;
    var reader = pipe.readerStreaming(io, &buffer);
    const message = "import complete; applications remain stopped\n";
    var response: [message.len]u8 = undefined;
    try reader.interface.readSliceAll(&response);
    if (!std.mem.eql(u8, &response, message)) return error.TransferSshProtocol;
    if (reader.interface.takeByte()) |_|
        return error.TransferSshProtocol
    else |err| if (err != error.EndOfStream)
        return err;
    if (!(try child.wait(io)).success()) return error.TransferSshImport;
}

pub fn capture(
    io: Io,
    a: A,
    name: []const u8,
    at: []const u8,
    on: howl.Platform,
    service: ?[]const u8,
    identity: ?[]const u8,
    endpoint: ?Endpoint,
    work: []const u8,
    why: *howl.Why,
) !data.Policy {
    const args = try arguments(io, a, name, at, on, service, identity, endpoint, "export-v1", why);
    var child = try std.process.spawn(
        io,
        .{ .argv = args, .stdin = .ignore, .stdout = .pipe, .stderr = .inherit },
    );
    defer child.kill(io);
    const output = try Dir.cwd().createFile(io, try a.print("{s}/archive.tar.zst", .{work}), .{
        .exclusive = true,
        .permissions = .fromMode(0o600),
    });
    defer output.close(io);
    const Event = union(enum) { capture: anyerror!data.Policy, deadline: Io.Cancelable!void };
    var events: [2]Event = undefined;
    var select = Io.Select(Event).init(io, &events);
    defer select.cancelDiscard();
    try select.concurrent(.capture, receive, .{ io, a, &child, output });
    try select.concurrent(.deadline, Io.sleep, .{ io, Io.Duration.fromSeconds(12 * 3600), .awake });
    return switch (try select.await()) {
        .capture => |result| try result,
        .deadline => error.TransferTimeout,
    };
}

fn receive(io: Io, a: A, child: *std.process.Child, output: Io.File) !data.Policy {
    const pipe = child.stdout.?;
    child.stdout = null;
    defer pipe.close(io);
    var buffer: [64 << 10]u8 = undefined;
    var input = pipe.readerStreaming(io, &buffer);
    var greeting: [10]u8 = undefined;
    try input.interface.readSliceAll(&greeting);
    if (!std.mem.eql(u8, &greeting, "WWEXPORT1\n")) return error.TransferSshProtocol;
    var length: [4]u8 = undefined;
    try input.interface.readSliceAll(&length);
    const size = std.mem.readInt(u32, &length, .big);
    if (size == 0 or size > 1 << 20) return error.TransferSshProtocol;
    const text = try a.alloc(u8, size);
    defer a.free(text);
    try input.interface.readSliceAll(text);
    const policy = try std.json.parseFromSliceLeaky(
        data.Policy,
        a,
        text,
        .{ .allocate = .alloc_always },
    );
    if (policy.services.len > 4096 or policy.users.len > 8192 or policy.groups.len > 8192)
        return error.TransferSshProtocol;
    try data.check(
        a,
        .{ .image = policy.image, .arch = policy.arch, .entries = &.{} },
        policy,
        null,
    );
    var bytes: [64 << 10]u8 = undefined;
    while (true) {
        const n = try input.interface.readSliceShort(&bytes);
        if (n == 0) break;
        try output.writeStreamingAll(io, bytes[0..n]);
    }
    // A complete compression frame alone does not prove writers stayed down.
    // The authenticated SSH exit status follows the reader's final checks.
    if (!(try child.wait(io)).success()) return error.TransferSshCapture;
    try output.sync(io);
    return policy;
}
