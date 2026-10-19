//! Inspect generated secrets and require the live TLS listener to reject plaintext.
const std = @import("std");
const driver = @import("test-driver");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const linux = std.os.linux;

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 4) return error.Usage;
    const ctx = try driver.Run.load(init.io, a, args[3]);
    if (std.mem.eql(u8, args[2], "files")) {
        try scan(init.io, a, "/run/svc/opensearch", false);
        try ctx.result(init.io, args[1], "os-no-plaintext-secrets", true);
        try scan(init.io, a, "/usr/share/opensearch", true);
        try ctx.result(init.io, args[1], "os-no-demo-certificates", true);
    } else if (std.mem.eql(u8, args[2], "plaintext")) {
        try plaintext();
        try ctx.result(init.io, args[1], "os-no-plain-http", true);
    } else return error.Usage;
}

fn scan(io: Io, a: Allocator, root: []const u8, names_only: bool) !void {
    var dir = try Io.Dir.cwd().openDir(io, root, .{ .iterate = true });
    defer dir.close(io);
    var walk = try dir.walk(a);
    defer walk.deinit();
    var count: usize = 0;
    while (try walk.next(io)) |entry| {
        count += 1;
        if (count > 20000) return error.TooManyFiles;
        if (names_only) {
            if (demoCertificate(entry.basename)) return error.DemoCertificate;
        } else if (entry.kind == .file or entry.kind == .sym_link) {
            var attempt: std.heap.ArenaAllocator = .init(a);
            defer attempt.deinit();
            const path = try attempt.allocator().print("{s}/{s}", .{ root, entry.path });
            const bytes = try driver.system.read(io, attempt.allocator(), path);
            if (std.mem.find(u8, bytes, "werewolf-check-pass-1") != null)
                return error.PlaintextPassword;
        }
    }
}

fn demoCertificate(name: []const u8) bool {
    return std.mem.endsWith(u8, name, ".pem") or std.mem.startsWith(u8, name, "esnode") or
        std.mem.startsWith(u8, name, "kirk");
}

fn plaintext() !void {
    const rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return error.Socket;
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    const timeout: linux.timeval = .{ .sec = 5, .usec = 0 };
    if (linux.errno(linux.setsockopt(
        fd,
        linux.SOL.SOCKET,
        linux.SO.RCVTIMEO,
        @ptrCast(&timeout),
        @sizeOf(@TypeOf(timeout)),
    )) != .SUCCESS) return error.SocketTimeout;
    if (linux.errno(linux.setsockopt(
        fd,
        linux.SOL.SOCKET,
        linux.SO.SNDTIMEO,
        @ptrCast(&timeout),
        @sizeOf(@TypeOf(timeout)),
    )) != .SUCCESS) return error.SocketTimeout;
    const address: linux.sockaddr.in = .{
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
        .port = std.mem.nativeToBig(u16, 9200),
    };
    if (linux.errno(linux.connect(fd, @ptrCast(&address), @sizeOf(@TypeOf(address)))) != .SUCCESS)
        return error.Connect;
    const message = "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    const sent = linux.sendto(fd, message, message.len, linux.MSG.NOSIGNAL, null, 0);
    if (linux.errno(sent) != .SUCCESS or sent != message.len) return error.Send;
    var byte: [1]u8 = undefined;
    const got = linux.read(fd, &byte, 1);
    switch (linux.errno(got)) {
        .CONNRESET => {},
        .SUCCESS => if (got != 0) return error.PlaintextResponse,
        else => return error.PlaintextNotRefused,
    }
}

test "reject every legacy demo certificate filename" {
    try std.testing.expect(demoCertificate("root-ca.pem"));
    try std.testing.expect(demoCertificate("esnode-key"));
    try std.testing.expect(demoCertificate("kirk.csr"));
    try std.testing.expect(!demoCertificate("opensearch.yml"));
    try std.testing.expect(!demoCertificate("transport.jar"));
}
