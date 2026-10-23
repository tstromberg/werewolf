//! Set Blocky's DNS listeners to loopback and the machine's LAN address.
//! service-config has already rendered /tmp/config.yml before leash runs us.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

pub fn main(init: std.process.Init) void {
    const gpa = init.arena.allocator();
    run(init.io, gpa) catch |err| {
        std.debug.print("blocky-bind: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
}

fn run(io: Io, gpa: Allocator) !void {
    const ip = try Dir.cwd().readFileAlloc(
        io,
        "/etc/werewolf-network/service-address",
        gpa,
        .limited(64),
    );
    if (ip.len < 7 or ip.len > 15 or std.mem.startsWith(u8, ip, "127.") or
        std.mem.eql(u8, ip, "0.0.0.0") or std.mem.findScalar(u8, ip, ':') != null)
        return error.NoLanAddress;
    _ = Io.net.IpAddress.parse(ip, 0) catch return error.NoLanAddress;
    const input = try Dir.cwd().readFileAlloc(io, "/tmp/config.yml", gpa, .limited(1 << 20));
    const output = try bindConfig(gpa, input, ip);
    try Dir.cwd().writeFile(io, .{ .sub_path = "/tmp/config.yml", .data = output });
}

fn bindConfig(gpa: Allocator, input: []const u8, ip: []const u8) ![]const u8 {
    const doc = try std.json.parseFromSliceLeaky(std.json.Value, gpa, input, .{});
    if (doc != .object) return error.BadConfig;
    const ports = doc.object.getPtr("ports") orelse return error.BadConfig;
    if (ports.* != .object) return error.BadConfig;
    const dns = ports.object.getPtr("dns") orelse return error.BadConfig;
    dns.* = .{ .string = try gpa.print("127.0.0.1:53,{s}:53", .{ip}) };
    return try std.json.Stringify.valueAlloc(gpa, doc, .{});
}

test "bindConfig keeps the rest of Blocky's config" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const out = try bindConfig(
        gpa,
        "{\"ports\":{\"dns\":53},\"log\":{\"privacy\":true}}",
        "10.0.2.15",
    );
    try std.testing.expect(std.mem.find(u8, out, "127.0.0.1:53,10.0.2.15:53") != null);
    try std.testing.expect(std.mem.find(u8, out, "\"privacy\":true") != null);
}
