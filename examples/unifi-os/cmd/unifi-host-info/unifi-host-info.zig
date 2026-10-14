//! Read-only replacement for the vendor's sudo/ubnt-tools metadata call.
//! It never changes privilege, executes a command or manages the host.
const std = @import("std");
const Io = std.Io;

pub fn main(init: std.process.Init) void {
    run(init.io, init.arena.allocator(), init.minimal.args) catch |err| {
        var buf: [128]u8 = undefined;
        const line = std.mem.print(&buf, "unifi-host-info: {s}\n", .{@errorName(err)}) catch return;
        Io.File.stderr().writeStreamingAll(init.io, line) catch {};
        std.process.exit(126);
    };
}

fn run(io: Io, gpa: std.mem.Allocator, args: std.process.Args) !void {
    const argv = try args.toSlice(gpa);
    if (!metadataCall(argv)) return error.UnsupportedHostAction;
    const uuid = try Io.Dir.cwd().readFileAlloc(io, "/data/unifi-core/uuid", gpa, .limited(64));
    if (!uuidOk(uuid)) return error.BadIdentity;
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(uuid, &digest, .{});
    digest[0] = (digest[0] | 2) & 0xfe;
    const serial = std.fmt.bytesToHex(digest[0..6].*, .lower);
    var output: [512]u8 = undefined;
    const text = try std.mem.print(
        &output,
        "board.sysid=0xae01\nboard.name=UniFi OS Server\nboard.shortname=UOSSERVER\n" ++
            "board.uuid={s}\nboard.hwrev=0x0000\nboard.serialno={s}\n",
        .{ uuid, &serial },
    );
    try Io.File.stdout().writeStreamingAll(io, text);
}

fn metadataCall(argv: []const []const u8) bool {
    if (argv.len != 5) return false;
    return std.mem.eql(u8, argv[1], "-E") and std.mem.eql(u8, argv[2], "-n") and
        std.mem.eql(u8, argv[3], "ubnt-tools") and std.mem.eql(u8, argv[4], "id");
}

fn uuidOk(uuid: []const u8) bool {
    if (uuid.len != 36) return false;
    for (uuid, 0..) |c, i| {
        if (i == 8 or i == 13 or i == 18 or i == 23) {
            if (c != '-') return false;
        } else if (!std.ascii.isHex(c)) return false;
    }
    return true;
}

test "only the fixed read-only metadata call is accepted" {
    try std.testing.expect(metadataCall(&.{ "sudo", "-E", "-n", "ubnt-tools", "id" }));
    try std.testing.expect(!metadataCall(&.{ "sudo", "-E", "-n", "systemctl", "restart" }));
    try std.testing.expect(!metadataCall(&.{ "sudo", "-E", "-n", "ubnt-tools", "upgrade" }));
    try std.testing.expect(uuidOk("12345678-1234-4234-8234-123456789abc"));
    try std.testing.expect(!uuidOk("12345678-1234-4234-8234-123456789ab\n"));
}
