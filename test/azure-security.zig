//! azure-security reads `az vm show`'s JSON on standard input and exits 0
//! only when the machine is a Trusted Launch VM with Secure Boot and a vTPM
//! on, from a specialized image: no OS profile provisioned it (test/cloud).

const std = @import("std");
const json = std.json;
const Io = std.Io;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();
    var buf: [64 << 10]u8 = undefined;
    var in = Io.File.stdin().readerStreaming(io, &buf);
    const text = try in.interface.allocRemaining(gpa, .limited(1 << 20));
    const value = json.parseFromSliceLeaky(json.Value, gpa, text, .{}) catch std.process.exit(1);
    std.process.exit(if (trusted(value)) 0 else 1);
}

/// trusted is whether vm is Trusted Launch, Secure Boot and vTPM on, with
/// no OS provisioning profile.
fn trusted(vm: json.Value) bool {
    if (vm != .object) return false;
    // "os" must be present and null: a specialized image has no profile.
    const os = vm.object.get("os") orelse return false;
    if (os != .null) return false;
    const security = vm.object.get("security") orelse return false;
    if (security != .object) return false;
    const kind = security.object.get("securityType") orelse return false;
    if (kind != .string or !std.mem.eql(u8, kind.string, "TrustedLaunch")) return false;
    const uefi = security.object.get("uefiSettings") orelse return false;
    if (uefi != .object) return false;
    for ([_][]const u8{ "secureBootEnabled", "vTpmEnabled" }) |flag| {
        const on = uefi.object.get(flag) orelse return false;
        if (on != .bool or !on.bool) return false;
    }
    return true;
}

test "only enforced Trusted Launch on a specialized image passes" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const good =
        \\{"os": null, "security": {"securityType": "TrustedLaunch",
        \\ "uefiSettings": {"secureBootEnabled": true, "vTpmEnabled": true}}}
    ;
    try std.testing.expect(trusted(try json.parseFromSliceLeaky(json.Value, gpa, good, .{})));
    for ([_][]const u8{ "secureBootEnabled", "vTpmEnabled" }) |flag| {
        for ([_][]const u8{ "false", "null", "\"true\"", "1" }) |bad| {
            var altered = try json.parseFromSliceLeaky(json.Value, gpa, good, .{});
            const uefi = altered.object.getPtr("security").?.object.getPtr("uefiSettings").?;
            try uefi.object.put(gpa, flag, try json.parseFromSliceLeaky(json.Value, gpa, bad, .{}));
            try std.testing.expect(!trusted(altered));
        }
    }
    var provisioned = try json.parseFromSliceLeaky(json.Value, gpa, good, .{});
    try provisioned.object.put(gpa, "os", try json.parseFromSliceLeaky(
        json.Value,
        gpa,
        "{\"linuxConfiguration\": {\"ssh\": {\"publicKeys\": []}}}",
        .{},
    ));
    try std.testing.expect(!trusted(provisioned));
    for ([_][]const u8{
        "null",
        "{}",
        "{\"os\": null}",
        "{\"security\": {\"securityType\": \"TrustedLaunch\", \"uefiSettings\": " ++
            "{\"secureBootEnabled\": true, \"vTpmEnabled\": true}}}",
    }) |bad| try std.testing.expect(!trusted(try json.parseFromSliceLeaky(
        json.Value,
        gpa,
        bad,
        .{},
    )));
}
