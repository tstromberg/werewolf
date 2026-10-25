//! Bounded wire inputs only; no broker operations or devices are invoked.
const std = @import("std");
const broker = @import("broker");
const t = std.testing;
const hash = "0000000000000000000000000000000000000000000000000000000000000000";

test "fuzz broker wire parsers" {
    try t.fuzz({}, probe, .{ .corpus = &.{
        "",
        "\x00\xff" ++
            "\n",
        "owner-channel",
        "reboot extra",
        "floor",
        "slot-root k=18446744073709551616:" ++ hash,
        "slot-decl c=" ++ hash ++
            " n=-",
        "slot-meta a=1:" ++ hash ++ " b=2:" ++ hash ++ " c=3:" ++ hash,
        "esp-install k=1:" ++ hash ++ " s=2:" ++ hash ++ " u=- c=3:" ++ hash,
        "ok k=1:" ++ hash ++
            " s=- u=-",
    } });
}

fn probe(_: void, smith: *t.Smith) !void {
    var bytes: [2048]u8 = undefined;
    const input = bytes[0..smith.slice(&bytes)];
    try parse(input);
    // Also mutate a valid request: random bytes alone mostly stop at the
    // operation name and do not exercise artifact sizes, digests or duplicates.
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(input, &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    const artifact: broker.EspArtifact = .{ .size = input.len + 1, .sha256 = &hex };
    var wire: [1024]u8 = undefined;
    const good = try broker.formatEspInstall(
        &wire,
        artifact,
        artifact,
        if (input.len % 2 == 0) artifact else null,
        artifact,
    );
    try parse(good);
    if (input.len > 0) {
        wire[@as(usize, input[0]) % good.len] = input[input.len - 1];
        try parse(wire[0..good.len]);
    }
}

fn parse(input: []const u8) !void {
    _ = broker.parseSlotRoot(input) catch null;
    _ = broker.parseSlotDecl(input) catch null;
    _ = broker.parseSlotMeta(input) catch null;
    _ = broker.parseEspFiles(input) catch null;
    if (broker.parseEspInstall(input)) |request| {
        var out: [1024]u8 = undefined;
        const wire = try broker.formatEspInstall(
            &out,
            request.vmlinuz,
            request.stage0,
            request.uki,
            request.cmdline,
        );
        const again = try broker.parseEspInstall(wire);
        try t.expectEqualDeep(request, again);
    } else |_| {}
}
