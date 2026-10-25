//! Read boot identity for the provider A/B regression runner.
const std = @import("std");
const cmdline = @import("cmdline");
const ipe = @import("ipe");
const tpm = @import("tpm");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();
    var bad: cmdline.Failure = .{};
    const boot = cmdline.parse(try read(io, gpa, "/proc/cmdline"), &bad) orelse
        return error.BadBootIdentity;
    const on = read(
        io,
        gpa,
        "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c",
    ) catch "";
    const setup = read(
        io,
        gpa,
        "/sys/firmware/efi/efivars/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c",
    ) catch "";
    const mounts = try read(io, gpa, "/proc/mounts");
    var verified_root = false;
    var lines = std.mem.tokenizeScalar(u8, mounts, '\n');
    while (lines.next()) |line| {
        var fields = std.mem.tokenizeScalar(u8, line, ' ');
        const device = fields.next() orelse continue;
        if (!std.mem.eql(u8, fields.next() orelse continue, "/")) continue;
        const fs = fields.next() orelse continue;
        const opts = fields.next() orelse continue;
        verified_root = (std.mem.eql(u8, device, "/dev/mapper/root") or
            std.mem.startsWith(u8, device, "/dev/dm-")) and
            std.mem.eql(u8, fs, "erofs") and std.mem.startsWith(u8, opts, "ro,");
    }
    const policy = read(io, gpa, ipe.policy_path) catch "";
    const active = read(io, gpa, ipe.active) catch "";
    const enforce = read(io, gpa, ipe.base ++ "/enforce") catch "";
    const policy_root = ipe.policyRoot(policy);
    const hash = std.fmt.bytesToHex(policy_root orelse return error.BadIpePolicy, .lower);
    // stage0's record of the floor it admitted this boot at; a root SSH
    // session may not read init's records, so then take posture's at boot.
    var found: ?tpm.Marker = null;
    var cached = false;
    if (boot.channel != null) {
        if (read(io, gpa, tpm.Marker.path)) |text| {
            found = tpm.Marker.parse(text);
        } else |err| switch (err) {
            error.AccessDenied => {
                const saved = try bootReport(io, gpa);
                const state = saved.tpm orelse return error.NoBootTpmState;
                found = .{ .handle = state.handle, .floor = state.floor, .index = state.index };
                cached = true;
            },
            else => return err,
        }
    }
    const protected = if (found) |m|
        tpm.handle(boot.channel.?) == m.handle and boot.index.? == m.index and m.floor <= m.index
    else
        false;
    const output = try std.json.Stringify.valueAlloc(gpa, .{
        .boot_id = std.mem.trim(u8, try read(io, gpa, "/proc/sys/kernel/random/boot_id"), "\n"),
        .release = std.mem.trim(u8, try read(io, gpa, "/usr/share/werewolf/ab-release"), "\n"),
        .channel = if (boot.channel) |channel| &std.fmt.bytesToHex(channel, .lower) else "",
        .index = boot.index orelse 0,
        .slot = if (boot.slot) |s| @tagName(s) else "",
        .root_hash = &hash,
        .verified_root = verified_root,
        .ipe = ipe.enforced(policy, active, enforce),
        .secure_boot = on.len == 5 and on[4] == 1 and setup.len == 5 and setup[4] == 0,
        .committed = exists(io, "/run/werewolf/committed"),
        .rollback_protected = protected,
        .floor = if (found) |m| m.floor else 0,
        .handle = if (found) |m| m.handle else 0,
        .cached = cached,
    }, .{});
    try std.Io.File.stdout().writeStreamingAll(io, output);
    try std.Io.File.stdout().writeStreamingAll(io, "\n");
}

/// BootReport is what ab-status needs of posture's report at boot.
const BootReport = struct {
    tpm: ?struct { handle: u32, floor: u64, index: u64 } = null,
    checks: []const struct { id: []const u8, result: []const u8 },
};

fn bootReport(io: std.Io, gpa: std.mem.Allocator) !BootReport {
    const file = try std.Io.Dir.cwd().openFile(io, "/run/werewolf/posture.json", .{});
    defer file.close(io);
    var buf: [4096]u8 = undefined;
    var r = file.readerStreaming(io, &buf);
    const json = try r.interface.allocRemaining(gpa, .limited(16 << 20));
    return std.json.parseFromSliceLeaky(BootReport, gpa, json, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });
}

fn read(io: std.Io, gpa: std.mem.Allocator, path: []const u8) ![]const u8 {
    const file = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    const data = try gpa.alloc(u8, 32 << 10);
    return data[0..try file.readPositionalAll(io, data, 0)];
}

fn exists(io: std.Io, path: []const u8) bool {
    std.Io.Dir.cwd().access(io, path, .{}) catch return false;
    return true;
}
