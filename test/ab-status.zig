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
    var anchor: [64]u8 = @splat(0);
    var pcr: [64]u8 = @splat(0);
    var protected = false;
    if (boot.tpm) {
        const key = try tpm.keyAt(io, gpa, "");
        var device = try tpm.Device.open(io);
        defer device.close();
        anchor = std.fmt.bytesToHex(try device.anchor(key), .lower);
        pcr = std.fmt.bytesToHex(try device.pcr11(), .lower);
        protected = tpm.protected(io, gpa, boot.release, "/boot/state");
    }
    const output = try std.json.Stringify.valueAlloc(gpa, .{
        .boot_id = std.mem.trim(u8, try read(io, gpa, "/proc/sys/kernel/random/boot_id"), "\n"),
        .release = std.mem.trim(u8, try read(io, gpa, "/usr/share/werewolf/ab-release"), "\n"),
        .release_id = if (boot.release) |release| &std.fmt.bytesToHex(release, .lower) else "",
        .slot = if (boot.slot) |s| @tagName(s) else "",
        .root_hash = &hash,
        .verified_root = verified_root,
        .ipe = ipe.enforced(policy, active, enforce),
        .secure_boot = on.len == 5 and on[4] == 1 and setup.len == 5 and setup[4] == 0,
        .committed = exists(io, "/run/werewolf/committed"),
        .rollback_protected = protected,
        .tpm_anchor = if (boot.tpm) anchor[0..] else "",
        .pcr11 = if (boot.tpm) pcr[0..] else "",
    }, .{});
    try std.Io.File.stdout().writeStreamingAll(io, output);
    try std.Io.File.stdout().writeStreamingAll(io, "\n");
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
