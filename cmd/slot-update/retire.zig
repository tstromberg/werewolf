//! Authenticate and journal machine-specific retirement before inactive-slot writes.
const std = @import("std");
const tpm = @import("tpm");
const apk = @import("apk");
const m = @import("slot-update.zig");

pub fn identity(image: @import("prebuilt").Manifest) ![32]u8 {
    var hashes: [3][32]u8 = undefined;
    for ([3][]const u8{
        image.files.@"root.erofs".sha256,
        image.files.vmlinuz.sha256,
        image.files.@"stage0.zst".sha256,
    }, 0..) |text, i|
        _ = try std.fmt.hexToBytes(&hashes[i], text);
    var context: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&context, image.boot_context orelse return error.MissingBootContext);
    return tpm.releaseId(image.arch, hashes[0], hashes[1], hashes[2], context);
}

pub const Prepared = struct {
    device: tpm.Device,
    key: apk.Key,
    record: tpm.Record,
    signature: []const u8,
    completed: bool,

    pub fn close(p: *Prepared) void {
        p.device.close();
    }

    pub fn apply(p: *Prepared) !void {
        if (!p.completed) try p.device.retire(p.key, p.record, p.signature);
    }
};

pub fn prepare(u: *m.Update, victim: []const u8) !?Prepared {
    const running = u.cmd.release orelse return null;
    const image = u.image orelse return error.TpmNeedsSignedImage;
    const candidate = try identity(image.manifest);
    const binary = try std.Io.Dir.cwd().readFileAlloc(
        u.io,
        m.work_dir ++ "/slot/uki.efi",
        u.gpa,
        .limited(512 << 20),
    );
    const line = try @import("uki").section(binary, ".cmdline") orelse return error.BadCmdline;
    var bad: @import("cmdline").Failure = .{};
    const parsed = @import("cmdline").parse(std.mem.trimEnd(u8, line, "\x00"), &bad) orelse
        return error.BadCmdline;
    if (!parsed.tpm or parsed.release == null or
        !std.mem.eql(u8, &parsed.release.?, &candidate)) return error.WrongReleaseIdentity;
    const key = try tpm.keyAt(u.io, u.gpa, "");
    var device = try tpm.Device.open(u.io);
    errdefer device.close();
    const directory = try u.gpa.print("{s}{s}/boot-state", .{ victim, u.cmd.victim.?.path });
    const old = try tpm.current(u.io, u.gpa, key, directory, try device.anchor(key), running);
    const base = try u.gpa.print("{s}/{s}/permits/{x}/{x}.permit", .{
        image.manifest.channel, image.manifest.arch, &old.record.machine, &candidate,
    });
    const contextual = if (u.read(@import("prebuilt").metadata ++ "/permit-context")) |data|
        std.mem.eql(u8, data, "2\n")
    else |_|
        false;
    const url = if (contextual) try u.gpa.print("{s}?from={x}&retain={x}", .{
        base, &old.record.anchor(), &running,
    }) else base;
    const raw = try u.downloadMax(url, m.work_dir ++ "/boot.permit", tpm.record_size + 512);
    const next = try tpm.bundle(key, raw);
    if (!std.mem.eql(u8, &next.candidate, &candidate) or
        !std.mem.eql(u8, &next.retained, &running)) return error.UnsafeRetirement;
    const completed = std.mem.eql(u8, &old.record.anchor(), &next.anchor());
    if (!completed) {
        try old.record.transition(next, running, try device.pcr11());
        try tpm.publish(u.io, u.gpa, directory, old.position ^ 1, raw);
        _ = try tpm.current(u.io, u.gpa, key, directory, next.anchor(), running);
    }
    return .{
        .device = device,
        .key = key,
        .record = next,
        .signature = raw[tpm.record_size..],
        .completed = completed,
    };
}

pub fn requireOther(u: *m.Update, image: @import("prebuilt").Manifest) !void {
    const running = u.cmd.release orelse return;
    const key = try tpm.keyAt(u.io, u.gpa, "");
    var device = try tpm.Device.open(u.io);
    defer device.close();
    const directory = try u.gpa.print("/victim{s}/boot-state", .{u.cmd.victim.?.path});
    const state = try tpm.current(u.io, u.gpa, key, directory, try device.anchor(key), running);
    if (!state.record.allows(try identity(image))) return error.RollbackRefused;
}
