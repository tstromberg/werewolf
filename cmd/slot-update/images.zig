//! Fetch authenticated whole slots; retain proof for arming and reboot.
const std = @import("std");
const apk = @import("apk");
const ipe = @import("ipe");
const signed = @import("prebuilt");
const broker = @import("broker");
const cmdline = @import("cmdline");
const m = @import("slot-update.zig");
const Dir = m.Dir;
const Update = m.Update;
const work = m.work_dir;
const meta = signed.metadata;
const floor_path = m.coord_dir ++ "/image-floor";

pub const Verified = struct { manifest: signed.Manifest, data: []const u8, signature: []const u8 };

pub fn applied(u: *Update) !bool {
    const have = try u.read(meta ++ "/declaration");
    return !std.mem.eql(u8, have, u.image.?.manifest.declaration orelse "");
}

fn identity(u: *Update, arch: []const u8) !signed.Identity {
    const url = u.read(meta ++ "/url") catch |err| switch (err) {
        error.FileNotFound => return error.IpeSignedImageRequired,
        else => return err,
    };
    try signed.channel(url);
    const selection = u.read("/usr/share/werewolf/variants") catch |err| switch (err) {
        error.FileNotFound => "",
        else => return err,
    };
    var variants: std.ArrayList([]const u8) = .empty;
    const text = std.mem.trim(u8, selection, " \n");
    if (text.len > 0) {
        if (!signed.variantSelection(text)) return error.BadImageVariants;
        var it = std.mem.splitScalar(u8, text, ',');
        while (it.next()) |name| try variants.append(u.gpa, name);
    }
    const form = if (variants.items.len > 0)
        std.mem.trim(u8, try u.read("/usr/share/werewolf/form"), "\n")
    else
        null;
    return .{ .channel = url, .arch = arch, .form = form, .variants = variants.items };
}

fn open(u: *Update, arch: []const u8, data: []const u8, sig: []const u8) !signed.Manifest {
    const key = try apk.parseKey(u.gpa, try u.read(meta ++ "/image.pub"));
    return signed.open(u.gpa, key, data, sig, try identity(u, arch));
}

fn pseudo(u: *Update, path: []const u8) ![]const u8 {
    const workers = @import("workers.zig");
    const held = if (std.mem.eql(u8, path, ipe.policy_path))
        workers.ipe_policy
    else if (std.mem.eql(u8, path, ipe.active))
        workers.ipe_active
    else
        workers.ipe_enforce;
    if (held) |file| {
        const bytes = try u.gpa.alloc(u8, 4096);
        return bytes[0..try file.readPositionalAll(u.io, bytes, 0)];
    }
    const f = try Dir.cwd().openFile(u.io, path, .{});
    defer f.close(u.io);
    const buf = try u.gpa.alloc(u8, 4096);
    return buf[0..try f.readPositionalAll(u.io, buf, 0)];
}

fn rootHash(u: *Update) ![32]u8 {
    const policy = try pseudo(u, ipe.policy_path);
    if (!ipe.enforced(policy, try pseudo(u, ipe.active), try pseudo(u, ipe.base ++ "/enforce")))
        return error.IpeNotEnforced;
    return ipe.policyRoot(policy) orelse error.IpeNotEnforced;
}

fn fresh(u: *Update, image: signed.Manifest) !void {
    const data = u.read(floor_path) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
    const floor = if (data) |d|
        try std.json.parseFromSliceLeaky(signed.Floor, u.gpa, d, .{})
    else
        null;
    try signed.freshness(
        image,
        try u.read(meta ++ "/serial"),
        try rootHash(u),
        floor,
        m.nowSecs(u.io),
    );
}

/// release requires image to be a release of this machine's channel, as
/// the running UKI names it, and an update to come later in it. Without a
/// channel the machine has no TPM floor, and the serial floor alone holds.
fn release(u: *Update, image: signed.Manifest, newer: bool) !void {
    const channel = u.cmd.channel orelse return;
    if (!std.mem.eql(u8, image.channel_id, &std.fmt.bytesToHex(channel, .lower)))
        return error.WrongImageChannel;
    if (newer and image.index <= u.cmd.index.?) return error.OlderImage;
}

/// ukiRelease requires the staged UKI's signed command line to name the
/// release its manifest names: the identity stage0 will hold to the floor.
fn ukiRelease(u: *Update, image: signed.Manifest) !void {
    if (u.cmd.channel == null) return;
    if (image.files.@"uki.efi" == null) return error.MissingImageUki;
    const binary = try Dir.cwd().readFileAlloc(
        u.io,
        work ++ "/slot/uki.efi",
        u.gpa,
        .limited(512 << 20),
    );
    const line = try @import("uki").section(binary, ".cmdline") orelse return error.BadCmdline;
    var bad: cmdline.Failure = .{};
    const parsed = cmdline.parse(std.mem.trimEnd(u8, line, "\x00"), &bad) orelse
        return error.BadCmdline;
    const channel = parsed.channel orelse return error.WrongReleaseIdentity;
    if (!std.mem.eql(u8, &std.fmt.bytesToHex(channel, .lower), image.channel_id) or
        parsed.index.? != image.index) return error.WrongReleaseIdentity;
}

pub fn plan(u: *Update, arch: []const u8) !?m.Plan {
    u.step = "image-manifest";
    const id = try identity(u, arch);
    try u.netRoot();
    const base = try u.gpa.print("{s}/{s}", .{ id.channel, arch });
    const data = try u.downloadMax(
        try u.gpa.print("{s}/latest.json", .{base}),
        work ++ "/image.json",
        signed.max_manifest,
    );
    const sig = try u.downloadMax(
        try u.gpa.print("{s}/latest.json.sig", .{base}),
        work ++ "/image.sig",
        8192,
    );
    const image = try open(u, arch, data, sig);
    try fresh(u, image);
    const current_root = try rootHash(u);
    if (std.mem.eql(u8, image.root_hash, &std.fmt.bytesToHex(current_root, .lower))) {
        try u.record(.{
            .event = "check",
            .result = "current",
            .build = image.build,
            .source = "signed-image",
        });
        return null;
    }
    // A bad image remains bad; fetch no payload and advance no floor for it.
    if (u.isBad(image.build)) return error.ImageRolledBack;
    try release(u, image, true);
    u.step = "image-files";
    try Dir.cwd().deleteTree(u.io, work ++ "/slot");
    try Dir.cwd().createDirPath(u.io, work ++ "/slot");
    _ = try u.sys(m.linux.fchmodat(m.linux.AT.FDCWD, work ++ "/slot", 0o750), "chmod slot");
    inline for (signed.names) |name| if (image.artifact(name)) |a| {
        const path = try u.gpa.printSentinel("{s}/slot/{s}", .{ work, name }, 0);
        const url = try u.gpa.print("{s}/{s}/{s}", .{ base, image.build, name });
        const got = try u.downloadLimit(url, path, @intCast(a.size));
        defer _ = m.linux.close(got.fd);
        try signed.matches(a, got.size, &got.sha256);
    };
    _ = try signed.cmdline(try u.read(work ++ "/slot/cmdline"));
    try ukiRelease(u, image);
    // The installer rehashes these files before taking writable mounts.
    u.image = .{ .manifest = image, .data = data, .signature = sig };
    return .{
        .build = image.build,
        .old_pkgs = try m.parseInstalled(u.gpa, try u.read("/usr/lib/apk/db/installed")),
        .new_pkgs = image.packages,
        .old_kernel = std.mem.trim(u8, try u.read(m.meta_dir ++ "/kernel"), "\n"),
        .new_kernel = image.kernel,
        .advisories = image.advisories,
    };
}

pub fn requireInstall(u: *Update) !void {
    if (!try u.needsSignedImage()) return;
    const v = u.image orelse return error.IpeSignedImageRequired;
    const image = try open(
        u,
        std.mem.trim(u8, try u.read("/etc/apk/arch"), "\n"),
        v.data,
        v.signature,
    );
    try fresh(u, image);
    try release(u, image, true);
    if (image.files.@"uki.efi" == null) {
        if (Dir.cwd().access(u.io, work ++ "/slot/uki.efi", .{})) |_|
            return error.UnselectedImageUki
        else |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        }
    }
    inline for (signed.names) |name| if (image.artifact(name)) |a| {
        const got = try signed.hashFile(
            u.io,
            u.gpa,
            try u.gpa.print("{s}/slot/{s}", .{ work, name }),
        );
        try signed.matches(a, got.size, got.sha256);
    };
    _ = try signed.cmdline(try u.read(work ++ "/slot/cmdline"));
    try ukiRelease(u, image);
    try u.writeReplacing(
        floor_path,
        try std.json.Stringify.valueAlloc(
            u.gpa,
            signed.Floor{ .serial = image.serial, .build = image.build },
            .{},
        ),
    );
}

/// Verify retained proof, then optionally all installed bytes. Automatic
/// reboot obeys the floor; an explicit operator try can select an older,
/// still-authenticated image without weakening IPE.
pub fn verifyOther(
    u: *Update,
    expected: ?[]const u8,
    contents: bool,
    rollback: bool,
) !signed.Manifest {
    const rdir = try u.gpa.print("/boot/slot/{s}", .{u.other});
    const image = try open(
        u,
        std.mem.trim(u8, try u.read("/etc/apk/arch"), "\n"),
        try u.read(try u.gpa.print("{s}/image.json", .{rdir})),
        try u.read(try u.gpa.print("{s}/image.json.sig", .{rdir})),
    );
    if (u.isBad(image.build)) return error.ImageRolledBack;
    if (!rollback) try fresh(u, image);
    // stage0 refuses a release below the floor; an operator's try may
    // pick an older one of this channel, and an automatic boot a later one.
    try release(u, image, !rollback);
    if (expected) |e| if (!std.mem.eql(u8, e, image.build)) return error.WrongStagedImage;
    if (contents) try checkEspInstalled(u, image, rdir);
    return image;
}

/// checkLocalOther verifies that the other slot's root image and ESP boot
/// files exist and are non-empty on machines that build slots locally.
pub fn checkLocalOther(u: *Update) !void {
    const root = try u.gpa.print("/boot/slot/{s}/root.erofs", .{u.other});
    const got = try signed.hashFile(u.io, u.gpa, root);
    if (got.size == 0) return error.MissingArtifact;
    const files = broker.espInspect() catch |err| {
        u.detail = broker.refusal;
        return err;
    };
    if (files.vmlinuz == null or files.stage0 == null) return error.MissingArtifact;
}

/// checkEspInstalled verifies an installed slot's bytes without an ESP
/// mount: the root files are read here, and the broker reports the boot
/// files' digests from its detached mount.
fn checkEspInstalled(u: *Update, image: signed.Manifest, rdir: []const u8) !void {
    const files = broker.espInspect() catch |err| {
        u.detail = broker.refusal;
        return err;
    };
    for ([_]struct { name: []const u8, path: []const u8 }{
        .{ .name = "root.erofs", .path = "root.erofs" },
        .{ .name = "cmdline", .path = "cmdline" },
    }) |f| {
        const path = try u.gpa.print("{s}/{s}", .{ rdir, f.path });
        if (image.artifact(f.name)) |want| {
            const got = try signed.hashFile(u.io, u.gpa, path);
            try signed.matches(want, got.size, got.sha256);
        } else {
            Dir.cwd().access(u.io, path, .{}) catch continue;
            return error.UnselectedImageUki;
        }
    }
    for ([_]struct { name: []const u8, file: ?broker.EspFile }{
        .{ .name = "vmlinuz", .file = files.vmlinuz },
        .{ .name = "stage0.zst", .file = files.stage0 },
        .{ .name = "uki.efi", .file = files.uki },
    }) |f| {
        if (image.artifact(f.name)) |want| {
            const got = f.file orelse return error.MissingArtifact;
            if (got.size != want.size or !std.mem.eql(u8, &got.sha256, want.sha256))
                return error.ArtifactMismatch;
        } else if (f.file != null and std.mem.eql(u8, f.name, "uki.efi")) {
            return error.UnselectedImageUki;
        }
    }
    _ = try signed.cmdline(try u.read(try u.gpa.print("{s}/cmdline", .{rdir})));
}

pub fn requireBoot(u: *Update, expected: []const u8, contents: bool) !void {
    errdefer if (u.cmd.esp != null) broker.espDisarm() catch {};
    if (u.isBad(expected)) return error.ImageRolledBack;
    if (try u.needsSignedImage()) {
        _ = try verifyOther(u, expected, contents, false);
        return;
    }
    if (contents) try checkLocalOther(u);
}
