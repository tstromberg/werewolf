//! Export a whole signed IPE slot to an immutable HTTPS channel layout.
const std = @import("std");
const signed = @import("prebuilt");
const verity = @import("verity");
const policy = @import("update-policy");
const embedded = @import("files");
const manifest = @import("manifest.zig");
const B = @import("build.zig").B;
const Dir = std.Io.Dir;

pub fn declaration(b: *B) !?[]const u8 {
    if (b.spec.app == null and std.mem.findScalar(u8, b.spec.form, '/') == null) return null;
    return try b.gpa.dupe(u8, &try @import("lock.zig").inputs(b.io, b.gpa, b.spec));
}

pub fn write(b: *B) !void {
    const url = b.spec.ipe_updates orelse return b.fail(
        "prebuilt needs --ipe-updates and --image-serial",
        .{},
    );
    if (b.spec.dev) return b.fail("refused: prebuilt images cannot contain a DEV root shell", .{});
    const boot_key = b.env.get("WEREWOLF_BOOT_KEY") orelse "";
    if (boot_key.len > 0 and b.spec.boot_key == null) try b.run(&.{
        @import("howl.zig").make_cmd,
        "--no-print-directory",
        try b.path("FORM={s}", .{b.spec.form}),
        try b.path("ARCH={t}", .{b.spec.arch}),
        try b.path("BUILD={s}", .{b.p.build}),
        try b.path("OUT={s}", .{b.p.out}),
        try b.path("{s}/slot/uki.efi", .{b.p.out}),
    }, .{ .env = b.env });
    const meta = try b.path("{s}/meta/usr/share/werewolf", .{b.p.out});
    const slot = try b.path("{s}/slot", .{b.p.out});
    var files: signed.Files = undefined;
    inline for (signed.names) |n| {
        const path = try b.path("{s}/{s}", .{ slot, n });
        if (comptime std.mem.eql(u8, n, "uki.efi")) {
            @field(
                files,
                n,
            ) = if (boot_key.len > 0 or b.spec.boot_key != null)
                try signed.hashFile(b.io, b.gpa, path)
            else
                null;
        } else @field(files, n) = try signed.hashFile(b.io, b.gpa, path);
    }
    const build = signed.buildId(files);
    const root = try verity.Params.parse(try b.read(
        try b.path("{s}/verity/verity", .{b.p.out}),
        4096,
    ));
    const root_hex = std.fmt.bytesToHex(root.root, .lower);
    var bad: policy.BadLine = .{};
    const db = try b.capture(
        meta,
        &.{
            "bsdtar",
            "-xOf",
            try b.path("{s}/rootfs.tar", .{b.p.out}),
            "usr/lib/apk/db/installed",
        },
    );
    const m: signed.Manifest = .{
        .format = signed.format,
        .ipe = true,
        .channel = url,
        .arch = @tagName(b.spec.arch),
        .serial = b.spec.image_serial.?,
        .build = &build,
        .root_hash = &root_hex,
        .kernel = std.mem.trim(u8, try b.read(try b.path("{s}/kernel", .{meta}), 4096), "\n"),
        .packages = try manifest.parsePackages(b.gpa, db),
        .advisories = try policy.parseAdvisories(b.gpa, embedded.advisories, &bad),
        .declaration = try declaration(b),
        .channel_id = &std.fmt.bytesToHex(b.spec.channelId(), .lower),
        .index = b.spec.image_index,
        .files = files,
    };
    try signed.check(m, .{ .channel = url, .arch = m.arch });
    const dir = try b.path("{s}/prebuilt/{s}", .{ b.p.out, m.arch });
    const objects = try b.path("{s}/{s}", .{ dir, &build });
    try Dir.cwd().createDirPath(b.io, objects);
    inline for (signed.names) |n| if (m.artifact(n) != null) {
        const target = try b.path("{s}/{s}", .{ objects, n });
        if (Dir.cwd().access(b.io, target, .{})) |_| {
            const got = try signed.hashFile(b.io, b.gpa, target);
            try signed.matches(m.artifact(n).?, got.size, got.sha256);
        } else |err| switch (err) {
            error.FileNotFound => {
                const temp_file = try b.tmp(target);
                try b.copy(try b.path("{s}/{s}", .{ slot, n }), temp_file);
                try b.rename(temp_file, target);
            },
            else => return err,
        }
    };
    const data = try std.json.Stringify.valueAlloc(b.gpa, m, .{ .whitespace = .indent_2 });
    const temp = try b.path("{s}/latest.json.new", .{dir});
    const sig = try b.path("{s}/latest.json.sig.new", .{dir});
    try b.write(temp, data);
    try b.run(
        &.{ "openssl", "dgst", "-sha256", "-sign", b.spec.ipe_key.?, "-out", sig, temp },
        .{},
    );
    try b.run(
        &.{
            "openssl",
            "dgst",
            "-sha256",
            "-verify",
            try b.path("{s}/image-update/image.pub", .{meta}),
            "-signature",
            sig,
            temp,
        },
        .{},
    );
    try b.rename(sig, try b.path("{s}/latest.json.sig", .{dir}));
    try b.rename(temp, try b.path("{s}/latest.json", .{dir}));
    try b.steps.note(
        "signed prebuilt image {s}: upload {s}/prebuilt to {s}",
        .{ &build, b.p.out, url },
    );
}
