//! Host-held boot keys, enrollment, and signed native UKIs.
const std = @import("std");
const howl = @import("howl.zig");
const embedded = @import("files");
const uki = @import("uki");
const B = @import("build.zig").B;
const Dir = std.Io.Dir;

pub const Keys = struct { key: []const u8, cert: []const u8 };

pub fn signer(
    io: std.Io,
    gpa: std.mem.Allocator,
    steps: *@import("progress.zig").Steps,
    dir: []const u8,
    kept: bool,
) !Keys {
    const key = try gpa.print("{s}/boot.key", .{dir});
    const cert = try gpa.print("{s}/boot.crt", .{dir});
    if (!kept) {
        try Dir.cwd().createDirPath(io, dir);
        try Dir.cwd().setFilePermissions(io, dir, .fromMode(0o700), .{});
    }
    const guard = try Dir.cwd().createFile(io, try gpa.print("{s}/signer.lock", .{dir}), .{
        .truncate = false,
        .permissions = .fromMode(0o600),
    });
    defer guard.close(io);
    try guard.lock(io, .exclusive);
    defer guard.unlock(io);
    if (!kept) {
        const have_key = if (Dir.cwd().access(io, key, .{})) |_| true else |_| false;
        const have_cert = if (Dir.cwd().access(io, cert, .{})) |_| true else |_| false;
        if (howl.environ.get("WEREWOLF_BOOT_KEY")) |configured| {
            const certificate_path = howl.environ.get(
                "WEREWOLF_BOOT_CRT",
            ) orelse "release/boot.crt";
            const private = try Dir.cwd().readFileAlloc(io, configured, gpa, .limited(32 << 10));
            const public_cert = try Dir.cwd().readFileAlloc(
                io,
                certificate_path,
                gpa,
                .limited(8192),
            );
            const f = try Dir.cwd().createFile(io, key, .{ .permissions = .fromMode(0o600) });
            defer f.close(io);
            try f.writeStreamingAll(io, private);
            try Dir.cwd().writeFile(io, .{ .sub_path = cert, .data = public_cert });
        } else if (!have_key or !have_cert) {
            const f = try Dir.cwd().createFile(
                io,
                key,
                .{ .permissions = .fromMode(0o600) },
            );
            f.close(io);
            const made = try steps.exec(&.{.{ .argv = &.{
                "openssl",  "req",                     "-newkey",
                "rsa:4096", "-nodes",                  "-x509",
                "-sha256",  "-days",                   "3650",
                "-subj",    "/CN=werewolf-local-boot", "-keyout",
                key,        "-out",                    cert,
            } }}, .{});
            if (!made.ok) return steps.fail("creating the local boot signer failed");
        }
    } else {
        for ([_][]const u8{ key, cert }) |file| Dir.cwd().access(io, file, .{}) catch
            return steps.fail(
                "the existing disk has no boot signer; enrollment cannot be replaced",
            );
    }
    try Dir.cwd().setFilePermissions(io, key, .fromMode(0o600), .{});
    return .{ .key = key, .cert = cert };
}

pub fn prepare(
    io: std.Io,
    gpa: std.mem.Allocator,
    steps: *@import("progress.zig").Steps,
    dir: []const u8,
    arch: howl.Arch,
    kept: bool,
) !Keys {
    const keys = try signer(io, gpa, steps, dir, kept);
    if (!kept) {
        const helper = try gpa.print("{s}/enroll-boot", .{dir});
        try Dir.cwd().writeFile(io, .{ .sub_path = helper, .data = embedded.enroll_boot });
        const enrolled = try steps.exec(
            &.{.{ .argv = &.{ "sh", helper, @tagName(arch), keys.cert, dir } }},
            .{},
        );
        if (!enrolled.ok) return steps.fail(
            "Secure Boot enrollment failed; plain firmware is not a fallback",
        );
        try Dir.cwd().deleteFile(io, helper);
    } else {
        for ([_][]const u8{
            try gpa.print("{s}/vars.fd", .{dir}),
            try gpa.print("{s}/code.fd", .{dir}),
        }) |file|
            Dir.cwd().access(io, file, .{}) catch
                return steps.fail(
                    "the existing disk has no enrolled firmware; refusing to replace its trust",
                );
    }
    return keys;
}

pub fn image(b: *B) !void {
    const key = b.spec.boot_key.?;
    const cert = b.spec.boot_cert orelse return error.BootCertificateRequired;
    const slot = try b.path("{s}/slot", .{b.p.out});
    const stub_path = b.env.get("UKI_STUB") orelse try b.path(
        "out/tools/stubs/{t}/linux.efi.stub",
        .{b.spec.arch},
    );
    const options = try b.path("{s}/uki.options", .{slot});
    const wanted = try b.path("native {any}\n{s}\n", .{
        b.spec.boot_native, try std.mem.join(b.gpa, " ", b.spec.disk.args),
    });
    const previous = std.Io.Dir.cwd().readFileAlloc(b.io, options, b.gpa, .limited(8192)) catch "";
    if (!std.mem.eql(u8, wanted, previous)) try b.write(options, wanted);
    const target = try b.path("{s}/uki.efi", .{slot});
    const initrd_path = if (b.spec.boot_native)
        try b.path("{s}/stage0.zst", .{slot})
    else
        try b.path("{s}/initramfs.zst", .{b.p.out});
    const began = try b.begin(target, &.{
        try b.path("{s}/vmlinuz", .{b.p.build}),
        initrd_path,
        try b.path("{s}/cmdline", .{slot}),
        stub_path,
        key,
        cert,
        options,
        b.self,
    }) orelse return;
    const stub = try b.read(stub_path, 1 << 20);
    const kernel = try b.read(try b.path("{s}/vmlinuz", .{b.p.build}), 512 << 20);
    const initrd = try b.read(initrd_path, 512 << 20);
    const base = std.mem.trimEnd(u8, try b.read(try b.path("{s}/cmdline", .{slot}), 4096), "\n");
    const extra = try std.mem.join(b.gpa, " ", b.spec.disk.args);
    const identity = if (b.spec.boot_native)
        "werewolf.native=1 werewolf.secure=1"
    else
        "werewolf.slot=a";
    const line = try b.path("{s} {s} init=/init panic=10 {s} {s} " ++
        "werewolf.victim={s}:/werewolf " ++
        "werewolf.esp=57E1-F000\x00", .{
        base,
        @import("disk.zig").consoles(b.spec.arch),
        extra,
        identity,
        @import("disk.zig").root_uuid,
    });
    const unsigned = try b.path("{s}/uki.efi.unsigned", .{slot});
    try b.write(
        unsigned,
        try uki.assemble(
            b.gpa,
            stub,
            &.{ ".linux", ".initrd", ".cmdline" },
            &.{ kernel, initrd, line },
        ),
    );
    const temp = try b.tmp(target);
    Dir.cwd().deleteFile(b.io, temp) catch {};
    try b.run(
        &.{ "osslsigncode", "sign", "-certs", cert, "-key", key, "-in", unsigned, "-out", temp },
        .{},
    );
    try b.rename(temp, target);
    try Dir.cwd().deleteFile(b.io, unsigned);
    try b.done(target, began);
}

/// Check both firmware-loaded files before uploading; a sidecar alone is not proof.
pub fn certificate(
    io: std.Io,
    gpa: std.mem.Allocator,
    disk: []const u8,
    work: []const u8,
    arch: howl.Arch,
    why: *howl.Why,
) ![]const u8 {
    const parent = std.fs.path.dirname(disk) orelse ".";
    const filename = std.fs.path.basename(disk);
    const cert = if (std.mem.endsWith(u8, filename, "-disk.qcow2"))
        try gpa.print(
            "{s}/{s}-boot.crt",
            .{ parent, filename[0 .. filename.len - "-disk.qcow2".len] },
        )
    else
        try gpa.print("{s}/boot.crt", .{parent});
    Dir.cwd().access(io, cert, .{}) catch return why.refuse(
        "{s}: signed cloud disks require their boot.crt certificate; rebuild with --boot-key " ++
            "and --boot-cert",
        .{disk},
    );
    const helper = try gpa.print("{s}/verify-boot-disk", .{work});
    try Dir.cwd().writeFile(io, .{ .sub_path = helper, .data = embedded.verify_boot_disk });
    defer Dir.cwd().deleteFile(io, helper) catch {};
    try howl.run(io, why, &.{ "sh", helper, @tagName(arch), disk, cert, work });
    return cert;
}
