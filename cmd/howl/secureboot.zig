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
        if (have_key != have_cert) return steps.fail(
            "partial boot identity; restore the existing signer instead of rotating trust",
        );
        if (howl.environ.get("WEREWOLF_BOOT_CRT") != null and
            howl.environ.get("WEREWOLF_BOOT_KEY") == null)
            return steps.fail("WEREWOLF_BOOT_CRT requires WEREWOLF_BOOT_KEY");
        if (howl.environ.get("WEREWOLF_BOOT_KEY")) |configured| {
            const certificate_path = howl.environ.get(
                "WEREWOLF_BOOT_CRT",
            ) orelse "release/boot.crt";
            try verifySigner(io, gpa, steps, configured, certificate_path);
            const private = try Dir.cwd().readFileAlloc(io, configured, gpa, .limited(32 << 10));
            defer std.crypto.secureZero(u8, private);
            const public_cert = try Dir.cwd().readFileAlloc(
                io,
                certificate_path,
                gpa,
                .limited(8192),
            );
            if (have_key) {
                const previous = try Dir.cwd().readFileAlloc(io, key, gpa, .limited(32 << 10));
                defer std.crypto.secureZero(u8, previous);
                const previous_cert = try Dir.cwd().readFileAlloc(io, cert, gpa, .limited(8192));
                if (!std.mem.eql(u8, previous, private) or
                    !std.mem.eql(u8, public_cert, previous_cert))
                    return steps.fail("the existing boot signer cannot be replaced");
            } else {
                const f = try Dir.cwd().createFile(io, key, .{
                    .exclusive = true,
                    .permissions = .fromMode(0o600),
                });
                defer f.close(io);
                try f.writeStreamingAll(io, private);
                try Dir.cwd().writeFile(io, .{ .sub_path = cert, .data = public_cert });
            }
        } else if (!have_key) {
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
    try verifySigner(io, gpa, steps, key, cert);
    return .{ .key = key, .cert = cert };
}

fn verifySigner(
    io: std.Io,
    gpa: std.mem.Allocator,
    steps: *@import("progress.zig").Steps,
    key: []const u8,
    cert: []const u8,
) !void {
    const private = try std.process.run(gpa, io, .{
        .argv = &.{ "openssl", "pkey", "-in", key, "-pubout" },
        .stdout_limit = .limited(8192),
        .stderr_limit = .limited(8192),
    });
    const public_cert = try std.process.run(gpa, io, .{
        .argv = &.{ "openssl", "x509", "-in", cert, "-pubkey", "-noout" },
        .stdout_limit = .limited(8192),
        .stderr_limit = .limited(8192),
    });
    if (private.term != .exited or private.term.exited != 0 or
        public_cert.term != .exited or public_cert.term.exited != 0 or
        !std.mem.eql(u8, private.stdout, public_cert.stdout))
        return steps.fail("boot key does not match its certificate");
}

test "caller boot credentials enroll once and mismatches never replace trust" {
    const t = std.testing;
    const io = t.io;
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", gpa);
    var env = std.process.Environ.Map.init(gpa);
    howl.environ = &env;
    defer howl.environ = undefined;
    var why: howl.Why = .{};
    var steps = try @import("progress.zig").Steps.init(io, gpa, &why, .{
        .verbose = true,
        .command = "test caller boot credentials",
        .log = "unused",
        .first = .{ .name = "Checking boot credentials", .short = "signer" },
    });
    for ([_][]const u8{ "first", "other" }) |name| {
        const key = try gpa.print("{s}/{s}.key", .{ root, name });
        const cert = try gpa.print("{s}/{s}.crt", .{ root, name });
        const made = try std.process.run(gpa, io, .{
            .argv = &.{
                "openssl",
                "req",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-x509",
                "-sha256",
                "-days",
                "2",
                "-subj",
                "/CN=werewolf-test",
                "-keyout",
                key,
                "-out",
                cert,
            },
            .stdout_limit = .limited(8192),
            .stderr_limit = .limited(8192),
        });
        try t.expect(made.term == .exited and made.term.exited == 0);
    }
    try env.put("WEREWOLF_BOOT_KEY", try gpa.print("{s}/first.key", .{root}));
    try env.put("WEREWOLF_BOOT_CRT", try gpa.print("{s}/first.crt", .{root}));
    const at = try gpa.print("{s}/enrolled", .{root});
    const kept = try signer(io, gpa, &steps, at, false);
    const before = try Dir.cwd().readFileAlloc(io, kept.key, gpa, .limited(8192));
    defer std.crypto.secureZero(u8, before);
    _ = try signer(io, gpa, &steps, at, false);
    try env.put("WEREWOLF_BOOT_CRT", try gpa.print("{s}/other.crt", .{root}));
    try t.expectError(error.Refused, signer(io, gpa, &steps, at, false));
    try env.put("WEREWOLF_BOOT_KEY", try gpa.print("{s}/other.key", .{root}));
    try t.expectError(error.Refused, signer(io, gpa, &steps, at, false));
    const after = try Dir.cwd().readFileAlloc(io, kept.key, gpa, .limited(8192));
    defer std.crypto.secureZero(u8, after);
    try t.expectEqualSlices(u8, before, after);
    try Dir.cwd().deleteFile(io, kept.cert);
    try t.expectError(error.Refused, signer(io, gpa, &steps, at, false));
    _ = env.swapRemove("WEREWOLF_BOOT_KEY");
    try t.expectError(
        error.Refused,
        signer(io, gpa, &steps, try gpa.print("{s}/new", .{root}), false),
    );
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
        try enroll(io, gpa, steps, dir, arch, keys.cert, keys.cert);
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

/// Enroll separate firmware administration and executable code certificates.
pub fn enroll(
    io: std.Io,
    gpa: std.mem.Allocator,
    steps: *@import("progress.zig").Steps,
    dir: []const u8,
    arch: howl.Arch,
    cert: []const u8,
    owner: []const u8,
) !void {
    const helper = try gpa.print("{s}/enroll-boot", .{dir});
    try Dir.cwd().writeFile(io, .{ .sub_path = helper, .data = embedded.enroll_boot });
    const setup = try gpa.print("{s}/build-helper", .{dir});
    const template = try gpa.print("{s}/build-helper.yaml", .{dir});
    const firmware = try gpa.print("{s}/native-firmware", .{dir});
    const requirements = try gpa.print("{s}/firmware-requirements.txt", .{dir});
    try Dir.cwd().writeFile(io, .{ .sub_path = setup, .data = embedded.build_helper });
    try Dir.cwd().writeFile(io, .{
        .sub_path = template,
        .data = embedded.build_helper_template,
    });
    try Dir.cwd().writeFile(io, .{ .sub_path = firmware, .data = embedded.native_firmware });
    try Dir.cwd().writeFile(io, .{
        .sub_path = requirements,
        .data = embedded.firmware_requirements,
    });
    var env = try howl.environ.clone(gpa);
    defer env.deinit();
    try env.put("WEREWOLF_HELPER_SETUP", setup);
    try env.put("WEREWOLF_HELPER_TEMPLATE", template);
    try env.put("WEREWOLF_FIRMWARE_SETUP", firmware);
    try env.put("WEREWOLF_FIRMWARE_REQUIREMENTS", requirements);
    const enrolled = try steps.exec(
        &.{.{ .argv = &.{
            "sh", helper, @tagName(arch), cert, dir, "local", owner,
        }, .env = &env }},
        .{},
    );
    if (!enrolled.ok) return steps.fail(
        "Secure Boot enrollment failed; plain firmware is not a fallback",
    );
    try Dir.cwd().deleteFile(io, helper);
}

pub fn image(b: *B) !void {
    const key = b.spec.boot_key.?;
    const cert = b.spec.boot_cert orelse return error.BootCertificateRequired;
    const slot = try b.path("{s}/slot", .{b.p.out});
    const stub_path = b.env.get("UKI_STUB") orelse try b.path(
        "out/tools/stubs/{t}/linux.efi.stub",
        .{b.spec.arch},
    );
    if ((b.spec.tpm_pub != null or b.spec.tpm_firmware) and b.env.get("UKI_STUB") == null)
        return b.fail(
            "TPM boot requires UKI_STUB with TPM measurement enabled; Alpine's default stub " ++
                "disables it",
            .{},
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
    const prefix = try b.path("{s} {s} init=/init panic=10 {s} {s} {s} " ++
        "werewolf.slots={s} werewolf.esp=57E1-F000\x00", .{
        base,
        @import(
            "disk.zig",
        ).consoles(b.spec.arch),
        extra,
        identity,
        if (b.spec.tpm_pub != null or b.spec.tpm_firmware) "werewolf.tpm=2" else "",
        @import("disk.zig").root_uuid,
    });
    const line = if (b.spec.tpm_pub != null or b.spec.tpm_firmware) blk: {
        const signed = @import("prebuilt");
        var hashes: [3][32]u8 = undefined;
        for ([3][]const u8{ "root.erofs", "vmlinuz", "stage0.zst" }, 0..) |name, i| {
            const file = try signed.hashFile(b.io, b.gpa, try b.path("{s}/{s}", .{ slot, name }));
            _ = try std.fmt.hexToBytes(&hashes[i], file.sha256);
        }
        const Sha256 = std.crypto.hash.sha2.Sha256;
        var hash = Sha256.init(.{});
        hash.update("werewolf.boot-context/2\x00");
        var stub_hash: [32]u8 = undefined;
        Sha256.hash(stub, &stub_hash, .{});
        hash.update(&stub_hash);
        hash.update(prefix);
        const context = hash.finalResult();
        const id = @import("tpm").releaseId(
            @tagName(b.arch),
            hashes[0],
            hashes[1],
            hashes[2],
            context,
        );
        try b.write(try b.path("{s}/release.id", .{slot}), &id);
        try b.write(try b.path("{s}/boot.context", .{slot}), &context);
        break :blk try b.path("{s} werewolf.release={x}\x00", .{
            std.mem.trimEnd(u8, prefix, "\x00"), &id,
        });
    } else prefix;
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
        &.{
            "osslsigncode", "sign", "-time", "0",      "-certs", cert,
            "-key",         key,    "-in",   unsigned, "-out",   temp,
        },
        .{},
    );
    try b.rename(temp, target);
    if (b.spec.tpm_pub != null or b.spec.tpm_firmware) try b.write(
        try b.path("{s}/pcr11", .{slot}),
        &try uki.pcr11(try b.read(target, 512 << 20)),
    );
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
