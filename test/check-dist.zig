//! check-dist QEMU... boots the actual release disk in DIST through
//! build/host/console (test/console.zig; make check-dist). A signed release must first prove its
//! disk, UKI and boot certificate are the bytes its manifest names; its
//! certificate is then enrolled, and replaces the generic firmware. A
//! form's test/config-shellfree, when it has one, makes the config disk.

const std = @import("std");
const host = @import("host");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const mem = std.mem;
const json = std.json;
const Why = host.check.Why;

pub fn main(init: std.process.Init) void {
    var c = host.Check.init(init, "dist") catch |err| std.process.fatal("check-dist: {t}", .{err});
    c.finish(run(&c));
}

fn run(c: *host.Check) !void {
    const io = c.io;
    const gpa = c.gpa;
    const arch = c.env.get("ARCH") orelse return c.fail("ARCH is not set", .{});
    const form = c.env.get("FORM") orelse return c.fail("FORM is not set", .{});
    if (!mem.eql(u8, arch, "aarch64") and !mem.eql(u8, arch, "x86_64"))
        return c.fail("unsupported release architecture", .{});
    const directory = c.env.get("DIST") orelse return c.fail("DIST is not set", .{});
    try c.setWork(c.env.get("CHECK") orelse return c.fail("CHECK is not set", .{}));
    const prefix = try gpa.print("{s}-{s}", .{ form, arch });
    const disk = try gpa.print("{s}/{s}-disk.qcow2", .{ directory, prefix });
    const manifest = try json.parseFromSliceLeaky(json.Value, gpa, try Io.Dir.cwd().readFileAlloc(
        io,
        try gpa.print("{s}/{s}.json", .{ directory, prefix }),
        gpa,
        .limited(1 << 20),
    ), .{});
    const cert = try gpa.print("{s}/{s}-boot.crt", .{ directory, prefix });
    var argv: std.ArrayList([]const u8) = .empty;
    for (c.args[1..]) |a| try argv.append(gpa, a);
    const files = if (manifest == .object) manifest.object.get("files") else null;
    const signed = if (files) |f|
        f == .object and (f.object.contains("boot.crt") or f.object.contains("uki"))
    else
        false;
    const has_cert = if (Io.Dir.cwd().access(io, cert, .{})) true else |_| false;
    if (signed or has_cert) {
        var why: Why = .{};
        authenticatedArtifacts(
            io,
            gpa,
            manifest,
            directory,
            prefix,
            &why,
        ) catch |err| switch (err) {
            error.Refused => return c.fail("{s}", .{why.text}),
            else => |e| return e,
        };
        _ = try c.must(
            &.{ "sh", "tools/verify-boot-disk", arch, disk, cert, c.work },
            "dist-verify",
            .{},
        );
        const enrolled = try c.path("dist-enrolled");
        _ = try c.must(&.{ "sh", "tools/enroll-boot", arch, cert, enrolled }, "dist-enroll", .{});
        const replaced = try firmwareArguments(gpa, argv.items, arch, enrolled);
        argv = .fromOwnedSlice(@constCast(replaced));
    } else {
        const firmware: []const u8 = c.env.get("FIRMWARE") orelse "";
        if (firmware.len == 0) return c.fail("missing UEFI firmware", .{});
        if (mem.eql(u8, arch, "x86_64")) try Io.Dir.cwd().copyFile(
            c.env.get("UEFI_VARS").?,
            .cwd(),
            c.env.get("UEFI_VARS_COPY").?,
            io,
            .{},
        );
    }
    const form_dir = c.env.get("FORM_DIR") orelse try gpa.print("forms/{s}", .{form});
    const fixture = try gpa.print("{s}/test/config-shellfree", .{form_dir});
    const has_fixture = if (Io.Dir.cwd().statFile(io, fixture, .{})) |st|
        st.kind == .file
    else |_|
        false;
    if (has_fixture) {
        const config = try c.path(try gpa.print("dist-{s}-config", .{form}));
        Io.Dir.cwd().deleteTree(io, config) catch {};
        try Io.Dir.cwd().createDir(io, config, .default_dir);
        try Io.Dir.cwd().writeFile(io, .{
            .sub_path = try gpa.print("{s}/data.key", .{config}),
            .data = &@as([64]u8, @splat('k')),
        });
        _ = try c.must(&.{ fixture, config }, "dist-config", .{});
        const tar = try gpa.print("{s}.tar", .{config});
        _ = try c.must(&.{
            c.env.get("HOWL") orelse "build/host/howl", "pack",     "--build", "--with",
            c.env.get("FORM_REF") orelse form,          "--config", config,    "-o",
            tar,
        }, "dist-pack", .{});
        try argv.appendSlice(
            gpa,
            &.{ "-drive", try gpa.print("file={s},format=raw,if=virtio,readonly=on", .{tar}) },
        );
    }
    const console = c.env.get("CONSOLE") orelse "";
    var boot: std.ArrayList([]const u8) = .empty;
    try boot.appendSlice(gpa, &.{
        "build/host/console",
        try gpa.print("dist-{s}", .{form}),
        if (console.len > 0) console else "-",
        try c.path("dist.log"),
    });
    try boot.appendSlice(gpa, argv.items);
    try boot.appendSlice(
        gpa,
        &.{ "-drive", try gpa.print("file={s},format=qcow2,if=virtio", .{disk}) },
    );
    const err = std.process.replace(io, .{ .argv = boot.items, .environ_map = &c.env });
    return c.fail("build/host/console: {t}", .{err});
}

/// firmwareArguments replaces generic firmware in argv, rather than adding
/// a second flash bank: the enrolled code and variables, the machine with
/// SMM on x86_64, whose flash only SMM may write.
fn firmwareArguments(
    gpa: Allocator,
    argv: []const []const u8,
    arch: []const u8,
    enrolled: []const u8,
) ![]const []const u8 {
    const arm = mem.eql(u8, arch, "aarch64");
    var out: std.ArrayList([]const u8) = .empty;
    var i: usize = 0;
    while (i < argv.len) {
        const flag = argv[i];
        if ((mem.eql(u8, flag, "-bios") or mem.eql(u8, flag, "-drive")) and i + 1 < argv.len) {
            var options = mem.splitScalar(u8, argv[i + 1], ',');
            const pflash = while (options.next()) |o| {
                if (mem.eql(u8, o, "if=pflash")) break true;
            } else false;
            if (mem.eql(u8, flag, "-bios") or pflash) {
                i += 2;
                continue;
            }
        }
        try out.append(gpa, flag);
        if (mem.eql(u8, flag, "-M")) {
            if (i + 1 == argv.len) return error.MachineArgumentMissing;
            try out.append(gpa, if (arm) "virt" else "q35,smm=on");
            i += 2;
            continue;
        }
        i += 1;
    }
    try out.appendSlice(gpa, &.{
        "-drive",
        try gpa.print(
            "if=pflash,format=raw,unit=0,readonly=on,file={s}/code.fd",
            .{enrolled},
        ),
        "-drive",
        try gpa.print(
            "if=pflash,format=raw,unit=1,{s}file={s}/vars.fd",
            .{ if (arm) "readonly=on," else "", enrolled },
        ),
    });
    if (!arm) try out.appendSlice(
        gpa,
        &.{ "-global", "driver=cfi.pflash01,property=secure,value=on" },
    );
    return out.items;
}

/// authenticatedArtifacts requires the disk, UKI and boot certificate in
/// directory to be exactly the size and SHA-256 manifest names.
fn authenticatedArtifacts(
    io: Io,
    gpa: Allocator,
    manifest: json.Value,
    directory: []const u8,
    prefix: []const u8,
    why: *Why,
) !void {
    const files = (if (manifest == .object) manifest.object.get("files") else null) orelse
        return why.refuse("release manifest names no files", .{});
    for ([_][]const u8{ "disk.qcow2", "uki", "boot.crt" }) |name| {
        const record = (if (files == .object) files.object.get(name) else null) orelse
            return why.refuse("release manifest does not name {s}", .{name});
        const size = if (record == .object) record.object.get("size") else null;
        const sha = if (record == .object) record.object.get("sha256") else null;
        const source = try gpa.print("{s}/{s}-{s}", .{ directory, prefix, name });
        const st = Io.Dir.cwd().statFile(
            io,
            source,
            .{},
        ) catch return why.refuse("release artifact missing: {s}", .{name});
        const digest = try host.check.hexDigest(io, source);
        if (size == null or size.? != .integer or size.?.integer != st.size or sha == null or
            sha.? != .string or !mem.eql(u8, sha.?.string, &digest))
            return why.refuse("release artifact mismatch: {s}", .{name});
    }
}

const testing = std.testing;

test "a signed release replaces generic firmware and enforces SMM" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const result = try firmwareArguments(gpa, &.{
        "qemu-system-x86_64",             "-M",
        "q35",                            "-bios",
        "generic.fd",                     "-drive",
        "if=pflash,unit=1,file=old-vars", "-drive",
        "file=config.tar,if=virtio",      "-snapshot",
    }, "x86_64", "/owned");
    var pflash: usize = 0;
    for (result, 0..) |a, i| {
        try testing.expect(!mem.eql(u8, a, "-bios") and
            !mem.eql(u8, a, "if=pflash,unit=1,file=old-vars"));
        if (mem.find(u8, a, "if=pflash") != null) pflash += 1;
        if (mem.eql(u8, a, "-M")) try testing.expectEqualStrings("q35,smm=on", result[i + 1]);
    }
    try testing.expectEqual(2, pflash);
    try testing.expect(contains(result, "file=config.tar,if=virtio"));
    try testing.expect(contains(result, "driver=cfi.pflash01,property=secure,value=on"));
    const arm = try firmwareArguments(
        gpa,
        &.{ "qemu-system-aarch64", "-M", "virt", "-bios", "old.fd" },
        "aarch64",
        "/owned",
    );
    try testing.expect(contains(
        arm,
        "if=pflash,format=raw,unit=1,readonly=on,file=/owned/vars.fd",
    ));
    try testing.expectError(
        error.MachineArgumentMissing,
        firmwareArguments(gpa, &.{ "qemu", "-M" }, "aarch64", "/owned"),
    );
}

fn contains(list: []const []const u8, want: []const u8) bool {
    for (list) |a| if (mem.eql(u8, a, want)) return true;
    return false;
}

test "a release proof needs every signed artifact, byte for byte" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", gpa);
    var records: std.ArrayList(u8) = .empty;
    const names = [_][]const u8{ "disk.qcow2", "uki", "boot.crt" };
    for (names, 0..) |name, i| {
        try tmp.dir.writeFile(
            io,
            .{ .sub_path = try gpa.print("prod-aarch64-{s}", .{name}), .data = name },
        );
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(name, &digest, .{});
        try records.print(gpa, "{s}\"{s}\":{{\"size\":{d},\"sha256\":\"{s}\"}}", .{
            if (i > 0) "," else "", name, name.len, &std.fmt.bytesToHex(digest, .lower),
        });
    }
    const text = try gpa.print("{{\"files\":{{{s}}}}}", .{records.items});
    var why: Why = .{};
    const manifest = try json.parseFromSliceLeaky(json.Value, gpa, text, .{});
    try authenticatedArtifacts(io, gpa, manifest, root, "prod-aarch64", &why);
    for (names) |name| {
        var missing = try json.parseFromSliceLeaky(json.Value, gpa, text, .{});
        _ = missing.object.getPtr("files").?.object.orderedRemove(name);
        try testing.expectError(
            error.Refused,
            authenticatedArtifacts(io, gpa, missing, root, "prod-aarch64", &why),
        );
    }
    try tmp.dir.writeFile(io, .{ .sub_path = "prod-aarch64-uki", .data = "tampered" });
    try testing.expectError(
        error.Refused,
        authenticatedArtifacts(io, gpa, manifest, root, "prod-aarch64", &why),
    );
}
