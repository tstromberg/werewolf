//! check-legacy-image CANDIDATE LOGS boots the exact compatibility disk
//! and direct-boot image of a legacy release, without Secure Boot or a
//! TPM, through build/host/console (test/console.zig), which judges the
//! form's own posture from the console. The candidate's manifest must first match its files.

const std = @import("std");
const builtin = @import("builtin");
const host = @import("host");
const published = @import("published.zig");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const mem = std.mem;
const json = std.json;
const Why = host.check.Why;

pub fn main(init: std.process.Init) void {
    var c = host.Check.init(
        init,
        "legacy-image",
    ) catch |err| std.process.fatal("check-legacy-image: {t}", .{err});
    c.finish(run(&c));
}

fn run(c: *host.Check) !void {
    if (c.args.len != 3) return c.fail("usage: check-legacy-image CANDIDATE LOGS", .{});
    const io = c.io;
    const gpa = c.gpa;
    const directory = try Io.Dir.cwd().realPathFileAlloc(io, c.args[1], gpa);
    const output = try c.absolute(c.args[2]);
    const text = try Io.Dir.cwd().readFileAlloc(
        io,
        try gpa.print("{s}/manifest.json", .{directory}),
        gpa,
        .limited(1 << 20),
    );
    const manifest = json.parseFromSliceLeaky(
        json.Value,
        gpa,
        text,
        .{},
    ) catch return c.fail("invalid legacy boot manifest", .{});
    var why: Why = .{};
    const images = try published.Images.load(io, gpa);
    validate(io, gpa, images, manifest, directory, &why) catch |err| switch (err) {
        error.Refused => return c.fail("{s}", .{why.text}),
        else => |e| return e,
    };
    const arch = manifest.object.get("arch").?.string;
    const form = manifest.object.get("form").?.string;
    try Io.Dir.cwd().createDirPath(io, std.fs.path.dirname(output) orelse ".");
    Io.Dir.cwd().createDir(io, output, .default_dir) catch |err| switch (err) {
        error.PathAlreadyExists => return c.fail("{s} exists already", .{output}),
        else => |e| return e,
    };
    var form_args: std.ArrayList([]const u8) = .empty;
    try form_args.appendSlice(gpa, &.{ "build/host/form", "excuses", form });
    for (try published.variants(gpa, manifest)) |variant|
        try form_args.appendSlice(gpa, &.{ "--variant", variant });
    const excuses = try c.must(form_args.items, "", .{});
    try c.env.put("POSTURE_KNOWN", try known(gpa, excuses.stdout));

    const host_arch = if (builtin.cpu.arch == .aarch64) "aarch64" else "x86_64";
    const native = mem.eql(u8, host_arch, arch);
    const accel = if (!native)
        "tcg"
    else if (builtin.os.tag == .macos)
        "hvf"
    else if (Io.Dir.cwd().access(
        io,
        "/dev/kvm",
        .{ .read = true, .write = true },
    )) "kvm" else |_| "tcg";
    const arm = mem.eql(u8, arch, "aarch64");
    // Current AAVMF stalls before loading the disk with TCG's synthetic max
    // CPU. A Cortex-A72 boots the same firmware and exact release disk.
    const cpu = if (!mem.eql(u8, accel, "tcg")) "host" else if (arm) "cortex-a72" else "max";
    const command = [_][]const u8{
        try gpa.print(
            "qemu-system-{s}",
            .{arch},
        ),
        "-M",
        if (arm) "virt" else "q35",
        "-accel",
        accel,
        "-cpu",
        cpu,
        "-nographic",
        "-smp",
        "2",
        "-m",
        "2048",
        "-no-reboot",
        "-device",
        "virtio-rng-pci",
        "-netdev",
        "user,id=n0,restrict=on",
        "-device",
        "virtio-net-pci,netdev=n0,romfile=",
    };
    // Native serial posture checks judge production bytes without
    // injecting a shell or test agent into either published image.
    const bios = firmware(
        io,
        arch,
    ) orelse return c.fail("ordinary UEFI firmware is required to test legacy boot", .{});
    var uefi: []const []const u8 = try gpa.dupe([]const u8, &.{ "-bios", bios });
    if (mem.find(u8, bios, "_CODE") != null) {
        const template = try mem.replaceOwned(u8, gpa, bios, "_CODE", "_VARS");
        Io.Dir.cwd().access(
            io,
            template,
            .{},
        ) catch return c.fail("matching ordinary UEFI variable template is missing", .{});
        const variables = try gpa.print("{s}/vars.fd", .{output});
        try Io.Dir.cwd().copyFile(template, .cwd(), variables, io, .{});
        uefi = try gpa.dupe([]const u8, &.{
            "-drive", try gpa.print("if=pflash,format=raw,readonly=on,file={s}", .{bios}),
            "-drive", try gpa.print("if=pflash,format=raw,file={s}", .{variables}),
        });
    }
    const cmdline = mem.trim(
        u8,
        try Io.Dir.cwd().readFileAlloc(
            io,
            try gpa.print("{s}/cmdline", .{directory}),
            gpa,
            .limited(64 << 10),
        ),
        " \t\r\n",
    );
    const Mode = struct { name: []const u8, extra: []const []const u8 };
    for ([_]Mode{
        .{ .name = "uefi", .extra = try mem.concat(gpa, []const u8, &.{ uefi, &.{
            "-snapshot", "-drive",
            try gpa.print(
                "file={s}/disk.qcow2,format=qcow2,if=virtio",
                .{directory},
            ),
        } }) },
        .{ .name = "direct", .extra = &.{
            "-kernel", try gpa.print("{s}/vmlinuz", .{directory}),
            "-initrd", try gpa.print("{s}/initramfs.zst", .{directory}),
            "-append",
            try gpa.print(
                "{s} console={s}",
                .{ cmdline, if (arm) "ttyAMA0" else "ttyS0" },
            ),
        } },
    }) |mode| {
        const argv = try mem.concat(gpa, []const u8, &.{ &.{
            "build/host/console",
            try gpa.print("legacy-{s}-{s}", .{ form, mode.name }),
            "-",
            try gpa.print("{s}/{s}.log", .{ output, mode.name }),
        }, &command, mode.extra });
        var child = try std.process.spawn(
            io,
            .{ .argv = argv, .environ_map = &c.env, .stdin = .ignore },
        );
        const term = try child.wait(io);
        if (!term.success()) return c.fail(
            "{s} boot: {f}; see {s}/{s}.log",
            .{ mode.name, term, output, mode.name },
        );
    }
}

/// known is POSTURE_KNOWN for a legacy boot: the form's excuses, then what
/// a boot without Secure Boot, a TPM or IPE cannot pass.
fn known(gpa: Allocator, excuses: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var lines = mem.tokenizeScalar(u8, excuses, '\n');
    while (lines.next()) |line| {
        var words = mem.tokenizeAny(u8, line, " \t");
        const id = words.next() orelse continue;
        if (out.items.len > 0) try out.append(gpa, ' ');
        // QEMU restricts external traffic here. DNS and external HTTPS need
        // responding upstreams; the form's suite tests policy with live fixtures.
        if (mem.eql(u8, id, "network-root-dns-assigned") or
            mem.eql(u8, id, "network-root-https-arbitrary")) try out.append(gpa, '?');
        try out.appendSlice(gpa, id);
    }
    // Direct boot has no EFI variables, so the Secure Boot probe is skipped.
    for ([_][]const u8{
        "?boot-secure-boot",
        "boot-rollback-protected",
        "boot-ipe-enforced",
    }) |id| {
        if (out.items.len > 0) try out.append(gpa, ' ');
        try out.appendSlice(gpa, id);
    }
    return out.items;
}

fn firmware(io: Io, arch: []const u8) ?[]const u8 {
    const candidates: []const []const u8 = if (mem.eql(u8, arch, "aarch64")) &.{
        "/usr/share/AAVMF/AAVMF_CODE.fd",
        "/usr/share/qemu-efi-aarch64/QEMU_EFI.fd",
        "/opt/homebrew/share/qemu/edk2-aarch64-code.fd",
    } else &.{
        "/usr/share/OVMF/OVMF_CODE_4M.fd",
        "/usr/share/OVMF/OVMF_CODE.fd",
        "/usr/share/ovmf/OVMF.fd",
        "/opt/homebrew/share/qemu/edk2-x86_64-code.fd",
    };
    for (candidates) |p| {
        const st = Io.Dir.cwd().statFile(io, p, .{}) catch continue;
        if (st.kind == .file) return p;
    }
    return null;
}

const format = "werewolf-legacy-downloads/1";
const files = [_][]const u8{
    "disk.qcow2", "disk.img.zst", "vmlinuz",       "initramfs.zst", "cmdline",
    "stage0.zst", "root.erofs",   "inputs.tar.gz", "packages.json",
};

/// validate requires manifest to be a legacy release of a published form,
/// with Secure Boot, the TPM and IPE disabled by name, naming exactly its
/// files at their sizes and digests, and a command line with no protected
/// boot identity.
fn validate(
    io: Io,
    gpa: Allocator,
    images: published.Images,
    manifest: json.Value,
    directory: []const u8,
    why: *Why,
) !void {
    if (manifest != .object) return why.refuse("invalid legacy boot manifest", .{});
    const m = manifest.object;
    const form = string(m.get("form")) orelse "";
    const arch = string(m.get("arch")) orelse "";
    const profile = string(m.get("boot_profile")) orelse "";
    if (!images.isForm(form) or !images.isArch(arch) or !oneOf(profile, images.profiles))
        return why.refuse("unsupported published image identity", .{});
    const disabled = m.get("disabled") orelse .null;
    const listed = m.get("files") orelse .null;
    var same_disabled = disabled == .array and disabled.array.items.len == 3;
    if (same_disabled) for (disabled.array.items, [_][]const u8{
        "secureboot",
        "tpm",
        "ipe",
    }) |d, want| {
        if (!mem.eql(u8, string(d) orelse "", want)) same_disabled = false;
    };
    var same_files = listed == .object and listed.object.count() == files.len;
    if (same_files) for (files) |f| if (!listed.object.contains(f)) {
        same_files = false;
    };
    if (!mem.eql(u8, string(m.get("format")) orelse "", format) or
        !mem.eql(u8, profile, "legacy-boot") or
        !same_disabled or !same_files) return why.refuse("invalid legacy boot manifest", .{});
    if (!pattern(string(m.get("serial")) orelse "", "dddddddd-dddddd-") or
        !hex(string(m.get("commit")) orelse "", 40) or !hex(string(m.get("inputs")) orelse "", 64))
        return why.refuse("invalid legacy release identity", .{});
    const raw = m.get("raw_size") orelse .null;
    if (raw != .integer or raw.integer < 512 << 20 or raw.integer > 16 << 30)
        return why.refuse("invalid legacy raw disk size", .{});
    for (files) |name| {
        const path = try gpa.print("{s}/{s}", .{ directory, name });
        const st = Io.Dir.cwd().statFile(io, path, .{ .follow_symlinks = false }) catch
            return why.refuse("image assets must be regular files", .{});
        if (st.kind != .file) return why.refuse("image assets must be regular files", .{});
        const record = listed.object.get(name).?;
        const sha = if (record == .object) string(record.object.get("sha256")) else null;
        const size = if (record == .object) record.object.get("size") else null;
        if (record != .object or record.object.count() != 2 or sha == null or size == null or
            size.? != .integer or size.?.integer != st.size or
            !mem.eql(u8, sha.?, &try host.check.hexDigest(io, path)))
            return why.refuse("legacy image differs from its manifest: {s}", .{name});
    }
    const cmdline = Io.Dir.cwd().readFileAlloc(
        io,
        try gpa.print("{s}/cmdline", .{directory}),
        gpa,
        .limited(64 << 10),
    ) catch
        return why.refuse("image metadata is too large", .{});
    var words = mem.tokenizeAny(u8, cmdline, " \t\r\n");
    var disables = false;
    while (words.next()) |w| {
        for ([_][]const u8{
            "werewolf.secure=",
            "werewolf.tpm=",
            "werewolf.release=",
            "werewolf.native=",
        }) |p|
            if (mem.startsWith(
                u8,
                w,
                p,
            )) return why.refuse("legacy image has an incompatible boot identity", .{});
        if (mem.eql(u8, w, "werewolf.disable=secureboot,tpm,ipe")) disables = true;
    }
    if (!disables) return why.refuse("legacy image has an incompatible boot identity", .{});
}

fn string(v: ?json.Value) ?[]const u8 {
    const x = v orelse return null;
    return if (x == .string) x.string else null;
}

fn oneOf(s: []const u8, set: []const []const u8) bool {
    for (set) |x| if (mem.eql(u8, s, x)) return true;
    return false;
}

fn hex(s: []const u8, n: usize) bool {
    if (s.len != n) return false;
    for (s) |b| if (!std.ascii.isDigit(b) and (b < 'a' or b > 'f')) return false;
    return true;
}

/// pattern matches a serial, YYYYMMDDTHHMMSSZ: d is a digit, - the letter
/// the serial has there.
fn pattern(s: []const u8, shape: []const u8) bool {
    if (s.len != shape.len) return false;
    for (s, shape, 0..) |b, p, i| switch (p) {
        'd' => if (!std.ascii.isDigit(b)) return false,
        else => if (b != (if (i == 8) @as(u8, 'T') else 'Z')) return false,
    };
    return true;
}

const testing = std.testing;

test "known excuses what a legacy boot cannot pass" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    try testing.expectEqualStrings(
        "network-no-login ?network-root-dns-assigned ?network-root-https-arbitrary " ++
            "?boot-secure-boot boot-rollback-protected " ++
            "boot-ipe-enforced",
        try known(
            arena.allocator(),
            "network-no-login the form serves a shell\n\nnetwork-root-dns-assigned dns\n" ++
                "network-root-https-arbitrary external web\n",
        ),
    );
}

test "validate refuses a manifest that does not match its candidate" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = testing.io;
    const images = try published.Images.load(io, gpa);
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realPathFileAlloc(io, ".", gpa);
    var records: std.ArrayList(u8) = .empty;
    for (files, 0..) |name, i| {
        const data = if (mem.eql(u8, name, "cmdline"))
            "console=ttyS0 werewolf.disable=secureboot,tpm,ipe\n"
        else
            name;
        try tmp.dir.writeFile(io, .{ .sub_path = name, .data = data });
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(data, &digest, .{});
        try records.print(gpa, "{s}\"{s}\":{{\"sha256\":\"{s}\",\"size\":{d}}}", .{
            if (i > 0) "," else "", name, &std.fmt.bytesToHex(digest, .lower), data.len,
        });
    }
    const good = try gpa.print(
        "{{\"format\":\"{s}\",\"form\":\"prod-ssh\",\"arch\":\"x86_64\"," ++
            "\"boot_profile\":\"legacy-boot\"," ++
            "\"disabled\":[\"secureboot\",\"tpm\",\"ipe\"],\"serial\":\"20261024T120000Z\"," ++
            "\"commit\":\"{s}\",\"inputs\":\"{s}\",\"raw_size\":{d},\"files\":{{{s}}}}}",
        .{ format, &@as([40]u8, @splat('a')), &@as([64]u8, @splat('b')), 1 << 30, records.items },
    );
    var why: Why = .{};
    const manifest = try json.parseFromSliceLeaky(json.Value, gpa, good, .{});
    try validate(io, gpa, images, manifest, dir, &why);
    for ([_][2][]const u8{
        .{ "\"form\":\"prod-ssh\"", "\"form\":\"prod\"" },
        .{ "\"boot_profile\":\"legacy-boot\"", "\"boot_profile\":\"secure-boot\"" },
        .{
            "\"disabled\":[\"secureboot\",\"tpm\",\"ipe\"]",
            "\"disabled\":[\"secureboot\",\"tpm\"]",
        },
        .{ "\"serial\":\"20261024T120000Z\"", "\"serial\":\"2026-10-24\"" },
        .{ "\"raw_size\":1073741824", "\"raw_size\":1024" },
        .{
            "\"format\":\"werewolf-legacy-downloads/1\"",
            "\"format\":\"werewolf-legacy-downloads/2\"",
        },
    }) |change| {
        const bad = try mem.replaceOwned(u8, gpa, good, change[0], change[1]);
        const wrong = try json.parseFromSliceLeaky(json.Value, gpa, bad, .{});
        try testing.expectError(error.Refused, validate(io, gpa, images, wrong, dir, &why));
    }
    try tmp.dir.writeFile(io, .{ .sub_path = "vmlinuz", .data = "tampered" });
    try testing.expectError(error.Refused, validate(io, gpa, images, manifest, dir, &why));
}
