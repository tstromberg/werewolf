//! Protected image downloads take vendor trust from howl, never from the mirror.
const std = @import("std");
const howl = @import("howl.zig");
const files = @import("files");
const boot = @import("boot-image.zig");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

const Trust = struct {
    format: []const u8,
    source: []const u8,
};

/// trust is howl's embedded protected trust (release/protected/trust.json).
fn trust(gpa: Allocator) !Trust {
    const t = try std.json.parseFromSliceLeaky(Trust, gpa, files.protected_trust, .{});
    if (!std.mem.eql(u8, t.format, "werewolf-boot-trust/2")) return error.BadProtectedTrust;
    try @import("prebuilt").channel(t.source);
    return t;
}

/// channel is the update channel werewolf's published images of form for
/// provider follow: static files on its public mirror, which every machine
/// fetches for itself (docs/design/independent-updates.md).
pub fn channel(gpa: Allocator, form: []const u8, provider: howl.Platform) ![]const u8 {
    return gpa.print("{s}/{s}/{t}", .{ (try trust(gpa)).source, form, provider });
}

pub fn latest(
    io: Io,
    gpa: Allocator,
    form: []const u8,
    provider: howl.Platform,
    arch: howl.Arch,
    why: *howl.Why,
) !boot.Request {
    return selected(io, gpa, form, provider, arch, null, why);
}

pub fn selected(
    io: Io,
    gpa: Allocator,
    form: []const u8,
    provider: howl.Platform,
    arch: howl.Arch,
    version: ?[]const u8,
    why: *howl.Why,
) !boot.Request {
    if (!@import("form").isName(form)) return why.refuse(
        "protected downloads require a published form name; use --build for a custom image",
        .{},
    );
    if (provider != .lima and provider != .qemu) return error.BadSecuredProvider;
    const t = try trust(gpa);
    const root = "build/boot-download";
    try Dir.cwd().createDirPath(io, root);
    const script = root ++ "/boot-download";
    const code = root ++ "/boot.crt";
    const image = root ++ "/image.crt";
    try howl.writePrivate(io, gpa, script, files.boot_download, why);
    try howl.writePrivate(io, gpa, code, files.protected_boot_certificate, why);
    try howl.writePrivate(io, gpa, image, files.protected_image_certificate, why);
    const cwd = try std.process.currentPathAlloc(io, gpa);
    const config = try gpa.print("{s}/{s}/{s}-{t}-{t}.json", .{ cwd, root, form, provider, arch });
    const followed = try channel(gpa, form, provider);
    try howl.writePrivate(io, gpa, config, try std.json.Stringify.valueAlloc(gpa, .{
        .source = howl.environ.get("WEREWOLF_BOOT_MIRROR") orelse t.source,
        .cache = try gpa.print("{s}/build/boot-cache", .{cwd}),
        .boot_certificate = try gpa.print("{s}/{s}", .{ cwd, code }),
        .image_certificate = try gpa.print("{s}/{s}", .{ cwd, image }),
        .channel = followed,
        .form = form,
        .provider = @tagName(provider),
        .arch = @tagName(arch),
        .version = version,
    }, .{ .emit_null_optional_fields = false }), why);
    const result = try std.process.run(gpa, io, .{
        .argv = &.{ "python3", script, try std.process.executablePathAlloc(io, gpa), config },
        .stdout_limit = .limited(32 << 10),
        .stderr_limit = .limited(8192),
    });
    if (result.term != .exited or result.term.exited != 0) return why.refuse(
        "protected image download failed: {s}",
        .{std.mem.trim(u8, result.stderr, "\n ")},
    );
    const request = try std.json.parseFromSliceLeaky(boot.Request, gpa, result.stdout, .{});
    if (!std.mem.eql(u8, request.channel, followed)) return error.WrongImageChannel;
    return request;
}

pub fn validVersion(tag: []const u8) bool {
    const serial = std.mem.cutPrefix(u8, tag, "base-images-") orelse
        std.mem.cutPrefix(u8, tag, "protected-") orelse tag;
    if (serial.len != 16 or serial[8] != 'T' or serial[15] != 'Z') return false;
    for (serial, 0..) |c, i| {
        if (i != 8 and i != 15 and !std.ascii.isDigit(c)) return false;
    }
    return true;
}

/// versions lists releases carrying a complete bundle for one deployment target.
pub fn versions(io: Io, gpa: Allocator, args: []const []const u8, why: *howl.Why) !void {
    var form: []const u8 = "playground";
    var provider: ?howl.Platform = null;
    var arch = howl.hostArch();
    var json = false;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--json")) {
            json = true;
            continue;
        }
        if (std.mem.eql(u8, args[i], "-h") or std.mem.eql(u8, args[i], "--help")) {
            return Io.File.stdout().writeStreamingAll(
                io,
                "usage: howl versions [--with FORM] [--on qemu|lima] [--arch ARCH] [--json]\n" ++
                    "List base image releases; install with run/create --version SERIAL|TAG.\n",
            );
        }
        const flag, const value = try howl.flagValue(args, &i, why);
        if (std.mem.eql(u8, flag, "--with")) {
            form = value;
        } else if (std.mem.eql(u8, flag, "--on")) {
            provider = std.meta.stringToEnum(howl.Platform, value) orelse
                return why.refuse("--on {s}: versions supports qemu or lima", .{value});
        } else if (std.mem.eql(u8, flag, "--arch")) {
            arch = howl.archName(value) orelse return why.refuse(
                "unknown architecture {s}",
                .{value},
            );
        } else return why.refuse("{s}: versions takes --with, --on, --arch and --json", .{flag});
    }
    if (!@import("form").isName(form)) return why.refuse(
        "versions requires one published form name",
        .{},
    );
    const on = howl.engine(io, gpa, provider).on;
    if (on != .qemu and on != .lima) return why.refuse("versions supports qemu or lima", .{});
    const root = "build/boot-download";
    try Dir.cwd().createDirPath(io, root);
    const script = root ++ "/boot-download";
    try howl.writePrivate(io, gpa, script, files.boot_download, why);
    const target = @tagName(arch orelse return error.UnsupportedHostArch);
    const provider_name = @tagName(on);
    const format = if (json) "json" else "text";
    const result = try std.process.run(gpa, io, .{
        .argv = &.{ "python3", script, "versions", form, provider_name, target, format },
        .stdout_limit = .limited(1 << 20),
        .stderr_limit = .limited(8192),
    });
    if (result.term != .exited or result.term.exited != 0)
        return why.refuse(
            "image version discovery failed: {s}",
            .{std.mem.trim(u8, result.stderr, "\n ")},
        );
    try Io.File.stdout().writeStreamingAll(io, result.stdout);
}

test "image versions are release tags, never paths or URLs" {
    try std.testing.expect(validVersion("protected-20261014T232908Z"));
    try std.testing.expect(validVersion("base-images-20261014T232908Z"));
    try std.testing.expect(validVersion("20261014T232908Z"));
    for ([_][]const u8{ "", "latest", "protected-../x", "protected-20261014T232908Z/a" }) |tag|
        try std.testing.expect(!validVersion(tag));
}
