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
    permit_port: u16,
};

pub fn latest(
    io: Io,
    gpa: Allocator,
    form: []const u8,
    provider: howl.Platform,
    arch: howl.Arch,
    why: *howl.Why,
) !boot.Request {
    if (!@import("form").isName(form)) return why.refuse(
        "protected downloads require a published form name; use --build for a custom image",
        .{},
    );
    if (provider != .lima and provider != .qemu) return error.BadSecuredProvider;
    const trust = try std.json.parseFromSliceLeaky(Trust, gpa, files.protected_trust, .{});
    if (!std.mem.eql(u8, trust.format, "werewolf-boot-trust/1") or trust.permit_port == 0)
        return error.BadProtectedTrust;
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
    const channel = try gpa.print("https://{s}:{d}/{s}", .{
        if (provider == .lima) "192.168.5.2" else "10.0.2.2", trust.permit_port, form,
    });
    try howl.writePrivate(io, gpa, config, try std.json.Stringify.valueAlloc(gpa, .{
        .source = howl.environ.get("WEREWOLF_BOOT_MIRROR") orelse trust.source,
        .cache = try gpa.print("{s}/build/boot-cache", .{cwd}),
        .boot_certificate = try gpa.print("{s}/{s}", .{ cwd, code }),
        .image_certificate = try gpa.print("{s}/{s}", .{ cwd, image }),
        .channel = channel,
        .form = form,
        .provider = @tagName(provider),
        .arch = @tagName(arch),
    }, .{}), why);
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
    if (!std.mem.eql(u8, request.channel, channel)) return error.WrongImageChannel;
    return request;
}
