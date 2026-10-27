//! admission signs a candidate's boot descriptor for a trusted lifecycle
//! job, keeping the signature only for a bundle howl then admits, and
//! checks that the public mirror serves exactly a published bundle.

const std = @import("std");
const mem = std.mem;
const json = @import("json.zig");
const Json = json.Json;
const sys = @import("sys.zig");
const Sys = sys.Sys;
const boot = @import("boot.zig");
const exporter = @import("exporter.zig");
const plan = @import("plan.zig");
const bd = @import("boot-download");

/// authorize signs bundle's boot.json with the protected image key and
/// keeps the signature only if native admission then accepts the bundle.
pub fn authorize(
    s: *Sys,
    tree: plan.Tree,
    howl: []const u8,
    provider: []const u8,
    bundle_dir: []const u8,
) !void {
    const bundle = try sys.resolve(s, bundle_dir);
    const signature = try sys.join(s, &.{ bundle, "boot.json.sig" });
    if ((!mem.eql(u8, provider, "lima") and !mem.eql(u8, provider, "qemu")) or
        sys.exists(s, signature))
        return s.refuse("invalid candidate authorization request", .{});
    const head_path = try sys.join(s, &.{ bundle, "boot.json" });
    const raw = try sys.readJson(s, head_path, boot.head_limit);
    const request = try boot.request(
        s,
        try sys.resolve(s, tree.trust),
        try json.text(raw, "form"),
        try json.text(try json.field(raw, "image"), "arch"),
        provider,
    );
    const key = s.getenv("WEREWOLF_PROTECTED_IMAGE_KEY") orelse return s.refuse(
        "WEREWOLF_PROTECTED_IMAGE_KEY is required",
        .{},
    );
    errdefer std.Io.Dir.cwd().deleteFile(s.io, signature) catch {};
    const r = try sys.exec(
        s,
        &.{ "openssl", "dgst", "-sha256", "-sign", key, "-out", signature, head_path },
        .{ .capture = .both },
    );
    if (!r.ok()) return s.refuse("candidate signing failed", .{});
    const manifest = try boot.native(s, howl, "head", bundle, request);
    _ = try boot.freshness(s, manifest, &try sys.sha(s, head_path), null, s.now());
    _ = try boot.native(s, howl, "verify", bundle, request);
}

/// Native is the Admission howl's _boot-image gives a download.
const Native = struct {
    s: *Sys,
    howl: []const u8,
    request: boot.Request,

    fn admission(n: *Native) bd.Admission {
        return .{ .context = n, .head = head, .verify = verify };
    }

    fn head(context: *anyopaque, gpa: std.mem.Allocator, directory: []const u8) anyerror!bd.Head {
        const n: *Native = @ptrCast(@alignCast(context));
        const manifest = try boot.native(n.s, n.howl, "head", directory, n.request);
        const text = try json.encode(gpa, manifest);
        return std.json.parseFromSliceLeaky(bd.Head, gpa, text, .{ .ignore_unknown_fields = true });
    }

    fn verify(context: *anyopaque, gpa: std.mem.Allocator, directory: []const u8) anyerror!void {
        _ = gpa;
        const n: *Native = @ptrCast(@alignCast(context));
        _ = try boot.native(n.s, n.howl, "verify", directory, n.request);
    }
};

/// checkMirror downloads the published channel afresh, as a consumer
/// would, and requires the very bundle expected and every public object
/// byte for byte the release assets attached to GitHub.
pub fn checkMirror(
    s: *Sys,
    tree: plan.Tree,
    howl: []const u8,
    expected_dir: []const u8,
    provider: []const u8,
    assets_dir: []const u8,
) !void {
    const expected = try sys.resolve(s, expected_dir);
    const trust = try sys.resolve(s, tree.trust);
    const image = try sys.readJson(
        s,
        try sys.join(s, &.{ expected, "boot.json" }),
        boot.head_limit,
    );
    const form = try json.text(image, "form");
    const arch = try json.text(try json.field(image, "image"), "arch");
    const request = try boot.request(s, trust, form, arch, provider);
    const cache = try sys.scratch(s, null, "ww-public-download-check-");
    defer sys.remove(s, cache);
    var https: bd.Https = undefined;
    try https.init(s.io, s.gpa, .{ .ca_file = s.getenv("SSL_CERT_FILE"), .environ = s.env });
    defer https.deinit();
    var native: Native = .{ .s = s, .howl = howl, .request = request };
    var fresh = request;
    fresh.cache = cache;
    const bundle = bd.download(
        s.io,
        s.gpa,
        fresh,
        native.admission(),
        https.transport(),
        "public-mirror-check",
        s.now(),
    ) catch |err| switch (err) {
        error.Refused => return err,
        else => return s.refuse("public download failed: {s}", .{bd.describe(err)}),
    };
    if (!mem.eql(
        u8,
        &try sys.sha(s, try sys.join(s, &.{ bundle, "boot.json" })),
        &try sys.sha(s, try sys.join(s, &.{ expected, "boot.json" })),
    ))
        return s.refuse("public mirror serves a different signed release", .{});
    const assets = try sys.resolve(s, assets_dir);
    const prefix = try s.gpa.print("{s}-{s}-{s}", .{ try s.variantKey(form), provider, arch });
    const report = try sys.readJson(
        s,
        try sys.join(s, &.{ assets, try s.gpa.print("{s}-gates.json", .{prefix}) }),
        64 << 10,
    );
    const signed = try exporter.verify(s, assets, expected, report, provider, trust);
    const base = try s.gpa.print(
        "{s}/{s}/{s}/{s}/objects/{s}",
        .{
            mem.trimEnd(u8, request.source, "/"),
            try s.variantPath(form),
            provider,
            arch,
            try json.text(signed, "descriptor"),
        },
    );
    // Check every public object against the very bytes attached to GitHub,
    // including both signature pairs and the standalone qcow2.
    var names: std.ArrayList([]const u8) = .empty;
    try names.appendSlice(s.gpa, (try json.object(try json.field(signed, "files"))).keys());
    try names.appendSlice(s.gpa, &.{ "downloads.json", "downloads.json.sig" });
    for (names.items) |name| {
        const original = try sys.record(
            s,
            try sys.join(s, &.{ assets, try s.gpa.print("{s}-{s}", .{ prefix, name }) }),
        );
        try sys.download(
            s,
            try s.gpa.print("{s}/{s}", .{ base, name }),
            try sys.join(s, &.{ cache, try s.gpa.print("check-{s}", .{name}) }),
            original.size,
            original,
        );
    }
}
