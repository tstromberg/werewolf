//! Protected image downloads take vendor trust from howl, never from the
//! mirror: lib/boot-download.zig fetches and boot-image.zig admits, here.
const std = @import("std");
const howl = @import("howl.zig");
const files = @import("files");
const boot = @import("boot-image.zig");
const fetching = @import("boot-download");
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

/// x86 bhyve boots the same signed native UEFI disk and follows its existing
/// channel. Do not rewrite signed metadata or manufacture a separate publisher.
fn imageProvider(provider: howl.Platform, arch: howl.Arch) !howl.Platform {
    return switch (provider) {
        .qemu, .lima => provider,
        .bhyve => if (arch == .x86_64) .qemu else error.UnsupportedProtection,
        else => error.BadSecuredProvider,
    };
}

test "bhyve downloads keep the published x86 UEFI channel and refuse unsupported targets" {
    try std.testing.expectEqual(howl.Platform.qemu, try imageProvider(.bhyve, .x86_64));
    try std.testing.expectEqual(howl.Platform.lima, try imageProvider(.lima, .aarch64));
    try std.testing.expectError(error.UnsupportedProtection, imageProvider(.bhyve, .aarch64));
    try std.testing.expectError(error.BadSecuredProvider, imageProvider(.firecracker, .x86_64));
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

/// Native admits what a download fetched as `howl _boot-image head` and
/// `verify` do for the release tools, in this process.
const Native = struct {
    io: Io,
    boot_certificate: []const u8,
    image_certificate: []const u8,
    channel: []const u8,
    arch: howl.Arch,
    form: []const u8,

    fn request(n: *const Native, directory: []const u8) boot.Request {
        return .{
            .directory = directory,
            .boot_certificate = n.boot_certificate,
            .image_certificate = n.image_certificate,
            .channel = n.channel,
        };
    }

    fn admission(n: *Native) fetching.Admission {
        return .{ .context = n, .head = head, .verify = verify };
    }

    fn head(context: *anyopaque, gpa: Allocator, directory: []const u8) anyerror!fetching.Head {
        const n: *Native = @ptrCast(@alignCast(context));
        const m = try boot.admitDeployment(n.io, gpa, n.request(directory), n.arch, n.form);
        return .{ .image = m.image, .disk = m.disk };
    }

    fn verify(context: *anyopaque, gpa: Allocator, directory: []const u8) anyerror!void {
        const n: *Native = @ptrCast(@alignCast(context));
        _ = try boot.verify(n.io, gpa, n.request(directory), n.arch);
    }
};

fn refuse(
    why: *howl.Why,
    comptime what: []const u8,
    err: anyerror,
    https: *const fetching.Https,
) error{Refused} {
    if (err == error.MirrorRefused) return why.refuse(what ++ ": {s} (HTTP {d})", .{
        fetching.describe(err), https.status,
    });
    return why.refuse(what ++ ": {s}", .{fetching.describe(err)});
}

fn connect(io: Io, gpa: Allocator, h: *fetching.Https) !void {
    try h.init(io, gpa, .{ .ca_file = howl.environ.get("SSL_CERT_FILE"), .environ = howl.environ });
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
    const published = try imageProvider(provider, arch);
    const t = try trust(gpa);
    const cwd = try std.process.currentPathAlloc(io, gpa);
    const root = try gpa.print("{s}/build/boot-download", .{cwd});
    try Dir.cwd().createDirPath(io, root);
    const code = try gpa.print("{s}/boot.crt", .{root});
    const image = try gpa.print("{s}/image.crt", .{root});
    try howl.writePrivate(io, gpa, code, files.protected_boot_certificate, why);
    try howl.writePrivate(io, gpa, image, files.protected_image_certificate, why);
    const followed = try channel(gpa, form, published);
    var native: Native = .{
        .io = io,
        .boot_certificate = code,
        .image_certificate = image,
        .channel = followed,
        .arch = arch,
        .form = form,
    };
    var h: fetching.Https = undefined;
    try connect(io, gpa, &h);
    defer h.deinit();
    // A bundle another howl admitted is admitted again.
    const self = try Dir.cwd().statFile(io, try std.process.executablePathAlloc(io, gpa), .{});
    const validator = try gpa.print("howl {d} {d} {d} {d}", .{
        self.inode, self.size, self.mtime.nanoseconds, self.ctime.nanoseconds,
    });
    const bundle = fetching.download(io, gpa, .{
        .source = howl.environ.get("WEREWOLF_BOOT_MIRROR") orelse t.source,
        .cache = try gpa.print("{s}/build/boot-cache", .{cwd}),
        .boot_certificate = code,
        .image_certificate = image,
        .channel = followed,
        .form = form,
        .provider = @tagName(published),
        .arch = @tagName(arch),
        .version = version,
    }, native.admission(), h.transport(), validator, @intCast(@divTrunc(
        Io.Clock.real.now(io).nanoseconds,
        std.time.ns_per_s,
    ))) catch |err| return refuse(why, "protected image download failed", err, &h);
    return native.request(bundle);
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
                "usage: howl versions [--with FORM] [--on qemu|lima|bhyve] [--arch ARCH] " ++
                    "[--json]\n" ++
                    "List base image releases; install with run/create --version SERIAL|TAG.\n",
            );
        }
        const flag, const value = try howl.flagValue(args, &i, why);
        if (std.mem.eql(u8, flag, "--with")) {
            form = value;
        } else if (std.mem.eql(u8, flag, "--on")) {
            provider = std.meta.stringToEnum(howl.Platform, value) orelse
                return why.refuse(
                    "--on {s}: versions supports qemu, lima or x86_64 bhyve",
                    .{value},
                );
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
    const published = imageProvider(on, arch orelse return error.UnsupportedHostArch) catch
        return why.refuse("versions supports qemu, lima or x86_64 bhyve", .{});
    const target = @tagName(arch orelse return error.UnsupportedHostArch);
    const root = "build/boot-download";
    try Dir.cwd().createDirPath(io, root);
    var h: fetching.Https = undefined;
    try connect(io, gpa, &h);
    defer h.deinit();
    const tags = fetching.versions(
        io,
        gpa,
        h.transport(),
        root,
        form,
        @tagName(published),
        target,
    ) catch |err|
        return refuse(why, "image version discovery failed", err, &h);
    var out: Io.Writer.Allocating = .init(gpa);
    if (json) {
        try std.json.Stringify.value(.{
            .form = form,
            .provider = @tagName(on),
            .arch = target,
            .versions = tags,
        }, .{}, &out.writer);
        try out.writer.writeByte('\n');
    } else if (tags.len == 0) {
        try out.writer.print("No published base image versions for {s}/{t}/{s}.\n", .{
            form, on, target,
        });
    } else for (tags) |t| try out.writer.print("{s}\n", .{t});
    try Io.File.stdout().writeStreamingAll(io, out.written());
}

const testing = std.testing;
const prebuilt = @import("prebuilt");

/// Publisher signs heads as the vendor would, and serves them and their
/// artifacts from memory, with faults, as a mirror.
const Publisher = struct {
    gpa: Allocator,
    io: Io,
    root: []const u8,
    manifest: boot.Manifest,
    payloads: std.StringArrayHashMapUnmanaged([]const u8) = .empty,
    calls: std.ArrayList([]const u8) = .empty,
    urls: std.ArrayList([]const u8) = .empty,
    verifications: usize = 0,
    /// fault names a file served torn, or "verify".
    fault: ?[]const u8 = null,
    /// unrenamed serves no base-images- release, as before the rename.
    unrenamed: bool = false,
    native: Native,
    request: fetching.Request,
    validator: []const u8 = "test-validator",
    now: i64,

    fn init(gpa: Allocator, root: []const u8) !*Publisher {
        const io = testing.io;
        for ([_][]const u8{ "vendor", "foreign" }) |name| try run(gpa, &.{
            "openssl",                                     "req",
            "-newkey",                                     "rsa:2048",
            "-nodes",                                      "-x509",
            "-sha256",                                     "-days",
            "2",                                           "-subj",
            "/CN=werewolf-download-test",                  "-keyout",
            try gpa.print("{s}/{s}.key", .{ root, name }), "-out",
            try gpa.print("{s}/{s}.crt", .{ root, name }),
        });
        const cert = try gpa.print("{s}/vendor.crt", .{root});
        const followed = "https://vendor.test/boot/v1/playground/lima";
        const fixture = try Dir.cwd().readFileAlloc(
            io,
            "lib/testdata/prebuilt/image.json",
            gpa,
            .limited(1 << 20),
        );
        var image = try std.json.parseFromSliceLeaky(prebuilt.Manifest, gpa, fixture, .{});
        image.arch = "aarch64";
        image.channel = followed;
        image.index = 1;
        image.channel_id = try gpa.dupe(
            u8,
            &std.fmt.bytesToHex(prebuilt.channelId(followed), .lower),
        );
        image.serial = "20261013T000000Z";
        const p = try gpa.create(Publisher);
        p.* = .{
            .gpa = gpa,
            .io = io,
            .root = root,
            .manifest = undefined,
            .native = .{
                .io = io,
                .boot_certificate = cert,
                .image_certificate = cert,
                .channel = followed,
                .arch = .aarch64,
                .form = "playground",
            },
            .request = .{
                .source = "https://vendor.test/boot/v1",
                .cache = try gpa.print("{s}/cache", .{root}),
                .boot_certificate = cert,
                .image_certificate = cert,
                .channel = followed,
                .form = "playground",
                .arch = "aarch64",
                .provider = "lima",
            },
            .now = try @import("update-policy").parseSerial("20261013T010000Z"),
        };
        inline for (prebuilt.names) |name| {
            const raw = "fixture:" ++ name;
            try p.payloads.put(gpa, name, raw);
            @field(image.files, name) = try prebuilt.hashBytes(gpa, raw);
        }
        image.build = try gpa.dupe(u8, &prebuilt.buildId(image.files));
        const disk = "compressed-disk-fixture";
        try p.payloads.put(gpa, "disk.img.zst", disk);
        const der = try capture(gpa, &.{ "openssl", "x509", "-in", cert, "-outform", "DER" });
        p.manifest = .{
            .form = "playground",
            .image = image,
            .disk = try prebuilt.hashBytes(gpa, disk),
            .raw_size = 8 << 30,
            .boot_certificate = (try prebuilt.hashBytes(gpa, der)).sha256,
            .configuration = try std.json.parseFromSliceLeaky(
                @import("boot-config.zig").Definition,
                gpa,
                "{\"form\":\"playground\",\"interface\":{\"files\":[],\"settings\":[]}," ++
                    "\"ports\":[22],\"dhcp\":true,\"ssh\":\"files\",\"lima_managed\":true}",
                .{},
            ),
        };
        try p.publish("vendor");
        return p;
    }

    fn run(gpa: Allocator, argv: []const []const u8) !void {
        _ = try capture(gpa, argv);
    }

    fn capture(gpa: Allocator, argv: []const []const u8) ![]const u8 {
        const result = try std.process.run(gpa, testing.io, .{ .argv = argv });
        if (result.term != .exited or result.term.exited != 0) return error.CommandFailed;
        return result.stdout;
    }

    /// publish signs the manifest's head with signer's key and serves it.
    fn publish(p: *Publisher, signer: []const u8) !void {
        const bytes = try std.json.Stringify.valueAlloc(p.gpa, p.manifest, .{});
        const path = try p.gpa.print("{s}/head", .{p.root});
        try Dir.cwd().writeFile(p.io, .{ .sub_path = path, .data = bytes });
        const sig = try p.gpa.print("{s}/signature", .{p.root});
        try run(p.gpa, &.{
            "openssl",                                           "dgst", "-sha256", "-sign",
            try p.gpa.print("{s}/{s}.key", .{ p.root, signer }), "-out", sig,       path,
        });
        try p.payloads.put(p.gpa, "boot.json", bytes);
        try p.payloads.put(
            p.gpa,
            "boot.json.sig",
            try Dir.cwd().readFileAlloc(p.io, sig, p.gpa, .limited(4096)),
        );
        try p.payloads.put(
            p.gpa,
            "latest.json",
            try std.json.Stringify.valueAlloc(p.gpa, p.manifest.image, .{}),
        );
        try p.payloads.put(p.gpa, "latest.json.sig", "fixture");
    }

    fn fetch(
        context: *anyopaque,
        url: []const u8,
        path: []const u8,
        limit: u64,
        expected: ?prebuilt.Artifact,
    ) anyerror!void {
        _ = expected;
        const p: *Publisher = @ptrCast(@alignCast(context));
        try p.urls.append(p.gpa, try p.gpa.dupe(u8, url));
        if (p.unrenamed and
            std.mem.find(u8, url, "/base-images-") != null) return error.NotPublished;
        var name = url[std.mem.findScalarLast(u8, url, '/').? + 1 ..];
        if (std.mem.find(u8, url, "/releases/download/") != null)
            name = std.mem.cutPrefix(u8, name, "playground-lima-aarch64-").?;
        try p.calls.append(p.gpa, name);
        const raw = p.payloads.get(name) orelse return error.NotPublished;
        if (p.fault) |f| if (std.mem.eql(u8, f, name)) {
            try Dir.cwd().writeFile(p.io, .{ .sub_path = path, .data = raw[0..1] });
            return error.Interrupted;
        };
        if (raw.len > limit) return error.TooLarge;
        const file = try Dir.cwd().createFile(p.io, path, .{ .exclusive = true });
        defer file.close(p.io);
        try file.writeStreamingAll(p.io, raw);
    }

    fn head(context: *anyopaque, gpa: Allocator, directory: []const u8) anyerror!fetching.Head {
        const p: *Publisher = @ptrCast(@alignCast(context));
        return Native.head(&p.native, gpa, directory);
    }

    /// verify stands in for the PE and disk admission boot-image.zig tests.
    fn verify(context: *anyopaque, gpa: Allocator, directory: []const u8) anyerror!void {
        _ = gpa;
        _ = directory;
        const p: *Publisher = @ptrCast(@alignCast(context));
        p.verifications += 1;
        if (p.fault) |f| if (std.mem.eql(u8, f, "verify")) return error.PeAdmissionRefused;
    }

    fn download(p: *Publisher, at: i64) ![]const u8 {
        return fetching.download(
            p.io,
            p.gpa,
            p.request,
            .{ .context = p, .head = head, .verify = verify },
            .{ .context = p, .fetch = fetch },
            p.validator,
            at,
        );
    }

    /// floors are the channels' saved floors.
    fn floors(p: *Publisher) ![]const []const u8 {
        var out: std.ArrayList([]const u8) = .empty;
        const channels = try p.gpa.print("{s}/channels", .{p.request.cache});
        var dir = Dir.cwd().openDir(p.io, channels, .{ .iterate = true }) catch return out.items;
        defer dir.close(p.io);
        var it = dir.iterate();
        while (try it.next(p.io)) |entry| {
            const floor = try p.gpa.print("{s}/{s}/floor.json", .{ channels, entry.name });
            if (Dir.cwd().access(p.io, floor, .{})) |_| try out.append(p.gpa, floor) else |_| {}
        }
        return out.items;
    }

    fn read(p: *Publisher, path: []const u8) ![]const u8 {
        return Dir.cwd().readFileAlloc(p.io, path, p.gpa, .limited(1 << 20));
    }

    fn expectCalls(p: *Publisher, want: []const []const u8) !void {
        try testing.expectEqual(want.len, p.calls.items.len);
        for (want, p.calls.items) |w, got| try testing.expectEqualStrings(w, got);
    }
};

fn scratch(gpa: Allocator, tmp: *testing.TmpDir) ![]const u8 {
    return tmp.dir.realPathFileAlloc(testing.io, ".", gpa);
}

test "a fresh channel is asked nothing again, and a newer head reuses every artifact" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const p = try Publisher.init(gpa, try scratch(gpa, &tmp));
    const first = try p.download(p.now);
    const count = p.calls.items.len;
    try testing.expectEqualStrings(first, try p.download(p.now));
    try testing.expectEqual(count, p.calls.items.len);
    try testing.expectEqual(1, p.verifications);
    // The slot is the signed release alone: no host-computed release id or PCR 11.
    var slot = try Dir.cwd().openDir(
        p.io,
        try gpa.print("{s}/slot", .{first}),
        .{ .iterate = true },
    );
    defer slot.close(p.io);
    var it = slot.iterate();
    var n: usize = 0;
    while (try it.next(p.io)) |entry| : (n += 1) for (prebuilt.names) |name| {
        if (std.mem.eql(u8, name, entry.name)) break;
    } else return error.TestUnexpectedResult;
    try testing.expectEqual(prebuilt.names.len, n);
    const a = try Dir.cwd().statFile(p.io, try gpa.print("{s}/slot/vmlinuz", .{first}), .{});
    const b = try Dir.cwd().statFile(p.io, try gpa.print("{s}/prebuilt/aarch64/{s}/vmlinuz", .{
        first, p.manifest.image.build,
    }), .{});
    try testing.expectEqual(a.inode, b.inode);

    p.calls.clearRetainingCapacity();
    p.manifest.image.serial = "20261013T010000Z";
    try p.publish("vendor");
    const newer = try p.download(p.now + 301);
    try p.expectCalls(&.{ "boot.json.sig", "boot.json", "latest.json", "latest.json.sig" });
    const floors = try p.floors();
    try testing.expectEqual(1, floors.len);
    try testing.expect(std.mem.find(u8, try p.read(floors[0]), "20261013T010000Z") != null);

    // A changed cache file, a new validator or a short receipt admits again.
    try Dir.cwd().writeFile(p.io, .{
        .sub_path = try gpa.print("{s}/boot.json.sig", .{newer}),
        .data = try p.read(try gpa.print("{s}/boot.json.sig", .{newer})),
    });
    _ = try p.download(p.now + 301);
    try testing.expectEqual(3, p.verifications);
    p.validator = "new-validator";
    const again = try p.download(p.now + 301);
    try testing.expectEqual(4, p.verifications);
    const receipt = try gpa.print("{s}/complete.json", .{again});
    const text = try p.read(receipt);
    const cut = std.mem.find(u8, text, "\"slot/uki.efi\"").?;
    const end = std.mem.findScalarPos(u8, text, cut, '}').? + 1;
    try testing.expectEqual(',', text[end]);
    try Dir.cwd().writeFile(p.io, .{
        .sub_path = receipt,
        .data = try std.mem.concat(gpa, u8, &.{ text[0..cut], text[end + 1 ..] }),
    });
    _ = try p.download(p.now + 301);
    try testing.expectEqual(5, p.verifications);
}

test "explicit versions keep the latest floor, and old serials find old tags" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const p = try Publisher.init(gpa, try scratch(gpa, &tmp));
    const latest_bundle = try p.download(p.now);
    const latest_floor = (try p.floors())[0];
    const original = try p.read(latest_floor);
    p.request.version = "base-images-20261012T000000Z";
    p.manifest.image.serial = "20261012T000000Z";
    try p.publish("vendor");
    const old = try p.download(p.now);
    try testing.expect(!std.mem.eql(u8, latest_bundle, old));
    try testing.expectEqualStrings(original, try p.read(latest_floor));
    try testing.expectEqual(2, (try p.floors()).len);
    for (p.urls.items) |url| {
        if (std.mem.find(
            u8,
            url,
            "/releases/download/base-images-20261012T000000Z/",
        ) != null) break;
    } else return error.TestUnexpectedResult;
    const count = p.calls.items.len;
    try testing.expectEqualStrings(old, try p.download(p.now));
    try testing.expectEqual(count, p.calls.items.len);
    p.request.version = null;
    p.manifest.image.serial = "20261013T010000Z";
    try p.publish("vendor");
    _ = try p.download(p.now + 301);
    try testing.expect(std.mem.find(u8, try p.read(latest_floor), "20261013T010000Z") != null);

    // A serial falls back to protected-SERIAL only when base-images-SERIAL is absent.
    p.urls.clearRetainingCapacity();
    p.unrenamed = true;
    p.request.version = "20261013T000000Z";
    p.manifest.image.serial = "20261013T000000Z";
    try p.publish("vendor");
    _ = try p.download(p.now);
    try testing.expect(std.mem.find(u8, p.urls.items[0], "/base-images-20261013T000000Z/") != null);
    for (p.urls.items[1..]) |url|
        try testing.expect(std.mem.find(u8, url, "/protected-20261013T000000Z/") != null);

    p.calls.clearRetainingCapacity();
    for ([_][]const u8{
        "",
        "latest",
        "../older",
        "https://foreign.test/image",
        "base-images-20261013T000000Z/../other",
    }) |v| {
        p.request.version = v;
        try testing.expect(std.meta.isError(p.download(p.now)));
    }
    try p.expectCalls(&.{});
}

test "foreign, altered or mismatched heads fetch no artifacts and set no floor" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const p = try Publisher.init(gpa, try scratch(gpa, &tmp));
    try p.publish("foreign");
    try testing.expectError(error.BadSignature, p.download(p.now));
    try p.publish("vendor");
    try p.payloads.put(gpa, "boot.json", try gpa.print("{s} ", .{p.payloads.get("boot.json").?}));
    try testing.expectError(error.BadSignature, p.download(p.now));
    p.request.version = "protected-20261013T000000Z";
    try p.publish("foreign");
    try testing.expectError(error.BadSignature, p.download(p.now));
    p.request.version = null;
    const original = p.manifest;
    // The provider is part of the signed channel a release belongs to.
    const qemu = "https://vendor.test/boot/v1/playground/qemu";
    p.manifest.image.channel = qemu;
    p.manifest.image.channel_id = try gpa.dupe(
        u8,
        &std.fmt.bytesToHex(prebuilt.channelId(qemu), .lower),
    );
    try p.publish("vendor");
    try testing.expectError(error.WrongImageChannel, p.download(p.now));
    p.manifest = original;
    p.manifest.form = "prod";
    p.manifest.configuration.?.form = "prod";
    try p.publish("vendor");
    try testing.expectError(error.WrongBootForm, p.download(p.now));
    p.manifest = original;
    p.manifest.configuration = null;
    try p.publish("vendor");
    try testing.expectError(error.MissingDeploymentDefinition, p.download(p.now));
    p.manifest = original;
    p.manifest.configuration.?.form = "prod";
    try p.publish("vendor");
    try testing.expectError(error.BadDeploymentDefinition, p.download(p.now));
    for (0..7) |i| {
        try testing.expectEqualStrings("boot.json.sig", p.calls.items[2 * i]);
        try testing.expectEqualStrings("boot.json", p.calls.items[2 * i + 1]);
    }
    try testing.expectEqual(14, p.calls.items.len);
    try testing.expectEqual(0, (try p.floors()).len);

    // An image signature and signed code cannot stand in for a boot signature.
    p.manifest = original;
    try p.publish("vendor");
    const candidate = try gpa.print("{s}/unsigned-candidate", .{p.root});
    try Dir.cwd().createDirPath(p.io, try gpa.print("{s}/prebuilt/aarch64", .{candidate}));
    for ([_][2][]const u8{
        .{ "boot.json", "boot.json" },
        .{ "prebuilt/aarch64/latest.json", "latest.json" },
        .{ "prebuilt/aarch64/latest.json.sig", "boot.json.sig" },
    }) |file| try Dir.cwd().writeFile(p.io, .{
        .sub_path = try gpa.print("{s}/{s}", .{ candidate, file[0] }),
        .data = p.payloads.get(file[1]).?,
    });
    try testing.expectError(error.FileNotFound, Native.head(&p.native, gpa, candidate));
    try Dir.cwd().writeFile(p.io, .{
        .sub_path = try gpa.print("{s}/boot.json.sig", .{candidate}),
        .data = p.payloads.get("boot.json.sig").?,
    });
    try testing.expectEqualStrings(
        p.manifest.image.build,
        (try Native.head(&p.native, gpa, candidate)).image.build,
    );
}

test "torn transfers, refused bundles and tampered artifacts leave the floor" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const p = try Publisher.init(gpa, try scratch(gpa, &tmp));
    const forged = p.payloads.get("root.erofs").?;
    try p.payloads.put(gpa, "root.erofs", "forged artifact");
    try testing.expectError(error.UnauthenticatedObject, p.download(p.now));
    try testing.expectEqual(0, p.verifications);
    try testing.expectEqual(0, (try p.floors()).len);
    try p.payloads.put(gpa, "root.erofs", forged);
    p.fault = "disk.img.zst";
    try testing.expectError(error.Interrupted, p.download(p.now));
    p.fault = "verify";
    try testing.expectError(error.PeAdmissionRefused, p.download(p.now));
    try testing.expectEqual(0, (try p.floors()).len);
    var cache = try Dir.cwd().openDir(p.io, p.request.cache, .{ .iterate = true });
    defer cache.close(p.io);
    var walker = try cache.walk(gpa);
    while (try walker.next(p.io)) |entry|
        try testing.expect(!std.mem.endsWith(u8, entry.basename, ".part"));
    p.fault = null;
    const bundle = try p.download(p.now);
    try testing.expectEqual(1, (try p.floors()).len);

    // A torn latest head keeps the last verified bundle and floor.
    const floor = (try p.floors())[0];
    const original = try p.read(floor);
    p.manifest.image.serial = "20261013T010000Z";
    try p.publish("vendor");
    try p.payloads.put(gpa, "boot.json", try gpa.print("{s} ", .{p.payloads.get("boot.json").?}));
    try testing.expectError(error.BadSignature, p.download(p.now + 301));
    try testing.expectEqualStrings(original, try p.read(floor));
    try testing.expect(fetching.complete(p.io, gpa, bundle, p.validator));
}

test "the floor never lowers, for older heads, reused serials or other mirrors" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const p = try Publisher.init(gpa, try scratch(gpa, &tmp));
    const saved = p.request;
    _ = try p.download(p.now);
    const floor = (try p.floors())[0];
    const original = try p.read(floor);
    for ([_]struct { []const u8, anyerror }{
        .{ "20261012T000000Z", error.OlderBootRelease },
        .{ "20261013T000000Z", error.ReusedBootSerial },
    }) |case| {
        p.manifest.image.serial = case[0];
        p.manifest.image.index = 2;
        try p.publish("vendor");
        try testing.expectError(case[1], p.download(p.now + 301));
        try testing.expectEqualStrings(original, try p.read(floor));
    }
    // A mirror serves werewolf's channel; the floor is the channel's.
    p.manifest.image.index = 1;
    p.request.source = "https://other-mirror.test/boot/v1";
    p.manifest.image.serial = "20261012T000000Z";
    try p.publish("vendor");
    try testing.expectError(error.OlderBootRelease, p.download(p.now + 301));
    try testing.expectEqualStrings(original, try p.read(floor));
    // Nor can a mirror's own channel take releases signed for werewolf's.
    p.request.channel = "https://other-mirror.test/boot/v1/playground/lima";
    p.native.channel = p.request.channel;
    try testing.expectError(error.WrongImageChannel, p.download(p.now + 301));
    try testing.expectEqual(1, (try p.floors()).len);

    // A corrupt or missing floor refuses before anything is fetched.
    p.request = saved;
    p.native.channel = saved.channel;
    p.calls.clearRetainingCapacity();
    try Dir.cwd().writeFile(p.io, .{ .sub_path = floor, .data = "{}" });
    try testing.expectError(error.BadSavedFloor, p.download(p.now));
    try Dir.cwd().deleteFile(p.io, floor);
    try testing.expectError(error.MissingSavedFloor, p.download(p.now));
    try p.expectCalls(&.{});

    p.request.cache = try gpa.print("{s}/future", .{p.root});
    p.manifest.image.serial = "20261015T000000Z";
    try p.publish("vendor");
    try testing.expectError(error.FutureBootRelease, p.download(p.now));
    for ([_][]const u8{
        "http://vendor.test/",
        "https://user:pass@vendor.test/",
        "https://vendor.test/?key=secret",
    }) |source| {
        p.request.source = source;
        try testing.expectError(error.BadDownloadSource, p.download(p.now));
    }
}
