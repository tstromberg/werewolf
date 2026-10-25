//! published is what the checks of published images share: a private
//! HTTPS mirror laid out as the public one is, the release flow's table of
//! published forms and targets (release/images.yaml), and a running
//! release's identity.

const std = @import("std");
const builtin = @import("builtin");
const host = @import("host");
const form = @import("form");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const mem = std.mem;
const json = std.json;

/// Images is release/images.yaml, the release flow's table: the forms it
/// publishes, its boot profiles, and the providers each architecture has
/// images for.
pub const Images = struct {
    forms: []const []const u8,
    profiles: []const []const u8,
    arches: []const Arch,

    pub const Arch = struct { name: []const u8, providers: []const []const u8 };

    pub const path = "release/images.yaml";

    /// load reads the table from the checkout the check runs in.
    pub fn load(io: Io, gpa: Allocator) !Images {
        return parse(gpa, try Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(1 << 20)));
    }

    pub fn parse(gpa: Allocator, yaml: []const u8) !Images {
        var diag: form.Diagnostic = .{};
        const root = form.parse(gpa, yaml, &diag) catch |err| {
            std.log.err("{s}:{d}: {s}", .{ path, diag.line, diag.why });
            return err;
        };
        const arches = root.get("arches") orelse return error.BadImageTable;
        if (arches != .map) return error.BadImageTable;
        var out: std.ArrayList(Arch) = .empty;
        for (arches.map) |e| try out.append(gpa, .{
            .name = e.key,
            .providers = try names(gpa, e.value.get("providers")),
        });
        return .{
            .forms = try names(gpa, root.get("forms")),
            .profiles = try names(gpa, root.get("profiles")),
            .arches = out.items,
        };
    }

    fn names(gpa: Allocator, node: ?form.Node) ![]const []const u8 {
        const list = node orelse return error.BadImageTable;
        if (list != .list) return error.BadImageTable;
        var out: std.ArrayList([]const u8) = .empty;
        for (list.list) |item| {
            if (item != .scalar) return error.BadImageTable;
            try out.append(gpa, item.scalar.text);
        }
        return out.items;
    }

    /// providers are those arch has images for; none for an arch the
    /// table does not name.
    pub fn providers(t: Images, arch: []const u8) []const []const u8 {
        for (t.arches) |a| if (mem.eql(u8, a.name, arch)) return a.providers;
        return &.{};
    }

    pub fn isForm(t: Images, name: []const u8) bool {
        return contains(t.forms, name);
    }

    pub fn isArch(t: Images, arch: []const u8) bool {
        for (t.arches) |a| if (mem.eql(u8, a.name, arch)) return true;
        return false;
    }

    /// isTarget is whether form/provider/arch names an image the catalog
    /// may list: a form name, [a-z][a-z0-9-]{0,63}, on a provider its
    /// architecture has.
    pub fn isTarget(t: Images, name: []const u8, provider: []const u8, arch: []const u8) bool {
        if (name.len == 0 or name.len > 64 or !std.ascii.isLower(name[0])) return false;
        for (name) |c|
            if (!std.ascii.isLower(c) and !std.ascii.isDigit(c) and c != '-') return false;
        return contains(t.providers(arch), provider);
    }
};

fn contains(list: []const []const u8, want: []const u8) bool {
    for (list) |x| if (mem.eql(u8, x, want)) return true;
    return false;
}

/// Mirror serves a directory over HTTPS on loopback, as the public mirror
/// serves its tree, with a certificate of an authority made for the run.
pub const Mirror = struct {
    io: Io,
    root: Io.Dir,
    files: host.http.Files,
    server: host.http.Server,
    /// authority is what a client must trust, as PEM.
    authority: []const u8,

    /// start serves dir. m must not move until stop; gpa, an arena safe
    /// to use from several threads, outlives it.
    pub fn start(m: *Mirror, io: Io, gpa: Allocator, dir: []const u8, name: []const u8) !void {
        const ca = try host.tls.Authority.init(io, gpa, name);
        const identity = try gpa.create(host.tls.Identity);
        identity.* = try ca.issue(io, gpa, &.{"127.0.0.1"});
        m.* = .{
            .io = io,
            .root = try Io.Dir.cwd().openDir(io, dir, .{}),
            .files = undefined,
            .server = undefined,
            .authority = try ca.pem(gpa),
        };
        m.files = .{ .io = io, .gpa = gpa, .root = m.root };
        try m.server.start(io, gpa, .{ .identity = identity, .handler = m.files.handler() });
    }

    pub fn url(m: *const Mirror, gpa: Allocator) ![]const u8 {
        return gpa.print("https://127.0.0.1:{d}", .{m.server.port()});
    }

    /// requests is how many requests the mirror has had.
    pub fn requests(m: *Mirror, gpa: Allocator) !usize {
        return (try m.files.asked(gpa)).len;
    }

    pub fn stop(m: *Mirror) void {
        m.server.stop();
        m.root.close(m.io);
    }
};

/// stock links a bundle's objects into base/objects/DESCRIPTOR, as the
/// release flow publishes them, and returns the descriptor: the SHA-256
/// of its boot.json.
pub fn stock(
    io: Io,
    gpa: Allocator,
    bundle: []const u8,
    base: []const u8,
    arch: []const u8,
) ![64]u8 {
    const descriptor = try host.check.hexDigest(io, try join(gpa, bundle, "boot.json"));
    const objects = try std.fs.path.join(gpa, &.{ base, "objects", &descriptor });
    try Io.Dir.cwd().createDirPath(io, objects);
    const prebuilt = try gpa.print("prebuilt/{s}/", .{arch});
    for ([_][]const u8{
        "slot/vmlinuz",
        "slot/root.erofs",
        "slot/stage0.zst",
        "slot/cmdline",
        "slot/uki.efi",
        "disk.img.zst",
        try gpa.print("{s}latest.json", .{prebuilt}),
        try gpa.print("{s}latest.json.sig", .{prebuilt}),
    }) |name| try Io.Dir.cwd().hardLink(
        try join(gpa, bundle, name),
        .cwd(),
        try join(gpa, objects, std.fs.path.basename(name)),
        io,
        .{},
    );
    return descriptor;
}

/// promote makes bundle's signed head the mirror's latest: its signature
/// first, each replaced whole, as a publisher uploads it.
pub fn promote(io: Io, gpa: Allocator, bundle: []const u8, latest: []const u8) !void {
    for ([_][]const u8{ "boot.json.sig", "boot.json" }) |name| {
        const incoming = try gpa.print("{s}/{s}.new", .{ latest, name });
        try Io.Dir.cwd().copyFile(try join(gpa, bundle, name), .cwd(), incoming, io, .{});
        try Io.Dir.cwd().rename(incoming, .cwd(), try join(gpa, latest, name), io);
    }
}

fn join(gpa: Allocator, a: []const u8, b: []const u8) ![]const u8 {
    return std.fs.path.join(gpa, &.{ a, b });
}

/// temporary makes a new private directory under /tmp, whose short path
/// keeps QEMU's and Lima's sockets within the Unix path limit.
pub fn temporary(io: Io, gpa: Allocator, prefix: []const u8) ![]const u8 {
    while (true) {
        var id: [6]u8 = undefined;
        io.random(&id);
        const dir = try gpa.print("/tmp/{s}{s}", .{ prefix, &std.fmt.bytesToHex(id, .lower) });
        Io.Dir.cwd().createDir(io, dir, .fromMode(0o700)) catch |err| switch (err) {
            error.PathAlreadyExists => continue,
            else => |e| return e,
        };
        return dir;
    }
}

/// private makes what this process and its children create private.
pub fn private() void {
    if (builtin.os.tag == .linux)
        _ = std.os.linux.syscall1(.umask, 0o077)
    else
        _ = std.c.umask(0o077);
}

/// field is v's member key, if v is an object with one.
pub fn field(v: json.Value, key: []const u8) ?json.Value {
    return if (v == .object) v.object.get(key) else null;
}

/// isTrue is whether v is JSON true.
pub fn isTrue(v: ?json.Value) bool {
    const x = v orelse return false;
    return x == .bool and x.bool;
}

/// text is v's string member key, or null.
pub fn text(v: json.Value, key: []const u8) ?[]const u8 {
    const s = field(v, key) orelse return null;
    return if (s == .string) s.string else null;
}

/// missing lists the required checks that did not pass, with their
/// results, for a refusal to quote.
pub fn missing(
    gpa: Allocator,
    checks: host.evidence.Results,
    required: []const []const u8,
) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (required) |id| {
        const result = checks.get(id) orelse "absent";
        if (mem.eql(u8, result, "pass")) continue;
        try out.print(gpa, "{s}{s}={s}", .{ if (out.items.len > 0) ", " else "", id, result });
    }
    return out.items;
}

/// vendorFree is whether a machine's profile.json holds no vendor signing
/// key: a consumer boots what the vendor signed.
pub fn vendorFree(profile: json.Value) bool {
    const spec = field(profile, "spec") orelse return false;
    const boot_key = field(spec, "boot_key") orelse return false;
    const ipe_key = field(spec, "ipe_key") orelse return false;
    return boot_key == .null and ipe_key == .null;
}

/// bundleDirectory is where a machine's profile.json says its downloaded
/// bundle is.
pub fn bundleDirectory(profile: json.Value) ?[]const u8 {
    return text(field(profile, "bundle") orelse return null, "directory");
}

test "targets are the published forms on their architecture's providers" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const t = try Images.load(std.testing.io, arena.allocator());
    try std.testing.expect(t.isTarget("prod-ssh", "qemu", "x86_64"));
    try std.testing.expect(t.isTarget("playground", "lima", "aarch64"));
    try std.testing.expect(!t.isTarget("playground", "lima", "x86_64"));
    try std.testing.expect(!t.isTarget("Prod", "qemu", "x86_64"));
    try std.testing.expect(!t.isTarget("1x", "qemu", "aarch64"));
    try std.testing.expect(!t.isTarget("minimal", "qemu", "riscv64"));
    try std.testing.expect(t.isForm("minimal") and !t.isForm("sshd"));
    try std.testing.expect(t.isArch("x86_64") and !t.isArch("riscv64"));
    try std.testing.expect(contains(t.profiles, "legacy-boot"));
}

test "a consumer's profile holds no vendor key" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const parse = struct {
        fn f(a: Allocator, s: []const u8) !json.Value {
            return json.parseFromSliceLeaky(json.Value, a, s, .{});
        }
    }.f;
    const good = try parse(gpa, "{\"spec\":{\"boot_key\":null,\"ipe_key\":null}," ++
        "\"bundle\":{\"directory\":\"/d\"}}");
    try std.testing.expect(vendorFree(good));
    try std.testing.expectEqualStrings("/d", bundleDirectory(good).?);
    const keyed = "{\"spec\":{\"boot_key\":\"k\",\"ipe_key\":null}}";
    try std.testing.expect(!vendorFree(try parse(gpa, keyed)));
    try std.testing.expect(!vendorFree(try parse(gpa, "{\"spec\":{\"boot_key\":null}}")));
    try std.testing.expect(!vendorFree(try parse(gpa, "{}")));
}

test "the mirror serves a stocked bundle over TLS and counts requests" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", gpa);
    for ([_][]const u8{
        "bundle/slot/vmlinuz",                "bundle/slot/root.erofs",
        "bundle/slot/stage0.zst",             "bundle/slot/cmdline",
        "bundle/slot/uki.efi",                "bundle/disk.img.zst",
        "bundle/prebuilt/x86_64/latest.json", "bundle/prebuilt/x86_64/latest.json.sig",
        "bundle/boot.json",                   "bundle/boot.json.sig",
    }) |name| {
        try tmp.dir.createDirPath(io, std.fs.path.dirname(name).?);
        try tmp.dir.writeFile(io, .{ .sub_path = name, .data = name });
    }
    const bundle = try join(gpa, root, "bundle");
    const base = try join(gpa, root, "mirror/minimal/qemu/x86_64");
    const descriptor = try stock(io, gpa, bundle, base, "x86_64");
    const boot_json = try join(gpa, bundle, "boot.json");
    try std.testing.expectEqualStrings(&try host.check.hexDigest(io, boot_json), &descriptor);
    try tmp.dir.createDirPath(io, "mirror/minimal/qemu/x86_64/latest");
    try promote(io, gpa, bundle, try join(gpa, base, "latest"));
    try std.testing.expectEqualStrings("bundle/boot.json", try tmp.dir.readFileAlloc(
        io,
        "mirror/minimal/qemu/x86_64/latest/boot.json",
        gpa,
        .unlimited,
    ));
    var mirror: Mirror = undefined;
    try mirror.start(io, gpa, try join(gpa, root, "mirror"), "werewolf test mirror");
    defer mirror.stop();
    var bundle_certs: std.crypto.Certificate.Bundle = .empty;
    const now = Io.Clock.real.now(io);
    for (try host.pem.certificates(gpa, mirror.authority)) |cert| {
        try bundle_certs.bytes.appendSlice(gpa, cert.der);
        try bundle_certs.parseCert(gpa, 0, @intCast(@divFloor(now.nanoseconds, std.time.ns_per_s)));
    }
    var client: std.http.Client = .{
        .allocator = gpa,
        .io = io,
        .ca_bundle = bundle_certs,
        .now = now,
    };
    defer client.deinit();
    var body: Io.Writer.Allocating = .init(gpa);
    const object = try gpa.print("{s}/minimal/qemu/x86_64/objects/{s}/cmdline", .{
        try mirror.url(gpa),
        &descriptor,
    });
    const got = try client.fetch(.{
        .location = .{ .url = object },
        .response_writer = &body.writer,
    });
    try std.testing.expectEqual(.ok, got.status);
    try std.testing.expectEqualStrings("bundle/slot/cmdline", body.written());
    try std.testing.expectEqual(1, try mirror.requests(gpa));
}
