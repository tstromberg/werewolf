//! exporter signs one gated bundle's release assets for GitHub and R2: its
//! files under target prefixes, a qcow2 with the authenticated raw disk's
//! contents, the lifecycle evidence, and a downloads manifest over all of
//! them with the workflow's provenance.

const std = @import("std");
const mem = std.mem;
const Io = std.Io;
const json = @import("json.zig");
const Json = json.Json;
const sys = @import("sys.zig");
const Sys = sys.Sys;
const boot = @import("boot.zig");
const prepare = @import("prepare.zig");
const catalog = @import("catalog.zig");

/// extras are what the form pipeline adds to a bundle: what it was built
/// from and how it changed. The signed manifest covers them like the rest.
pub const extras = [_][]const u8{
    "inputs.tar.gz",      "packages.json",     "tests.json", "release-notes.json",
    "release-notes.html", "secure-boot.qcow2",
};

pub const Source = struct { name: []const u8, path: []const u8 };

/// sources are the bundle's files and the pins, by release name.
pub fn sources(s: *Sys, bundle: []const u8, trust: []const u8) ![]Source {
    const head = try sys.readJson(s, try sys.join(s, &.{ bundle, "boot.json" }), boot.head_limit);
    const arch = try json.text(try json.field(head, "image"), "arch");
    var out: std.ArrayList(Source) = .empty;
    for (boot.files) |name| try out.append(
        s.gpa,
        .{ .name = name, .path = try sys.join(s, &.{ bundle, "slot", name }) },
    );
    for ([_][]const u8{ "boot.json", "boot.json.sig", "disk.img.zst" }) |name|
        try out.append(s.gpa, .{ .name = name, .path = try sys.join(s, &.{ bundle, name }) });
    for ([_][]const u8{ "latest.json", "latest.json.sig" }) |name|
        try out.append(
            s.gpa,
            .{ .name = name, .path = try sys.join(s, &.{ bundle, "prebuilt", arch, name }) },
        );
    for ([_][]const u8{ "boot.crt", "image.crt" }) |name|
        try out.append(s.gpa, .{ .name = name, .path = try sys.join(s, &.{ trust, name }) });
    return out.items;
}

fn source(all: []const Source, name: []const u8) ?[]const u8 {
    for (all) |x| if (mem.eql(u8, x.name, name)) return x.path;
    return null;
}

/// unpack writes the zstd raw disk at from to a new file, refusing a
/// stream that differs from the authenticated size; zero MiBs stay holes.
pub fn unpack(s: *Sys, from: []const u8, to: []const u8, size: Json) !void {
    if (size != .integer or size.integer < 512 << 20 or size.integer > 16 << 30)
        return s.refuse("invalid authenticated raw disk size", .{});
    const want: u64 = @intCast(size.integer);
    var child = try std.process.spawn(s.io, .{
        .argv = &.{ "zstd", "-q", "-dc", from },
        .environ_map = s.env,
        .stdout = .pipe,
        .stderr = .ignore,
    });
    defer child.kill(s.io);
    const out = try Io.Dir.cwd().createFile(s.io, to, .{ .exclusive = true });
    defer out.close(s.io);
    const block = try s.gpa.alloc(u8, 1 << 20);
    defer s.gpa.free(block);
    var reader = child.stdout.?.readerStreaming(s.io, &.{});
    var total: u64 = 0;
    while (true) {
        const n = try reader.interface.readSliceShort(block);
        if (n == 0) break;
        if (total + n > want) return s.refuse("raw disk exceeds its authenticated size", .{});
        if (!zero(block[0..n])) try out.writePositionalAll(s.io, block[0..n], total);
        total += n;
    }
    const term = try child.wait(s.io);
    if (term != .exited or term.exited != 0 or
        total != want) return s.refuse("raw disk differs from its authenticated size", .{});
    try out.setLength(s.io, want);
}

/// zero says whether block is all zero bytes, a hole in a sparse disk.
fn zero(block: []const u8) bool {
    const V = @Vector(64, u8);
    var any: V = @splat(0);
    var i: usize = 0;
    while (i + 64 <= block.len) : (i += 64) any |= @as(V, block[i..][0..64].*);
    var tail: u8 = 0;
    for (block[i..]) |b| tail |= b;
    return @reduce(.Or, any) == 0 and tail == 0;
}

/// compare refuses unless qcow2 is a standalone, consistent image of the
/// authenticated size with raw's contents.
pub fn compare(s: *Sys, raw: []const u8, qcow2: []const u8, size: Json) !void {
    const info = try json.parse(
        s.gpa,
        try sys.output(s, &.{ "qemu-img", "info", "--output=json", "-f", "qcow2", qcow2 }),
    );
    const virtual = json.get(info, "virtual-size") orelse .null;
    if (!mem.eql(u8, json.text(info, "format") catch "", "qcow2") or !json.eql(virtual, size) or
        json.get(info, "backing-filename") != null or
        json.get(info, "full-backing-filename") != null or
        json.get(info, "data-file") != null)
        return s.refuse("qcow2 must be a standalone disk of the authenticated size", .{});
    if (json.get(json.get(info, "format-specific") orelse .null, "data")) |data| {
        if (json.get(
            data,
            "data-file",
        )) |file| if (truthy(file)) return s.refuse("qcow2 has an external data file", .{});
    }
    for ([_][]const []const u8{
        &.{ "qemu-img", "check", "-f", "qcow2", qcow2 },
        &.{ "qemu-img", "compare", "-f", "raw", "-F", "qcow2", raw, qcow2 },
    }) |argv| {
        const r = try sys.exec(s, argv, .{ .capture = .both });
        if (!r.ok()) return s.refuse(
            "qcow2 differs from the authenticated raw disk ({s})",
            .{argv[1]},
        );
    }
}

/// truthy is Python's bool() of a JSON value.
fn truthy(v: Json) bool {
    return switch (v) {
        .null => false,
        .bool => |b| b,
        .integer => |i| i != 0,
        .float => |f| f != 0,
        .number_string => true,
        .string => |t| t.len > 0,
        .array => |a| a.items.len > 0,
        .object => |o| o.count() > 0,
    };
}

/// provenance is the GitHub Actions run a release comes from; outside one
/// a release is refused.
pub fn provenance(s: *Sys) !Json {
    const repository = s.getenv("GITHUB_REPOSITORY") orelse "";
    const commit = s.getenv("GITHUB_SHA") orelse "";
    const run = s.getenv("GITHUB_RUN_ID") orelse "";
    // GITHUB_RUN_ID is decimal digits, as Python's str.isdecimal saw them.
    const decimal = run.len > 0 and for (run) |c| {
        if (!std.ascii.isDigit(c)) break false;
    } else true;
    if (!mem.eql(u8, repository, "werewolf-linux/werewolf") or !catalog.isHex(commit, 40) or
        !decimal)
        return s.refuse("protected release export requires GitHub Actions provenance", .{});
    return json.from(s.gpa, .{
        .repository = repository,
        .commit = commit,
        .run = try s.gpa.print("https://github.com/{s}/actions/runs/{s}", .{ repository, run }),
        .attempt = s.getenv("GITHUB_RUN_ATTEMPT") orelse "1",
    });
}

/// verify checks a release export against its bundle and evidence: the
/// signature, the identity, every asset's bytes, nothing more, and that
/// the qcow2 is the authenticated disk. It returns the signed manifest.
pub fn verify(
    s: *Sys,
    directory: []const u8,
    bundle: []const u8,
    report: Json,
    provider: []const u8,
    trust: []const u8,
) !Json {
    const manifest = try sys.readJson(
        s,
        try sys.join(s, &.{ bundle, "boot.json" }),
        boot.head_limit,
    );
    const image = try json.field(manifest, "image");
    const form = try json.text(manifest, "form");
    const arch = try json.text(image, "arch");
    const prefix = try s.gpa.print("{s}-{s}-{s}", .{ form, provider, arch });
    const head_name = try s.gpa.print("{s}-downloads.json", .{prefix});
    const signature_name = try s.gpa.print("{s}.sig", .{head_name});
    const head = try sys.join(s, &.{ directory, head_name });
    const signature = try sys.join(s, &.{ directory, signature_name });
    const work = try sys.scratch(s, null, "ww-download-verify-");
    defer sys.remove(s, work);
    const key = try sys.join(s, &.{ work, "image.pub" });
    try sys.write(s, key, try catalog.publicKey(s, try sys.join(s, &.{ trust, "image.crt" })));
    const sig_len = (try sys.read(s, signature, boot.signature_limit)).len;
    if (sig_len != 256 and sig_len != 512) return s.refuse("invalid downloads signature", .{});
    const checked = try sys.exec(
        s,
        &.{ "openssl", "dgst", "-sha256", "-verify", key, "-signature", signature, head },
        .{ .capture = .both },
    );
    if (!checked.ok()) return s.refuse("downloads manifest signature does not verify", .{});
    const signed = try sys.readJson(s, head, boot.head_limit);
    const descriptor = try sys.sha(s, try sys.join(s, &.{ bundle, "boot.json" }));
    const expected = try json.from(s.gpa, .{
        .format = "werewolf-downloads/1",
        .boot_profile = "secure-boot",
        .descriptor = &descriptor,
        .form = form,
        .provider = provider,
        .arch = arch,
        .serial = try json.field(image, "serial"),
    });
    var names: std.ArrayList([]const u8) = .empty;
    try names.appendSlice(s.gpa, expected.object.keys());
    try names.appendSlice(s.gpa, &.{ "files", "provenance" });
    if (!json.hasKeys(
        signed,
        names.items,
    )) return s.refuse("download manifest describes another protected bundle", .{});
    var it = expected.object.iterator();
    while (it.next()) |e| if (!json.eql(signed.object.get(e.key_ptr.*).?, e.value_ptr.*))
        return s.refuse("download manifest describes another protected bundle", .{});
    const original = try sources(s, bundle, trust);
    const files = json.object(signed.object.get("files").?) catch return s.refuse(
        "download manifest has incomplete or unexpected files",
        .{},
    );
    for (original) |o| if (files.get(o.name) == null) return s.refuse(
        "download manifest has incomplete or unexpected files",
        .{},
    );
    for ([_][]const u8{
        "disk.qcow2",
        "gates.json",
    }) |n| if (files.get(n) == null) return s.refuse(
        "download manifest has incomplete or unexpected files",
        .{},
    );
    for (files.keys()) |n| {
        if (source(original, n) == null and !mem.eql(u8, n, "disk.qcow2") and
            !mem.eql(u8, n, "gates.json") and !isExtra(n))
            return s.refuse("download manifest has incomplete or unexpected files", .{});
    }
    var assets: std.ArrayList([]const u8) = .empty;
    try assets.appendSlice(s.gpa, &.{ head_name, signature_name });
    var fit = files.iterator();
    while (fit.next()) |e| {
        const name = e.key_ptr.*;
        const r = e.value_ptr.*;
        const asset = json.text(r, "asset") catch "";
        if (!json.hasKeys(r, &.{ "asset", "sha256", "size" }) or
            !mem.eql(u8, asset, try s.gpa.print("{s}-{s}", .{ prefix, name })))
            return s.refuse("invalid release asset mapping", .{});
        const path = try sys.join(s, &.{ directory, asset });
        if (sys.kind(
            s,
            path,
        ) != .file) return s.refuse("release asset differs from its signed digest", .{});
        const actual = try sys.record(s, path);
        if (!actual.matches(r)) return s.refuse(
            "release asset differs from its signed digest",
            .{},
        );
        if (source(original, name)) |from| {
            if (!mem.eql(
                u8,
                &try sys.sha(s, from),
                try json.text(r, "sha256"),
            )) return s.refuse("GitHub and R2 bundle bytes differ", .{});
        }
        try assets.append(s.gpa, asset);
    }
    if (files.get("secure-boot.qcow2")) |named| {
        const disk = files.get("disk.qcow2").?;
        for ([_][]const u8{
            "size",
            "sha256",
        }) |k| if (!json.eql(json.get(named, k).?, json.get(disk, k).?))
            return s.refuse("named secure boot disk differs from the admitted disk", .{});
    }
    if (!json.eql(
        try sys.readJson(
            s,
            try sys.join(s, &.{ directory, try s.gpa.print("{s}-gates.json", .{prefix}) }),
            64 << 10,
        ),
        report,
    ))
        return s.refuse("release carries different lifecycle evidence", .{});
    const present = try sys.list(s, directory);
    if (present.len != assets.items.len) return s.refuse(
        "unexpected files in protected release export",
        .{},
    );
    for (present) |p| {
        for (assets.items) |a| {
            if (mem.eql(u8, a, p)) break;
        } else return s.refuse("unexpected files in protected release export", .{});
    }
    const raw = try sys.join(s, &.{ work, "disk.raw" });
    const size = try json.field(manifest, "raw_size");
    try unpack(s, try sys.join(s, &.{ bundle, "disk.img.zst" }), raw, size);
    try compare(
        s,
        raw,
        try sys.join(s, &.{ directory, try s.gpa.print("{s}-disk.qcow2", .{prefix}) }),
        size,
    );
    return signed;
}

pub fn isExtra(name: []const u8) bool {
    for (extras) |e| if (mem.eql(u8, e, name)) return true;
    return false;
}

/// Extra is a form pipeline file to sign with a bundle.
pub const Extra = struct { name: []const u8, path: []const u8 };

/// exportBundle admits a gated bundle and writes its signed release assets
/// to output, which must not exist. It returns the signed manifest.
pub fn exportBundle(
    s: *Sys,
    howl: []const u8,
    bundle_dir: []const u8,
    report: Json,
    provider: []const u8,
    output_dir: []const u8,
    trust_dir: []const u8,
    added: ?[]const Extra,
) !Json {
    const bundle = try sys.resolve(s, bundle_dir);
    const output = try sys.resolve(s, output_dir);
    const trust = try sys.resolve(s, trust_dir);
    if (sys.exists(s, output)) return s.refuse("release export already exists", .{});
    const parent = std.fs.path.dirname(output).?;
    try sys.mkdirs(s, parent);
    const work = try sys.scratch(s, parent, "protected-export-");
    defer sys.remove(s, work);
    // Authenticate code and exact-artifact runtime gates before deriving or signing anything.
    const plan = try prepare.prepare(
        s,
        howl,
        bundle,
        report,
        provider,
        try sys.join(s, &.{ work, "admitted" }),
        trust,
        null,
    );
    const manifest = try sys.readJson(
        s,
        try sys.join(s, &.{ bundle, "boot.json" }),
        boot.head_limit,
    );
    const form = try json.text(plan, "form");
    const arch = try json.text(plan, "arch");
    const prefix = try s.gpa.print("{s}-{s}-{s}", .{ form, provider, arch });
    const staging = try sys.join(s, &.{ work, "assets" });
    try sys.mkdir(s, staging);
    var originals: std.ArrayList(Source) = .empty;
    try originals.appendSlice(s.gpa, try sources(s, bundle, trust));
    if (added) |more| for (more) |x| {
        if (!isExtra(x.name)) return s.refuse("unexpected release extras", .{});
        for (originals.items) |*o| {
            if (mem.eql(u8, o.name, x.name)) {
                o.path = x.path;
                break;
            }
        } else try originals.append(s.gpa, .{ .name = x.name, .path = x.path });
    };
    for (originals.items) |o| try sys.copy(
        s,
        o.path,
        try sys.join(s, &.{ staging, try s.gpa.print("{s}-{s}", .{ prefix, o.name }) }),
    );
    try sys.atomic(
        s,
        try sys.join(s, &.{ staging, try s.gpa.print("{s}-gates.json", .{prefix}) }),
        report,
    );
    const raw = try sys.join(s, &.{ work, "disk.raw" });
    const size = try json.field(manifest, "raw_size");
    try unpack(s, try sys.join(s, &.{ bundle, "disk.img.zst" }), raw, size);
    const qcow2 = try sys.join(s, &.{ staging, try s.gpa.print("{s}-disk.qcow2", .{prefix}) });
    try sys.run(s, &.{
        "qemu-img",
        "convert",
        "-f",
        "raw",
        "-O",
        "qcow2",
        "-c",
        "-o",
        "compat=1.1,cluster_size=65536,lazy_refcounts=off,compression_type=zstd",
        raw,
        qcow2,
    }, .{});
    try compare(s, raw, qcow2, size);
    try sys.copy(
        s,
        qcow2,
        try sys.join(s, &.{ staging, try s.gpa.print("{s}-secure-boot.qcow2", .{prefix}) }),
    );
    var files: json.Map = .empty;
    for (try sys.list(s, staging)) |name| {
        const r = try sys.record(s, try sys.join(s, &.{ staging, name }));
        try files.put(s.gpa, name[prefix.len + 1 ..], try json.from(s.gpa, .{
            .asset = name,
            .size = r.size,
            .sha256 = try s.gpa.dupe(u8, &r.sha256),
        }));
    }
    const signed = try json.from(s.gpa, .{
        .format = "werewolf-downloads/1",
        .boot_profile = "secure-boot",
        .descriptor = try json.field(plan, "descriptor"),
        .form = form,
        .provider = provider,
        .arch = arch,
        .serial = try json.field(plan, "serial"),
        .files = files,
        .provenance = try provenance(s),
    });
    const head = try sys.join(s, &.{ staging, try s.gpa.print("{s}-downloads.json", .{prefix}) });
    try sys.atomic(s, head, signed);
    const key = s.getenv("WEREWOLF_PROTECTED_IMAGE_KEY") orelse return s.refuse(
        "WEREWOLF_PROTECTED_IMAGE_KEY is required",
        .{},
    );
    const r = try sys.exec(
        s,
        &.{
            "openssl",
            "dgst",
            "-sha256",
            "-sign",
            key,
            "-out",
            try s.gpa.print("{s}.sig", .{head}),
            head,
        },
        .{ .capture = .both },
    );
    if (!r.ok()) return s.refuse("signing the downloads manifest failed", .{});
    _ = try verify(s, staging, bundle, report, provider, trust);
    try sys.rename(s, staging, output);
    return signed;
}

const testing = std.testing;
const fixture = @import("fixture.zig");
const publish = @import("publish.zig");
const Store = @import("store.zig").Store;

/// Exported is a signed playground bundle, its evidence and its export,
/// made the way the real one is: RSA signatures, zstd and qemu-img. Only
/// howl's admission is answered by the fixture.
pub const Exported = struct {
    f: fixture.Fixture,
    trust: []const u8,
    bundle: []const u8,
    report: Json,
    assets: []const u8,
    signed: Json,
    keys: fixture.Keys,

    pub const prefix = "playground-qemu-x86_64";

    pub fn init(e: *Exported) !void {
        try e.f.init();
        const f = &e.f;
        const s = &f.s;
        const gpa = f.gpa();
        e.keys = try fixture.keys(f, "image");
        e.trust = f.path("trust");
        try sys.mkdirs(s, e.trust);
        try sys.copy(s, e.keys.crt, f.path("trust/image.crt"));
        try sys.copy(s, e.keys.crt, f.path("trust/boot.crt"));
        try sys.write(
            s,
            f.path("trust/trust.json"),
            "{\"format\": \"werewolf-boot-trust/2\", \"source\": \"https://vendor.test/boot/v1\"}",
        );
        e.bundle = f.path("bundle");
        const serial = sys.serial(s.now());
        try sys.write(s, f.path("bundle/boot.json"), try json.dumps(gpa, try json.from(gpa, .{
            .form = "playground",
            .image = .{
                .arch = "x86_64",
                .build = fixture.rep('a', 64),
                .index = 1,
                .serial = &serial,
            },
            .raw_size = 512 << 20,
        })));
        try sys.write(
            s,
            f.path("bundle/boot.json.sig"),
            try fixture.signed(f, "image", try sys.read(s, f.path("bundle/boot.json"), 4096)),
        );
        for (boot.files) |name| try sys.write(
            s,
            try sys.join(s, &.{ e.bundle, "slot", name }),
            name,
        );
        try sys.write(
            s,
            f.path("bundle/prebuilt/x86_64/latest.json"),
            "exact original image manifest",
        );
        try sys.write(
            s,
            f.path("bundle/prebuilt/x86_64/latest.json.sig"),
            "exact original image signature",
        );
        const raw = f.path("disk.raw");
        {
            const out = try Io.Dir.cwd().createFile(s.io, raw, .{});
            defer out.close(s.io);
            try out.writePositionalAll(s.io, "protected disk header", 0);
            try out.writePositionalAll(s.io, "protected slot bytes", (256 << 20) + 73);
            try out.writePositionalAll(s.io, "backup disk header!", (512 << 20) - 19);
        }
        try sys.run(s, &.{ "zstd", "-q", raw, "-o", f.path("bundle/disk.img.zst") }, .{});
        var checks: json.Map = .empty;
        for (prepare.gates) |g| try checks.put(gpa, g, .{ .bool = true });
        e.report = try json.from(gpa, .{
            .format = "werewolf-boot-gates/1",
            .descriptor = try gpa.dupe(u8, &try sys.sha(s, f.path("bundle/boot.json"))),
            .arch = "x86_64",
            .provider = "qemu",
            .checks = checks,
        });
        try f.env.put("WEREWOLF_PROTECTED_IMAGE_KEY", e.keys.key);
        try f.env.put("GITHUB_REPOSITORY", "werewolf-linux/werewolf");
        try f.env.put("GITHUB_SHA", fixture.rep('a', 40));
        try f.env.put("GITHUB_RUN_ID", "12345");
        try f.env.put("GITHUB_RUN_ATTEMPT", "1");
        f.answer = fixture.admit;
        e.assets = f.path("assets");
        e.signed = try exportBundle(s, "howl", e.bundle, e.report, "qemu", e.assets, e.trust, null);
    }

    pub fn deinit(e: *Exported) void {
        e.f.deinit();
    }

    /// copy is a fresh copy of the export to tamper with.
    pub fn copy(e: *Exported, name: []const u8) ![]const u8 {
        const to = e.f.path(name);
        try sys.copyTree(&e.f.s, e.assets, to);
        return to;
    }

    pub fn asset(e: *Exported, dir: []const u8, name: []const u8) ![]const u8 {
        return sys.join(&e.f.s, &.{ dir, try e.f.gpa().print("{s}-{s}", .{ prefix, name }) });
    }
};

test "the qcow2 round trips and both mirrors keep the original signatures" {
    var e: Exported = undefined;
    try e.init();
    defer e.deinit();
    const s = &e.f.s;
    const copied = try e.copy("copy");
    const signed = try verify(s, copied, e.bundle, e.report, "qemu", e.trust);
    try testing.expect(json.eql(e.signed, signed));
    try testing.expectEqualStrings("secure-boot", try json.text(signed, "boot_profile"));
    const named = try sys.read(s, try e.asset(copied, "secure-boot.qcow2"), 64 << 20);
    try testing.expectEqualStrings(
        try sys.read(s, try e.asset(copied, "disk.qcow2"), 64 << 20),
        named,
    );
    try testing.expectEqualStrings(
        &sys.sha256(named),
        try json.text(json.get(json.get(signed, "files").?, "secure-boot.qcow2").?, "sha256"),
    );
    const plan = try publish.publish(
        s,
        "howl",
        e.bundle,
        e.report,
        "qemu",
        Store.init(e.f.path("store")),
        e.trust,
        copied,
    );
    const objects = e.f.path(try s.gpa.print(
        "store/playground/qemu/x86_64/objects/{s}",
        .{try json.text(plan, "descriptor")},
    ));
    var names: std.ArrayList([]const u8) = .empty;
    try names.appendSlice(s.gpa, (try json.object(json.get(signed, "files").?)).keys());
    try names.appendSlice(s.gpa, &.{ "downloads.json", "downloads.json.sig" });
    for (names.items) |name|
        try testing.expectEqualStrings(
            try sys.read(s, try e.asset(copied, name), 64 << 20),
            try sys.read(s, try sys.join(s, &.{ objects, name }), 64 << 20),
        );
    // The update head machines follow is the same signed image head.
    for ([_][]const u8{ "latest.json", "latest.json.sig" }) |name|
        try testing.expectEqualStrings(
            try sys.read(s, try sys.join(s, &.{ e.bundle, "prebuilt/x86_64", name }), 4096),
            try sys.read(
                s,
                e.f.path(try s.gpa.print("store/playground/qemu/x86_64/{s}", .{name})),
                4096,
            ),
        );
}

test "tampered exports, evidence and disks refuse" {
    var e: Exported = undefined;
    try e.init();
    defer e.deinit();
    const s = &e.f.s;
    const gpa = e.f.gpa();
    // A modified qcow2 or signature.
    for ([_][]const u8{ "disk.qcow2", "downloads.json.sig" }, 0..) |name, i| {
        const copied = try e.copy(try gpa.print("modified-{d}", .{i}));
        const path = try e.asset(copied, name);
        try sys.write(s, path, try gpa.print("{s}tamper", .{try sys.read(s, path, 64 << 20)}));
        try testing.expectError(
            error.Refused,
            verify(s, copied, e.bundle, e.report, "qemu", e.trust),
        );
    }
    // A signed alternate named disk does not replace the admitted one.
    {
        const copied = try e.copy("alternate");
        const named = try e.asset(copied, "secure-boot.qcow2");
        try sys.write(s, named, "an untested alternate disk");
        const head = try e.asset(copied, "downloads.json");
        var signed = try sys.readJson(s, head, 1 << 20);
        const record = &signed.object.getPtr("files").?.object.getPtr("secure-boot.qcow2").?.object;
        try record.put(gpa, "size", .{ .integer = "an untested alternate disk".len });
        try record.put(
            gpa,
            "sha256",
            .{ .string = try gpa.dupe(u8, &sys.sha256("an untested alternate disk")) },
        );
        try sys.write(s, head, try json.dumps(gpa, signed));
        try sys.run(
            s,
            &.{
                "openssl",
                "dgst",
                "-sha256",
                "-sign",
                e.keys.key,
                "-out",
                try gpa.print("{s}.sig", .{head}),
                head,
            },
            .{},
        );
        try testing.expectError(
            error.Refused,
            verify(s, copied, e.bundle, e.report, "qemu", e.trust),
        );
        try testing.expectEqualStrings(
            "named secure boot disk differs from the admitted disk",
            s.why.text,
        );
    }
    // A replaced boot signature cannot be mirrored.
    {
        const copied = try e.copy("foreign-signature");
        try sys.write(s, try e.asset(copied, "boot.json.sig"), "foreign signature");
        try testing.expectError(
            error.Refused,
            verify(s, copied, e.bundle, e.report, "qemu", e.trust),
        );
        try testing.expectEqualStrings("release asset differs from its signed digest", s.why.text);
    }
    // Another provider's evidence, then an unsigned extra file.
    {
        const copied = try e.copy("extra");
        var wrong = try json.parse(gpa, try json.encode(gpa, e.report));
        try wrong.object.put(gpa, "provider", .{ .string = "lima" });
        try testing.expectError(error.Refused, verify(s, copied, e.bundle, wrong, "qemu", e.trust));
        try testing.expectEqualStrings("release carries different lifecycle evidence", s.why.text);
        try sys.write(s, try sys.join(s, &.{ copied, "private.key" }), "must never upload");
        try testing.expectError(
            error.Refused,
            verify(s, copied, e.bundle, e.report, "qemu", e.trust),
        );
        try testing.expectEqualStrings("unexpected files in protected release export", s.why.text);
    }
    // A truncated raw disk, and a qcow2 with a backing file.
    {
        const short = e.f.path("short.zst");
        try sys.run(
            s,
            &.{ "zstd", "-q", try sys.join(s, &.{ e.bundle, "slot/cmdline" }), "-o", short },
            .{},
        );
        try testing.expectError(
            error.Refused,
            unpack(s, short, e.f.path("short.raw"), .{ .integer = 512 << 20 }),
        );
        try testing.expectEqualStrings("raw disk differs from its authenticated size", s.why.text);
        const overlay = e.f.path("overlay.qcow2");
        try sys.run(
            s,
            &.{
                "qemu-img",
                "create",
                "-q",
                "-f",
                "qcow2",
                "-F",
                "raw",
                "-b",
                e.f.path("disk.raw"),
                overlay,
            },
            .{},
        );
        try testing.expectError(
            error.Refused,
            compare(s, e.f.path("disk.raw"), overlay, .{ .integer = 512 << 20 }),
        );
        try testing.expectEqualStrings(
            "qcow2 must be a standalone disk of the authenticated size",
            s.why.text,
        );
    }
}

test "a false gate never exports, and only known extras are signed and mirrored" {
    var e: Exported = undefined;
    try e.init();
    defer e.deinit();
    const s = &e.f.s;
    const gpa = e.f.gpa();
    var bad = try json.parse(gpa, try json.encode(gpa, e.report));
    try bad.object.getPtr("checks").?.object.put(gpa, "ab_upgrade", .{ .bool = false });
    try testing.expectError(
        error.Refused,
        exportBundle(s, "howl", e.bundle, bad, "qemu", e.f.path("refused"), e.trust, null),
    );
    try testing.expect(!sys.exists(s, e.f.path("refused")));
    const notes = e.f.path("notes.html");
    try sys.write(s, notes, "<p>release notes</p>");
    const signed = try exportBundle(
        s,
        "howl",
        e.bundle,
        e.report,
        "qemu",
        e.f.path("extras"),
        e.trust,
        &.{.{ .name = "release-notes.html", .path = notes }},
    );
    try testing.expectEqualStrings(
        "<p>release notes</p>",
        try sys.read(s, try e.asset(e.f.path("extras"), "release-notes.html"), 4096),
    );
    try testing.expect(json.get(json.get(signed, "files").?, "release-notes.html") != null);
    const plan = try publish.publish(
        s,
        "howl",
        e.bundle,
        e.report,
        "qemu",
        Store.init(e.f.path("store")),
        e.trust,
        e.f.path("extras"),
    );
    try testing.expectEqualStrings(
        "<p>release notes</p>",
        try sys.read(
            s,
            e.f.path(try gpa.print(
                "store/playground/qemu/x86_64/objects/{s}/release-notes.html",
                .{try json.text(plan, "descriptor")},
            )),
            4096,
        ),
    );
    try testing.expectError(
        error.Refused,
        exportBundle(
            s,
            "howl",
            e.bundle,
            e.report,
            "qemu",
            e.f.path("refused"),
            e.trust,
            &.{.{ .name = "private.key", .path = notes }},
        ),
    );
    try testing.expectEqualStrings("unexpected release extras", s.why.text);
    try testing.expect(!sys.exists(s, e.f.path("refused")));
}
