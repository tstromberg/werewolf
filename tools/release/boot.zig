//! boot is what publication asks of a protected bundle before trusting
//! it: the request naming its channel and pins, howl's native admission
//! (howl _boot-image head|verify) and the release floor's order, which
//! lib/boot-download.zig keeps for howl's downloads too.

const std = @import("std");
const mem = std.mem;
const json = @import("json.zig");
const Json = json.Json;
const sys = @import("sys.zig");
const Sys = sys.Sys;
const bd = @import("boot-download");

/// files are a slot's, as a bundle's slot/ and a channel's BUILD/ hold them.
pub const files = bd.names;
pub const head_limit = bd.head_limit;
pub const signature_limit = bd.signature_limit;
pub const Request = bd.Request;
pub const Floor = bd.Floor;

/// request is the admission request for a bundle of form and arch on
/// provider, under the committed trust in trust_dir. form and arch only
/// choose what to expect: admission authenticates the bytes.
pub fn request(
    s: *Sys,
    trust_dir: []const u8,
    form: []const u8,
    arch: []const u8,
    provider: []const u8,
) !Request {
    const metadata = try sys.readJson(s, try sys.join(s, &.{ trust_dir, "trust.json" }), 4096);
    if (!json.hasKeys(metadata, &.{ "format", "source" }) or
        !mem.eql(u8, json.text(metadata, "format") catch "", "werewolf-boot-trust/2"))
        return s.refuse("invalid committed publication trust", .{});
    const source = try json.text(metadata, "source");
    const r: Request = .{
        .source = source,
        .cache = "unused",
        .form = form,
        .arch = arch,
        .provider = provider,
        .boot_certificate = try sys.join(s, &.{ trust_dir, "boot.crt" }),
        .image_certificate = try sys.join(s, &.{ trust_dir, "image.crt" }),
        .channel = try s.gpa.print("{s}/{s}/{s}", .{ source, form, provider }),
    };
    bd.validate(r) catch |err| return s.refuse("{s}", .{bd.describe(err)});
    return r;
}

/// native runs howl's admission of the bundle in dir: head authenticates
/// its descriptor and prints it, verify checks every artifact.
pub fn native(s: *Sys, howl: []const u8, operation: []const u8, dir: []const u8, r: Request) !Json {
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(
        s.gpa,
        &.{
            howl,
            "_boot-image",
            operation,
            dir,
            r.boot_certificate,
            r.image_certificate,
            r.channel,
            r.arch,
        },
    );
    if (mem.eql(u8, operation, "head")) try argv.append(s.gpa, r.form);
    const result = try sys.exec(s, argv.items, .{ .capture = .both });
    // Native diagnostics name the failed check, never a private credential.
    if (!result.ok()) return s.refuse(
        "native boot admission refused: {s}",
        .{mem.trim(u8, result.stderr, " \t\r\n")},
    );
    return json.parse(s.gpa, result.stdout);
}

/// previous authenticates a publication floor. Only the publisher can migrate
/// a signed /1 head: it cannot boot one, and candidates still require native
/// /2 admission. Legacy channels named the provider's fixed host gateway.
pub fn previous(s: *Sys, howl: []const u8, dir: []const u8, r: Request) !Json {
    const raw = try sys.read(s, try sys.join(s, &.{ dir, "boot.json" }), head_limit);
    const head = try std.json.parseFromSliceLeaky(Json, s.gpa, raw, .{});
    if (!mem.eql(u8, json.text(head, "format") catch "", "werewolf-boot/1"))
        return native(s, howl, "head", dir, r);
    try @import("catalog.zig").verify(
        s,
        raw,
        try sys.read(s, try sys.join(s, &.{ dir, "boot.json.sig" }), signature_limit),
        r.image_certificate,
    );
    const image = try json.field(head, "image");
    const gateway: []const u8 = if (mem.eql(u8, r.provider, "lima"))
        "192.168.5.2"
    else if (mem.eql(u8, r.provider, "qemu"))
        "10.0.2.2"
    else
        return s.refuse("unsupported legacy publication provider", .{});
    const channel = try s.gpa.print("https://{s}:9443/{s}", .{ gateway, r.form });
    const der = try sys.output(
        s,
        &.{ "openssl", "x509", "-in", r.boot_certificate, "-outform", "DER" },
    );
    const certificate = sys.sha256(der);
    if (!mem.eql(u8, json.text(head, "form") catch "", r.form) or
        !mem.eql(u8, json.text(try json.field(head, "configuration"), "form") catch "", r.form) or
        !mem.eql(u8, json.text(image, "format") catch "", "werewolf-image/1") or
        !mem.eql(u8, json.text(image, "arch") catch "", r.arch) or
        !mem.eql(u8, json.text(image, "channel") catch "", channel) or
        !mem.eql(u8, json.text(head, "permit_host") catch "", gateway) or
        !json.eql(try json.field(head, "permit_port"), .{ .integer = 9443 }) or
        !mem.eql(u8, json.text(head, "boot_certificate") catch "", &certificate) or
        json.get(image, "index") != null)
        return s.refuse("foreign legacy protected publication floor", .{});
    if (sys.serialTime(try json.text(image, "serial")) == null or
        !digest(try json.text(image, "build")))
        return s.refuse("invalid legacy protected publication floor", .{});
    return head;
}

fn digest(value: []const u8) bool {
    if (value.len != 64) return false;
    for (value) |c| if (!std.ascii.isDigit(c) and (c < 'a' or c > 'f')) return false;
    return true;
}

/// freshness refuses a release from the future, one older than floor, or
/// one that reuses floor's serial for other bytes; it is the new floor.
pub fn freshness(s: *Sys, manifest: Json, descriptor: []const u8, floor: ?Floor, now: i64) !Floor {
    const image = try json.field(manifest, "image");
    return bd.freshness(
        try json.text(image, "serial"),
        try json.text(image, "build"),
        descriptor,
        floor,
        now,
    ) catch |err|
        s.refuse("{s}", .{bd.describe(err)});
}

const testing = std.testing;
const fixture = @import("fixture.zig");

test "legacy publication floors require the signature and every namespace pin" {
    var f: fixture.Fixture = undefined;
    try f.init();
    defer f.deinit();
    const s = &f.s;
    const identity = try fixture.keys(&f, "legacy-floor");
    const der = try sys.output(s, &.{ "openssl", "x509", "-in", identity.crt, "-outform", "DER" });
    const pin = sys.sha256(der);
    const r: Request = .{
        .source = "https://vendor.test/boot/v1",
        .cache = "unused",
        .form = "playground",
        .arch = "aarch64",
        .provider = "lima",
        .boot_certificate = identity.crt,
        .image_certificate = identity.crt,
        .channel = "https://vendor.test/boot/v1/playground/lima",
    };
    const good = try json.from(s.gpa, .{
        .format = "werewolf-boot/1",
        .form = "playground",
        .configuration = .{ .form = "playground" },
        .boot_certificate = &pin,
        .permit_host = "192.168.5.2",
        .permit_port = 9443,
        .image = .{
            .format = "werewolf-image/1",
            .channel = "https://192.168.5.2:9443/playground",
            .arch = "aarch64",
            .serial = "20261015T120000Z",
            .build = fixture.rep('a', 64),
        },
    });
    const bytes = try json.encode(s.gpa, good);
    const head_path = f.path("prior/boot.json");
    const sig_path = f.path("prior/boot.json.sig");
    try sys.write(s, head_path, bytes);
    const signature = try fixture.signed(&f, "legacy-floor", bytes);
    try sys.write(s, sig_path, signature);
    const admitted = try previous(s, "unused-howl", f.path("prior"), r);
    try testing.expect(json.eql(good, admitted));
    // Even a well-formed replacement must authenticate its original bytes.
    const corrupt = try s.gpa.dupe(u8, signature);
    corrupt[0] ^= 1;
    try sys.write(s, sig_path, corrupt);
    try testing.expectError(error.Refused, previous(s, "unused-howl", f.path("prior"), r));
    const substitutions = .{
        .{ "", "form", "minimal" },
        .{ "configuration", "form", "minimal" },
        .{ "", "boot_certificate", fixture.rep('b', 64) },
        .{ "", "permit_host", "10.0.2.2" },
        .{ "image", "format", "werewolf-image/2" },
        .{ "image", "channel", "https://10.0.2.2:9443/playground" },
        .{ "image", "arch", "x86_64" },
        .{ "image", "serial", "invalid" },
        .{ "image", "build", "invalid" },
    };
    inline for (substitutions) |sub| {
        var changed = try json.parse(s.gpa, bytes);
        const parent = if (sub[0].len == 0) &changed else changed.object.getPtr(sub[0]).?;
        try parent.object.put(s.gpa, sub[1], .{ .string = sub[2] });
        const raw = try json.encode(s.gpa, changed);
        try sys.write(s, head_path, raw);
        try sys.write(s, sig_path, try fixture.signed(&f, "legacy-floor", raw));
        try testing.expectError(error.Refused, previous(s, "unused-howl", f.path("prior"), r));
    }
    for ([_]bool{ false, true }) |indexed| {
        var changed = try json.parse(s.gpa, bytes);
        if (indexed) {
            try changed.object.getPtr("image").?.object.put(s.gpa, "index", .{ .integer = 7 });
        } else {
            try changed.object.put(s.gpa, "permit_port", .{ .integer = 9444 });
        }
        const raw = try json.encode(s.gpa, changed);
        try sys.write(s, head_path, raw);
        try sys.write(s, sig_path, try fixture.signed(&f, "legacy-floor", raw));
        try testing.expectError(error.Refused, previous(s, "unused-howl", f.path("prior"), r));
    }
    // A newer current candidate must still respect the authenticated /1 serial.
    const old_floor: Floor = .{
        .serial = "20261015T120000Z",
        .build = fixture.rep('a', 64),
        .descriptor = &sys.sha256(bytes),
    };
    try testing.expectError(
        error.Refused,
        freshness(s, good, fixture.rep('c', 64), old_floor, sys.serialTime("20261015T120000Z").?),
    );
}

test "a request names the published channel of committed trust" {
    var f: fixture.Fixture = undefined;
    try f.init();
    defer f.deinit();
    const s = &f.s;
    const trust = f.path("trust");
    try sys.write(
        s,
        f.path("trust/trust.json"),
        "{\"format\":\"werewolf-boot-trust/2\",\"source\":\"https://vendor.test/boot/v1\"}",
    );
    const r = try request(s, trust, "playground", "aarch64", "lima");
    try testing.expectEqualStrings("https://vendor.test/boot/v1/playground/lima", r.channel);
    try testing.expectError(error.Refused, request(s, trust, "../playground", "aarch64", "lima"));
    try testing.expectError(error.Refused, request(s, trust, "playground", "riscv64", "lima"));
    try sys.write(
        s,
        f.path("trust/trust.json"),
        "{\"format\":\"werewolf-boot-trust/2\",\"source\":\"http://vendor.test/boot/v1\"}",
    );
    try testing.expectError(error.Refused, request(s, trust, "playground", "aarch64", "lima"));
    try sys.write(
        s,
        f.path("trust/trust.json"),
        "{\"format\":\"werewolf-boot-trust/1\",\"source\":\"https://vendor.test/boot/v1\"}",
    );
    try testing.expectError(error.Refused, request(s, trust, "playground", "aarch64", "lima"));
}

test "freshness refuses an older release and a reused serial" {
    var f: fixture.Fixture = undefined;
    try f.init();
    defer f.deinit();
    const s = &f.s;
    const now = sys.serialTime("20261015T120000Z").?;
    const head = try json.parse(
        f.gpa(),
        "{\"image\":{\"serial\":\"20261015T120000Z\",\"build\":\"" ++ fixture.rep('a', 64) ++
            "\"}}",
    );
    const d = fixture.rep('d', 64);
    const fresh = try freshness(s, head, d, null, now);
    _ = try freshness(s, head, d, fresh, now);
    try testing.expectError(
        error.Refused,
        freshness(
            s,
            head,
            d,
            .{ .serial = "20261015T120001Z", .build = fixture.rep('b', 64), .descriptor = d },
            now,
        ),
    );
    try testing.expectEqualStrings("older protected boot release", s.why.text);
    try testing.expectError(
        error.Refused,
        freshness(
            s,
            head,
            d,
            .{ .serial = "20261015T120000Z", .build = fixture.rep('b', 64), .descriptor = d },
            now,
        ),
    );
    try testing.expectEqualStrings("protected release serial reused", s.why.text);
}
