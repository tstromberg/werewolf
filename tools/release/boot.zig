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
