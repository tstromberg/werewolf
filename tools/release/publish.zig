//! publish uploads an admitted bundle's immutable objects before its signed
//! heads, the channel's update head last, keeping a signed release floor:
//! an interrupted publication can be retried and never lowers a channel.

const std = @import("std");
const mem = std.mem;
const json = @import("json.zig");
const Json = json.Json;
const sys = @import("sys.zig");
const Sys = sys.Sys;
const boot = @import("boot.zig");
const prepare = @import("prepare.zig");
const catalog = @import("catalog.zig");
const Store = @import("store.zig").Store;

/// advances refuses a new release that does not take a later index of its
/// channel than the head it replaces: a machine's TPM floor rises by these
/// indices and never falls.
pub fn advances(
    s: *Sys,
    previous: Json,
    current: Json,
    old_descriptor: []const u8,
    new_descriptor: []const u8,
) !void {
    if (mem.eql(u8, old_descriptor, new_descriptor)) return;
    const was = json.get(try json.field(previous, "image"), "index") orelse Json{ .integer = 0 };
    const now = try json.field(try json.field(current, "image"), "index");
    if (now != .integer or was != .integer or now.integer <= was.integer)
        return s.refuse("a published release must take a later channel index", .{});
}

fn floorOf(s: *Sys, manifest: Json, descriptor: []const u8) !boot.Floor {
    const image = try json.field(manifest, "image");
    return .{
        .serial = try json.text(image, "serial"),
        .build = try json.text(image, "build"),
        .descriptor = try s.gpa.dupe(u8, descriptor),
    };
}

/// publish publishes bundle to store and returns its upload plan.
pub fn publish(
    s: *Sys,
    howl: []const u8,
    bundle: []const u8,
    report: Json,
    provider: []const u8,
    store: Store,
    trust_dir: []const u8,
    release_assets: ?[]const u8,
) !Json {
    const work = try sys.scratch(s, null, "ww-protected-publication-");
    defer sys.remove(s, work);
    const public = try sys.join(s, &.{ work, "public" });
    const plan = try prepare.prepare(
        s,
        howl,
        bundle,
        report,
        provider,
        public,
        trust_dir,
        release_assets,
    );
    const form = try json.text(plan, "form");
    const arch = try json.text(plan, "arch");
    const descriptor = try json.text(plan, "descriptor");
    const namespace = try s.gpa.print(
        "{s}/{s}/{s}",
        .{ try s.variantPath(form), try json.text(plan, "provider"), arch },
    );
    const request = try boot.request(s, try sys.resolve(s, trust_dir), form, arch, provider);
    const old = try sys.join(s, &.{ work, "previous" });
    try sys.mkdir(s, old);
    const old_head = try sys.join(s, &.{ old, "boot.json" });
    const old_signature = try sys.join(s, &.{ old, "boot.json.sig" });
    const had_signature = try store.fetch(
        s,
        try key(s, namespace, "latest/boot.json.sig"),
        old_signature,
    );
    var had_head = try store.fetch(s, try key(s, namespace, "latest/boot.json"), old_head);
    const current = try boot.native(s, howl, "head", bundle, request);
    // One atomic object retains the newest authenticated publication intent.
    // A cut between the two public head writes cannot lower this release floor.
    const accepted = try sys.join(s, &.{ work, "accepted" });
    try sys.mkdir(s, accepted);
    const receipt_path = try sys.join(s, &.{ accepted, "receipt.json" });
    if (try store.fetch(s, try key(s, namespace, "latest/accepted-head.json"), receipt_path)) {
        const receipt = try sys.readJson(s, receipt_path, 3 << 20);
        if (!json.hasKeys(
            receipt,
            &.{ "head", "signature" },
        )) return s.refuse("invalid protected publication receipt", .{});
        const head_path = try sys.join(s, &.{ accepted, "boot.json" });
        try sys.write(s, head_path, try json.text(receipt, "head"));
        try sys.write(
            s,
            try sys.join(s, &.{ accepted, "boot.json.sig" }),
            try catalog.unhex(s, try json.text(receipt, "signature")),
        );
        const previous = try boot.previous(s, howl, accepted, request);
        const floor = try floorOf(s, previous, &try sys.sha(s, head_path));
        _ = try boot.freshness(s, current, descriptor, floor, s.now());
        try advances(s, previous, current, floor.descriptor, descriptor);
    }
    if (had_signature and !had_head) {
        if (!mem.eql(
            u8,
            try sys.read(s, old_signature, boot.signature_limit),
            try sys.read(s, try sys.join(s, &.{ bundle, "boot.json.sig" }), boot.signature_limit),
        ))
            return s.refuse("incomplete boot publication is not this candidate", .{});
        try sys.copy(s, try sys.join(s, &.{ bundle, "boot.json" }), old_head);
        had_head = true;
    }
    if (had_head and
        !had_signature) return s.refuse("published boot head is missing its signature", .{});
    if (had_head) {
        const old_descriptor = try sys.sha(s, old_head);
        // A prior interrupted JSON/signature update can be recovered only
        // with the signature for those exact bytes stored immutably earlier.
        const previous = boot.previous(s, howl, old, request) catch |err| switch (err) {
            error.Refused => blk: {
                const stored = try s.gpa.print(
                    "{s}/objects/{s}/boot.json.sig",
                    .{ namespace, &old_descriptor },
                );
                if (!try store.fetch(
                    s,
                    stored,
                    old_signature,
                )) return s.refuse("cannot authenticate the prior boot head", .{});
                break :blk try boot.previous(s, howl, old, request);
            },
            else => return err,
        };
        const floor = try floorOf(s, previous, &old_descriptor);
        _ = try boot.freshness(s, current, descriptor, floor, s.now());
        try advances(s, previous, current, floor.descriptor, descriptor);
    }
    // Check immutable collisions before changing any head. Overwriting a key
    // under the same content identity is refused, even with publication access.
    const found = try sys.join(s, &.{ work, "existing" });
    for (try json.items(try json.field(plan, "files"))) |entry| {
        const immutable = try json.field(entry, "immutable");
        if (immutable != .bool or !immutable.bool) continue;
        const k = try json.text(entry, "key");
        if (try store.fetch(s, k, found)) {
            const r = try sys.record(s, found);
            if (!r.matches(entry)) return s.refuse("immutable protected object collision", .{});
        } else {
            try store.upload(s, k, try sys.join(s, &.{ public, k }), true);
        }
        std.Io.Dir.cwd().deleteFile(s.io, found) catch {};
    }
    // JSON/signature tears refuse in the downloader without lowering its floor.
    const receipt = try sys.join(s, &.{ work, "accepted-head.json" });
    try sys.atomic(s, receipt, try json.from(s.gpa, .{
        .head = try sys.read(s, try sys.join(s, &.{ bundle, "boot.json" }), boot.head_limit),
        .signature = try sys.hexAlloc(
            s.gpa,
            try sys.read(s, try sys.join(s, &.{ bundle, "boot.json.sig" }), boot.signature_limit),
        ),
    }));
    try store.upload(s, try key(s, namespace, "latest/accepted-head.json"), receipt, false);
    for ([_][]const u8{
        "latest/boot.json.sig",
        "latest/boot.json",
        "latest.json.sig",
        "latest.json",
    }) |name| {
        // The update head last: every machine on the channel takes it.
        const k = try key(s, namespace, name);
        try store.upload(s, k, try sys.join(s, &.{ public, k }), false);
    }
    return plan;
}

fn key(s: *Sys, namespace: []const u8, name: []const u8) ![]const u8 {
    return s.gpa.print("{s}/{s}", .{ namespace, name });
}

const testing = std.testing;
const fixture = @import("fixture.zig");

/// Publication is a channel on a recording bucket. Its bundles' "signature"
/// is the descriptor's hash, which the fake admission checks: these tests
/// isolate ordering and interruption; native admission has its own.
const Publication = struct {
    f: fixture.Fixture,
    bucket: fixture.FakeBucket,
    trust: []const u8,
    namespace: []const u8,

    fn init(p: *Publication) !void {
        try p.f.init();
        p.bucket = .{ .root = p.f.path("store") };
        p.f.bucket = &p.bucket;
        p.f.answer = admit;
        p.trust = p.f.path("trust");
        try sys.writeJson(&p.f.s, try sys.join(
            &p.f.s,
            &.{ p.trust, "trust.json" },
        ), try json.from(p.f.gpa(), .{
            .format = "werewolf-boot-trust/2",
            .source = "https://vendor.test/boot/v1",
        }));
        p.namespace = p.f.path("store/playground/lima/aarch64");
    }

    fn deinit(p: *Publication) void {
        p.f.deinit();
    }

    fn bundle(p: *Publication, name: []const u8, minute: i64, index: ?i64) ![]const u8 {
        const s = &p.f.s;
        const gpa = p.f.gpa();
        const dir = p.f.path(name);
        const serial = sys.serial(@divTrunc(s.now(), 60) * 60 + minute * 60);
        const build = try gpa.alloc(u8, 64);
        @memset(build, name[0]);
        try sys.write(s, try sys.join(
            s,
            &.{ dir, "boot.json" },
        ), try json.dumps(gpa, try json.from(gpa, .{
            .form = "playground",
            .image = .{
                .arch = "aarch64",
                .build = build,
                .serial = &serial,
                .index = index orelse minute + 1,
            },
        })));
        try sys.write(
            s,
            try sys.join(s, &.{ dir, "boot.json.sig" }),
            &try sys.sha(s, try sys.join(s, &.{ dir, "boot.json" })),
        );
        try sys.write(
            s,
            try sys.join(s, &.{ dir, "disk.img.zst" }),
            try gpa.print("disk:{s}", .{name}),
        );
        for (boot.files) |file| try sys.write(
            s,
            try sys.join(s, &.{ dir, "slot", file }),
            try gpa.print("{s}{s}", .{ file, name }),
        );
        for ([_][]const u8{ "latest.json", "latest.json.sig" }) |file|
            try sys.write(
                s,
                try sys.join(s, &.{ dir, "prebuilt/aarch64", file }),
                try gpa.print("{s}{s}", .{ file, name }),
            );
        return dir;
    }

    fn report(p: *Publication, dir: []const u8) !Json {
        const gpa = p.f.gpa();
        var checks: json.Map = .empty;
        for (prepare.gates) |g| try checks.put(gpa, g, .{ .bool = true });
        return json.from(gpa, .{
            .format = "werewolf-boot-gates/1",
            .descriptor = try gpa.dupe(
                u8,
                &try sys.sha(&p.f.s, try sys.join(&p.f.s, &.{ dir, "boot.json" })),
            ),
            .arch = "aarch64",
            .provider = "lima",
            .checks = checks,
        });
    }

    fn send(p: *Publication, dir: []const u8) !Json {
        return sendTo(p, dir, "s3://store");
    }

    fn sendTo(p: *Publication, dir: []const u8, bucket: []const u8) !Json {
        return publish(
            &p.f.s,
            "howl",
            dir,
            try p.report(dir),
            "lima",
            Store.init(bucket),
            p.trust,
            null,
        );
    }

    fn heads(p: *Publication) ![]const u8 {
        const s = &p.f.s;
        var all: std.ArrayList(u8) = .empty;
        for ([_][]const u8{
            "latest/boot.json",
            "latest/boot.json.sig",
            "latest/accepted-head.json",
            "latest.json",
            "latest.json.sig",
        }) |name| {
            const path = try sys.join(s, &.{ p.namespace, name });
            try all.appendSlice(
                p.f.gpa(),
                if (sys.exists(s, path)) try sys.read(s, path, 1 << 20) else "-",
            );
        }
        return all.items;
    }

    fn admit(f: *fixture.Fixture, argv: []const []const u8) anyerror!?sys.Result {
        if (argv.len < 8 or !mem.eql(u8, argv[1], "_boot-image")) return null;
        try testing.expectEqualStrings("https://vendor.test/boot/v1/playground/lima", argv[6]);
        const head = try sys.join(&f.s, &.{ argv[3], "boot.json" });
        if (mem.eql(u8, argv[2], "head")) {
            const signature = try sys.read(
                &f.s,
                try sys.join(&f.s, &.{ argv[3], "boot.json.sig" }),
                512,
            );
            if (!mem.eql(
                u8,
                signature,
                &try sys.sha(&f.s, head),
            )) return .{ .term = .{ .exited = 1 }, .stderr = "test head signature differs" };
            return .{ .term = .{ .exited = 0 }, .stdout = try sys.read(&f.s, head, 1 << 20) };
        }
        try testing.expectEqualStrings("verify", argv[2]);
        return .{ .term = .{ .exited = 0 }, .stdout = "{}" };
    }

    fn immutables(p: *Publication) usize {
        var n: usize = 0;
        for (p.bucket.writes.items) |w| n += @intFromBool(w.immutable);
        return n;
    }
};

test "objects precede the atomic floor, the boot head and last the update head" {
    var p: Publication = undefined;
    try p.init();
    defer p.deinit();
    const s = &p.f.s;
    const a = try p.bundle("a", 0, null);
    const plan = try p.send(a);
    const writes = p.bucket.writes.items;
    try testing.expectEqual(@as(usize, 15), p.immutables());
    for (writes[0 .. writes.len - 5]) |w| try testing.expect(w.immutable);
    const last = [_][]const u8{
        "latest/accepted-head.json",
        "latest/boot.json.sig",
        "latest/boot.json",
        "latest.json.sig",
        "latest.json",
    };
    for (last, writes[writes.len - 5 ..]) |want, w| try testing.expectEqualStrings(
        try s.gpa.print("playground/lima/aarch64/{s}", .{want}),
        w.key,
    );
    for (try json.items(json.get(plan, "files").?)) |entry|
        try testing.expectEqualStrings(
            try json.text(entry, "sha256"),
            &try sys.sha(s, p.f.path(try s.gpa.print("store/{s}", .{try json.text(entry, "key")}))),
        );
    try testing.expectEqualStrings(
        try sys.read(s, p.f.path("a/boot.json"), 4096),
        try sys.read(s, try sys.join(s, &.{ p.namespace, "latest/boot.json" }), 4096),
    );
    try testing.expectEqualStrings(
        try sys.read(s, p.f.path("a/prebuilt/aarch64/latest.json"), 4096),
        try sys.read(s, try sys.join(s, &.{ p.namespace, "latest.json" }), 4096),
    );
}

test "a missing lifecycle gate writes nothing" {
    var p: Publication = undefined;
    try p.init();
    defer p.deinit();
    const a = try p.bundle("a", 0, null);
    var report = try p.report(a);
    _ = report.object.getPtr("checks").?.object.orderedRemove("retirement_cuts");
    try testing.expectError(
        error.Refused,
        publish(&p.f.s, "howl", a, report, "lima", Store.init("s3://store"), p.trust, null),
    );
    try testing.expectEqual(@as(usize, 0), p.bucket.writes.items.len);
    try testing.expect(!sys.exists(&p.f.s, p.namespace));
}

test "an object failure keeps the previous heads and floor until retried" {
    var p: Publication = undefined;
    try p.init();
    defer p.deinit();
    _ = try p.send(try p.bundle("a", 0, null));
    const before = try p.heads();
    const b = try p.bundle("b", 1, null);
    p.bucket.fail = "/root.erofs";
    try testing.expectError(error.Refused, p.send(b));
    try testing.expectEqualStrings(before, try p.heads());
    p.bucket.fail = null;
    _ = try p.send(b);
}

test "an immutable collision never advances the head" {
    var p: Publication = undefined;
    try p.init();
    defer p.deinit();
    const s = &p.f.s;
    _ = try p.send(try p.bundle("a", 0, null));
    const before = try sys.read(s, try sys.join(s, &.{ p.namespace, "latest/boot.json" }), 4096);
    const b = try p.bundle("b", 1, null);
    try sys.write(
        s,
        try sys.join(
            s,
            &.{
                p.namespace,
                "objects",
                &try sys.sha(s, try sys.join(s, &.{ b, "boot.json" })),
                "root.erofs",
            },
        ),
        "collision",
    );
    try testing.expectError(error.Refused, p.send(b));
    try testing.expectEqualStrings("immutable protected object collision", s.why.text);
    try testing.expectEqualStrings(
        before,
        try sys.read(s, try sys.join(s, &.{ p.namespace, "latest/boot.json" }), 4096),
    );
}

test "a torn head recovers and keeps the newer authenticated floor" {
    var p: Publication = undefined;
    try p.init();
    defer p.deinit();
    const s = &p.f.s;
    const a = try p.bundle("a", 0, null);
    const b = try p.bundle("b", 1, null);
    _ = try p.send(a);
    p.bucket.fail = "/latest/boot.json";
    try testing.expectError(error.Refused, p.send(b));
    try testing.expectError(error.Refused, p.send(a));
    try testing.expectEqualStrings("older protected boot release", s.why.text);
    p.bucket.fail = null;
    _ = try p.send(b);
    try testing.expectEqualStrings(
        try sys.read(s, try sys.join(s, &.{ b, "boot.json" }), 4096),
        try sys.read(s, try sys.join(s, &.{ p.namespace, "latest/boot.json" }), 4096),
    );
}

test "a cut before the update head keeps machines on the previous release until retried" {
    var p: Publication = undefined;
    try p.init();
    defer p.deinit();
    const s = &p.f.s;
    const a = try p.bundle("a", 0, null);
    const b = try p.bundle("b", 1, null);
    _ = try p.send(a);
    p.bucket.fail = "aarch64/latest.json";
    try testing.expectError(error.Refused, p.send(b));
    const channel = try sys.join(s, &.{ p.namespace, "latest.json" });
    try testing.expectEqualStrings(
        try sys.read(s, try sys.join(s, &.{ b, "boot.json" }), 4096),
        try sys.read(s, try sys.join(s, &.{ p.namespace, "latest/boot.json" }), 4096),
    );
    try testing.expectEqualStrings(
        try sys.read(s, try sys.join(s, &.{ a, "prebuilt/aarch64/latest.json" }), 4096),
        try sys.read(s, channel, 4096),
    );
    try testing.expectError(error.Refused, p.send(a));
    try testing.expectEqualStrings("older protected boot release", s.why.text);
    p.bucket.fail = null;
    _ = try p.send(b);
    try testing.expectEqualStrings(
        try sys.read(s, try sys.join(s, &.{ b, "prebuilt/aarch64/latest.json" }), 4096),
        try sys.read(s, channel, 4096),
    );
}

test "a published release must take a later channel index" {
    var p: Publication = undefined;
    try p.init();
    defer p.deinit();
    const s = &p.f.s;
    _ = try p.send(try p.bundle("b", 1, null));
    p.bucket.writes.clearRetainingCapacity();
    for ([_]struct { []const u8, i64 }{ .{ "d", 2 }, .{ "e", 1 } }) |c| {
        try testing.expectError(error.Refused, p.send(try p.bundle(c[0], 2, c[1])));
        try testing.expectEqualStrings(
            "a published release must take a later channel index",
            s.why.text,
        );
        try testing.expectEqual(@as(usize, 0), p.bucket.writes.items.len);
    }
    _ = try p.send(try p.bundle("f", 3, 3));
    const head = try sys.readJson(s, try sys.join(s, &.{ p.namespace, "latest/boot.json" }), 4096);
    try testing.expectEqual(@as(i64, 3), try json.int(try json.field(head, "image"), "index"));
}

test "a head published before channel indices precedes every indexed release" {
    var p: Publication = undefined;
    try p.init();
    defer p.deinit();
    const s = &p.f.s;
    const head = try sys.join(s, &.{ p.namespace, "latest/boot.json" });
    try sys.write(s, head, try json.dumps(s.gpa, try json.from(s.gpa, .{ .form = "playgroun" ++
        "d", .image = .{
        .arch = "aarch64",
        .build = fixture.rep('9', 64),
        .serial = "20260101T000000Z",
    } })));
    try sys.write(
        s,
        try sys.join(s, &.{ p.namespace, "latest/boot.json.sig" }),
        &try sys.sha(s, head),
    );
    const a = try p.bundle("a", 0, null);
    _ = try p.send(a);
    try testing.expectEqualStrings(
        try sys.read(s, try sys.join(s, &.{ a, "boot.json" }), 4096),
        try sys.read(s, head, 4096),
    );
}

test "a first publication cut at any head can be retried" {
    var p: Publication = undefined;
    try p.init();
    defer p.deinit();
    const a = try p.bundle("a", 0, null);
    for ([_][]const u8{
        "/latest/boot.json.sig",
        "/latest/boot.json",
        "aarch64/latest.json.sig",
        "aarch64/latest.json",
    }, 0..) |failure, i| {
        p.bucket = .{ .root = p.f.path(try p.f.gpa().print("first-{d}", .{i})), .fail = failure };
        try testing.expectError(error.Refused, p.send(a));
        p.bucket.fail = null;
        _ = try p.send(a);
    }
}

test "a tampered publication receipt refuses every write" {
    var p: Publication = undefined;
    try p.init();
    defer p.deinit();
    const s = &p.f.s;
    _ = try p.send(try p.bundle("a", 0, null));
    const receipt = try sys.join(s, &.{ p.namespace, "latest/accepted-head.json" });
    var saved = try sys.readJson(s, receipt, 1 << 20);
    try saved.object.put(
        s.gpa,
        "head",
        .{ .string = try s.gpa.print("{s} ", .{try json.text(saved, "head")}) },
    );
    try sys.write(s, receipt, try json.dumps(s.gpa, saved));
    p.bucket.writes.clearRetainingCapacity();
    try testing.expectError(error.Refused, p.send(try p.bundle("b", 1, null)));
    try testing.expectEqual(@as(usize, 0), p.bucket.writes.items.len);
}

test "replay and equivocation refuse, an identical retry uploads only heads" {
    var p: Publication = undefined;
    try p.init();
    defer p.deinit();
    const s = &p.f.s;
    const a = try p.bundle("a", 0, null);
    _ = try p.send(a);
    p.bucket.writes.clearRetainingCapacity();
    _ = try p.send(a);
    try testing.expectEqual(@as(usize, 5), p.bucket.writes.items.len);
    try testing.expectEqual(@as(usize, 0), p.immutables());
    _ = try p.send(try p.bundle("b", 1, null));
    try testing.expectError(error.Refused, p.send(a));
    try testing.expectEqualStrings("older protected boot release", s.why.text);
    try testing.expectError(error.Refused, p.send(try p.bundle("c", 1, null)));
    try testing.expectEqualStrings("protected release serial reused", s.why.text);
}

test "a directory store publishes in the same order" {
    var p: Publication = undefined;
    try p.init();
    defer p.deinit();
    const s = &p.f.s;
    const a = try p.bundle("a", 0, null);
    _ = try p.sendTo(a, p.f.path("local"));
    try testing.expectEqualStrings(
        try sys.read(s, try sys.join(s, &.{ a, "boot.json" }), 4096),
        try sys.read(s, p.f.path("local/playground/lima/aarch64/latest/boot.json"), 4096),
    );
    try testing.expectEqual(@as(usize, 0), p.bucket.writes.items.len);
}
