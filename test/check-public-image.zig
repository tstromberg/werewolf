//! check-public-image HOWL TARGETS_JSON OUTPUT discovers, downloads and
//! operates each newly published QEMU image, as a consumer with no source
//! tree and no guest test additions would: the signed public catalog must
//! advertise it, the downloaded bundle must be the vendor's, boots must be
//! protected and committed, a repeat must reuse the boot and authority, the
//! machine must check the public channel itself, and a resume must keep
//! its enrollment. It needs a native Linux QEMU runner.

const std = @import("std");
const builtin = @import("builtin");
const host = @import("host");
const form = @import("form");
const published = @import("published.zig");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const mem = std.mem;
const json = std.json;

const machine_name = "public-image";

pub fn main(init: std.process.Init) !void {
    var c = try host.Check.init(init, "public image");
    if (c.args.len != 4) {
        complain(c.io, "usage: check-public-image HOWL TARGETS_JSON OUTPUT", .{});
        std.process.exit(1);
    }
    const howl = try c.absolute(c.args[1]);
    const output = try c.absolute(c.args[3]);
    const targets = json.parseFromSliceLeaky(json.Value, c.gpa, c.args[2], .{}) catch
        c.finish(c.fail("TARGETS_JSON is not JSON", .{}));
    if (targets != .array) c.finish(c.fail("TARGETS_JSON is not a list of targets", .{}));
    const table = try host.evidence.load(c.gpa, form);
    const images = try published.Images.load(c.io, c.gpa);
    var failed = false;
    for (targets.array.items) |target| {
        var one: Public = .{ .c = &c, .howl = howl, .required = table.published, .images = images };
        one.check(target, output) catch |err| {
            const why = if (err == error.CheckFailed) c.why else @errorName(err);
            complain(c.io, "FAIL public image: {s}", .{why});
            failed = true;
        };
    }
    std.process.exit(if (failed) 1 else 0);
}

/// complain says one line on standard error.
fn complain(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [4096]u8 = undefined;
    var out = Io.File.stderr().writerStreaming(io, &buf);
    out.interface.print(fmt ++ "\n", args) catch return;
    out.interface.flush() catch {};
}

/// Entry is one command of a target's journal, commands.json.
const Entry = struct { label: []const u8, exit: ?u8, log: []const u8 };

const Public = struct {
    c: *host.Check,
    howl: []const u8,
    required: []const []const u8,
    images: published.Images,
    env: std.process.Environ.Map = undefined,
    consumer: []const u8 = "",
    machine: []const u8 = "",
    journal: std.ArrayList(Entry) = .empty,

    fn check(p: *Public, target: json.Value, output: []const u8) !void {
        const c = p.c;
        const gpa = c.gpa;
        const io = c.io;
        const name = published.text(target, "form") orelse
            return c.fail("a target names no form", .{});
        const arch = published.text(target, "arch") orelse
            return c.fail("a target names no arch", .{});
        if (!p.images.isTarget(name, "qemu", arch))
            return c.fail("invalid form image target", .{});
        const cpu_arch = builtin.cpu.arch;
        const host_arch = if (cpu_arch == .aarch64) "aarch64" else @tagName(cpu_arch);
        if (builtin.os.tag != .linux or !mem.eql(u8, host_arch, arch))
            return c.fail("public image checks require a native Linux QEMU runner", .{});
        const leaf = try gpa.print("{s}-{s}", .{ name, arch });
        const work = try std.fs.path.join(gpa, &.{ output, leaf });
        if (exists(io, work)) return c.fail("{s} exists already", .{work});
        try c.setWork(work);
        p.consumer = try published.temporary(io, gpa, "ww-public-");
        p.machine = try std.fs.path.join(gpa, &.{ p.consumer, "build/machines", machine_name });
        const bin = try std.fs.path.join(gpa, &.{ p.consumer, "bin" });
        try Io.Dir.cwd().createDir(io, bin, .default_dir);
        try host.consumer.refuseBuilds(io, gpa, bin);
        p.env = try c.env.clone(gpa);
        try host.consumer.scrub(gpa, &p.env);
        try p.env.put("XDG_DATA_HOME", try std.fs.path.join(gpa, &.{ p.consumer, "data" }));
        try p.env.put("PATH", try gpa.print("{s}:{s}", .{ bin, c.env.get("PATH") orelse "" }));
        var successful = false;
        defer p.finish(successful);
        try p.operate(target, name, arch);
        successful = true;
        c.say(
            "pass: public {s}/qemu/{s} discovery, protected boot, reuse, update check and resume",
            .{ name, arch },
        );
    }

    fn operate(p: *Public, target: json.Value, name: []const u8, arch: []const u8) !void {
        const c = p.c;
        const gpa = c.gpa;
        const discover = [_][]const u8{ p.howl, "forms", "--published", "--arch", arch, "--json" };
        const listing = try p.must(&discover, "discovery");
        const catalog = json.parseFromSliceLeaky(json.Value, gpa, listing.stdout, .{}) catch
            return c.fail("discovery: howl forms said no JSON", .{});
        const object = published.text(target, "object") orelse
            return c.fail("a target names no object", .{});
        const advertised = latestObject(catalog, name, arch) orelse
            return c.fail("signed public catalog has no single {s}/qemu/{s} row", .{ name, arch });
        if (!mem.eql(u8, advertised, object))
            return c.fail("signed public catalog does not advertise the published descriptor", .{});
        var create: std.ArrayList([]const u8) = .empty;
        try create.appendSlice(gpa, &.{
            p.howl,
            "create",
            machine_name,
            "--with",
            name,
            "--on",
            "qemu",
            "--yes",
            "--add-current-user",
            "no",
        });
        if (mem.eql(u8, name, "postdoc-server")) {
            const config = try c.path("config");
            _ = try c.must(&.{ "forms/postdoc-server/test/config", config }, "config", .{});
            try create.appendSlice(gpa, &.{ "--config", config });
        }
        _ = try p.must(create.items, "download-and-boot");
        const first = try p.status(null);
        const record = try p.profile();
        const bundle = published.bundleDirectory(record) orelse "";
        const head = try std.fs.path.join(gpa, &.{ bundle, "boot.json" });
        const downloaded = host.check.hexDigest(c.io, head) catch @as([64]u8, @splat('-'));
        const descriptor = published.text(target, "descriptor") orelse "";
        if (!mem.eql(u8, &downloaded, descriptor) or !published.vendorFree(record))
            return c.fail("consumer did not use the expected vendor-signed public image", .{});
        const keys = try p.authority();
        _ = try p.must(create.items, "repeat");
        const again = try p.status(null);
        if (!mem.eql(u8, again.boot_id, first.boot_id) or !mem.eql(u8, &try p.authority(), &keys))
            return c.fail("unchanged public run replaced the boot or owner authority", .{});
        _ = try p.must(&.{ p.howl, "owner", machine_name, "check" }, "authenticated-update-check");
        _ = try p.must(&.{ p.howl, "stop", machine_name, "--on", "qemu" }, "stop");
        _ = try p.must(create.items, "resume");
        const resumed = try p.status(first.boot_id);
        if (!mem.eql(u8, &try p.authority(), &keys))
            return c.fail("public resume replaced the enrollment", .{});
        _ = try p.must(&.{ p.howl, "delete", machine_name, "--on", "qemu" }, "cleanup");
        if (exists(c.io, p.machine))
            return c.fail("public consumer cleanup left the machine behind", .{});
        const result = try json.Stringify.valueAlloc(gpa, .{
            .target = target,
            .public_download = true,
            .source_free_consumer = true,
            .guest_test_additions = false,
            .first_boot = first.boot_id,
            .resumed_boot = resumed.boot_id,
            .retained_authority = true,
            .authenticated_update_check = true,
            .scope = "Public R2 discovery, native admission, protected boots and the " ++
                "machine's own check of the public channel",
        }, .{ .whitespace = .indent_2 });
        const path = try c.path("result.json");
        const data = try gpa.print("{s}\n", .{result});
        try Io.Dir.cwd().writeFile(c.io, .{ .sub_path = path, .data = data });
    }

    /// finish keeps the journal and, on failure, the consumer and its
    /// machine, stopped; on success it removes the consumer.
    fn finish(p: *Public, successful: bool) void {
        const c = p.c;
        const gpa = c.gpa;
        const stop = [_][]const u8{ p.howl, "stop", machine_name, "--on", "qemu" };
        if (exists(c.io, p.machine))
            _ = p.run(&stop, "retain-failure") catch {};
        if (json.Stringify.valueAlloc(gpa, p.journal.items, .{ .whitespace = .indent_2 })) |text| {
            const path = c.path("commands.json") catch return;
            const data = gpa.print("{s}\n", .{text}) catch return;
            Io.Dir.cwd().writeFile(c.io, .{ .sub_path = path, .data = data }) catch {};
        } else |_| {}
        if (successful) {
            Io.Dir.cwd().deleteTree(c.io, p.consumer) catch {};
        } else {
            const path = c.path("retained-consumer.txt") catch return;
            const data = gpa.print("{s}\n", .{p.consumer}) catch return;
            Io.Dir.cwd().writeFile(c.io, .{ .sub_path = path, .data = data }) catch {};
        }
    }

    /// run runs argv in the consumer, its output in NNN-label.log, and
    /// notes it in the journal.
    fn run(p: *Public, argv: []const []const u8, label: []const u8) !host.check.Result {
        return p.timed(argv, label, 600);
    }

    fn timed(
        p: *Public,
        argv: []const []const u8,
        label: []const u8,
        seconds: i64,
    ) !host.check.Result {
        const c = p.c;
        const log = try c.gpa.print("{d:0>3}-{s}.log", .{ p.journal.items.len, label });
        const r = host.check.command(c.io, c.gpa, argv, .{
            .environ_map = &p.env,
            .cwd = p.consumer,
            .timeout = .fromSeconds(seconds),
        }) catch |err| {
            try p.journal.append(c.gpa, .{ .label = label, .exit = null, .log = log });
            try Io.Dir.cwd().writeFile(c.io, .{
                .sub_path = try c.path(log),
                .data = @errorName(err),
            });
            return err;
        };
        try Io.Dir.cwd().writeFile(c.io, .{
            .sub_path = try c.path(log),
            .data = try mem.concat(c.gpa, u8, &.{ r.stdout, r.stderr }),
        });
        try p.journal.append(c.gpa, .{ .label = label, .exit = r.code(), .log = log });
        return r;
    }

    fn must(p: *Public, argv: []const []const u8, label: []const u8) !host.check.Result {
        const r = p.run(argv, label) catch |err| return p.c.fail("{s}: {t}", .{ label, err });
        if (!r.ok()) return p.c.fail("{s}: {s}", .{ label, host.check.tail(r.stderr, 2000) });
        return r;
    }

    const Status = struct { boot_id: []const u8 };

    /// status waits for a committed, protected boot other than previous,
    /// and pauses its updater, so nothing changes between steps.
    fn status(p: *Public, previous: ?[]const u8) !Status {
        const c = p.c;
        const deadline = host.qemu.after(c.io, 240);
        while (Io.Clock.Timestamp.now(c.io, .awake).compare(.lt, deadline)) {
            const argv = [_][]const u8{ p.howl, "owner", machine_name, "status" };
            const reply = p.timed(&argv, "status", 20) catch null;
            const value: json.Value = if (reply != null and reply.?.ok())
                json.parseFromSliceLeaky(json.Value, c.gpa, reply.?.stdout, .{}) catch .null
            else
                .null;
            if (try ready(c.gpa, value, previous, p.required)) |boot_id| {
                if (boot_id.len == 0) {
                    const results = try host.evidence.results(c.gpa, value);
                    const missing = try published.missing(c.gpa, results, p.required);
                    return c.fail("public image reports missing protection: {s}", .{missing});
                }
                _ = try p.must(&.{ p.howl, "owner", machine_name, "pause" }, "pause");
                return .{ .boot_id = boot_id };
            }
            try c.io.sleep(.fromSeconds(2), .awake);
        }
        return c.fail("public image did not report a committed protected boot", .{});
    }

    fn profile(p: *Public) !json.Value {
        const path = try std.fs.path.join(p.c.gpa, &.{ p.machine, "authority/profile.json" });
        const data = try Io.Dir.cwd().readFileAlloc(p.c.io, path, p.c.gpa, .limited(1 << 20));
        return json.parseFromSliceLeaky(json.Value, p.c.gpa, data, .{});
    }

    /// authority is the digest of what the host keeps of the machine's
    /// authority: its enrolled boot certificate and profile, no TPM secret.
    fn authority(p: *Public) ![64]u8 {
        var h: std.crypto.hash.sha2.Sha256 = .init(.{});
        for ([_][]const u8{ "boot.crt", "authority/profile.json" }) |name| {
            const path = try std.fs.path.join(p.c.gpa, &.{ p.machine, name });
            h.update(&try host.check.digest(p.c.io, path));
        }
        return std.fmt.bytesToHex(h.finalResult(), .lower);
    }
};

/// ready judges an owner status: null until it is ready, committed and a
/// boot other than previous; then its boot ID, or "" if a required check
/// did not pass.
fn ready(
    gpa: Allocator,
    value: json.Value,
    previous: ?[]const u8,
    required: []const []const u8,
) !?[]const u8 {
    if (!published.isTrue(published.field(value, "ready")) or
        !published.isTrue(published.field(value, "committed"))) return null;
    const boot_id = published.text(value, "boot_id") orelse return null;
    if (previous) |p| if (mem.eql(u8, p, boot_id)) return null;
    if (!host.evidence.passes(try host.evidence.results(gpa, value), required)) return "";
    return boot_id;
}

/// latestObject is the object the catalog's one row for form/qemu/arch
/// advertises as latest, or null if there is not exactly one such row.
fn latestObject(catalog: json.Value, name: []const u8, arch: []const u8) ?[]const u8 {
    const rows = published.field(catalog, "forms") orelse return null;
    if (rows != .array) return null;
    var found: ?json.Value = null;
    for (rows.array.items) |row| {
        const f = published.text(row, "form") orelse continue;
        const provider = published.text(row, "provider") orelse continue;
        const a = published.text(row, "arch") orelse continue;
        if (!mem.eql(u8, f, name) or !mem.eql(u8, provider, "qemu") or !mem.eql(u8, a, arch))
            continue;
        if (found != null) return null;
        found = row;
    }
    const latest = published.field(found orelse return null, "latest") orelse return null;
    return published.text(latest, "object");
}

fn exists(io: Io, path: []const u8) bool {
    Io.Dir.cwd().access(io, path, .{}) catch return false;
    return true;
}

test "the catalog must advertise one row for the target" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const catalog = try json.parseFromSliceLeaky(json.Value, gpa,
        \\{"forms": [
        \\  {"form": "minimal", "provider": "lima", "arch": "aarch64", "latest": {"object": "l"}},
        \\  {"form": "minimal", "provider": "qemu", "arch": "aarch64", "latest": {"object": "q"}},
        \\  {"form": "prod-ssh", "provider": "qemu", "arch": "aarch64", "latest": null},
        \\  {"form": "playground", "provider": "qemu", "arch": "x86_64"},
        \\  {"form": "playground", "provider": "qemu", "arch": "x86_64"}
        \\]}
    , .{});
    try std.testing.expectEqualStrings("q", latestObject(catalog, "minimal", "aarch64").?);
    try std.testing.expectEqual(null, latestObject(catalog, "prod-ssh", "aarch64"));
    try std.testing.expectEqual(null, latestObject(catalog, "playground", "x86_64"));
    try std.testing.expectEqual(null, latestObject(catalog, "minimal", "x86_64"));
}

test "a status passes once ready, committed, fresh and protected" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const required = (try host.evidence.load(gpa, form)).published;
    var checks: std.ArrayList(u8) = .empty;
    for (required, 0..) |id, i| {
        const sep = if (i > 0) "," else "";
        try checks.print(gpa, "{s}{{\"id\":\"{s}\",\"result\":\"pass\"}}", .{ sep, id });
    }
    const good = try gpa.print(
        "{{\"ready\":true,\"committed\":true,\"boot_id\":\"b1\",\"checks\":[{s}]}}",
        .{checks.items},
    );
    const parse = struct {
        fn f(a: Allocator, s: []const u8) !json.Value {
            return json.parseFromSliceLeaky(json.Value, a, s, .{});
        }
    }.f;
    try std.testing.expectEqualStrings(
        "b1",
        (try ready(gpa, try parse(gpa, good), null, required)).?,
    );
    try std.testing.expectEqual(null, try ready(gpa, try parse(gpa, good), "b1", required));
    const changes = [_][2][]const u8{
        .{ "\"ready\":true", "\"ready\":false" },
        .{ "\"committed\":true", "\"committed\":false" },
    };
    for (changes) |change| {
        const changed = try mem.replaceOwned(u8, gpa, good, change[0], change[1]);
        try std.testing.expectEqual(null, try ready(gpa, try parse(gpa, changed), null, required));
    }
    for (required) |id| {
        const pass = try gpa.print("\"{s}\",\"result\":\"pass\"", .{id});
        const fail = try gpa.print("\"{s}\",\"result\":\"fail\"", .{id});
        const failing = try mem.replaceOwned(u8, gpa, good, pass, fail);
        try std.testing.expectEqualStrings(
            "",
            (try ready(gpa, try parse(gpa, failing), null, required)).?,
        );
    }
    try std.testing.expectEqual(null, try ready(gpa, .null, null, required));
}
