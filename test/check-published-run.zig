//! check-published-run HOWL BUNDLE OUTPUT [--public] boots the actual
//! production-signed playground bundle through a default `howl run`, on
//! Lima, from a directory with no source tree: the bundle from a private
//! HTTPS mirror laid out as the public one, or with --public from the
//! public mirror itself. The boot must be protected and committed, a
//! repeat run must neither reboot, download nor recheck the mirror, and a
//! resume after stop must keep the machine's enrollment. OUTPUT must not
//! exist yet.

const std = @import("std");
const host = @import("host");
const form = @import("form");
const published = @import("published.zig");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const mem = std.mem;
const json = std.json;

const machine_name = "werewolf-run";

pub fn main(init: std.process.Init) !void {
    var c = try host.Check.init(init, "published run");
    const public = c.args.len == 5 and mem.eql(u8, c.args[4], "--public");
    if (c.args.len != 4 and !public) {
        var buf: [256]u8 = undefined;
        var out = Io.File.stderr().writerStreaming(c.io, &buf);
        const usage = "usage: check-published-run HOWL BUNDLE OUTPUT [--public]\n";
        out.interface.writeAll(usage) catch {};
        out.interface.flush() catch {};
        std.process.exit(1);
    }
    var run: Run = .{ .c = &c, .public = public };
    c.finish(run.check());
}

const Run = struct {
    c: *host.Check,
    public: bool,
    howl: []const u8 = "",
    consumer: []const u8 = "",
    machine: []const u8 = "",
    identity: []const u8 = "",
    lima_home: []const u8 = "",
    env: std.process.Environ.Map = undefined,
    mirror: published.Mirror = undefined,
    required: []const []const u8 = &.{},

    fn check(r: *Run) !void {
        const c = r.c;
        const gpa = c.gpa;
        const io = c.io;
        published.private();
        r.howl = try c.absolute(c.args[1]);
        const bundle = try c.absolute(c.args[2]);
        const work = try c.absolute(c.args[3]);
        if (exists(io, work)) return c.fail("{s} exists already", .{work});
        try c.setWork(work);
        r.required = (try host.evidence.load(gpa, form)).ssh;
        r.consumer = try c.path("consumer");
        try Io.Dir.cwd().createDir(io, r.consumer, .default_dir);
        const mirror = try c.path("mirror");
        const base = try std.fs.path.join(gpa, &.{ mirror, "playground/lima/aarch64" });
        const descriptor = try published.stock(io, gpa, bundle, base, "aarch64");
        const latest = try std.fs.path.join(gpa, &.{ base, "latest" });
        try Io.Dir.cwd().createDirPath(io, latest);
        try published.promote(io, gpa, bundle, latest);
        r.identity = try c.path("ssh.key");
        const keygen = [_][]const u8{ "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f" };
        _ = try c.must(&(keygen ++ .{r.identity}), "", .{});
        r.env = try c.env.clone(gpa);
        try host.consumer.scrub(gpa, &r.env);
        try r.mirror.start(io, gpa, mirror, "werewolf-local-mirror");
        defer r.cleanup();
        const bin = try c.path("bin");
        try Io.Dir.cwd().createDir(io, bin, .default_dir);
        try host.consumer.refuseBuilds(io, gpa, bin);
        const ssh = host.consumer.which(io, gpa, &c.env, "ssh") orelse
            return c.fail("no ssh on PATH", .{});
        try host.consumer.sshWith(io, gpa, bin, ssh, r.identity);
        r.lima_home = try published.temporary(io, gpa, "ww-production-run-");
        const roots = try c.path("mirror-roots.pem");
        const bundles = &host.consumer.system_bundles;
        const pem = host.consumer.mirrorRoots(io, gpa, &c.env, bundles, r.mirror.authority) catch
            return c.fail("public TLS roots are missing; install ca-certificates", .{});
        try Io.Dir.cwd().writeFile(io, .{ .sub_path = roots, .data = pem });
        try r.env.put("LIMA_HOME", r.lima_home);
        try r.env.put("XDG_DATA_HOME", try std.fs.path.join(gpa, &.{ r.consumer, "data" }));
        try r.env.put("PATH", try gpa.print("{s}:{s}", .{ bin, c.env.get("PATH") orelse "" }));
        if (r.public) {
            // The production mirror, trusted as this host trusts the web.
            if (c.env.get("SSL_CERT_FILE")) |file| {
                try r.env.put("SSL_CERT_FILE", file);
            } else {
                _ = r.env.swapRemove("SSL_CERT_FILE");
            }
        } else {
            try r.env.put("SSL_CERT_FILE", roots);
            try r.env.put("WEREWOLF_BOOT_MIRROR", try r.mirror.url(gpa));
        }
        r.machine = try std.fs.path.join(gpa, &.{ r.consumer, "build/machines", machine_name });
        const root_keys = try gpa.print("{s}.pub", .{r.identity});
        const run_argv = [_][]const u8{ r.howl, "run", "--root-keys", root_keys };
        _ = try r.must(&run_argv, "first-run", 600);
        const boot = try r.committed() orelse
            return c.fail("actual production image did not report committed protected boot", .{});
        // The host keeps no TPM authority: only the enrolled boot certificate and profile.
        const before = try r.authority();
        const downloaded = try r.mirror.requests(gpa);
        const checked = try r.freshness();
        const began = Io.Clock.Timestamp.now(io, .awake);
        _ = try r.must(&run_argv, "repeat-run", 300);
        const elapsed = began.untilNow(io).raw.toMilliseconds();
        const now = try r.status();
        if (now == null or !mem.eql(u8, now.?, boot) or try r.mirror.requests(gpa) != downloaded)
            return c.fail("unchanged run rebooted or performed another download", .{});
        if (!mem.eql(u8, &checked, &try r.freshness()))
            return c.fail("unchanged run repeated mirror freshness checks", .{});
        if (!mem.eql(u8, &before, &try r.authority()))
            return c.fail("repeat run replaced machine authority", .{});
        const profile_path = try std.fs.path.join(gpa, &.{ r.machine, "authority/profile.json" });
        const text = try Io.Dir.cwd().readFileAlloc(io, profile_path, gpa, .limited(1 << 20));
        const profile = try json.parseFromSliceLeaky(json.Value, gpa, text, .{});
        const directory = published.bundleDirectory(profile) orelse "";
        const head = try std.fs.path.join(gpa, &.{ directory, "boot.json" });
        const got = host.check.hexDigest(io, head) catch @as([64]u8, @splat('-'));
        if (!mem.eql(u8, &got, &descriptor))
            return c.fail("actual download differs from the expected published image", .{});
        if (!published.vendorFree(profile))
            return c.fail("consumer owns a vendor signing key", .{});
        _ = try r.must(&.{ r.howl, "stop" }, "stop", 300);
        _ = try r.must(&run_argv, "resume", 600);
        const resumed = try r.committed();
        if (resumed == null or mem.eql(u8, resumed.?, boot))
            return c.fail("stopped production machine did not resume", .{});
        if (!mem.eql(u8, &before, &try r.authority()))
            return c.fail("resume replaced the enrollment", .{});
        const result = try json.Stringify.valueAlloc(gpa, .{
            .descriptor = &descriptor,
            .default_signed_download = true,
            .no_consumer_builds = true,
            .production_mirror = r.public,
            .no_vendor_private_keys = true,
            .secure_boot = true,
            .ipe = true,
            .rollback_protected = true,
            .verified_root = true,
            .retained_enrollment_on_resume = true,
            .unchanged_run_seconds = @as(f64, @floatFromInt(elapsed)) / 1000,
            .unchanged_run_no_network = true,
        }, .{ .whitespace = .indent_2 });
        try Io.Dir.cwd().writeFile(io, .{
            .sub_path = try c.path("result.json"),
            .data = try gpa.print("{s}\n", .{result}),
        });
        c.say("pass: actual production image, default download, protected boot, " ++
            "cached reuse and retained enrollment", .{});
    }

    fn cleanup(r: *Run) void {
        const c = r.c;
        _ = r.run(&.{ r.howl, "delete", machine_name, "--on", "lima" }, "cleanup", 180) catch {};
        r.mirror.stop();
        if (r.lima_home.len > 0) Io.Dir.cwd().deleteTree(c.io, r.lima_home) catch {};
        if (std.fs.path.join(c.gpa, &.{ r.consumer, "build/machines" })) |machines|
            Io.Dir.cwd().deleteTree(c.io, machines) catch {}
        else |_| {}
        Io.Dir.cwd().deleteFile(c.io, r.identity) catch {};
    }

    /// run runs argv in the consumer, its output in work/label.log.
    fn run(r: *Run, argv: []const []const u8, label: []const u8, seconds: i64) !host.check.Result {
        const result = try host.check.command(r.c.io, r.c.gpa, argv, .{
            .environ_map = &r.env,
            .cwd = r.consumer,
            .timeout = .fromSeconds(seconds),
        });
        Io.Dir.cwd().writeFile(r.c.io, .{
            .sub_path = try r.c.path(try r.c.gpa.print("{s}.log", .{label})),
            .data = try mem.concat(r.c.gpa, u8, &.{ result.stdout, result.stderr }),
        }) catch {};
        return result;
    }

    fn must(
        r: *Run,
        argv: []const []const u8,
        label: []const u8,
        seconds: i64,
    ) !host.check.Result {
        const result = r.run(argv, label, seconds) catch |err|
            return r.c.fail("{s}: {t}", .{ label, err });
        if (!result.ok())
            return r.c.fail("{s}: {s}", .{ label, host.check.tail(result.stderr, 3000) });
        return result;
    }

    /// status is the running boot's ID once it is committed, or null; it
    /// fails if a protection is missing, from the raw posture report rather
    /// than a boot marker alone.
    fn status(r: *Run) !?[]const u8 {
        const command = "/usr/lib/werewolf/posture --json; printf \"\\nBOOT-ID \"; " ++
            "cat /proc/sys/kernel/random/boot_id; " ++
            "printf \"COMMITTED \"; test -e /run/werewolf/committed && echo yes";
        const argv = [_][]const u8{ r.howl, "ssh", "root@" ++ machine_name, "--", command };
        const reply = r.run(&argv, "status", 15) catch |err| switch (err) {
            error.Timeout => return error.Unready,
            else => |e| return e,
        };
        if (!reply.ok()) return null;
        var why: host.check.Why = .{};
        return judge(r.c.gpa, reply.stdout, r.required, &why) catch |err| switch (err) {
            error.Refused => r.c.fail("{s}", .{why.text}),
            else => |e| e,
        };
    }

    /// committed waits up to three minutes for a committed boot.
    fn committed(r: *Run) !?[]const u8 {
        const deadline = host.qemu.after(r.c.io, 180);
        while (Io.Clock.Timestamp.now(r.c.io, .awake).compare(.lt, deadline)) {
            const boot = r.status() catch |err| switch (err) {
                error.Unready => null,
                else => |e| return e,
            };
            if (boot) |b| return b;
            try r.c.io.sleep(.fromSeconds(2), .awake);
        }
        return null;
    }

    fn authority(r: *Run) ![64]u8 {
        var h: std.crypto.hash.sha2.Sha256 = .init(.{});
        for ([_][]const u8{ "boot.crt", "authority/profile.json" }) |name| {
            const path = try std.fs.path.join(r.c.gpa, &.{ r.machine, name });
            h.update(&try host.check.digest(r.c.io, path));
        }
        return std.fmt.bytesToHex(h.finalResult(), .lower);
    }

    /// freshness is the digest of every mirror freshness record howl keeps.
    fn freshness(r: *Run) ![64]u8 {
        const io = r.c.io;
        const gpa = r.c.gpa;
        var h: std.crypto.hash.sha2.Sha256 = .init(.{});
        const cache = try std.fs.path.join(gpa, &.{ r.consumer, "build/boot-cache" });
        var dir = Io.Dir.cwd().openDir(io, cache, .{ .iterate = true }) catch
            return std.fmt.bytesToHex(h.finalResult(), .lower);
        defer dir.close(io);
        var names: std.ArrayList([]const u8) = .empty;
        var walker = try dir.walk(gpa);
        defer walker.deinit();
        while (try walker.next(io)) |e| {
            if (e.kind == .file and mem.eql(u8, e.basename, "current.json"))
                try names.append(gpa, try gpa.dupe(u8, e.path));
        }
        mem.sortUnstable([]const u8, names.items, {}, struct {
            fn less(_: void, a: []const u8, b: []const u8) bool {
                return mem.lessThan(u8, a, b);
            }
        }.less);
        for (names.items) |name| {
            h.update(name);
            h.update(&try host.check.digest(io, try std.fs.path.join(gpa, &.{ cache, name })));
        }
        return std.fmt.bytesToHex(h.finalResult(), .lower);
    }
};

/// judge reads the status reply: the posture report, then BOOT-ID and
/// COMMITTED lines. It refuses a report missing a required protection,
/// and returns the boot ID once the boot committed, else null.
fn judge(
    gpa: Allocator,
    reply: []const u8,
    required: []const []const u8,
    why: *host.check.Why,
) !?[]const u8 {
    const marker = "\nBOOT-ID ";
    const end = mem.find(u8, reply, marker) orelse return error.Unready;
    const report = json.parseFromSliceLeaky(json.Value, gpa, reply[0..end], .{}) catch
        return error.Unready;
    const checks = try host.evidence.results(gpa, report);
    if (!host.evidence.passes(checks, required)) {
        const missing = try published.missing(gpa, checks, required);
        return why.refuse("guest protection missing: {s}", .{missing});
    }
    if (mem.find(u8, reply, "COMMITTED yes") == null) return null;
    const rest = reply[end + marker.len ..];
    return rest[0 .. mem.findScalar(u8, rest, '\n') orelse rest.len];
}

fn exists(io: Io, path: []const u8) bool {
    Io.Dir.cwd().access(io, path, .{}) catch return false;
    return true;
}

test "a run's status needs every protection, and a commit to count" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const required = (try host.evidence.load(gpa, form)).ssh;
    var checks: std.ArrayList(u8) = .empty;
    for (required, 0..) |id, i| {
        const comma = if (i > 0) "," else "";
        try checks.print(gpa, "{s}{{\"id\":\"{s}\",\"result\":\"pass\"}}", .{ comma, id });
    }
    const report = try gpa.print("{{\"checks\":[{s}]}}", .{checks.items});
    const boot = "12345678-1234-1234-1234-123456789abc";
    var why: host.check.Why = .{};
    const good = try gpa.print("{s}\nBOOT-ID {s}\nCOMMITTED yes\n", .{ report, boot });
    try std.testing.expectEqualStrings(boot, (try judge(gpa, good, required, &why)).?);
    const trial = try gpa.print("{s}\nBOOT-ID {s}\nCOMMITTED ", .{ report, boot });
    try std.testing.expectEqual(null, try judge(gpa, trial, required, &why));
    try std.testing.expectError(error.Unready, judge(gpa, "no report", required, &why));
    for (required) |id| {
        const passed = try gpa.print("\"{s}\",\"result\":\"pass\"", .{id});
        const skipped = try gpa.print("\"{s}\",\"result\":\"skip\"", .{id});
        const failing = try mem.replaceOwned(u8, gpa, good, passed, skipped);
        try std.testing.expectError(error.Refused, judge(gpa, failing, required, &why));
        try std.testing.expect(mem.find(u8, why.text, id) != null);
    }
}
