//! check-protected-qemu exercises Linux publication on a disposable
//! GitHub-hosted runner with a temporary test authority. It mints throwaway
//! protected signing keys, builds three signed bundles of each base form
//! with them, authorizes and admits them through the published lifecycle,
//! and exports the gated assets. The committed certificate pins are saved
//! and restored, so a run leaves release/protected as it found it. Fixture
//! keys never come from production secrets and never leave this host.

const std = @import("std");
const builtin = @import("builtin");
const host = @import("host");
const published = @import("published.zig");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const mem = std.mem;

const trust = "release/protected";
/// release is the release workstream's tool; its verbs replace the scripts.
const release = "build/host/release";
const pins = [2][]const u8{ "boot.crt", "image.crt" };

pub fn main(init: std.process.Init) !void {
    var c = try host.Check.init(init, "protected-qemu");
    var p: Protected = .{ .c = &c };
    const result = p.check();
    p.restore();
    c.finish(result);
}

const Protected = struct {
    c: *host.Check,
    saved: [2][]const u8 = .{ "", "" },
    work: []const u8 = "",

    fn check(p: *Protected) !void {
        const c = p.c;
        const gpa = c.gpa;
        const io = c.io;
        if (!mem.eql(u8, c.env.get("GITHUB_ACTIONS") orelse "", "true") or
            !mem.eql(u8, c.env.get("RUNNER_ENVIRONMENT") orelse "", "github-hosted"))
            return c.fail(
                "temporary trust validation requires a disposable GitHub-hosted runner",
                .{},
            );
        if (builtin.os.tag != .linux or builtin.cpu.arch != .x86_64)
            return c.fail("QEMU publication validation requires a native x86_64 Linux runner", .{});
        published.private();
        for (pins, 0..) |name, i| {
            const pin = try joinPath(gpa, &.{ trust, name });
            p.saved[i] = try Io.Dir.cwd().readFileAlloc(io, pin, gpa, .limited(1 << 20));
        }

        p.work = try published.temporary(io, gpa, "ww-qemu-validation-");
        var env = try c.env.clone(gpa);
        const private = try joinPath(gpa, &.{ p.work, "private" });
        const public = try joinPath(gpa, &.{ p.work, "public" });
        const tools = [_][]const u8{
            "make",
            release,
            "build/host/check-published-lifecycle",
            "build/host/check-independent-updates",
            "build/host/test-sk.so",
        };
        try p.run(&tools, &env, "make-tools", 3600);
        const create = [_][]const u8{ release, "create-protected-trust", private, public };
        try p.run(&create, &env, "create-trust", 600);
        for ([2][]const u8{ "boot", "image" }) |kind| {
            const crt = try gpa.print("{s}.crt", .{kind});
            const from = try joinPath(gpa, &.{ public, crt });
            try Io.Dir.cwd().copyFile(from, .cwd(), try joinPath(gpa, &.{ trust, crt }), io, .{});
            var upper: [8]u8 = undefined;
            const name = std.ascii.upperString(upper[0..kind.len], kind);
            const basename = try gpa.print("{s}.key", .{kind});
            const key = try joinPath(gpa, &.{ private, basename });
            try env.put(try gpa.print("WEREWOLF_PROTECTED_{s}_KEY", .{name}), key);
        }
        // howl embeds the trust pins, so it is built with the run's.
        try p.run(&.{ "make", "howl" }, &env, "make", 3600);

        // The published kernel's IPE trusts only the committed image certificate.
        const kernel = try joinPath(gpa, &.{ p.work, "test-kernel.tar" });
        const image_crt = try joinPath(gpa, &.{ trust, "image.crt" });
        const test_kernel = [_][]const u8{ "sh", "tools/test-kernel", "x86_64", image_crt, kernel };
        try p.run(&test_kernel, &env, "test-kernel", 1800);
        try env.put("WEREWOLF_PROTECTED_TEST_KERNEL", kernel);

        const updates = "build/protected-qemu-validation/updates";
        var update_env = try env.clone(gpa);
        for ([_][]const u8{
            "WEREWOLF_PROTECTED_BOOT_KEY",
            "WEREWOLF_PROTECTED_IMAGE_KEY",
            "WEREWOLF_PROTECTED_TEST_KERNEL",
        }) |key| _ = update_env.swapRemove(key);
        try update_env.put("XDG_DATA_HOME", try joinPath(gpa, &.{ p.work, "data" }));
        try update_env.put("WEREWOLF_IPE_KERNEL", kernel);
        try update_env.put("WEREWOLF_IPE_KEY", try joinPath(gpa, &.{ private, "image.key" }));
        try update_env.put("WEREWOLF_IPE_CRT", image_crt);
        const images = try published.Images.load(io, gpa);
        const workload: []const u8 = for (images.forms) |form| {
            if (mem.eql(u8, form, "postdoc-server")) break "postdoc-server";
        } else "playground";
        try p.run(
            &.{
                "build/host/check-independent-updates",
                "build/host/howl",
                updates,
                "qemu",
                workload,
            },
            &update_env,
            "independent-updates",
            7200,
        );

        const candidates = "build/qemu-validation-candidates";
        for (images.forms) |form| {
            const start = @divFloor(Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s);
            var bundles: [3][]const u8 = undefined;
            for (0..3) |offset| {
                const stamp = serial(@intCast(start + @as(i128, offset)));
                const n = try gpa.print("{d}", .{offset});
                // Each bundle is the next release of the channel: index 1, 2, 3.
                const index = try gpa.print("{d}", .{offset + 1});
                bundles[offset] = try joinPath(gpa, &.{ candidates, form, n });
                try p.run(&.{
                    release,
                    "with-protected-keys",
                    release,
                    "build-protected",
                    form,
                    "qemu",
                    "x86_64",
                    &stamp,
                    index,
                    bundles[offset],
                }, &env, try gpa.print("build-{s}-{d}", .{ form, offset }), 3600);
            }
            try p.run(&.{
                release,
                "with-protected-keys",
                release,
                "authorize-protected",
                "build/host/howl",
                "qemu",
                bundles[0],
                bundles[1],
                bundles[2],
            }, &env, try gpa.print("authorize-{s}", .{form}), 600);
            const output = try joinPath(gpa, &.{ "build/protected-qemu-validation", form });
            try p.run(&.{
                "build/host/check-published-lifecycle",
                "build/host/howl",
                "qemu",
                bundles[0],
                updates,
                output,
            }, &env, try gpa.print("lifecycle-{s}", .{form}), 7200);
            // Exercise the actual signatures, export admission and qcow2 too.
            const assets_name = try gpa.print("assets-{s}", .{form});
            const assets = try joinPath(gpa, &.{ p.work, assets_name });
            try p.run(&.{
                release,
                "with-protected-keys",
                release,
                "export-protected",
                "build/host/howl",
                bundles[0],
                try joinPath(gpa, &.{ output, "gates.json" }),
                "qemu",
                assets,
            }, &env, try gpa.print("export-{s}", .{form}), 1800);
        }
    }

    fn run(
        p: *Protected,
        argv: []const []const u8,
        env: *const std.process.Environ.Map,
        label: []const u8,
        seconds: i64,
    ) !void {
        const options: host.check.Options = .{
            .environ_map = env,
            .timeout = .fromSeconds(seconds),
        };
        const r = p.c.run(argv, label, options) catch |err|
            return p.c.fail("{s}: {t}", .{ label, err });
        if (!r.ok()) return p.c.fail("{s}: {s}", .{ label, host.check.tail(r.stderr, 3000) });
    }

    /// restore puts the committed certificate pins back and removes the
    /// disposable signing host, so a run leaves release/protected unchanged.
    fn restore(p: *Protected) void {
        const c = p.c;
        for (pins, p.saved) |name, data| {
            if (data.len == 0) continue;
            const path = std.fs.path.join(c.gpa, &.{ trust, name }) catch continue;
            Io.Dir.cwd().writeFile(c.io, .{ .sub_path = path, .data = data }) catch {};
        }
        if (p.work.len > 0) Io.Dir.cwd().deleteTree(c.io, p.work) catch {};
    }
};

/// joinPath joins path parts under the working directory's allocator.
fn joinPath(gpa: Allocator, parts: []const []const u8) ![]const u8 {
    return std.fs.path.join(gpa, parts);
}

/// serial is the release serial of a moment: YYYYMMDDThhmmssZ in UTC.
fn serial(seconds: u64) [16]u8 {
    const at: std.time.epoch.EpochSeconds = .{ .secs = seconds };
    const year = at.getEpochDay().calculateYearDay();
    const month = year.calculateMonthDay();
    const day = at.getDaySeconds();
    var out: [16]u8 = undefined;
    _ = std.mem.print(&out, "{d:0>4}{d:0>2}{d:0>2}T{d:0>2}{d:0>2}{d:0>2}Z", .{
        year.year,             month.month.numeric(),    month.day_index + 1,
        day.getHoursIntoDay(), day.getMinutesIntoHour(), day.getSecondsIntoMinute(),
    }) catch unreachable;
    return out;
}

test "serial is the release serial of a moment" {
    try std.testing.expectEqualStrings("20261024T235959Z", &serial(1792886399));
}
