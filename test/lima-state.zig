//! lima-state runs howl create and run against a fake limactl, booting
//! nothing: a stale Lima enrollment goes only when its instance is gone.
//!
//!     lima-state HOWL
const std = @import("std");
const host = @import("host");
const Dir = std.Io.Dir;

pub fn main(init: std.process.Init) !void {
    var c = try host.Check.init(init, "lima-state");
    c.finish(cases(&c));
}

fn cases(c: *host.Check) !void {
    const howl = try c.absolute(if (c.args.len > 1) c.args[1] else "build/host/howl");
    const forms = try c.absolute("forms");

    // Deliberately incomplete: an absent instance must not need a usable profile.
    var absent = try create(c, howl, forms, "another-vm", 0);
    defer absent.remove(c);
    if (absent.result.ok()) return c.fail("create succeeded without an instance", .{});
    try expectSaid(c, absent.result, "protected deployment requires Lima on macOS");
    for ([_][]const u8{
        "build/machines/state-test/authority/profile.json",
        "build/machines/state-test/authority/policy.key",
        "build/machines/.orphaned",
    }) |path| if (try absent.exists(c, path)) return c.fail("{s} survived", .{path});
    c.say("pass   lima-state: an absent instance clears stale enrollment before provisioning", .{});

    var present = try create(c, howl, forms, "state-test", 0);
    defer present.remove(c);
    if (present.result.ok()) return c.fail("create succeeded past a failing limactl", .{});
    try expectFile(c, present, "authority/policy.key", "old private key");
    c.say("pass   lima-state: a present instance keeps its enrollment", .{});

    var unlisted = try create(c, howl, forms, "", 1);
    defer unlisted.remove(c);
    if (unlisted.result.ok()) return c.fail("create succeeded without a Lima listing", .{});
    try expectSaid(c, unlisted.result, "cannot query Lima");
    try expectFile(c, unlisted, "authority/profile.json", "old enrollment");
    c.say("pass   lima-state: a failed listing keeps the enrollment", .{});

    var legacy = try Fixture.init(c, forms);
    defer legacy.remove(c);
    try legacy.write(c, "build/machines/werewolf-run/engine", "lima", 0o644);
    try legacy.write(c, "build/machines/werewolf-run/disk.img", "previous data", 0o600);
    try legacy.write(c, "fake-lima/werewolf-run/lima.yaml", "# werewolf-form: playground\n", 0o644);
    try legacy.write(c, "bin/limactl",
        \\#!/bin/sh
        \\if [ "$1" = list ]; then
        \\  case "$*" in
        \\    *'{{.Dir}}'*) printf '%s\n' "$FAKE_LIMA_DIR" ;;
        \\    *) printf '%s\n' werewolf-run ;;
        \\  esac
        \\  exit 0
        \\fi
        \\if [ "$1" = delete ]; then
        \\  : >"$FAKE_LIMA_DELETED"
        \\  exit 0
        \\fi
        \\if [ "$1" = disk ]; then exit 0; fi
        \\exit 1
        \\
    , 0o755);
    var env = try legacy.environment(c);
    try env.put("FAKE_LIMA_DIR", try legacy.path(c, "fake-lima/werewolf-run"));
    try env.put("FAKE_LIMA_DELETED", try legacy.path(c, "deleted"));
    const run = try c.run(&.{
        howl,   "run",  "--with",   "minimal",        "--build", "--yes",
        "--on", "lima", "--config", "missing-config",
    }, "", .{ .environ_map = &env, .cwd = legacy.root, .timeout = .fromSeconds(30) });
    if (run.ok()) return c.fail("run succeeded with a missing config", .{});
    if (try legacy.exists(c, "deleted"))
        return c.fail("run deleted a legacy VM before host admission", .{});
    const disk = try Dir.cwd().readFileAlloc(
        c.io,
        try legacy.path(c, "build/machines/werewolf-run/disk.img"),
        c.gpa,
        .limited(100),
    );
    if (!std.mem.eql(u8, disk, "previous data"))
        return c.fail("run changed the legacy disk before host admission", .{});
    try expectSaid(c, run, "protected deployment requires Lima on macOS");
    if (std.mem.find(u8, run.stderr, "Building the protected image") != null)
        return c.fail("run built before replacing the legacy VM", .{});
    c.say("pass   lima-state: an unavailable host preserves the legacy VM", .{});
}

/// Fixture is a scratch directory howl runs in, with the checkout's forms.
const Fixture = struct {
    root: []const u8,
    result: host.check.Result = undefined,

    fn init(c: *host.Check, forms: []const u8) !Fixture {
        var nonce: [6]u8 = undefined;
        c.io.random(&nonce);
        const root = try c.gpa.print("/tmp/ww-lima-state-{x}", .{&nonce});
        try Dir.cwd().createDir(c.io, root, .fromMode(0o700));
        try Dir.cwd().symLink(c.io, forms, try std.fs.path.join(c.gpa, &.{ root, "forms" }), .{
            .is_directory = true,
        });
        return .{ .root = root };
    }

    fn remove(f: *Fixture, c: *host.Check) void {
        Dir.cwd().deleteTree(c.io, f.root) catch {};
    }

    fn path(f: *Fixture, c: *host.Check, name: []const u8) ![]const u8 {
        return std.fs.path.join(c.gpa, &.{ f.root, name });
    }

    fn write(
        f: *Fixture,
        c: *host.Check,
        name: []const u8,
        data: []const u8,
        mode: std.posix.mode_t,
    ) !void {
        const file = try f.path(c, name);
        try Dir.cwd().createDirPath(c.io, std.fs.path.dirname(file).?);
        try Dir.cwd().writeFile(c.io, .{
            .sub_path = file,
            .data = data,
            .flags = .{ .permissions = .fromMode(mode) },
        });
    }

    fn exists(f: *Fixture, c: *host.Check, name: []const u8) !bool {
        Dir.cwd().access(c.io, try f.path(c, name), .{}) catch |err| switch (err) {
            error.FileNotFound => return false,
            else => return err,
        };
        return true;
    }

    /// environment finds the fake limactl first.
    fn environment(f: *Fixture, c: *host.Check) !std.process.Environ.Map {
        var env = try c.env.clone(c.gpa);
        try env.put(
            "PATH",
            try c.gpa.print("{s}/bin:{s}", .{ f.root, c.env.get("PATH") orelse "" }),
        );
        return env;
    }
};

/// create gives a Lima machine a stale enrollment and runs a protected
/// create, with a limactl that lists listing and exits status.
fn create(
    c: *host.Check,
    howl: []const u8,
    forms: []const u8,
    listing: []const u8,
    status: u8,
) !Fixture {
    var f = try Fixture.init(c, forms);
    errdefer f.remove(c);
    try f.write(c, "build/machines/state-test/engine", "lima", 0o644);
    try f.write(c, "build/machines/state-test/authority/profile.json", "old enrollment", 0o600);
    try f.write(c, "build/machines/state-test/authority/policy.key", "old private key", 0o600);
    try f.write(c, "bin/limactl", try c.gpa.print(
        \\#!/bin/sh
        \\if [ "$1" = list ]; then
        \\  printf '%s\n' {s}
        \\  exit {d}
        \\fi
        \\# Stop before provisioning or building a new VM.
        \\exit 1
        \\
    , .{ try host.check.quote(c.gpa, listing), status }), 0o755);
    var env = try f.environment(c);
    f.result = try c.run(&.{
        howl, "create", "state-test", "--with", "minimal", "--build", "--yes", "--on", "lima",
    }, "", .{ .environ_map = &env, .cwd = f.root, .timeout = .fromSeconds(30) });
    return f;
}

fn expectSaid(c: *host.Check, r: host.check.Result, text: []const u8) !void {
    if (std.mem.find(u8, r.stderr, text) == null)
        return c.fail("howl did not say {s}: {s}", .{ text, host.check.tail(r.stderr, 2000) });
}

fn expectFile(c: *host.Check, f: Fixture, name: []const u8, want: []const u8) !void {
    const file = try std.fs.path.join(c.gpa, &.{ f.root, "build/machines/state-test", name });
    const got = Dir.cwd().readFileAlloc(c.io, file, c.gpa, .limited(4096)) catch |err|
        return c.fail("{s}: {t}", .{ name, err });
    if (!std.mem.eql(u8, got, want)) return c.fail("{s} changed: {s}", .{ name, got });
}
