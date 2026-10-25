//! build-traced-stub --output FILE [--helper NAME] [--sync-arm-cache]
//! [--firmware-kernel-loader] builds the pinned measured EFI stub with
//! progress messages only (test/trace-stub.zig), on a Linux build helper
//! that holds public inputs alone: tools/build-tpm-stub, run there in a
//! private directory, traces the sources before it compiles them. The
//! helper's log is FILE's directory's build.log.

const std = @import("std");
const host = @import("host");
const Io = std.Io;
const mem = std.mem;

pub fn main(init: std.process.Init) void {
    var c = host.Check.init(init, "build-traced-stub") catch std.process.exit(1);
    c.finish(run(&c));
}

pub const Request = struct {
    helper: []const u8 = "werewolf-build-26.04",
    output: ?[]const u8 = null,
    sync_arm_cache: bool = false,
    firmware_kernel_loader: bool = false,
};

/// parse reads the command line, refusing anything it does not know.
pub fn parse(args: []const []const u8, why: *host.check.Why) !Request {
    var r: Request = .{};
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (mem.eql(u8, a, "--sync-arm-cache")) {
            r.sync_arm_cache = true;
        } else if (mem.eql(u8, a, "--firmware-kernel-loader")) {
            r.firmware_kernel_loader = true;
        } else if (mem.eql(u8, a, "--helper") or mem.eql(u8, a, "--output")) {
            i += 1;
            if (i == args.len) return why.refuse("{s} needs a value", .{a});
            if (mem.eql(u8, a, "--helper")) r.helper = args[i] else r.output = args[i];
        } else return why.refuse("unknown argument {s}", .{a});
    }
    if (r.output == null) return why.refuse("--output is required", .{});
    return r;
}

/// marker is the phase build-tpm-stub compiles in, after it has unpacked
/// the sources.
const marker = "phase stub-compile " ++
    "\"Compiling systemd $version EFI stub (meson compile systemd-boot)\"";

/// traced is build-tpm-stub tracing the sources it unpacked before it
/// compiles them.
pub fn traced(
    gpa: mem.Allocator,
    script: []const u8,
    r: Request,
    why: *host.check.Why,
) ![]const u8 {
    if (mem.count(u8, script, marker) != 1)
        return why.refuse("tools/build-tpm-stub has no single stub-compile phase", .{});
    const tracer = "\"$root/tools/trace-stub\" \"$out/systemd-$version/src/boot/stub.c\"";
    const line = try gpa.print("{s}{s}{s}\n", .{
        tracer,
        if (r.sync_arm_cache) " --sync-arm-cache" else "",
        if (r.firmware_kernel_loader) " --firmware-kernel-loader" else "",
    });
    return mem.replaceOwned(u8, gpa, script, marker, try mem.concat(gpa, u8, &.{ line, marker }));
}

/// privateDir is whether d is mktemp's directory on the helper.
pub fn privateDir(d: []const u8) bool {
    const prefix = "/var/tmp/ww-traced-stub.";
    return mem.startsWith(u8, d, prefix) and d.len > prefix.len and
        mem.findScalar(u8, d[prefix.len..], '/') == null;
}

/// shell runs argv on the helper, its output in build.log.
fn shell(
    c: *host.Check,
    helper: []const u8,
    argv: []const []const u8,
    seconds: i64,
) !host.check.Result {
    const lima = [_][]const u8{ "limactl", "shell", helper, "--" };
    const command = try mem.concat(c.gpa, []const u8, &.{ &lima, argv });
    return c.must(command, "build", .{ .timeout = .fromSeconds(seconds) });
}

/// copy runs limactl copy, its output in build.log.
fn copy(c: *host.Check, from: []const u8, to: []const u8) !void {
    _ = try c.must(&.{ "limactl", "copy", from, to }, "build", .{});
}

fn run(c: *host.Check) !void {
    const io = c.io;
    const gpa = c.gpa;
    const cwd = Io.Dir.cwd();
    var why: host.check.Why = .{};
    const r = parse(c.args[1..], &why) catch return c.fail("{s}", .{why.text});
    const output = try c.absolute(r.output.?);
    if (cwd.access(io, output, .{})) |_| {
        return c.fail("refusing to overwrite an existing stub", .{});
    } else |_| {}
    try c.setWork(std.fs.path.dirname(output) orelse ".");
    const script = try cwd.readFileAlloc(io, "tools/build-tpm-stub", gpa, .limited(1 << 20));
    const local = try c.path(".traced-stub");
    try cwd.deleteTree(io, local);
    try cwd.createDir(io, local, .fromMode(0o700));
    defer cwd.deleteTree(io, local) catch {};
    const build = try std.fs.path.join(gpa, &.{ local, "build-tpm-stub" });
    const rewritten = traced(gpa, script, r, &why) catch return c.fail("{s}", .{why.text});
    try cwd.writeFile(io, .{ .sub_path = build, .data = rewritten });
    const uname = try shell(c, r.helper, &.{ "uname", "-m" }, 120);
    const machine = mem.trim(u8, uname.stdout, " \t\r\n");
    if (!mem.eql(u8, machine, "aarch64") and !mem.eql(u8, machine, "x86_64"))
        return c.fail("unsupported helper architecture {s}", .{machine});
    const tracer = try std.fs.path.join(gpa, &.{ local, "trace-stub" });
    const target = try gpa.print("{s}-linux-musl", .{machine});
    const emit = try gpa.print("-femit-bin={s}", .{tracer});
    const compile = [_][]const u8{
        "zig",
        "build-exe",
        "-O",
        "ReleaseSafe",
        "-target",
        target,
        "test/trace-stub.zig",
        emit,
    };
    _ = try c.must(&compile, "build", .{});
    const mktemp = [_][]const u8{ "mktemp", "-d", "/var/tmp/ww-traced-stub.XXXXXXXX" };
    const made = try shell(c, r.helper, &mktemp, 120);
    const remote = mem.trim(u8, made.stdout, " \t\r\n");
    if (!privateDir(remote)) return c.fail("unexpected helper directory", .{});
    const built = buildRemote(c, r.helper, remote, build, tracer, output);
    const removed = shell(c, r.helper, &.{ "rm", "-rf", "--", remote }, 120);
    try built;
    _ = try removed;
    c.say("traced measured stub: {s}", .{output});
}

fn buildRemote(
    c: *host.Check,
    helper: []const u8,
    remote: []const u8,
    build: []const u8,
    tracer: []const u8,
    output: []const u8,
) !void {
    const gpa = c.gpa;
    const at = try gpa.print("{s}:{s}", .{ helper, remote });
    const boot = try gpa.print("{s}/boot", .{remote});
    const tools = try gpa.print("{s}/tools", .{remote});
    _ = try shell(c, helper, &.{ "mkdir", "-p", boot, tools }, 120);
    try copy(c, "boot/stub-source", try gpa.print("{s}/boot/stub-source", .{at}));
    try copy(c, build, try gpa.print("{s}/tools/build-tpm-stub", .{at}));
    try copy(c, tracer, try gpa.print("{s}/tools/trace-stub", .{at}));
    _ = try shell(c, helper, &.{ "chmod", "755", try gpa.print("{s}/trace-stub", .{tools}) }, 120);
    const log = try c.path("build.log");
    c.say("Building pinned measured stub with trace messages; log: {s}", .{log});
    const script = try gpa.print("{s}/build-tpm-stub", .{tools});
    _ = try shell(c, helper, &.{ "sh", script, try gpa.print("{s}/stub", .{remote}) }, 7200);
    try copy(c, try gpa.print("{s}/stub/linux.efi.stub", .{at}), output);
}

test "the command line, the traced build script and the helper's directory" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var why: host.check.Why = .{};
    const r = try parse(&.{ "--output", "out/stub", "--sync-arm-cache" }, &why);
    try std.testing.expectEqualStrings("out/stub", r.output.?);
    try std.testing.expectEqualStrings("werewolf-build-26.04", r.helper);
    try std.testing.expect(r.sync_arm_cache and !r.firmware_kernel_loader);
    try std.testing.expectError(error.Refused, parse(&.{"--sync-arm-cache"}, &why));
    try std.testing.expectError(error.Refused, parse(&.{ "--output", "x", "--bogus" }, &why));
    try std.testing.expectError(error.Refused, parse(&.{"--helper"}, &why));
    const out = try traced(gpa, "unpack\n" ++ marker ++ "\nmeson\n", r, &why);
    const line = "\"$root/tools/trace-stub\" \"$out/systemd-$version/src/boot/stub.c\" " ++
        "--sync-arm-cache\n" ++ marker;
    try std.testing.expect(mem.find(u8, out, line) != null);
    try std.testing.expectError(error.Refused, traced(gpa, "no phases\n", r, &why));
    try std.testing.expect(privateDir("/var/tmp/ww-traced-stub.Ab12cD34"));
    try std.testing.expect(!privateDir("/var/tmp/ww-traced-stub."));
    try std.testing.expect(!privateDir("/var/tmp/ww-traced-stub.a/../b"));
    const path = "tools/build-tpm-stub";
    const real = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, gpa, .limited(1 << 20));
    _ = try traced(gpa, real, .{ .output = "x" }, &why);
}
