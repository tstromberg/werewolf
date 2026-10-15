//! Run a checkout's existing form checks with their output, logs and exit status.
const std = @import("std");
const forms = @import("form");
const howl = @import("howl.zig");

const syntax = "usage: howl test --with FORM [--arch ARCH]\n" ++
    "Builds and runs check-FORM and check-shellfree-FORM under QEMU.\n" ++
    "Uses this checkout; logs remain in build/ARCH/check/.";

pub fn command(
    io: std.Io,
    gpa: std.mem.Allocator,
    args: []const []const u8,
    why: *howl.Why,
) !void {
    for (args) |arg| if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
        howl.say(io, "{s}", .{syntax});
        return;
    };
    var form: ?[]const u8 = null;
    var arch: ?howl.Arch = null;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const flag, const value = try howl.flagValue(args, &i, why);
        if (std.mem.eql(u8, flag, "--with")) {
            if (form != null) return why.refuse("--with given twice; test one form at a time", .{});
            if (!forms.isName(value)) return why.refuse("--with needs one existing form name", .{});
            form = value;
        } else if (std.mem.eql(u8, flag, "--arch")) {
            if (arch != null) return why.refuse("--arch given twice", .{});
            arch = howl.archName(value) orelse return why.refuse(howl.arch_refusal, .{value});
        } else return why.refuse("{s}: test takes --with and --arch\n{s}", .{ flag, syntax });
    }
    const name = form orelse return why.refuse("no form\n{s}", .{syntax});
    const target = arch orelse try howl.localArch(why);
    for ([_][]const u8{ "Makefile", "test/check-form", "test/check-shellfree" }) |path|
        std.Io.Dir.cwd().access(io, path, .{}) catch
            return why.refuse(
                "howl test needs a werewolf checkout; run it from the checkout root",
                .{},
            );
    const manifest = try gpa.print("forms/{s}/form.yaml", .{name});
    std.Io.Dir.cwd().access(io, manifest, .{}) catch
        return why.refuse("no {s}; test one form from this checkout", .{manifest});
    const argv = &.{
        howl.make_cmd,
        "--no-print-directory",
        "-k",
        try gpa.print("ARCH={t}", .{target}),
        try gpa.print("check-{s}", .{name}),
        try gpa.print("check-shellfree-{s}", .{name}),
    };
    // An outer make's dry-run flags or command-line overrides must not turn
    // a test invocation into a successful run that never executes its checks.
    var env = try howl.environ.clone(gpa);
    defer env.deinit();
    for ([_][]const u8{ "MAKEFLAGS", "MFLAGS", "MAKELEVEL" }) |key| _ = env.swapRemove(key);
    howl.say(io, "testing {s} on {t}; logs in build/{t}/check/", .{ name, target, target });
    const err = std.process.replace(io, .{ .argv = argv, .environ_map = &env });
    return why.refuse("{s}: {s}", .{ howl.make_cmd, @errorName(err) });
}
