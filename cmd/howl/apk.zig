//! build-apk builds a package from a melange recipe the way a form build
//! would, so an author can try it before adding it to forms/NAME/melange/.
//! See README.md.
//!
//!     howl build-apk RECIPE [--arch ARCH] [--verbose]

const std = @import("std");
const howl = @import("howl.zig");
const native = @import("build.zig");
const melange = @import("melange.zig");
const progress = @import("progress.zig");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

const syntax = "howl build-apk RECIPE [--arch ARCH] [--verbose]";

/// build builds RECIPE's packages and prints each one's file and the
/// libraries it links. It must run in a werewolf checkout.
pub fn build(io: Io, gpa: Allocator, given: []const []const u8, why: *howl.Why) !void {
    const verbose, const args = try howl.verboseFlag(gpa, given);
    var recipe: ?[]const u8 = null;
    var arch = howl.hostArch();
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (a.len > 0 and a[0] == '-') {
            const flag, const v = try howl.flagValue(args, &i, why);
            if (!std.mem.eql(u8, flag, "--arch"))
                return why.refuse("build-apk takes no {s}: {s}", .{ flag, syntax });
            arch = howl.archName(v) orelse return why.refuse(howl.arch_refusal, .{v});
        } else if (recipe != null) {
            return why.refuse("one recipe at a time: {s}", .{syntax});
        } else recipe = a;
    }
    const r = recipe orelse return why.refuse("{s}", .{syntax});
    const for_arch = arch orelse return why.refuse("{s}: --arch", .{howl.not_built_here});
    if (!isRecipePath(r)) return why.refuse(
        "{s}: a recipe is a .yaml path of [A-Za-z0-9._/-]",
        .{r},
    );
    Dir.cwd().access(io, r, .{}) catch return why.refuse("{s}: no such recipe", .{r});
    var forms = Dir.cwd().openDir(io, "forms", .{}) catch
        return why.refuse("no ./forms: run howl in a werewolf checkout", .{});
    forms.close(io);
    var steps: progress.Steps = try .init(io, gpa, why, .{
        .verbose = verbose,
        .command = try gpa.print("howl build-apk {s}", .{try std.mem.join(gpa, " ", given)}),
        .log = try gpa.print("build/log/{s}-{t}-build-apk.log", .{ std.fs.path.stem(r), for_arch }),
        .first = howl.start_phase,
    });
    report(io, gpa, &steps, for_arch, r) catch |err| switch (err) {
        error.Refused => return err,
        else => return steps.fail(@errorName(err)),
    };
}

/// report builds recipe's packages for arch and prints them. It plans a
/// build of minimal, the smallest form, as melange's VM boots the kernel
/// any form's build fetches.
fn report(
    io: Io,
    gpa: Allocator,
    steps: *progress.Steps,
    arch: howl.Arch,
    recipe: []const u8,
) !void {
    var b = try native.prepare(io, gpa, steps, .{
        .form = "minimal",
        .arch = arch,
    });
    try melange.build(&b, recipe);
    const made = try melange.made(&b, recipe, try melange.stamp(&b, recipe));
    const done = try steps.finish();
    const look: progress.Look = .of(io, Io.File.stderr());
    howl.say(io, "{s} built {s} for {t} in {f}", .{
        look.check(), recipe, arch, progress.Clock{ .seconds = done.seconds },
    });
    var out = Io.File.stdout().writerStreaming(io, &.{});
    const w = &out.interface;
    for (made) |p| {
        try w.print("{s}\n", .{p.file});
        for (p.links) |so| try w.print("  links {s}\n", .{so});
    }
}

/// isRecipePath reports whether p is a .yaml path of [A-Za-z0-9._/-] with no
/// empty part: its stamp and log are named after it.
fn isRecipePath(p: []const u8) bool {
    if (!std.mem.endsWith(u8, p, ".yaml") or p.len > 255) return false;
    for (p) |c| if (!std.ascii.isAlphanumeric(c) and std.mem.findScalar(u8, "._/-", c) == null)
        return false;
    return std.mem.find(u8, p, "//") == null;
}

test isRecipePath {
    try std.testing.expect(isRecipePath("forms/vaultwarden/melange/vaultwarden.yaml"));
    try std.testing.expect(isRecipePath("../myapp/myapp.yaml"));
    try std.testing.expect(isRecipePath("/home/me/app.yaml"));
    for ([_][]const u8{
        "vendor/x.yml",
        "a b.yaml",
        "$(shell id).yaml",
        "a//b.yaml",
        "x;y.yaml",
        "",
    }) |bad|
        try std.testing.expect(!isRecipePath(bad));
}
