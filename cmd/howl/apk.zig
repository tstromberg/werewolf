//! build-apk: a form's own package, from a melange recipe in Wolfi's
//! style (melange.mk), built as the form's build builds it, for the
//! recipe's author to try before a form keeps it in forms/NAME/melange/.
//!
//!     howl build-apk RECIPE [--arch ARCH]
//!
//! make's _build-apk does the work, as build's _dist-form does: melange in
//! bubblewrap on Linux, or on macOS in QEMU from werewolf's own Alpine
//! kernel. It prints each package it made and the libraries each links,
//! which a form must name among its packages. RECIPE is a path, of
//! letters, digits and . _ - /, since make takes it as a word.

const std = @import("std");
const howl = @import("howl.zig");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

const syntax = "howl build-apk RECIPE [--arch ARCH]";

pub fn build(io: Io, gpa: Allocator, args: []const []const u8, why: *howl.Why) !void {
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
    try howl.run(io, why, &.{
        howl.make_cmd,
        "--no-print-directory",
        try gpa.print("ARCH={t}", .{for_arch}),
        try gpa.print("RECIPE={s}", .{r}),
        "_build-apk",
    });
}

/// A path make can take as one word, and melange as a file: relative or
/// absolute, of [A-Za-z0-9._/-], ending .yaml, no empty part.
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
