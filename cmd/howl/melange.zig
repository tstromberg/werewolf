//! melange builds the packages Wolfi does not ship from a form's melange
//! recipes, forms/NAME/melange/*.yaml, and lays them over the image. See
//! docs/forms.md.

const std = @import("std");
const builtin = @import("builtin");
const forms = @import("form");
const howl = @import("howl.zig");
const native = @import("build.zig");
const packages = @import("packages.zig");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const mem = std.mem;
const B = native.B;

/// vendor holds what melange makes for every form and BUILD: the packages,
/// melange's cache, the QEMU guest and a stamp for each recipe built. CI
/// keeps its packages and stamps between runs.
const vendor = "build/vendor";

/// query is the template melange query fills in with a recipe's packages,
/// main package first, each NAME-VERSION-rEPOCH as its file is named.
const query = "{{.Package.Name}}-{{.Package.Version}}-r{{.Package.Epoch}}" ++
    "{{$v := print \"-\" .Package.Version \"-r\" .Package.Epoch}}" ++
    "{{range .Subpackages}} {{.Name}}{{$v}}{{end}}";

/// Runner is where melange builds: in bubblewrap, or in a QEMU VM booted
/// from werewolf's own kernel.
const Runner = enum { qemu, bubblewrap };

/// runner returns bubblewrap where bwrap is on the PATH, but never on
/// macOS, which has no namespaces; else qemu.
fn runner(b: *B) !Runner {
    if (builtin.os.tag == .macos) return .qemu;
    var dirs = mem.tokenizeScalar(u8, howl.environ.get("PATH") orelse "", ':');
    while (dirs.next()) |d| {
        Dir.cwd().access(b.io, try b.path("{s}/bwrap", .{d}), .{ .execute = true }) catch continue;
        return .bubblewrap;
    }
    return .qemu;
}

/// recipes returns the chain's recipes, base form's first, each form's sorted.
pub fn recipes(io: Io, gpa: Allocator, chain: []const forms.Form) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    for (chain) |c| {
        const dir = try gpa.print("{s}/melange", .{c.dir});
        var d = Dir.cwd().openDir(io, dir, .{ .iterate = true }) catch continue;
        defer d.close(io);
        const first = out.items.len;
        var it = d.iterate();
        while (try it.next(io)) |e| {
            if (e.kind == .directory or e.name[0] == '.' or !mem.endsWith(u8, e.name, ".yaml"))
                continue;
            try out.append(gpa, try gpa.print("{s}/{s}", .{ dir, e.name }));
        }
        mem.sortUnstable([]const u8, out.items[first..], {}, native.lessThan);
    }
    return out.items;
}

/// stampName returns recipe's path made a file name, ../ as up_ and / as _,
/// as make named its stamps, so those, and CI's cached ones, still count.
fn stampName(gpa: Allocator, recipe: []const u8) ![]const u8 {
    const name = try mem.replaceOwned(u8, gpa, recipe, "../", "up_");
    mem.replaceScalar(u8, name, '/', '_');
    return name;
}

/// stamp returns the file whose time says when recipe's packages were built.
pub fn stamp(b: *B, recipe: []const u8) ![]const u8 {
    return b.path("{s}/stamps/{t}/{s}.built", .{
        vendor, b.spec.arch, try stampName(b.gpa, recipe),
    });
}

/// build builds recipe's packages into build/vendor/packages/ARCH, unless
/// its stamp is newer than the recipe and, under QEMU, than the guest and
/// kernel. melange checks each source by sha256.
pub fn build(b: *B, recipe: []const u8) !void {
    // One melange at a time, across builds: they share the guest's scratch
    // files, the cache and the packages, and two at once read each other's
    // half-written files. One that waited finds its package made.
    try Dir.cwd().createDirPath(b.io, vendor);
    const lock = try Dir.cwd().createFile(b.io, vendor ++ "/melange.lock", .{ .truncate = false });
    defer lock.close(b.io);
    try lock.lock(b.io, .exclusive);
    const r = try runner(b);
    const at = try b.absolute(vendor);
    const scratch = try b.path("{s}/melange-tmp", .{at});
    var env = try b.env.clone(b.gpa);
    try env.put("TMPDIR", scratch);
    var inputs: std.ArrayList([]const u8) = .empty;
    try inputs.append(b.gpa, recipe);
    if (r == .qemu) {
        try packages.kernel(b);
        const kernel = try b.path("{s}/vmlinuz", .{b.p.build});
        const initramfs = try guest(b);
        try inputs.appendSlice(b.gpa, &.{ initramfs, kernel });
        try env.put("QEMU_KERNEL_IMAGE", try b.absolute(kernel));
        try env.put("QEMU_BASE_INITRAMFS", try b.absolute(initramfs));
        // The guest's disk is a sparse 50 GiB file, which melange leaves
        // behind when a build dies: here, not in the checkout's root.
        try env.put("QEMU_DISKS_PATH", scratch);
    }
    const target = try stamp(b, recipe);
    const began = try b.begin(target, inputs.items) orelse return;
    try Dir.cwd().createDirPath(b.io, vendor ++ "/packages");
    try Dir.cwd().createDirPath(b.io, vendor ++ "/melange-tmp");
    try Dir.cwd().createDirPath(b.io, std.fs.path.dirname(target).?);
    // Half the host's CPUs, as a Rust build is most of the wait, and 8 GiB.
    const n = std.Thread.getCpuCount() catch 1;
    const cpus = setting("MELANGE_CPU") orelse try b.path("{d}", .{if (n > 2) n / 2 else 1});
    try b.run(&.{
        "melange",
        "build",
        "--runner",
        @tagName(r),
        recipe,
        "--arch",
        @tagName(b.spec.arch),
        "--cpu",
        cpus,
        "--memory",
        setting("MELANGE_MEMORY") orelse "8Gi",
        "--out-dir",
        try b.path("{s}/packages", .{at}),
        "--cache-dir",
        try b.path("{s}/melange-cache", .{at}),
    }, .{ .env = &env });
    try Dir.cwd().writeFile(b.io, .{ .sub_path = target, .data = "" });
    try b.done(target, began);
}

/// setting returns environment variable name, or null if it is unset or empty.
fn setting(name: []const u8) ?[]const u8 {
    const v = howl.environ.get(name) orelse return null;
    return if (v.len > 0) v else null;
}

/// guest makes the QEMU runner's initramfs: melange's, with the kernel's
/// modules appended under usr/lib/modules. melange's QEMU_KERNEL_MODULES
/// puts them under /lib, which replaces the guest's /lib -> usr/lib link
/// and so its loader. It returns the initramfs's path.
fn guest(b: *B) ![]const u8 {
    const target = try b.path("{s}/melange-guest-{t}.cpio", .{ vendor, b.spec.arch });
    const kernel = try b.path("{s}/vmlinuz", .{b.p.build});
    const began = try b.begin(target, &.{kernel}) orelse return target;
    const d = try b.path("{s}.d", .{target});
    const base = try b.path("{s}.base", .{target});
    const modules = try b.path("{s}/usr/lib/modules", .{d});
    try Dir.cwd().deleteTree(b.io, d);
    try Dir.cwd().createDirPath(b.io, modules);
    try b.run(&.{ "melange", "initramfs", "--arch", @tagName(b.spec.arch), "--output", base }, .{});
    try copyTree(b, try b.path("{s}/kernel/x/lib/modules", .{b.p.build}), modules);
    const t = try b.tmp(target);
    {
        const f = try Dir.cwd().createFile(b.io, t, .{});
        defer f.close(b.io);
        const tar: []const []const u8 = &.{
            "bsdtar",
            "--format",
            "newc",
            "--uid",
            "0",
            "--gid",
            "0",
            "--numeric-owner",
            "-cf",
            "-",
            "usr/lib/modules",
        };
        const ran = try b.steps.exec(&.{
            .{ .argv = tar, .cwd = d, .env = b.env },
            .{ .argv = &.{ "cat", base, "-" }, .env = b.env },
        }, .{ .stdout = f });
        if (!ran.ok) return b.fail("{s}: bsdtar or cat failed", .{target});
    }
    try b.rename(t, target);
    try Dir.cwd().deleteTree(b.io, d);
    try Dir.cwd().deleteFile(b.io, base);
    try b.done(target, began);
    return target;
}

/// copyTree copies the directories and files under from into to. It leaves
/// out links, such as the modules' vmlinuz, which would dangle in the guest.
fn copyTree(b: *B, from: []const u8, to: []const u8) !void {
    var src = try Dir.cwd().openDir(b.io, from, .{ .iterate = true });
    defer src.close(b.io);
    var dst = try Dir.cwd().openDir(b.io, to, .{});
    defer dst.close(b.io);
    var w = try src.walk(b.gpa);
    defer w.deinit();
    while (try w.next(b.io)) |e| switch (e.kind) {
        .directory => try dst.createDirPath(b.io, e.path),
        .file => try Dir.copyFile(src, e.path, dst, e.path, b.io, .{}),
        else => {},
    };
}

/// Package is a package file a recipe makes, and the libraries it links.
pub const Package = struct { file: []const u8, links: []const []const u8 };

/// made returns recipe's packages, main package first, once build has
/// built them. It reads melange's and bsdtar's output from a file beside
/// target, which no other build writes: forms that share a recipe may
/// build side by side.
pub fn made(b: *B, recipe: []const u8, target: []const u8) ![]const Package {
    const names = try b.capture(target, &.{ "melange", "query", recipe, query });
    var out: std.ArrayList(Package) = .empty;
    var it = mem.tokenizeAny(u8, names, " \t\r\n");
    while (it.next()) |name| {
        const file = try b.path("{s}/packages/{t}/{s}.apk", .{ vendor, b.spec.arch, name });
        const info = try b.capture(target, &.{ "bsdtar", "-xzOf", file, ".PKGINFO" });
        try out.append(b.gpa, .{ .file = file, .links = try links(b.gpa, info) });
    }
    if (out.items.len == 0) return b.fail("{s}: melange query named no package", .{recipe});
    return out.items;
}

/// links returns the libraries a package's .PKGINFO says it links: its
/// so: dependencies.
fn links(gpa: Allocator, pkginfo: []const u8) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var lines = mem.splitScalar(u8, pkginfo, '\n');
    while (lines.next()) |l| if (mem.startsWith(u8, l, "depend = so:"))
        try out.append(gpa, l["depend = so:".len..]);
    return out.items;
}

/// provides reports whether listing, a tar's names one a line, holds a
/// file named so in some directory.
fn provides(listing: []const u8, so: []const u8) bool {
    var lines = mem.splitScalar(u8, listing, '\n');
    while (lines.next()) |l| {
        if (l.len > so.len and mem.endsWith(u8, l, so) and l[l.len - so.len - 1] == '/')
            return true;
    }
    return false;
}

/// lay builds the chain's recipes and unpacks every package they make, but
/// its metadata, into OUT/melange, which the overlay lays over the image.
/// It fails if a package links a library none of the form's packages in
/// rootfs holds: Wolfi's fixes to that library would never reach it.
pub fn lay(b: *B, rootfs: []const u8) !void {
    if (b.recipes.len == 0) return;
    var inputs: std.ArrayList([]const u8) = .empty;
    for (b.recipes) |r| {
        try build(b, r);
        try inputs.append(b.gpa, try stamp(b, r));
    }
    try inputs.append(b.gpa, rootfs);
    const target = try b.path("{s}/melange.stamp", .{b.p.out});
    const began = try b.begin(target, inputs.items) orelse return;
    // A step that fails part way leaves no stamp to call it made.
    Dir.cwd().deleteFile(b.io, target) catch {};
    const dir = try b.path("{s}/melange", .{b.p.out});
    try Dir.cwd().deleteTree(b.io, dir);
    try Dir.cwd().createDirPath(b.io, dir);
    const listing = try b.capture(target, &.{ "bsdtar", "-tf", rootfs });
    for (b.recipes) |r| for (try made(b, r, target)) |p| {
        for (p.links) |so| if (!provides(listing, so)) return b.fail(
            "{s} links {s}, which no package of form {s} provides",
            .{ p.file, so, b.name },
        );
        try b.run(&.{
            "bsdtar",        "-xzf",     p.file,      "-C",      dir,
            "--exclude",     ".PKGINFO", "--exclude", ".SIGN.*", "--exclude",
            ".melange.yaml",
        }, .{});
        try b.steps.note("melange: {s}", .{p.file});
    };
    try Dir.cwd().writeFile(b.io, .{ .sub_path = target, .data = "" });
    try b.done(target, began);
}

const testing = std.testing;

test stampName {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectEqualStrings(
        "forms_vaultwarden_melange_vaultwarden.yaml",
        try stampName(a, "forms/vaultwarden/melange/vaultwarden.yaml"),
    );
    try testing.expectEqualStrings(
        "up_up_apps_myapp_melange_x.yaml",
        try stampName(a, "../../apps/myapp/melange/x.yaml"),
    );
    try testing.expectEqualStrings("_home_me_app.yaml", try stampName(a, "/home/me/app.yaml"));
}

test links {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const info =
        \\pkgname = vaultwarden
        \\depend = so:libc.so.6
        \\depend = ca-certificates-bundle
        \\depend = so:libssl.so.4
        \\provides = cmd:vaultwarden=1.37.4-r0
        \\
    ;
    const l = try links(arena.allocator(), info);
    try testing.expectEqual(2, l.len);
    try testing.expectEqualStrings("libc.so.6", l[0]);
    try testing.expectEqualStrings("libssl.so.4", l[1]);
}

test provides {
    const listing = "usr/\nusr/lib/\nusr/lib/libssl.so.4\nusr/lib/libstdc++.so.6\nlibroot.so\n";
    try testing.expect(provides(listing, "libssl.so.4"));
    try testing.expect(provides(listing, "libstdc++.so.6"));
    try testing.expect(!provides(listing, "libssl.so.3"));
    try testing.expect(!provides(listing, "ssl.so.4"));
    try testing.expect(!provides(listing, "libroot.so"));
}
