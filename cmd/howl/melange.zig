//! melange builds the packages Wolfi does not ship from a form's declared
//! recipes in ../packages, and lays them over the image. See
//! docs/forms.md.

const std = @import("std");
const builtin = @import("builtin");
const forms = @import("form");
const howl = @import("howl.zig");
const native = @import("build.zig");
const packages = @import("packages.zig");
const image = @import("image");
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

/// Runner is where melange builds: in bubblewrap, or in a QEMU VM (guest).
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

/// recipes returns declared recipes base first, once each. Opening each here
/// catches a missing package checkout before any image build begins.
pub fn recipes(io: Io, gpa: Allocator, chain: []const forms.Form) ![]const []const u8 {
    var out: std.array_hash_map.String(void) = .empty;
    for (chain) |c| {
        for (try c.recipes(io, gpa, Dir.cwd())) |path| {
            const file = try Dir.cwd().openFile(io, path, .{});
            file.close(io);
            try out.put(gpa, path, {});
        }
    }
    return out.keys();
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
    var pins: std.ArrayList([]const u8) = .empty;
    if (setting("WEREWOLF_FORM_INPUTS")) |snapshot| {
        const index = try b.path("{s}/melange.json", .{snapshot});
        const locks = try std.json.parseFromSliceLeaky(
            std.json.Value,
            b.gpa,
            try b.read(index, 1 << 20),
            .{},
        );
        if (locks != .object) return b.fail("invalid form-image Melange snapshot", .{});
        const locked = locks.object.get(recipe) orelse
            return b.fail("missing form-image Melange snapshot for {s}", .{recipe});
        if (locked != .string) return b.fail("invalid Melange lock filename", .{});
        const file = try b.path("{s}/{s}", .{ snapshot, locked.string });
        try inputs.append(b.gpa, file);
        for (try packages.pins(b.gpa, try b.read(file, 64 << 20), @tagName(b.spec.arch))) |pin|
            try pins.appendSlice(b.gpa, &.{ "--package-append", pin });
    }
    if (r == .qemu) {
        const g = try guest(b);
        try inputs.appendSlice(b.gpa, &.{ g.initramfs, g.kernel });
        try env.put("QEMU_KERNEL_IMAGE", try b.absolute(g.kernel));
        try env.put("QEMU_BASE_INITRAMFS", try b.absolute(g.initramfs));
        // The guest's disk is a sparse 50 GiB file, which melange leaves
        // behind when a build dies: here, not in the checkout's root.
        try env.put("QEMU_DISKS_PATH", scratch);
    }
    // The recipe's directory is the build's source. Another file there, a
    // stand-in's Java, is an input too, or editing it would not rebuild.
    if (std.fs.path.dirname(recipe)) |dir| {
        var listing = try Dir.cwd().openDir(b.io, dir, .{ .iterate = true });
        defer listing.close(b.io);
        var it = listing.iterate();
        while (try it.next(b.io)) |e| {
            if (e.kind != .file or e.name[0] == '.') continue;
            const path = try b.gpa.print("{s}/{s}", .{ dir, e.name });
            if (mem.eql(u8, path, recipe)) continue;
            try inputs.append(b.gpa, path);
        }
    }
    const target = try stamp(b, recipe);
    const began = try b.begin(target, inputs.items) orelse return;
    try Dir.cwd().createDirPath(b.io, vendor ++ "/packages");
    try Dir.cwd().createDirPath(b.io, vendor ++ "/melange-tmp");
    try Dir.cwd().createDirPath(b.io, std.fs.path.dirname(target).?);
    // Half the host's CPUs, as a Rust build is most of the wait, and 8 GiB.
    const n = std.Thread.getCpuCount() catch 1;
    const cpus = setting("MELANGE_CPU") orelse try b.path("{d}", .{if (n > 2) n / 2 else 1});
    const args = try std.mem.concat(b.gpa, []const u8, &.{ &.{
        "melange",
        "build",
        "--runner",
        @tagName(r),
        recipe,
        "--source-dir",
        try b.absolute(std.fs.path.dirname(recipe) orelse "."),
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
    }, pins.items });
    try b.run(args, .{ .env = &env });
    try Dir.cwd().writeFile(b.io, .{ .sub_path = target, .data = "" });
    try b.done(target, began);
}

/// setting returns environment variable name, or null if it is unset or empty.
fn setting(name: []const u8) ?[]const u8 {
    const v = howl.environ.get(name) orelse return null;
    return if (v.len > 0) v else null;
}

/// Guest is the kernel and initramfs melange's QEMU runner boots.
pub const Guest = struct { kernel: []const u8, initramfs: []const u8 };

/// guest makes the QEMU runner's kernel and initramfs from Alpine's
/// linux-virt (boot/melange-guest.yaml). melange's initramfs loads its
/// drivers as modules, which werewolf's kernel does not have; the guest
/// only builds packages, and no image boots it. The modules go under
/// usr/lib/modules: melange's QEMU_KERNEL_MODULES puts them under /lib,
/// which replaces the guest's /lib -> usr/lib link and so its loader.
pub fn guest(b: *B) !Guest {
    const yaml = try packages.bootConfig(b, "melange-guest.yaml");
    const lock = "build/lock/melange-guest.lock.json";
    try packages.relock(b, lock, yaml);
    const rootfs = try b.path("{s}/melange-guest-{t}.tar", .{ vendor, b.spec.arch });
    try packages.apkoBuild(b, rootfs, yaml, lock, &.{lock});
    const out: Guest = .{
        .kernel = try b.path("{s}/melange-guest-{t}.vmlinuz", .{ vendor, b.spec.arch }),
        .initramfs = try b.path("{s}/melange-guest-{t}.cpio", .{ vendor, b.spec.arch }),
    };
    const began = try b.begin(out.initramfs, &.{rootfs}) orelse return out;
    const d = try b.path("{s}.d", .{out.initramfs});
    const base = try b.path("{s}.base", .{out.initramfs});
    const usr = try b.path("{s}/usr", .{d});
    try Dir.cwd().deleteTree(b.io, d);
    try Dir.cwd().createDirPath(b.io, usr);
    try b.run(&.{ "melange", "initramfs", "--arch", @tagName(b.spec.arch), "--output", base }, .{});
    // The modules' vmlinuz links to /boot, which would dangle in the guest.
    try b.run(
        &.{
            "bsdtar",
            "-xf",
            rootfs,
            "-C",
            usr,
            "--exclude",
            "lib/modules/*/vmlinuz",
            "lib/modules",
        },
        .{},
    );
    try b.run(&.{ "bsdtar", "-xf", rootfs, "-C", d, "boot/vmlinuz-virt" }, .{});
    // QEMU boots an arm64 EFI zboot image, but as melange has always booted
    // the raw Image, the guest gets that. unwrapZboot returns others as they are.
    const shipped = try b.read(try b.path("{s}/boot/vmlinuz-virt", .{d}), image.max_gunzip);
    const kern = image.unwrapZboot(b.gpa, shipped) catch |err|
        return b.fail("{s}: {t}", .{ rootfs, err });
    try b.write(out.kernel, kern);
    const t = try b.tmp(out.initramfs);
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
        if (!ran.ok) return b.fail("{s}: bsdtar or cat failed", .{out.initramfs});
    }
    try b.rename(t, out.initramfs);
    try Dir.cwd().deleteTree(b.io, d);
    try Dir.cwd().deleteFile(b.io, base);
    try b.done(out.initramfs, began);
    return out;
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
        "up_packages_security_vaultwarden_vaultwarden.yaml",
        try stampName(a, "../packages/security/vaultwarden/vaultwarden.yaml"),
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
