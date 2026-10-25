//! package-consumers checks, without the network, that forms consume
//! published packages: a form's own recipes stay in the forms tree, Plex
//! and Pi-hole name their packages rather than build them, and CI needs no
//! sibling package checkout. It asks build/host/form.

const std = @import("std");
const host = @import("host");
const Io = std.Io;
const mem = std.mem;

pub fn main(init: std.process.Init) void {
    var c = host.Check.init(
        init,
        "package-consumers",
    ) catch |err| std.process.fatal("package-consumers: {t}", .{err});
    c.finish(run(&c));
}

fn query(c: *host.Check, args: []const []const u8) ![]const []const u8 {
    const r = try c.must(
        try mem.concat(c.gpa, []const u8, &.{ &.{"build/host/form"}, args }),
        "",
        .{},
    );
    var out: std.ArrayList([]const u8) = .empty;
    var lines = mem.tokenizeScalar(u8, r.stdout, '\n');
    while (lines.next()) |line| try out.append(c.gpa, line);
    return out.items;
}

fn has(list: []const []const u8, want: []const u8) bool {
    for (list) |x| if (mem.eql(u8, x, want)) return true;
    return false;
}

fn run(c: *host.Check) !void {
    const io = c.io;
    const gpa = c.gpa;
    const forms = try Io.Dir.cwd().realPathFileAlloc(io, "forms", gpa);
    var dir = try Io.Dir.cwd().openDir(io, "forms", .{ .iterate = true });
    defer dir.close(io);
    var it = dir.iterate();
    var count: usize = 0;
    while (try it.next(io)) |e| {
        if (e.kind != .directory) continue;
        dir.access(io, try gpa.print("{s}/form.yaml", .{e.name}), .{}) catch continue;
        count += 1;
        for (try query(c, &.{ "recipes", e.name })) |recipe| {
            const path = Io.Dir.cwd().realPathFileAlloc(io, recipe, gpa) catch
                return c.fail("{s}: recipe {s} is not a file", .{ e.name, recipe });
            const st = try Io.Dir.cwd().statFile(io, path, .{});
            if (st.kind != .file) return c.fail(
                "{s}: recipe {s} is not a file",
                .{ e.name, recipe },
            );
            if (!mem.startsWith(u8, path, forms) or path.len <= forms.len or path[forms.len] != '/')
                return c.fail("{s}: recipe {s} is outside the forms tree", .{ e.name, recipe });
        }
    }
    if (count == 0) return c.fail("no forms", .{});

    const packaged = try query(c, &.{"packaged"});
    for ([_]struct { []const u8, []const []const u8 }{
        .{ "plex", &.{ "musl-werewolf", "plexmediaserver", "caddy" } },
        .{ "pi-hole", &.{"pihole-curl"} },
    }) |case| {
        const name = case[0];
        if ((try query(
            c,
            &.{ "recipes", name },
        )).len != 0) return c.fail("{s} builds its own packages", .{name});
        const listed = try query(c, &.{ "list", name, "packages" });
        const depends = try query(c, &.{ "depends", name });
        for (case[1]) |want| {
            if (!has(listed, want)) return c.fail("{s} does not list package {s}", .{ name, want });
            if (!has(depends, want)) return c.fail("{s} does not depend on {s}", .{ name, want });
        }
        if (!has(packaged, name)) return c.fail("{s} is not a packaged form", .{name});
    }

    var workflows = try Io.Dir.cwd().openDir(io, ".github/workflows", .{ .iterate = true });
    defer workflows.close(io);
    var wit = workflows.iterate();
    while (try wit.next(io)) |e| {
        if (!mem.endsWith(u8, e.name, ".yml")) continue;
        const text = try workflows.readFileAlloc(io, e.name, gpa, .limited(1 << 20));
        for ([_][]const u8{
            "tools/checkout-packages",
            "release/package-sources.json",
            "WEREWOLF_PACKAGES_REF",
        }) |word|
            if (mem.find(u8, text, word) != null)
                return c.fail("{s} needs a sibling package checkout: {s}", .{ e.name, word });
    }
    c.say(
        "pass   package-consumers: recipes in the forms tree, published dependencies, no " ++
            "package checkout in CI",
        .{},
    );
}
