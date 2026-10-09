//! form answers the build's questions about a form: its chain of bases,
//! form.yaml keys, kernel arguments, modules and composed files.
//! See README.md and forms/README.md.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const form = @import("form");
const compose = @import("compose");

const usage = "usage: form names|dirs|listens|weaknesses|excuses FORM, " ++
    "list|check FORM KEY, cmdline|module-params FORM ARCH, modules FORM ARCH native|bitten|all, " ++
    "compose FORM ARCH KNOWN ACCOUNTS RO META [dev], " ++
    "having KEY [VALUE], every KEY, apko FORM [PKG...], tree";

pub fn main(init: std.process.Init) !void {
    const gpa = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(gpa);
    var buf: [4096]u8 = undefined;
    var out = Io.File.stdout().writerStreaming(io, &buf);
    const w = &out.interface;
    var f: form.Failure = .{};
    run(io, gpa, w, args[1..], &f) catch |err| switch (err) {
        error.Form => {
            std.log.err("{s}", .{f.text});
            std.process.exit(1);
        },
        error.Usage => {
            std.log.err("{s}", .{usage});
            std.process.exit(2);
        },
        else => return err,
    };
    try w.flush();
}

fn run(io: Io, gpa: Allocator, w: *Io.Writer, args: []const []const u8, f: *form.Failure) !void {
    if (args.len == 0) return error.Usage;
    const verb = args[0];
    const root = Dir.cwd();
    if (is(verb, "tree") and args.len == 1) {
        for (try all(io, gpa)) |name| {
            const top = try form.load(io, gpa, root, name, f);
            try w.print("{s: <18} ", .{name});
            for (try form.bases(io, gpa, root, top, f), 0..) |c, i|
                try w.print("{s}{s}", .{ if (i > 0) " > " else "", c.name });
            const with = try top.items(gpa, "with");
            if (with.len > 0) {
                try w.writeAll("  (with");
                for (with) |m| try w.print(" {s}", .{m});
                try w.writeAll(")");
            }
            try w.writeAll("\n");
        }
        return;
    }
    if (is(verb, "having") and (args.len == 2 or args.len == 3)) {
        const want = if (args.len == 3) args[2] else "true";
        for (try all(io, gpa)) |name| {
            const c = (try form.load(io, gpa, root, name, f)).check(args[1]) orelse continue;
            if (c == .scalar and is(c.scalar.text, want)) try w.print("{s}\n", .{name});
        }
        return;
    }
    if (is(verb, "every") and args.len == 2) {
        var seen: std.array_hash_map.String(void) = .empty;
        for (try all(io, gpa)) |name| {
            const one = try form.load(io, gpa, root, name, f);
            for (try one.items(gpa, args[1])) |item| try seen.put(gpa, item, {});
        }
        for (seen.keys()) |item| try w.print("{s}\n", .{item});
        return;
    }
    if (args.len < 2) return error.Usage;
    const forms = try form.chain(io, gpa, root, args[1], f);
    if (is(verb, "names") and args.len == 2) {
        for (forms) |c| try w.print("{s}\n", .{c.name});
    } else if (is(verb, "dirs") and args.len == 2) {
        for (forms) |c| try w.print("{s}\n", .{c.dir});
    } else if (is(verb, "list") and args.len == 3) {
        for (forms) |c| for (try c.items(gpa, args[2])) |line| try w.print("{s}\n", .{line});
    } else if (is(verb, "check") and args.len == 3) {
        const c = forms[forms.len - 1].check(args[2]) orelse return;
        switch (c) {
            .scalar => |s| try w.print("{s}\n", .{s.text}),
            .list => |l| for (l) |item| try w.print("{s}\n", .{item.scalar.text}),
            .map => unreachable,
        }
    } else if (is(verb, "listens") and args.len == 2) {
        for (try form.listens(gpa, forms, f)) |port| try w.print("{d}\n", .{port});
    } else if (is(verb, "weaknesses") and args.len == 2) {
        for (forms[forms.len - 1].weaknesses()) |e| try w.print("{s}\n", .{e.key});
    } else if (is(verb, "excuses") and args.len == 2) {
        for (forms[forms.len - 1].weaknesses()) |e|
            try w.print("{s} {s}\n", .{ e.key, e.value.scalar.text });
    } else if (is(verb, "cmdline") and args.len == 3) {
        const allowed = try compose.allowances(gpa, forms, f);
        try w.print("{s}\n", .{try compose.cmdline(gpa, allowed, try arch(args[2]))});
    } else if (is(verb, "module-params") and args.len == 3) {
        const allowed = try compose.allowances(gpa, forms, f);
        for (compose.moduleParams(allowed, try arch(args[2]))) |p|
            try w.print("{s}:{s}\n", .{ p.module, p.value });
    } else if (is(verb, "modules") and args.len == 4) {
        const m = try compose.modules(gpa, forms, try arch(args[2]));
        const list = if (is(args[3], "native"))
            m.native
        else if (is(args[3], "bitten"))
            m.bitten
        else if (is(args[3], "all"))
            m.all
        else
            return error.Usage;
        for (list) |name| try w.print("{s}\n", .{name});
    } else if (is(verb, "compose") and (args.len == 7 or (args.len == 8 and is(args[7], "dev")))) {
        const b: compose.Build = .{
            .arch = try arch(args[2]),
            .dev = args.len == 8,
            .posture_known = try root.readFileAlloc(io, args[3], gpa, .limited(64 << 10)),
        };
        var image: [3][]const u8 = undefined;
        for (&image, [_][]const u8{ "passwd", "group", "shadow" }) |*text, name| {
            const path = try gpa.print("{s}/etc/{s}", .{ args[4], name });
            text.* = try root.readFileAlloc(io, path, gpa, .limited(1 << 20));
        }
        const accounts: compose.Accounts = .{
            .passwd = image[0],
            .group = image[1],
            .shadow = image[2],
        };
        var ro = try root.createDirPathOpen(io, args[5], .{});
        defer ro.close(io);
        var meta = try root.createDirPathOpen(io, args[6], .{});
        defer meta.close(io);
        try compose.compose(io, gpa, root, forms, accounts, ro, meta, b, f);
    } else if (is(verb, "apko")) {
        try form.write(w, try compose.apko(io, gpa, root, forms, args[2..], f));
    } else return error.Usage;
}

fn is(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

fn arch(name: []const u8) error{Usage}!compose.Arch {
    return std.meta.stringToEnum(compose.Arch, name) orelse error.Usage;
}

/// all returns the sorted names of the directories in forms/ that hold an apko.yaml.
fn all(io: Io, gpa: Allocator) ![]const []const u8 {
    var dir = try Dir.cwd().openDir(io, "forms", .{ .iterate = true });
    defer dir.close(io);
    var names: std.ArrayList([]const u8) = .empty;
    var it = dir.iterate();
    while (try it.next(io)) |e| {
        if (e.kind != .directory or !form.isName(e.name)) continue;
        const path = try gpa.print("{s}/apko.yaml", .{e.name});
        dir.access(io, path, .{}) catch continue;
        try names.append(gpa, try gpa.dupe(u8, e.name));
    }
    std.mem.sortUnstable([]const u8, names.items, {}, struct {
        fn lt(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lt);
    return names.items;
}
