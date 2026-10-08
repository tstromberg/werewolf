//! form: what the build asks of a form (lib/form.zig, forms/README.md).
//! FORM is a form's name in forms/, or a directory holding a form.
//!
//!   form names FORM          the chain's forms, base first
//!   form dirs FORM           their directories
//!   form list FORM KEY       form.yaml's KEY along the chain, a line each
//!   form check FORM KEY      the form's own check KEY, an item a line
//!   form listens FORM        the TCP ports the chain's net serves, a line each
//!   form weaknesses FORM     the posture checks the form's own weaknesses name
//!   form excuses FORM        the same, each with its excuse, a line each
//!   form oci FORM            the services with a root (an image baked in), a line each:
//!                            `root NAME DIR USER`, then `write NAME PATH` for each path
//!   form pledge FORM         the machine's promises: every service's pledge, as one;
//!                            refused, a service leash refuses or that listens
//!                            where no net line does
//!   form sshd FORM           the chain's sshd: as sshd_config lines, or nothing
//!   form bastion-keys FORM   the bastion's authorized_keys, from bastion: users:
//!   form bastion-permit FORM the bastion's PermitOpen line, or nothing
//!   form bastion-service FORM the bastion's service file, connecting where net says
//!   form having KEY [VALUE]  the forms in forms/ whose check KEY is VALUE (true)
//!   form every KEY           form.yaml's KEY in every form in forms/, once each
//!   form apko FORM [PKG...]  the chain's apko configs as one, and PKGs
//!   form tree                every form in forms/ and its chain
//!
//! A form that cannot be read fails the command, with the file and line.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const form = @import("form");
const seal = @import("seal");
const service = @import("service");

const usage = "usage: form names|dirs|listens|weaknesses|excuses|pledge|oci|sshd|bastion-keys|" ++
    "bastion-permit|bastion-service FORM, " ++
    "list|check FORM KEY, having KEY [VALUE], every KEY, apko FORM [PKG...], tree";

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
    } else if (is(verb, "oci") and args.len == 2) {
        // What init binds beneath each image root and fence allows there
        // (cmd/init/oci.zig, cmd/fence): read as leash reads the file.
        for (try form.services(io, gpa, root, forms, f)) |s| {
            var bad: service.Bad = .{};
            const parsed = service.parse(gpa, s.text, &bad) catch |err| switch (err) {
                error.Invalid => return f.fail(
                    gpa,
                    "{s}, line {d}: {s}",
                    .{ s.path, bad.line, bad.why },
                ),
                else => |e| return e,
            };
            const dir = parsed.root orelse continue;
            try w.print("root {s} {s} {s}\n", .{ s.name, dir, parsed.user });
            for (parsed.write) |path| try w.print("write {s} {s}\n", .{ s.name, path });
        }
    } else if (is(verb, "pledge") and args.len == 2) {
        // Each service file read whole, as leash reads it: one leash would
        // refuse fails the build, rather than give the machine the wrong
        // promises; and so does one that listens where the chain's net
        // does not, whose bind fence would refuse at boot.
        var declared: std.ArrayList(u16) = .empty;
        for (forms) |fm| for (try fm.items(gpa, "net")) |line| {
            var why: []const u8 = "";
            const l = (form.listen(gpa, line, &why) catch |err| switch (err) {
                error.Invalid => return f.fail(
                    gpa,
                    "{s}/form.yaml: net: {s}: {s}",
                    .{ fm.dir, line, why },
                ),
                error.OutOfMemory => return error.OutOfMemory,
            }) orelse continue;
            try declared.appendSlice(gpa, l.ports);
        };
        var promises: seal.Set = .empty;
        for (try form.services(io, gpa, root, forms, f)) |s| {
            var bad: service.Bad = .{};
            const parsed = service.parse(gpa, s.text, &bad) catch |err| switch (err) {
                error.Invalid => return f.fail(
                    gpa,
                    "{s}, line {d}: {s}",
                    .{ s.path, bad.line, bad.why },
                ),
                else => |e| return e,
            };
            for (parsed.listen) |port| if (std.mem.findScalar(u16, declared.items, port) == null)
                return f.fail(
                    gpa,
                    "{s}: listen tcp/{d}, which no net line declares: fence refuses the bind " ++
                        "(`listen tcp/{d} loopback` for the machine alone)",
                    .{ s.path, port, port },
                );
            promises.setUnion(parsed.pledge);
        }
        var it = promises.iterator();
        var sep: []const u8 = "";
        while (it.next()) |p| : (sep = " ") try w.print("{s}{t}", .{ sep, p });
        try w.writeAll("\n");
    } else if (is(verb, "sshd") and args.len == 2) {
        try w.writeAll(try form.sshdConfig(gpa, forms, f));
    } else if (is(verb, "bastion-keys") and args.len == 2) {
        try w.writeAll((try form.bastionFiles(gpa, forms, f)).keys);
    } else if (is(verb, "bastion-permit") and args.len == 2) {
        try w.writeAll((try form.bastionFiles(gpa, forms, f)).permit);
    } else if (is(verb, "bastion-service") and args.len == 2) {
        try w.writeAll(try form.bastionService(io, gpa, root, forms, f));
    } else if (is(verb, "apko")) {
        try form.write(w, try form.apko(io, gpa, root, forms, args[2..], f));
    } else return error.Usage;
}

fn is(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

/// The names of the forms in forms/, sorted.
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
