//! package packs werewolf's programs as apk packages, then indexes and signs
//! their repository with lib/package.zig. See tools/README.md.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const package = @import("package");

const usage = "usage: package pack DIR TREE NAME VERSION ARCH TIME DESCRIPTION " ++
    "[depend:D|provide:P]..., index DIR OLD|-, sign DIR KEYNAME SIGNATURE, " ++
    "open INDEX KEYNAME SIGNATURE MEMBER";
const limit: Io.Limit = .limited(256 << 20);

pub fn main(init: std.process.Init) !void {
    const gpa = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(gpa);
    run(io, gpa, args[1..]) catch |err| switch (err) {
        error.Usage => {
            std.log.err("{s}", .{usage});
            std.process.exit(2);
        },
        else => return err,
    };
}

fn run(io: Io, gpa: Allocator, args: []const []const u8) !void {
    const cwd = Dir.cwd();
    if (args.len >= 8 and is(args[0], "pack")) {
        var depends: std.ArrayList([]const u8) = .empty;
        var provides: std.ArrayList([]const u8) = .empty;
        for (args[8..]) |a| {
            if (std.mem.startsWith(u8, a, "depend:")) {
                try depends.append(gpa, a["depend:".len..]);
            } else if (std.mem.startsWith(u8, a, "provide:")) {
                try provides.append(gpa, a["provide:".len..]);
            } else return error.Usage;
        }
        var tree = try cwd.openDir(io, args[2], .{ .iterate = true });
        defer tree.close(io);
        var entries: std.ArrayList(package.Entry) = .empty;
        try walk(io, gpa, tree, "", &entries);
        const time = std.fmt.parseInt(u64, args[6], 10) catch return error.Usage;
        const version = if (is(args[4], "-")) try package.version(gpa, time) else args[4];
        const p = try package.pack(gpa, .{
            .name = args[3],
            .version = version,
            .arch = args[5],
            .time = time,
            .description = args[7],
            .depends = depends.items,
            .provides = provides.items,
        }, entries.items);
        const apk = try gpa.print("{s}/{s}-{s}.apk", .{ args[1], args[3], version });
        try cwd.writeFile(io, .{ .sub_path = apk, .data = p.bytes });
        try cwd.writeFile(
            io,
            .{ .sub_path = try gpa.print("{s}.stanza", .{apk}), .data = p.stanza },
        );
    } else if (args.len == 3 and is(args[0], "index")) {
        const old = if (is(args[2], "-")) "" else try cwd.readFileAlloc(io, args[2], gpa, limit);
        var dir = try cwd.openDir(io, args[1], .{ .iterate = true });
        defer dir.close(io);
        var stanzas: std.ArrayList([]const u8) = .empty;
        var it = dir.iterate();
        while (try it.next(io)) |e| {
            if (!std.mem.endsWith(u8, e.name, ".apk.stanza")) continue;
            try stanzas.append(gpa, try dir.readFileAlloc(io, e.name, gpa, limit));
        }
        const apkindex = try package.index(gpa, old, stanzas.items);
        try dir.writeFile(io, .{ .sub_path = "APKINDEX", .data = apkindex });
        const member = try package.indexMember(gpa, "werewolf", apkindex);
        try dir.writeFile(io, .{ .sub_path = "APKINDEX.member", .data = member });
    } else if (args.len == 5 and is(args[0], "open")) {
        const whole = try cwd.readFileAlloc(io, args[1], gpa, limit);
        const o = try package.open(gpa, whole, args[2]);
        try cwd.writeFile(io, .{ .sub_path = args[3], .data = o.signature });
        try cwd.writeFile(io, .{ .sub_path = args[4], .data = o.member });
    } else if (args.len == 4 and is(args[0], "sign")) {
        var dir = try cwd.openDir(io, args[1], .{});
        defer dir.close(io);
        const member = try dir.readFileAlloc(io, "APKINDEX.member", gpa, limit);
        const signature = try cwd.readFileAlloc(io, args[3], gpa, .limited(64 << 10));
        const whole = try package.signed(gpa, args[2], signature, member);
        try dir.writeFile(io, .{ .sub_path = "APKINDEX.tar.gz", .data = whole });
    } else return error.Usage;
}

fn is(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

/// walk appends what is under dir, at path, to entries: each directory, then
/// its contents, sorted by name so the same tree packs the same bytes.
fn walk(
    io: Io,
    gpa: Allocator,
    dir: Dir,
    path: []const u8,
    entries: *std.ArrayList(package.Entry),
) !void {
    var names: std.ArrayList([]const u8) = .empty;
    var it = dir.iterate();
    while (try it.next(io)) |e| {
        if (is(e.name, ".DS_Store")) continue;
        try names.append(gpa, try gpa.dupe(u8, e.name));
    }
    std.mem.sortUnstable([]const u8, names.items, {}, struct {
        fn lt(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lt);
    for (names.items) |name| {
        const sub = if (path.len == 0) name else try gpa.print("{s}/{s}", .{ path, name });
        const st = try dir.statFile(io, name, .{ .follow_symlinks = false });
        switch (st.kind) {
            .directory => {
                try entries.append(gpa, .{ .path = sub, .kind = .dir });
                var child = try dir.openDir(io, name, .{ .iterate = true });
                defer child.close(io);
                try walk(io, gpa, child, sub, entries);
            },
            .sym_link => {
                var buf: [Dir.max_path_bytes]u8 = undefined;
                const target = buf[0..try dir.readLink(io, name, &buf)];
                try entries.append(
                    gpa,
                    .{ .path = sub, .kind = .link, .data = try gpa.dupe(u8, target) },
                );
            },
            .file => try entries.append(gpa, .{
                .path = sub,
                .kind = .file,
                .mode = if (st.permissions.toMode() & 0o111 != 0) 0o755 else 0o644,
                .data = try dir.readFileAlloc(io, name, gpa, limit),
            }),
            else => return error.UnexpectedFileKind,
        }
    }
}
