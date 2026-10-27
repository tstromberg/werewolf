//! Policy comes from the verified image and durable owner identity ledger.
const std = @import("std");
const data = @import("data-transfer");
const people = @import("people");
const services = @import("service");
const linux = std.os.linux;
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const mem = std.mem;
pub const Identity = struct { image: []const u8, arch: data.Arch, users: []const u8 = "", nocloud: ?people.NoCloud = null };

pub fn cleanPostgres(io: Io, a: Allocator, root: Dir, session: bool) !void {
    var service = data.parentDir(io, root, "svc/postgres/entry") catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    defer service.close(io);
    // An interrupted initdb is not a complete, clean physical backup.
    if (service.statFile(io, "data.new", .{ .follow_symlinks = false })) |_| {
        return error.TransferPostgresUnclean;
    } else |err| if (err != error.FileNotFound) return err;
    var parent = data.parentDir(io, root, "svc/postgres/data/PG_VERSION") catch |err| switch (err) {
        error.FileNotFound => {
            // Other service files can exist before initdb. A cluster marker
            // without its complete data directory is an interrupted setup.
            for ([_][]const u8{ "data", "cluster-made" }) |name| {
                if (service.statFile(io, name, .{ .follow_symlinks = false })) |_|
                    return error.TransferPostgresUnclean
                else |e| if (e != error.FileNotFound) return e;
            }
            return;
        },
        else => return err,
    };
    defer parent.close(io);
    const version = try data.openRegular(io, parent, "PG_VERSION");
    defer version.close(io);
    var buffer: [32]u8 = undefined;
    const n = try version.readPositionalAll(io, &buffer, 0);
    if (!mem.eql(u8, mem.trim(u8, buffer[0..n], "\n"), "18")) return error.TransferPostgresVersion;
    var global = try data.parentDir(io, root, "svc/postgres/data/global/pg_control");
    defer global.close(io);
    const control = try data.openRegular(io, global, "pg_control");
    defer control.close(io);
    var contents: [8192]u8 = undefined;
    if ((try control.stat(io)).size != contents.len or
        try control.readPositionalAll(io, &contents, 0) != contents.len) return error.TransferPostgresControl;
    try Dir.cwd().createDirPath(io, "/run/pg-check/global");
    try Dir.cwd().setFilePermissions(io, "/run/pg-check", .fromMode(0o755), .{});
    try Dir.cwd().setFilePermissions(io, "/run/pg-check/global", .fromMode(0o755), .{});
    Dir.cwd().deleteFile(io, "/run/pg-check/global/pg_control") catch |err| if (err != error.FileNotFound) return err;
    try Dir.cwd().writeFile(io, .{ .sub_path = "/run/pg-check/global/pg_control", .data = &contents, .flags = .{ .permissions = .fromMode(0o444) } });
    var env: std.process.Environ.Map = .init(a);
    try env.put("LC_ALL", "C");
    const result = try std.process.run(a, io, .{
        .argv = &.{ "/usr/lib/werewolf/data-transfer-tool", if (session) "postgres-session" else "postgres" },
        .environ_map = &env,
        .stdout_limit = .limited(8192),
        .stderr_limit = .limited(4096),
    });
    if (result.term != .exited or result.term.exited != 0 or result.stderr.len != 0)
        return error.TransferPostgresControl;
    var lines = mem.splitScalar(u8, result.stdout, '\n');
    while (lines.next()) |line| if (mem.startsWith(u8, line, "Database cluster state:")) {
        if (mem.eql(u8, mem.trim(u8, line["Database cluster state:".len..], " \t"), "shut down")) return;
        return error.TransferPostgresUnclean;
    };
    return error.TransferPostgresControl;
}

pub fn catalog(io: Io, a: Allocator, image: Dir, root: Dir, c: Identity, initialize: bool) !data.Policy {
    var base: people.Files = .{
        .passwd = try image.readFileAlloc(io, "usr/share/werewolf/etc/passwd", a, .limited(1 << 20)),
        .group = try image.readFileAlloc(io, "usr/share/werewolf/etc/group", a, .limited(1 << 20)),
        .shadow = try image.readFileAlloc(io, "usr/share/werewolf/etc/shadow", a, .limited(1 << 20)),
        .made = "",
    };
    var ledger: []const people.Identity = &.{};
    if (root.openDir(io, ".werewolf", .{ .iterate = true, .follow_symlinks = false })) |dir| {
        defer dir.close(io);
        ledger = people.loadLedger(a, dir.handle) catch |err| switch (err) {
            error.NoLedger => &.{},
            else => return err,
        };
    } else |err| if (err != error.FileNotFound) return err;
    if (initialize) {
        if (!try people.freshData(root.handle)) return error.TransferConflict;
        const change = try people.applyReserved(a, base, &.{}, c.users, "/sbin/nologin", c.nocloud, true);
        if (change.refused.len != 0) return error.TransferIdentity;
        const dir = try people.openLedgerDir(root.handle);
        defer _ = linux.close(dir);
        try people.commitLedger(a, dir, change.identities);
        try data.install.syncDir(io, root);
        ledger = change.identities;
        base.passwd = change.passwd;
        base.group = change.group;
    }
    var users: std.ArrayList(data.Identity) = .empty;
    var groups: std.ArrayList(data.Identity) = .empty;
    try accountList(a, base.passwd, &users);
    try accountList(a, base.group, &groups);
    for (ledger) |id| {
        try addIdentity(a, &users, id.name, id.id);
        try addIdentity(a, &groups, id.name, id.id);
    }
    var names: std.ArrayList([]const u8) = .empty;
    var dir = try image.openDir(io, "etc/sv", .{ .iterate = true });
    defer dir.close(io);
    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        if (!data.validName(entry.name) or names.items.len >= 4096) return error.TransferService;
        const text = dir.readFileAlloc(io, try a.print("{s}/service", .{entry.name}), a, .limited(64 << 10)) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };
        var bad: services.Bad = .{};
        const s = try services.parse(a, text, &bad);
        const uid = try data.identityByName(users.items, if (s.user.len == 0) "root" else s.user);
        if (uid > services.system_id_max) try names.append(a, try a.dupe(u8, entry.name));
    }
    return .{ .image = c.image, .arch = c.arch, .services = names.items, .users = users.items, .groups = groups.items };
}

fn accountList(a: Allocator, text: []const u8, list: *std.ArrayList(data.Identity)) !void {
    var lines = mem.tokenizeScalar(u8, text, '\n');
    while (lines.next()) |line| {
        var fields = mem.splitScalar(u8, line, ':');
        const name = fields.next() orelse return error.TransferIdentity;
        _ = fields.next() orelse return error.TransferIdentity;
        const id = try std.fmt.parseUnsigned(u32, fields.next() orelse return error.TransferIdentity, 10);
        try addIdentity(a, list, name, id);
    }
}

fn addIdentity(a: Allocator, list: *std.ArrayList(data.Identity), name: []const u8, id: u32) !void {
    if (!data.validIdentity(name) or list.items.len >= 8192) return error.TransferIdentity;
    for (list.items) |old| {
        if (old.id == id and mem.eql(u8, old.name, name)) return;
        if (old.id == id or mem.eql(u8, old.name, name)) return error.TransferIdentity;
    }
    try list.append(a, .{ .name = name, .id = id });
}
