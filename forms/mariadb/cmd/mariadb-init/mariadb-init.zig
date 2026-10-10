//! mariadb-init makes MariaDB's data directory once, as mariadb-install-db
//! would, and applies the image's SQL before each start of the server.
//! See forms/mariadb/README.md.

const std = @import("std");
const linux = std.os.linux;
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

const svc_dir = "/data/svc/mariadb";
const data_dir = svc_dir ++ "/data";
const sql_dir = "/usr/share/werewolf-mariadb";
/// share holds MariaDB's own SQL: its system tables, help and sys schema.
const share = "/usr/share/mariadb-12.3";
const mariadbd = "/usr/bin/mariadbd";
const defaults = "--defaults-file=/etc/mariadb/werewolf.cnf";
/// made marks that a data directory was made. If the data is gone but the
/// mark is not, the data was lost, and mariadb-init refuses to make an
/// empty one over it.
const made = "data-made";
/// system lists MariaDB's SQL in the order mariadb-install-db feeds it,
/// leaving out its test database.
const system = [_][]const u8{
    "mariadb_system_tables.sql",
    "mariadb_performance_tables.sql",
    "mariadb_system_tables_data.sql",
    "fill_help_tables.sql",
    "maria_add_gis_sp_bootstrap.sql",
    "mariadb_sys_schema.sql",
};

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();
    var svc = try Dir.cwd().openDir(io, svc_dir, .{});
    defer svc.close(io);
    // werewolf.cnf's tmpdir, for sorts and temporary tables.
    svc.createDir(io, "tmp", .fromMode(0o700)) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    if (svc.access(io, "data/mysql", .{})) |_| {
        say(io, "keeping the data in {s}", .{data_dir});
        // data exists only once the bootstrap finished, so it is whole.
        // Mark it if a crash came before the mark.
        if (svc.access(io, made, .{})) |_| {} else |_| try mark(io, svc, made);
    } else |_| {
        if (svc.access(io, made, .{})) |_| {
            say(io, "the data in {s} is gone, though it was made here; not making it empty " ++
                "over its loss", .{data_dir});
            return error.DataLost;
        } else |_| {}
        // The bootstrap writes as it goes, so an interrupted one would
        // look like data. Make it in data.new and rename it when whole.
        if (svc.access(io, "data.new", .{})) |_| {
            say(io, "removing the data a stopped start left half made", .{});
            try svc.deleteTree(io, "data.new");
        } else |_| {}
        try svc.createDir(io, "data.new", .fromMode(0o700));
        say(io, "making the data in {s}", .{data_dir});
        var sql: std.ArrayList(u8) = .empty;
        // The service's own user administers it, by its UNIX socket, as
        // mariadb-install-db makes it when run as that user.
        try sql.appendSlice(gpa, "create database if not exists mysql;\nuse mysql;\n" ++
            "SET @auth_root_socket='mariadb';\n");
        for (system) |name| try sql.appendSlice(gpa, try Dir.cwd().readFileAlloc(
            io,
            try gpa.print("{s}/{s}", .{ share, name }),
            gpa,
            .limited(8 << 20),
        ));
        try bootstrap(
            io,
            &.{ "--datadir=" ++ svc_dir ++ "/data.new", "--enforce-storage-engine=" },
            sql.items,
        );
        svc.rename("data.new", svc, "data", io) catch |err| {
            say(io, "{s} holds something, but no data: {s}", .{ data_dir, @errorName(err) });
            return err;
        };
        try syncSvc(io);
        try mark(io, svc, made);
    }

    var names: std.ArrayList([]const u8) = .empty;
    if (Dir.cwd().openDir(io, sql_dir, .{ .iterate = true })) |d| {
        var dir = d;
        defer dir.close(io);
        var it = dir.iterate();
        while (try it.next(io)) |e| {
            if (e.kind != .file or !std.mem.endsWith(u8, e.name, ".sql")) continue;
            try names.append(gpa, try gpa.dupe(u8, e.name));
        }
    } else |_| {}
    std.mem.sort([]const u8, names.items, {}, lessThan);
    if (names.items.len == 0) return;
    // Bootstrap mode starts without the grant tables, so account
    // statements (CREATE USER, GRANT) would be refused: load them first.
    var sql: std.ArrayList(u8) = .empty;
    try sql.appendSlice(gpa, "FLUSH PRIVILEGES;\n");
    for (names.items) |name| {
        try sql.appendSlice(gpa, try Dir.cwd().readFileAlloc(
            io,
            try gpa.print("{s}/{s}", .{ sql_dir, name }),
            gpa,
            .limited(1 << 20),
        ));
        try sql.append(gpa, '\n');
    }
    try bootstrap(io, &.{}, sql.items);
    say(io, "applied {d} SQL file{s} from {s}", .{
        names.items.len,
        if (names.items.len == 1) "" else "s",
        sql_dir,
    });
}

/// bootstrap runs sql through `mariadbd --bootstrap`, the server with no
/// clients, as mariadb-install-db does. It stops at the first error.
fn bootstrap(io: Io, extra: []const []const u8, sql: []const u8) !void {
    var argv: [8][]const u8 = undefined;
    const base = [_][]const u8{ mariadbd, defaults, "--bootstrap", "--log-warnings=0" };
    @memcpy(argv[0..base.len], &base);
    @memcpy(argv[base.len..][0..extra.len], extra);
    var child = try std.process.spawn(io, .{
        .argv = argv[0 .. base.len + extra.len],
        .stdin = .pipe,
        .stdout = .ignore,
    });
    child.stdin.?.writeStreamingAll(io, sql) catch {};
    child.stdin.?.close(io);
    child.stdin = null;
    const term = try child.wait(io);
    if (term != .exited or term.exited != 0) {
        say(io, "{s} --bootstrap failed; see above", .{mariadbd});
        return error.BootstrapFailed;
    }
}

/// mark creates the empty file name in dir and syncs it and its directory
/// entry to disk.
fn mark(io: Io, dir: Dir, name: []const u8) !void {
    const f = try dir.createFile(io, name, .{});
    defer f.close(io);
    try f.sync(io);
    try syncSvc(io);
}

/// syncSvc fsyncs svc_dir so renames and new files in it survive a crash.
/// It opens its own descriptor because Dir's may be O_PATH, which fsync
/// refuses.
fn syncSvc(io: Io) !void {
    const rc = linux.open(svc_dir, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
    var e = linux.errno(rc);
    if (e == .SUCCESS) {
        e = linux.errno(linux.fsync(@intCast(rc)));
        _ = linux.close(@intCast(rc));
    }
    if (e == .SUCCESS) return;
    say(io, "syncing {s}: {s}", .{ svc_dir, @tagName(e) });
    return error.SyncFailed;
}

fn lessThan(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

fn say(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const line = std.mem.print(&buf, "mariadb-init: " ++ fmt ++ "\n", args) catch return;
    Io.File.stdout().writeStreamingAll(io, line) catch {};
}
