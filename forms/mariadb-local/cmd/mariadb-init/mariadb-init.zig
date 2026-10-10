//! mariadb-init makes MariaDB's data directory once, as mariadb-install-db
//! would, and applies the image's SQL before each start of the server.
//! See forms/mariadb-local/README.md. It also writes the server's network
//! file: closed, unless PORT is 3306, which is mariadb-tcp.

const std = @import("std");
const linux = std.os.linux;
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

const run_dir = "/run/svc/mariadb";
/// network_cnf is what werewolf.cnf includes. Closed unless PORT is 3306.
const network_cnf = run_dir ++ "/network.cnf";
const svc_dir = "/data/svc/mariadb";
const data_dir = svc_dir ++ "/data";
const sql_dir = "/usr/share/werewolf-mariadb";
/// import_dir is the read-only disk init mounts. Its .sql is applied once,
/// into the data directory as that directory is first made.
const import_dir = "/run/werewolf/import";
const import_failed = import_dir ++ "/import-failed";
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
    const open = openPort(gpa, init.minimal.environ) catch |err| {
        say(io, "PORT is 3306, the one port this form may bind", .{});
        return err;
    };
    try writeNetwork(io, networkText(open));
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
        if (importBlocked(io)) {
            say(io, "import disk did not mount; not making empty data", .{});
            return error.ImportFailed;
        }
        const dump = try sqlFiles(io, gpa, import_dir);
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
        if (dump.len > 0) bootstrapFiles(
            io,
            gpa,
            &.{ "--datadir=" ++ svc_dir ++ "/data.new", "--enforce-storage-engine=" },
            dump,
        ) catch |err| {
            svc.deleteTree(io, "data.new") catch |del| {
                say(io, "removing {s}/data.new: {s}", .{ svc_dir, @errorName(del) });
            };
            say(io, "import kept on {s}", .{import_dir});
            return err;
        };
        svc.rename("data.new", svc, "data", io) catch |err| {
            say(io, "{s} holds something, but no data: {s}", .{ data_dir, @errorName(err) });
            return err;
        };
        try syncSvc(io);
        try mark(io, svc, made);
        for (dump) |path| say(io, "imported {s}", .{path});
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

/// networkText is the include werewolf.cnf reads. open binds 0.0.0.0:3306.
/// Otherwise the server has no TCP listener.
fn networkText(open: bool) []const u8 {
    if (open) return "[mariadbd]\nbind-address=0.0.0.0\nport=3306\n";
    return "[mariadbd]\nskip-networking\n";
}

/// openPort is true when PORT is 3306. Unset is closed. Anything else is
/// refused: Landlock allows that port alone, and only on mariadb-tcp.
fn openPort(gpa: Allocator, environ: std.process.Environ) !bool {
    const v = environ.getAlloc(gpa, "PORT") catch return false;
    if (v.len == 0) return false;
    const n = std.fmt.parseInt(u16, v, 10) catch return error.BadPort;
    if (n != 3306) return error.BadPort;
    return true;
}

/// writeNetwork replaces network_cnf whole, so a start never sees a half
/// written file.
fn writeNetwork(io: Io, text: []const u8) !void {
    var dir = try Dir.cwd().openDir(io, run_dir, .{});
    defer dir.close(io);
    const name = std.fs.path.basename(network_cnf);
    dir.deleteFile(io, ".network.cnf.tmp") catch {};
    {
        var f = try dir.createFile(io, ".network.cnf.tmp", .{
            .exclusive = true,
            .permissions = .fromMode(0o644),
        });
        defer f.close(io);
        try f.writeStreamingAll(io, text);
        try f.sync(io);
    }
    try Dir.rename(dir, ".network.cnf.tmp", dir, name, io);
}

/// bootstrap runs sql through `mariadbd --bootstrap`, the server with no
/// clients, as mariadb-install-db does. It stops at the first error.
fn bootstrap(io: Io, extra: []const []const u8, sql: []const u8) !void {
    try bootstrapFeeds(io, extra, &.{.{ .bytes = sql }}, false);
}

/// bootstrapFiles streams each path into a bootstrap of the data directory
/// extra names. Grant tables are loaded first, so CREATE USER is accepted.
/// A short read is a failure: the server's own success does not commit a
/// dump that was cut off.
fn bootstrapFiles(
    io: Io,
    gpa: Allocator,
    extra: []const []const u8,
    paths: []const []const u8,
) !void {
    var feeds: std.ArrayList(Feed) = .empty;
    try feeds.append(gpa, .{ .bytes = "FLUSH PRIVILEGES;\n" });
    for (paths) |p| try feeds.append(gpa, .{ .file = p });
    try bootstrapFeeds(io, extra, feeds.items, true);
}

/// importBlocked reports that init could not mount the import disk.
fn importBlocked(io: Io) bool {
    return if (Dir.cwd().access(io, import_failed, .{})) |_| true else |_| false;
}

/// sqlFiles returns dir's regular .sql files, in name order. A symlink is
/// refused: the import is read as the service finds it, and a link can
/// name something outside the disk.
fn sqlFiles(io: Io, gpa: Allocator, dir: []const u8) ![]const []const u8 {
    var d = Dir.cwd().openDir(io, dir, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return &.{},
        else => return err,
    };
    defer d.close(io);
    var names: std.ArrayList([]const u8) = .empty;
    var it = d.iterate();
    while (try it.next(io)) |e| {
        if (e.name.len == 0 or e.name[0] == '.') continue;
        if (std.mem.eql(u8, e.name, "import-failed")) continue;
        switch (e.kind) {
            .file => if (std.mem.endsWith(u8, e.name, ".sql"))
                try names.append(gpa, try gpa.dupe(u8, e.name)),
            .sym_link => {
                say(io, "{s}/{s} is a symlink; not importing", .{ dir, e.name });
                return error.Symlink;
            },
            else => {},
        }
    }
    std.mem.sort([]const u8, names.items, {}, lessThan);
    var paths: std.ArrayList([]const u8) = .empty;
    for (names.items) |name| try paths.append(gpa, try gpa.print("{s}/{s}", .{ dir, name }));
    return paths.items;
}

const Feed = union(enum) { bytes: []const u8, file: []const u8 };

fn bootstrapFeeds(io: Io, extra: []const []const u8, feeds: []const Feed, report_read: bool) !void {
    var argv: [8][]const u8 = undefined;
    const base = [_][]const u8{ mariadbd, defaults, "--bootstrap", "--log-warnings=0" };
    @memcpy(argv[0..base.len], &base);
    @memcpy(argv[base.len..][0..extra.len], extra);
    var child = try std.process.spawn(io, .{
        .argv = argv[0 .. base.len + extra.len],
        .stdin = .pipe,
        .stdout = .ignore,
    });
    var read_err = false;
    for (feeds) |f| switch (f) {
        .bytes => |b| child.stdin.?.writeStreamingAll(io, b) catch break,
        .file => |p| streamFile(io, child.stdin.?, p) catch |err| {
            if (report_read) say(io, "{s}: {s}", .{ p, @errorName(err) });
            read_err = true;
            break;
        },
    };
    child.stdin.?.close(io);
    child.stdin = null;
    const term = try child.wait(io);
    if (term != .exited or term.exited != 0) {
        say(io, "{s} --bootstrap failed; see above", .{mariadbd});
        return error.BootstrapFailed;
    }
    if (read_err) return error.ImportFailed;
}

fn streamFile(io: Io, w: Io.File, path: []const u8) !void {
    var f = try Dir.cwd().openFile(io, path, .{ .follow_symlinks = false });
    defer f.close(io);
    var buf: [1 << 16]u8 = undefined;
    while (true) {
        const n = f.readStreaming(io, &.{&buf}) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        if (n == 0) break;
        w.writeStreamingAll(io, buf[0..n]) catch return;
    }
    w.writeStreamingAll(io, "\n") catch {};
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

test "network config stays closed until port 3306" {
    try std.testing.expectEqualStrings("[mariadbd]\nskip-networking\n", networkText(false));
    try std.testing.expectEqualStrings("[mariadbd]\nbind-address=0.0.0.0\nport=3306\n", networkText(true));
}

test "import lists regular sql files and refuses a symlink" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "b.sql", .data = "select 2;\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "a.sql", .data = "select 1;\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "note.txt", .data = "no" });
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const dir = std.fs.path.dirname(try tmp.dir.realPathFileAlloc(io, "a.sql", gpa)).?;
    const names = try sqlFiles(io, gpa, dir);
    try std.testing.expectEqual(@as(usize, 2), names.len);
    try std.testing.expect(std.mem.endsWith(u8, names[0], "/a.sql"));
    try std.testing.expect(std.mem.endsWith(u8, names[1], "/b.sql"));
    try tmp.dir.symLink(io, "a.sql", "c.sql", .{});
    try std.testing.expectError(error.Symlink, sqlFiles(io, gpa, dir));
}

fn lessThan(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

fn say(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const line = std.mem.print(&buf, "mariadb-init: " ++ fmt ++ "\n", args) catch return;
    Io.File.stdout().writeStreamingAll(io, line) catch {};
}
