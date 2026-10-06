//! pg-init: PostgreSQL's cluster, made once, and the image's SQL applied.
//!
//! leash runs it before the server, as the postgres user, leashed
//! (forms/postgresql/etc/sv/postgres/service). It does two things, and the
//! server starts only if both succeed:
//!
//!   1. The cluster, if /data/svc/postgres/data has none: initdb, with
//!      local connections by peer (a role is its system user's name) and
//!      none by TCP, which the server does not listen on anyway. initdb
//!      runs the server through popen(3) and system(3), which want a
//!      shell; popen-shim.so (cmd/popen-shim/popen-shim.zig), preloaded into initdb alone,
//!      runs its commands without one.
//!   2. The image's SQL: each /usr/share/werewolf-postgres/*.sql, in name order,
//!      in the postgres database, as the superuser, through the server in
//!      single-user mode, which runs while the real server is not yet up.
//!      A form brings its roles, schemas and grants this way, written so
//!      that applying them again changes nothing; the first error stops it.
//!
//! Nothing here comes from outside the image.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

const data_dir = "/data/svc/postgres/data";
const sql_dir = "/usr/share/werewolf-postgres";
const initdb = "/usr/bin/initdb";
const postgres = "/usr/bin/postgres";
const preload = "/usr/lib/werewolf/popen-shim.so";

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();

    if (Dir.cwd().access(io, data_dir ++ "/PG_VERSION", .{})) |_| {} else |_| {
        say(io, "making the cluster in {s}", .{data_dir});
        var env: std.process.Environ.Map = .init(gpa);
        try env.put("PATH", "/usr/bin");
        try env.put("LD_PRELOAD", preload);
        try run(
            io,
            .{
                .argv = &.{
                    initdb,
                    "-D",
                    data_dir,
                    "-U",
                    "postgres",
                    "-E",
                    "UTF8",
                    "--no-locale",
                    "--auth-local=peer",
                    "--auth-host=reject",
                    "--no-instructions",
                },
                .environ_map = &env,
                .stdin = .ignore,
                .stdout = .ignore,
            },
        );
    }

    var names: std.ArrayList([]const u8) = .empty;
    if (Dir.cwd().openDir(io, sql_dir, .{ .iterate = true })) |d| {
        var dir = d;
        defer dir.close(io);
        var it = dir.iterate();
        while (try it.next(io)) |e| {
            if (e.kind == .file and
                std.mem.endsWith(
                    u8,
                    e.name,
                    ".sql",
                )) try names.append(gpa, try gpa.dupe(u8, e.name));
        }
    } else |_| {}
    std.mem.sort([]const u8, names.items, {}, lessThan);
    if (names.items.len == 0) return;

    // -j: a statement ends at a semicolon before an empty line, so a DO
    // block may hold semicolons of its own.
    var sql: std.ArrayList(u8) = .empty;
    for (names.items) |name| {
        const text = try Dir.cwd().readFileAlloc(
            io,
            try gpa.print("{s}/{s}", .{ sql_dir, name }),
            gpa,
            .limited(1 << 20),
        );
        try sql.appendSlice(gpa, text);
        try sql.appendSlice(gpa, "\n\n");
    }
    var child = try std.process.spawn(io, .{
        .argv = &.{
            postgres,
            "--single",
            "-D",
            data_dir,
            "-j",
            "-c",
            "exit_on_error=true",
            "-c",
            "log_checkpoints=false",
            "postgres",
        },
        .stdin = .pipe,
        .stdout = .ignore,
    });
    child.stdin.?.writeStreamingAll(io, sql.items) catch {};
    child.stdin.?.close(io);
    child.stdin = null;
    const term = try child.wait(io);
    if (term != .exited or term.exited != 0) {
        say(io, "the SQL in {s} failed; see above", .{sql_dir});
        return error.SqlFailed;
    }
    say(
        io,
        "applied {d} SQL file{s} from {s}",
        .{ names.items.len, if (names.items.len == 1) "" else "s", sql_dir },
    );
}

fn run(io: Io, options: std.process.SpawnOptions) !void {
    var child = try std.process.spawn(io, options);
    const term = try child.wait(io);
    if (term != .exited or term.exited != 0) {
        say(io, "{s} failed; see above", .{options.argv[0]});
        return error.CommandFailed;
    }
}

fn lessThan(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

fn say(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const line = std.mem.print(&buf, "pg-init: " ++ fmt ++ "\n", args) catch return;
    Io.File.stdout().writeStreamingAll(io, line) catch {};
}
