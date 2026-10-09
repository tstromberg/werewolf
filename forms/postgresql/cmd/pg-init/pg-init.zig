//! pg-init makes the PostgreSQL cluster once and applies the image's SQL
//! before each start of the server. See README.md.

const std = @import("std");
const linux = std.os.linux;
const Io = std.Io;
const Dir = Io.Dir;

const svc_dir = "/data/svc/postgres";
const data_dir = svc_dir ++ "/data";
const sql_dir = "/usr/share/werewolf-postgres";
const initdb = "/usr/bin/initdb";
const postgres = "/usr/bin/postgres";
const preload = "/usr/lib/werewolf/popen-shim.so";
/// made marks that a cluster was made. If the cluster is gone but the mark
/// is not, the data was lost, and pg-init refuses to make an empty one.
const made = "cluster-made";
/// started marks the first start of this boot. /run is empty at boot, so a
/// lock found before this file exists was left by an earlier boot.
const started = "/run/svc/postgres/pg-init-started";

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();
    var svc = try Dir.cwd().openDir(io, svc_dir, .{});
    defer svc.close(io);

    const first_start = blk: {
        if (Dir.cwd().access(io, started, .{})) |_| break :blk false else |_| {}
        Dir.cwd().writeFile(io, .{ .sub_path = started, .data = "" }) catch |err| {
            say(io, "{s}: {s}", .{ started, @errorName(err) });
            break :blk false;
        };
        break :blk true;
    };

    if (svc.access(io, "data/PG_VERSION", .{})) |_| {
        say(io, "keeping the cluster in {s}", .{data_dir});
        // data exists only once initdb finished, so the cluster is whole.
        // Mark it if a crash came before the mark.
        if (svc.access(io, made, .{})) |_| {} else |_| try mark(io, svc, made);
        // A power cut leaves the last boot's lock, whose pid this boot may
        // have given to another process; the server would think itself
        // still running. On the first start of a boot the lock is stale, so
        // remove it. Later, it may be a server still stopping, which the
        // server checks itself.
        if (first_start) {
            if (svc.deleteFile(io, "data/postmaster.pid")) |_| {
                say(io, "removed the lock the last boot left", .{});
            } else |err| switch (err) {
                error.FileNotFound => {},
                else => say(io, "{s}/postmaster.pid: {s}", .{ data_dir, @errorName(err) }),
            }
        }
    } else |_| {
        if (svc.access(io, made, .{})) |_| {
            say(
                io,
                "the cluster in {s} is gone, though one was made here; not making an empty one " ++
                    "over its loss",
                .{data_dir},
            );
            return error.ClusterLost;
        } else |_| {}
        // initdb writes PG_VERSION first, so an interrupted run would look
        // like a cluster. Build it in data.new and rename it when whole.
        if (svc.access(io, "data.new", .{})) |_| {
            say(io, "removing the cluster a stopped start left half made", .{});
            try svc.deleteTree(io, "data.new");
        } else |_| {}
        say(io, "making the cluster in {s}", .{data_dir});
        var env: std.process.Environ.Map = .init(gpa);
        try env.put("PATH", "/usr/bin");
        try env.put("LD_PRELOAD", preload);
        var child = try std.process.spawn(io, .{
            .argv = &.{
                initdb,
                "-D",
                svc_dir ++ "/data.new",
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
        });
        const term = try child.wait(io);
        if (term != .exited or term.exited != 0) {
            say(io, "{s} failed; see above", .{initdb});
            return error.InitdbFailed;
        }
        svc.rename("data.new", svc, "data", io) catch |err| {
            say(io, "{s} holds something, but no cluster: {s}", .{ data_dir, @errorName(err) });
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

    // With -j a statement ends at a semicolon before an empty line, so a
    // DO block may contain semicolons.
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
    const line = std.mem.print(&buf, "pg-init: " ++ fmt ++ "\n", args) catch return;
    Io.File.stdout().writeStreamingAll(io, line) catch {};
}
