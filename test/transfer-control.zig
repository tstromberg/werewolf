//! Private VM fixture only. Replaces posture's run link, starts the real
//! posture check, seeds public fixtures and verifies restored PostgreSQL data.
//! No uploaded program or command text is executed.
const std = @import("std");
const linux = std.os.linux;
const Io = std.Io;
const Dir = Io.Dir;

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len == 2 and std.mem.eql(u8, args[1], "park")) {
        while (true) try init.io.sleep(.fromSeconds(3600), .awake);
    }
    if (args.len == 2 and std.mem.eql(u8, args[1], "prepare-postgres")) {
        const role = try Dir.cwd().readFileAlloc(init.io, "/run/svc/postgres/transfer-role", init.arena.allocator(), .limited(32));
        if (std.mem.eql(u8, std.mem.trim(u8, role, "\r\n"), "empty")) {
            if (Dir.cwd().access(init.io, "/data/svc/postgres/data/PG_VERSION", .{})) |_| {} else |err| {
                if (err == error.FileNotFound) return;
                return err;
            }
        }
        return std.process.replace(init.io, .{ .argv = &.{"/usr/lib/werewolf/pg-init"} });
    }
    const pid = linux.fork();
    if (linux.errno(pid) != .SUCCESS) return error.Fork;
    if (pid != 0) {
        const argv = [_:null]?[*:0]const u8{"run"};
        const env = [_:null]?[*:0]const u8{};
        _ = linux.execve("/usr/lib/werewolf/posture", &argv, &env);
        linux.exit_group(127);
    }
    _ = linux.close_range(3, std.math.maxInt(linux.fd_t), .{ .UNSHARE = false, .CLOEXEC = false });
    _ = linux.setsid();
    control(init.io, init.arena.allocator()) catch |err| {
        say(init.io, @errorName(err));
        linux.exit_group(1);
    };
}

fn control(io: Io, a: std.mem.Allocator) !void {
    const id = try postgresId(io, a);
    const role = try Dir.cwd().readFileAlloc(io, "/run/config/transfer-role", a, .limited(32));
    const empty = std.mem.eql(u8, std.mem.trim(u8, role, "\r\n"), "empty") and
        (if (Dir.cwd().access(io, "/data/svc/postgres/data/PG_VERSION", .{})) |_| false else |_| true);
    if (!empty) try ready(io, a, id);
    if (std.mem.eql(u8, std.mem.trim(u8, role, "\r\n"), "source") and
        (if (sql(io, a, id, "SELECT value FROM transfer_rows WHERE id=7", "acknowledged")) |_| false else |_| true))
    {
        try sql(io, a, id, "CREATE DATABASE transfer_a", null);
        try sql(io, a, id, "CREATE ROLE transfer_role; " ++
            "CREATE TABLE transfer_rows(id integer PRIMARY KEY, value text); " ++
            "INSERT INTO transfer_rows VALUES(7,'acknowledged'); " ++
            "GRANT SELECT ON transfer_rows TO transfer_role; " ++
            "CREATE SEQUENCE transfer_seq START 83; " ++
            "CREATE EXTENSION pgcrypto; " ++
            "SELECT lo_from_bytea(195001,decode('001122aaff','hex'));", null);
        try sqlAt(io, a, id, "transfer_a", "CREATE TABLE other_rows(value text); INSERT INTO other_rows VALUES('second database');", null);
    }
    if (!empty) {
        try verify(io, a, id);
        say(io, "database verified");
    }
    say(io, "ready");
    for (0..60) |_| {
        if (Dir.cwd().access(io, "/run/svc/sshd/host-key.pub", .{})) |_| break else |_| {}
        try io.sleep(.fromSeconds(1), .awake);
    }
    const pubkey = try Dir.cwd().readFileAlloc(io, "/run/svc/sshd/host-key.pub", a, .limited(4096));
    try Io.File.stdout().writeStreamingAll(io, try a.print("transfer-host-key: {s}", .{pubkey}));
    if (Dir.cwd().access(io, "/usr/share/werewolf/transfer-stop-fixture", .{})) |_| {
        var armed = false;
        while (true) {
            if (Dir.cwd().openFile(io, "/run/runit/supervise.transfer-stop/status", .{})) |file| {
                defer file.close(io);
                var status: [20]u8 = undefined;
                if (try file.readPositionalAll(io, &status, 0) != status.len) return error.Supervision;
                if (status[17] == 'd') armed = true;
                if (armed and status[17] == 'u') {
                    // Firecracker exits on a clean reboot; its supervisor's
                    // private host marker keeps this disposable fixture off.
                    try Dir.cwd().setFilePermissions(io, "/run/runit/reboot", .fromMode(0o100), .{});
                    try Dir.cwd().setFilePermissions(io, "/run/runit/stopit", .fromMode(0o100), .{});
                    if (linux.errno(linux.kill(1, linux.SIG.CONT)) != .SUCCESS) return error.Poweroff;
                    return;
                }
            } else |err| if (err != error.FileNotFound) return err;
            try io.sleep(.fromMilliseconds(100), .awake);
        }
    } else |err| if (err != error.FileNotFound) return err;
}

fn postgresId(io: Io, a: std.mem.Allocator) !u32 {
    const text = try Dir.cwd().readFileAlloc(io, "/etc/passwd", a, .limited(1 << 20));
    var lines = std.mem.tokenizeScalar(u8, text, '\n');
    while (lines.next()) |line| if (std.mem.startsWith(u8, line, "postgres:")) {
        var fields = std.mem.splitScalar(u8, line, ':');
        _ = fields.next();
        _ = fields.next();
        return std.fmt.parseUnsigned(u32, fields.next().?, 10);
    };
    return error.NoPostgres;
}

fn sql(io: Io, a: std.mem.Allocator, id: u32, query: []const u8, expected: ?[]const u8) !void {
    return sqlAt(io, a, id, "postgres", query, expected);
}

fn sqlAt(io: Io, a: std.mem.Allocator, id: u32, database: []const u8, query: []const u8, expected: ?[]const u8) !void {
    var child = try std.process.spawn(io, .{
        .argv = &.{ "/usr/bin/psql", "-XAt", "-v", "ON_ERROR_STOP=1", "-h", "/run/svc/postgres", "-U", "postgres", "-d", database, "-c", query },
        .uid = id,
        .gid = id,
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .ignore,
    });
    defer child.kill(io);
    const pipe = child.stdout.?;
    child.stdout = null;
    defer pipe.close(io);
    var buffer: [4096]u8 = undefined;
    var output = pipe.readerStreaming(io, &buffer);
    const text = try output.interface.allocRemaining(a, .limited(64 << 10));
    defer a.free(text);
    if (!(try child.wait(io)).success()) return error.Sql;
    if (expected) |want| if (!std.mem.eql(u8, std.mem.trim(u8, text, "\r\n"), want)) return error.Rows;
}

fn ready(io: Io, a: std.mem.Allocator, id: u32) !void {
    for (0..180) |_| {
        if (sql(io, a, id, "SELECT 1", "1")) |_| return else |_| {}
        try io.sleep(.fromSeconds(1), .awake);
    }
    return error.DatabaseTimeout;
}

fn verify(io: Io, a: std.mem.Allocator, id: u32) !void {
    try sql(io, a, id, "SELECT value FROM transfer_rows WHERE id=7", "acknowledged");
    try sql(io, a, id, "SELECT last_value FROM transfer_seq", "83");
    try sql(io, a, id, "SELECT encode(lo_get(195001),'hex')", "001122aaff");
    try sql(io, a, id, "SELECT count(*) FROM pg_roles WHERE rolname='transfer_role'", "1");
    try sql(io, a, id, "SELECT has_table_privilege('transfer_role','transfer_rows','SELECT')", "t");
    try sql(io, a, id, "SELECT count(*) FROM pg_database WHERE datname='transfer_a'", "1");
    try sql(io, a, id, "SELECT count(*) FROM pg_extension WHERE extname='pgcrypto'", "1");
    try sqlAt(io, a, id, "transfer_a", "SELECT value FROM other_rows", "second database");
}

fn say(io: Io, message: []const u8) void {
    var buf: [256]u8 = undefined;
    const line = std.mem.print(&buf, "transfer-fixture: {s}\n", .{message}) catch return;
    Io.File.stdout().writeStreamingAll(io, line) catch {};
}
