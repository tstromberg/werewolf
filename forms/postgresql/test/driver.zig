//! Exercise the real local server through psql, under leash, without a shell.
const std = @import("std");
const driver = @import("test-driver");
const Io = std.Io;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();
    const args = try init.minimal.args.toSlice(gpa);
    // A tiny child supplies known input/output for sh-shim's descriptor tests.
    // It is this same verified driver, not an injected command interpreter.
    if (args.len == 2 and std.mem.eql(u8, args[1], "shim-child")) {
        var buf: [1]u8 = undefined;
        const n = std.os.linux.read(0, &buf, buf.len);
        if (n != 0) return error.ExpectedEof;
        try Io.File.stdout().writeStreamingAll(io, "keep\n");
        return;
    }
    if (args.len != 4) return error.Usage;
    const suite = args[1];
    const ctx = try driver.Run.load(io, gpa, args[3]);
    if (std.mem.eql(u8, args[2], "policy")) return policy(io, gpa, ctx, suite);
    var env: std.process.Environ.Map = .init(gpa);
    try env.put("LC_ALL", "C");
    try env.put("PGCONNECT_TIMEOUT", "3");
    try env.put("PGOPTIONS", "-c statement_timeout=5000");
    const client: Client = .{ .io = io, .gpa = gpa, .env = &env };
    if (std.mem.eql(u8, args[2], "denied")) {
        // The allowed driver ran first, so an absent server cannot satisfy this.
        const result = try client.run("SELECT 1");
        defer result.deinit(gpa);
        try ctx.result(io, suite, "peer-refused", !result.ok and
            std.mem.indexOf(u8, result.stderr, "Peer authentication failed") != null);
        return;
    }
    if (!std.mem.eql(u8, args[2], "sql")) return error.Usage;
    var ready = false;
    for (0..90) |_| {
        const result = try client.run("SELECT 1");
        defer result.deinit(gpa);
        if (result.ok and std.mem.eql(u8, result.text(), "1")) {
            ready = true;
            break;
        }
        try io.sleep(.fromSeconds(1), .awake);
    }
    try ctx.result(io, suite, "ready", ready);
    try client.expect(ctx, suite, "locale", "SELECT current_setting('server_encoding') || '/' " ++
        "|| datcollate || '/' || datctype FROM " ++
        "pg_database WHERE datname=current_database()", "UTF8/C/C");
    if (std.mem.eql(u8, ctx.phase, "seed")) {
        const sql = try gpa.print("CREATE TABLE native_test(value text PRIMARY KEY); INSERT " ++
            "INTO native_test VALUES ('{s}'), ('h' || chr(233) || 'llo');", .{
            ctx.run,
        });
        const result = try client.run(sql);
        defer result.deinit(gpa);
        try ctx.result(io, suite, "write", result.ok);
    }
    const query = try gpa.print(
        "SELECT count(*) FROM native_test WHERE value='{s}'",
        .{ctx.run},
    );
    try client.expect(ctx, suite, "persisted-row", query, "1");
    try client.expect(
        ctx,
        suite,
        "utf8",
        "SELECT encode(convert_to(value, 'UTF8'),'hex') FROM native_test WHERE value LIKE 'h%'",
        "68c3a96c6c6f",
    );
    try client.expect(
        ctx,
        suite,
        "rollback",
        "BEGIN; INSERT INTO native_test VALUES ('rolled-back'); ROLLBACK; SELECT count(*) FROM " ++
            "native_test WHERE value='rolled-back'",
        "0",
    );
}

fn policy(io: Io, gpa: std.mem.Allocator, ctx: driver.Run, suite: []const u8) !void {
    const linux = std.os.linux;
    var link: [256]u8 = undefined;
    const n = linux.readlink("/usr/bin/sh", &link, link.len);
    const service = try Io.Dir.cwd().readFileAlloc(
        io,
        "/etc/sv/postgres/service",
        gpa,
        .limited(8192),
    );
    const no_preload = if (Io.Dir.cwd().access(io, "/usr/lib/werewolf/popen-shim.so", .{})) |_|
        false
    else |err| switch (err) {
        error.FileNotFound => true,
        else => return err,
    };
    try ctx.result(io, suite, "shim-policy", linux.errno(n) == .SUCCESS and
        std.mem.eql(u8, link[0..n], "/usr/lib/werewolf/sh-shim") and no_preload and
        std.mem.indexOf(u8, service, "run /usr/lib/werewolf/sh-shim\n") != null and
        std.mem.indexOf(u8, service, "run /usr/bin/locale\n") != null);
    const child = "/usr/lib/werewolf/test-postgres-policy shim-child";
    for ([_][]const u8{
        child ++ " < /dev/null",
        child ++ " < /dev/null > /dev/null 2>&1",
    }, 0..) |command, i| {
        const r = try std.process.run(gpa, io, .{
            .argv = &.{ "/usr/lib/werewolf/sh-shim", "-c", command },
            .stdout_limit = .limited(1024),
            .stderr_limit = .limited(1024),
            .timeout = driver.deadline(io, 10),
        });
        try ctx.result(io, suite, if (i == 0)
            "shim-output"
        else
            "shim-discard", r.term == .exited and r.term.exited == 0 and
            std.mem.eql(u8, r.stdout, if (i == 0) "keep\n" else ""));
    }
    const refused = try std.process.run(gpa, io, .{
        .argv = &.{
            "/usr/lib/werewolf/sh-shim",
            "-c",
            child ++ " > /run/svc/test-postgres-policy/created",
        },
        .stdout_limit = .limited(1024),
        .stderr_limit = .limited(1024),
        .timeout = driver.deadline(io, 10),
    });
    const absent = if (Io.Dir.cwd().access(io, "/run/svc/test-postgres-policy/created", .{})) |_|
        false
    else |err| switch (err) {
        error.FileNotFound => true,
        else => return err,
    };
    try ctx.result(io, suite, "shim-file-refused", refused.term == .exited and
        refused.term.exited == 126 and absent and
        std.mem.indexOf(u8, refused.stderr, "refused: only trailing /dev/null redirects") != null);
    try ctx.result(io, suite, "no-tcp-listener", try driver.tcpPrivate(io, gpa, 5432, false));
}

const Result = struct {
    ok: bool,
    stdout: []u8,
    stderr: []u8,
    fn text(r: Result) []const u8 {
        return std.mem.trim(u8, r.stdout, " \r\n\t");
    }
    fn deinit(r: Result, gpa: std.mem.Allocator) void {
        gpa.free(r.stdout);
        gpa.free(r.stderr);
    }
};
const Client = struct {
    io: Io,
    gpa: std.mem.Allocator,
    env: *const std.process.Environ.Map,
    fn run(c: Client, sql: []const u8) !Result {
        const r = try std.process.run(c.gpa, c.io, .{
            .argv = &.{
                "/usr/bin/psql",
                "-X",
                "-w",
                "-A",
                "-t",
                "-q",
                "-v",
                "ON_ERROR_STOP=1",
                "-P",
                "pager=off",
                "-h",
                "/run/svc/postgres",
                "-U",
                "postgres",
                "-d",
                "postgres",
                "-c",
                sql,
            },
            .environ_map = c.env,
            .stdout_limit = .limited(8192),
            .stderr_limit = .limited(8192),
            .timeout = driver.deadline(c.io, 10),
        });
        return .{
            .ok = r.term == .exited and r.term.exited == 0,
            .stdout = r.stdout,
            .stderr = r.stderr,
        };
    }
    fn expect(
        c: Client,
        ctx: driver.Run,
        suite: []const u8,
        name: []const u8,
        sql: []const u8,
        want: []const u8,
    ) !void {
        const result = try c.run(sql);
        defer result.deinit(c.gpa);
        if (!result.ok) try Io.File.stderr().writeStreamingAll(c.io, result.stderr);
        try ctx.result(c.io, suite, name, result.ok and std.mem.eql(u8, result.text(), want));
    }
};
