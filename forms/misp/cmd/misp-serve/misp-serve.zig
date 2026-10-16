//! misp-serve starts PHP and MISP's workers. The list is this program's.
//! There is no control socket and no config a request can rewrite, so
//! the web process cannot ask it to start another program. If one
//! exits, the rest are stopped and runit starts the service again.

const std = @import("std");
const Io = std.Io;
const linux = std.os.linux;

const php = "/usr/bin/php8.4";
const cake = "/var/www/MISP/app/Console/cake.php";
const webroot = "/var/www/MISP/app/webroot";
const router = "/usr/lib/werewolf/misp-router.php";
const dir = "/var/www/MISP";
const listen = "127.0.0.1:8080";
const worker = [_][]const u8{ php, "-q", cake, "-working", "/var/www/MISP/app" };

const jobs = [_][]const []const u8{
    &.{ php, "-S", listen, "-t", webroot, router },
    &(worker ++ .{ "start_worker", "default" }),
    &(worker ++ .{ "start_worker", "prio" }),
    &(worker ++ .{ "start_worker", "email" }),
    &(worker ++ .{ "start_worker", "cache" }),
    &(worker ++ .{ "start_worker", "update" }),
    &(worker ++ .{"scheduler_worker"}),
};

var stopping: std.atomic.Value(bool) = .init(false);

pub fn main(init: std.process.Init) void {
    run(init.io, init.minimal.environ) catch |err| {
        say(init.io, "{s}", .{@errorName(err)});
        std.process.exit(1);
    };
}

fn run(io: Io, environ: std.process.Environ) !void {
    // Inspect our own inherited environment. A separate sandbox cannot
    // read it through procfs, even under this service's UID.
    if (!passwordsPrivate(environ)) return error.PasswordInEnvironment;
    const act: linux.Sigaction = .{
        .handler = .{ .handler = onTerm },
        .mask = linux.sigemptyset(),
        .flags = 0,
    };
    _ = linux.sigaction(.TERM, &act, null);
    var pids: [jobs.len]i32 = @splat(0);
    for (jobs, 0..) |argv, i| {
        pids[i] = spawn(argv, environ) catch |err| {
            stopAll(&pids);
            return err;
        };
    }
    const local = std.mem.eql(u8, environ.getPosix("MYSQL_PASSWORD") orelse "", "misp") and
        std.mem.eql(u8, environ.getPosix("ENABLE_REDIS_EMPTY_PASSWORD") orelse "", "true");
    say(
        io,
        "{{\"event\":\"start\",\"listen\":\"{s}\",\"local-credentials\":{},\"passwords-private\"" ++
            ":true}}",
        .{ listen, local },
    );
    var status: i32 = 0;
    const gone = while (!stopping.load(.acquire)) {
        const pid = linux.waitpid(-1, &status, 0);
        if (linux.errno(pid) == .INTR) continue;
        if (linux.errno(pid) != .SUCCESS) return error.Wait;
        break pid;
    } else 0;
    stopAll(&pids);
    if (stopping.load(.acquire)) {
        say(io, "{{\"event\":\"down\",\"why\":\"terminated\"}}", .{});
        std.process.exit(0);
    }
    const s: u32 = @bitCast(status);
    const code: u8 = if (linux.W.IFEXITED(s)) linux.W.EXITSTATUS(s) else 1;
    say(io, "{{\"event\":\"down\",\"pid\":{d},\"code\":{d}}}", .{ gone, code });
    std.process.exit(code);
}

fn passwordsPrivate(environ: std.process.Environ) bool {
    for ([_][]const u8{ "ADMIN_PASSWORD", "GPG_PASSPHRASE", "SUPERVISOR_PASSWORD" }) |key| {
        if (environ.getPosix(key) != null) return false;
    }
    return true;
}

fn spawn(argv: []const []const u8, environ: std.process.Environ) !i32 {
    var storage: [8][160:0]u8 = undefined;
    var ptrs: [9:null]?[*:0]const u8 = @splat(null);
    if (argv.len == 0 or argv.len >= ptrs.len) return error.Arg;
    for (argv, 0..) |arg, i| {
        if (arg.len == 0 or arg.len >= storage[i].len) return error.Arg;
        @memcpy(storage[i][0..arg.len], arg);
        storage[i][arg.len] = 0;
        ptrs[i] = &storage[i];
    }
    const pid = linux.fork();
    if (linux.errno(pid) != .SUCCESS) return error.Fork;
    if (pid == 0) {
        if (linux.errno(linux.chdir(dir)) != .SUCCESS) linux.exit_group(127);
        const argvz: [*:null]const ?[*:0]const u8 = &ptrs;
        const raw = environ.block.view().slice;
        if (raw.len >= 256) linux.exit_group(127);
        var env: [256:null]?[*:0]const u8 = @splat(null);
        for (raw, 0..) |e, i| env[i] = e;
        _ = linux.execve(ptrs[0].?, argvz, &env);
        linux.exit_group(127);
    }
    return @intCast(pid);
}

fn stopAll(pids: []const i32) void {
    for (pids) |pid| if (pid > 0) {
        _ = linux.kill(pid, linux.SIG.TERM);
    };
}

fn onTerm(_: linux.SIG) callconv(.c) void {
    stopping.store(true, .release);
}

fn say(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [256]u8 = undefined;
    const line = std.mem.print(&buf, "misp-serve: " ++ fmt ++ "\n", args) catch return;
    Io.File.stdout().writeStreamingAll(io, line) catch {};
}

test "php listens on loopback and the list has no python or shell" {
    try std.testing.expectEqualStrings(listen, jobs[0][2]);
    try std.testing.expectEqualStrings(php, jobs[0][0]);
    for (jobs) |argv| {
        try std.testing.expect(std.mem.indexOf(u8, argv[0], "python") == null);
        try std.testing.expect(!std.mem.eql(u8, argv[0], "/bin/sh"));
        try std.testing.expect(!std.mem.eql(u8, argv[0], "/usr/bin/bash"));
    }
    try std.testing.expectEqualStrings("scheduler_worker", jobs[6][worker.len]);
}

test "the launcher refuses password variables before spawning PHP" {
    try std.testing.expect(passwordsPrivate(.empty));
    for ([_][*:0]const u8{
        "ADMIN_PASSWORD=private",
        "GPG_PASSPHRASE=passphrase",
        "SUPERVISOR_PASSWORD=supervisor",
    }) |entry| {
        const block: [:null]const ?[*:0]const u8 = &.{entry};
        try std.testing.expect(!passwordsPrivate(.{ .block = .{ .slice = block } }));
    }
}
