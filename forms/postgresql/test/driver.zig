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
    return error.Usage;
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
