//! neo4j-setup sets Neo4j's initial password from the config, once, before
//! Neo4j serves. A later boot leaves the password as it was: Neo4j accepts
//! an initial password only before the first start.
//!
//!     neo4j-setup
//!
//! leash runs it as the neo4j user (forms/bloodhound/form.yaml). See
//! forms/bloodhound/README.md.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

const password_path = "/run/svc/neo4j/neo4j-password";
const marker = "/data/svc/neo4j/initial-password-set";
const java = "/usr/bin/java";
const jna = switch (builtin.cpu.arch) {
    .aarch64 => "/usr/lib/jna/aarch64",
    .x86_64 => "/usr/lib/jna/x86_64",
    else => @compileError("no JNA library for this arch"),
};
// Java's seed file is /dev/urandom. The floor allows /dev/random too.
const tool_options = "-Djna.nosys=true -Djna.boot.library.path=" ++ jna ++
    " -Djava.security.egd=file:/dev/urandom";

const dirs = [_][]const u8{
    "/data/svc/neo4j/data",
    "/data/svc/neo4j/logs",
    "/data/svc/neo4j/transactions",
    "/data/svc/neo4j/import",
};

pub fn main(init: std.process.Init) void {
    const io = init.io;
    run(init) catch |err| {
        say(io, "{{\"event\":\"failed\",\"why\":\"{s}\"}}", .{@errorName(err)});
        std.process.exit(1);
    };
}

fn run(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();
    // Neo4j starts another JVM for the password command and drops flags
    // it does not know. The child still reads JAVA_TOOL_OPTIONS.
    try init.environ_map.put("JAVA_TOOL_OPTIONS", tool_options);
    for (dirs) |d| Dir.cwd().createDirPath(io, d) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    if (Dir.cwd().access(io, marker, .{})) |_| {
        say(io, "{{\"event\":\"password kept\"}}", .{});
        return;
    } else |_| {}

    const text = Dir.cwd().readFileAlloc(io, password_path, gpa, .limited(4 << 10)) catch |err|
        switch (err) {
            error.FileNotFound => return error.NoNeo4jPassword,
            else => return err,
        };
    const password = std.mem.trimEnd(u8, text, "\r\n");
    if (!acceptable(password)) return error.Neo4jPasswordRefused;

    var child = try std.process.spawn(io, .{
        .argv = &.{
            java,                                      "-Dapp.name=neo4j-admin",
            "-Dapp.home=/var/lib/neo4j",               "-Dbasedir=/var/lib/neo4j",
            "-Djava.io.tmpdir=/run/svc/neo4j",         "-Djava.security.egd=file:/dev/urandom",
            "-Djna.nosys=true",                        "-Djna.boot.library.path=" ++ jna,
            "-classpath",                              "/var/lib/neo4j/lib/*",
            "org.neo4j.server.startup.Neo4jAdminBoot", "set-initial-password",
            "--require-password-change=false",         password,
        },
        .environ_map = init.environ_map,
        .stdin = .ignore,
    });
    const term = try child.wait(io);
    if (term != .exited or term.exited != 0) return error.PasswordNotSet;

    var f = try Dir.cwd().createFile(io, marker, .{ .permissions = .fromMode(0o600) });
    defer f.close(io);
    try f.writeStreamingAll(io, "Neo4j's initial password is the config's.\n");
    try f.sync(io);
    say(io, "{{\"event\":\"password set\"}}", .{});
}

fn acceptable(s: []const u8) bool {
    if (s.len < 12 or s.len > 128 or s[0] == '-') return false;
    for (s) |c| if (c < 0x20 or c == 0x7f) return false;
    return true;
}

fn say(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [256]u8 = undefined;
    const line = std.mem.print(&buf, "neo4j-setup: " ++ fmt ++ "\n", args) catch return;
    Io.File.stdout().writeStreamingAll(io, line) catch {};
}

const testing = std.testing;

test "a neo4j password is long and not a flag" {
    try testing.expect(acceptable("werewolf-check-pass-1"));
    try testing.expect(!acceptable("short"));
    try testing.expect(!acceptable("-werewolf-check-pass"));
}
