//! ssh-su PORT PREFIX PROVIDER MODE attacks the su form in a booted,
//! disposable test machine (a host suite's program step runs it for
//! ssh-su, prod-ssh and playground): root through a forwarded security-key agent, and every way
//! that must be refused. PREFIX names the check's keys, PROVIDER the
//! software security key; MODE playground allows its local software keys.

const std = @import("std");
const host = @import("host");
const Io = std.Io;
const mem = std.mem;

const name = "ssh-su";
const result = "su-result:0:unset";
const denied = "Permission denied (publickey)";

pub fn main(init: std.process.Init) void {
    var c = host.Check.init(init, name) catch |err| std.process.fatal("{s}: {t}", .{ name, err });
    c.finish(run(&c));
}

/// Output is whether a command succeeded and what it said on either stream.
const Output = struct { ok: bool, text: []const u8 };

const Su = struct {
    c: *host.Check,
    ssh: []const []const u8,
    prefix: []const u8,
    agent_env: std.process.Environ.Map,

    /// output runs argv for at most 40 seconds.
    fn output(
        su: *Su,
        argv: []const []const u8,
        env: ?*const std.process.Environ.Map,
        input: ?[]const u8,
    ) !Output {
        const r = try host.check.command(su.c.io, su.c.gpa, argv, .{
            .environ_map = env orelse &su.c.env,
            .input = input,
            .timeout = .fromSeconds(40),
        });
        return .{ .ok = r.ok(), .text = try mem.concat(su.c.gpa, u8, &.{ r.stdout, r.stderr }) };
    }

    fn expect(su: *Su, label: []const u8, got: Output, success: bool, message: []const u8) !void {
        if (got.ok != success or mem.find(u8, got.text, message) == null)
            return su.c.fail(
                "{s}: {s}: {s}",
                .{ label, if (got.ok) "exit 0" else "failed", got.text },
            );
        su.c.say("pass   {s}", .{label});
    }

    fn admin(su: *Su, command: []const u8) ![]const u8 {
        return su.remote("root", command);
    }

    fn remote(su: *Su, user: []const u8, command: []const u8) ![]const u8 {
        const got = try su.output(
            try su.with(&.{ try su.c.gpa.print("{s}@127.0.0.1", .{user}), command }),
            null,
            null,
        );
        if (!got.ok) return su.c.fail("{s}", .{got.text});
        return got.text;
    }

    fn with(su: *Su, rest: []const []const u8) ![]const []const u8 {
        return mem.concat(su.c.gpa, []const u8, &.{ su.ssh, rest });
    }

    /// identity leaves only PREFIX-suffix in the test agent.
    fn identity(su: *Su, suffix: []const u8, constraints: []const []const u8) !void {
        const key = try mem.concat(su.c.gpa, u8, &.{ su.prefix, suffix });
        for ([_][]const []const u8{
            &.{ "ssh-add", "-D" },
            try mem.concat(su.c.gpa, []const u8, &.{ &.{"ssh-add"}, constraints, &.{key} }),
        }) |argv| {
            const got = try su.output(argv, &su.agent_env, null);
            if (!got.ok) return su.c.fail("{s}", .{got.text});
        }
    }

    const Elevate = struct {
        command: []const u8 = "su",
        forward: bool = true,
        tty: bool = true,
        user: []const u8 = "operator",
    };

    /// elevate runs su as user and reports the uid and agent it got. The
    /// outer login uses its own key, independent of the forwarded agent's.
    fn elevate(su: *Su, e: Elevate) !Output {
        var argv: std.ArrayList([]const u8) = .empty;
        try argv.appendSlice(su.c.gpa, su.ssh);
        try argv.append(su.c.gpa, if (e.forward) "-A" else "-a");
        if (e.tty) try argv.append(su.c.gpa, "-tt");
        try argv.appendSlice(
            su.c.gpa,
            &.{ try su.c.gpa.print("{s}@127.0.0.1", .{e.user}), e.command },
        );
        return su.output(
            argv.items,
            &su.agent_env,
            "printf '\\nsu-result:%s:%s\\n' \"$(id -u)\" \"${SSH_AUTH_SOCK-unset}\"; exit\n",
        );
    }
};

fn run(c: *host.Check) !void {
    const wrong_host = c.args.len == 6 and mem.eql(u8, c.args[5], "--wrong-host");
    if (c.args.len != 5 and
        !wrong_host) return c.fail("usage: ssh-su PORT PREFIX PROVIDER MODE [--wrong-host]", .{});
    const port = c.args[1];
    const prefix = try c.absolute(c.args[2]);
    const provider = try c.absolute(c.args[3]);
    const software = mem.eql(u8, c.args[4], "playground");
    const gpa = c.gpa;
    const io = c.io;
    const options = [_][]const u8{
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=10",
        "-o", "LogLevel=ERROR",
        "-o", "IdentitiesOnly=yes",
        "-o", try gpa.print("SecurityKeyProvider={s}", .{provider}),
        "-i", try gpa.print("{s}-sk-key", .{prefix}),
    };
    var su: Su = .{
        .c = c,
        .prefix = prefix,
        .agent_env = try c.env.clone(gpa),
        .ssh = try mem.concat(gpa, []const u8, &.{
            &.{ "ssh", "-F", "/dev/null", "-S", "none", "-p", port },
            &options,
        }),
    };
    var nonce: [6]u8 = undefined;
    io.random(&nonce);
    const tmp = try gpa.print("/tmp/su-agent-{s}", .{&std.fmt.bytesToHex(nonce, .lower)});
    try Io.Dir.cwd().createDir(io, tmp, .fromMode(0o700));
    defer Io.Dir.cwd().deleteTree(io, tmp) catch {};
    const socket = try gpa.print("{s}/agent", .{tmp});
    try su.agent_env.put("SSH_AUTH_SOCK", socket);
    var agent = try std.process.spawn(io, .{
        .argv = &.{ "ssh-agent", "-D", "-a", socket, "-P", provider },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    defer {
        if (agent.id) |pid| std.posix.kill(pid, .TERM) catch {};
        _ = agent.wait(io) catch {};
    }
    for (0..100) |_| {
        if (Io.Dir.cwd().access(io, socket, .{})) break else |_| {}
        try io.sleep(.fromMilliseconds(50), .awake);
    } else return c.fail("test ssh-agent did not start", .{});

    try su.identity("-sk-key", &.{});
    if (wrong_host) {
        try su.expect(
            "su-rejects-wrong-host",
            try su.elevate(.{}),
            false,
            "Host key verification failed",
        );
        return;
    }
    try su.expect("su-root-login", try su.elevate(.{}), true, result);
    try su.expect(
        "su-rejects-non-admin",
        try su.elevate(.{ .user = "guest" }),
        false,
        "administrator membership required",
    );
    try su.expect("direct-ssh-rejects-non-admin", try su.elevate(.{
        .user = "guest",
        .command = "ssh -F /etc/ssh/su_config root@127.0.0.1 true",
    }), false, "Permission denied");
    try su.expect(
        "su-agent-required",
        try su.elevate(.{ .forward = false }),
        false,
        "su: agent forwarding required; reconnect with ssh -A",
    );
    try su.expect(
        "su-terminal-required",
        try su.elevate(.{ .tty = false }),
        false,
        "su: unauthenticated session",
    );
    try su.expect(
        "su-busybox-unprivileged",
        try su.elevate(.{ .command = "busybox su -c 'id -u' root" }),
        false,
        "",
    );

    // User configuration cannot replace the pin or run a local command.
    _ = try su.remote("operator", "mkdir -p ~/.ssh; " ++
        "printf 'Host *\\n ProxyCommand /bin/false\\n' > ~/.ssh/config");
    try su.expect("su-ignores-user-config", try su.elevate(.{}), true, result);

    try su.expect(
        "su-host-pin-read-only",
        try su.output(
            try su.with(&.{ "root@127.0.0.1", ": >> /run/werewolf/ssh_known_hosts" }),
            null,
            null,
        ),
        false,
        "Permission denied",
    );

    // These keys are authorized for root, but their signatures lack a
    // required property. Each attempt uses a new SSH authentication.
    for ([_][2][]const u8{
        .{ "-no-verify", "su-requires-verification" },
        .{ "-no-touch", "su-requires-presence" },
        .{ "-key", "su-rejects-software-key" },
        .{ "-stranger", "su-rejects-unlisted-key" },
    }) |case| {
        try su.identity(case[0], &.{});
        const allowed = software and (mem.eql(u8, case[0], "-no-verify") or
            mem.eql(u8, case[0], "-key"));
        const label = if (!allowed)
            case[1]
        else if (mem.eql(
            u8,
            case[0],
            "-key",
        )) "su-local-software-key" else "su-local-no-verification";
        try su.expect(label, try su.elevate(.{}), allowed, if (allowed) result else denied);
    }
    try su.identity("-sk-key", &.{});
    try su.expect("su-fresh-authentication", try su.elevate(.{}), true, result);

    // Four auth failures exceed the default source-penalty threshold.
    // Keep them sequential so MaxStartups does not drop an authentication.
    // Another user must still be able to elevate immediately.
    try su.identity("-stranger", &.{});
    const burst = try su.output(try su.with(&.{
        "-A",
        "operator@127.0.0.1",
        "for n in 1 2 3 4; do ssh -F /etc/ssh/su_config -S none root@127.0.0.1 true; done",
    }), &su.agent_env, null);
    if (mem.count(
        u8,
        burst.text,
        denied,
    ) != 4) return c.fail("su-penalty-burst: {s}", .{burst.text});
    try su.identity("-sk-key", &.{});
    try su.expect(
        "su-other-user-after-failures",
        try su.elevate(.{ .user = "second" }),
        true,
        result,
    );

    // The documented same-host hop must work with destination constraints.
    const keys = try su.admin("cat /run/svc/sshd/host-key.pub");
    var lines = mem.splitScalar(u8, keys, '\n');
    const public = while (lines.next()) |line| {
        if (mem.startsWith(u8, line, "ssh-ed25519 ")) break line;
    } else return c.fail("missing host public key: {s}", .{keys});
    const known_hosts = try gpa.print("{s}/known_hosts", .{tmp});
    try Io.Dir.cwd().writeFile(
        io,
        .{ .sub_path = known_hosts, .data = try gpa.print("server {s}\n", .{public}) },
    );
    try su.identity(
        "-sk-key",
        &.{ "-t", "20h", "-H", known_hosts, "-h", "operator@server", "-h", "server>root@server" },
    );
    try su.expect("su-constrained-agent", try su.elevate(.{}), true, result);
}
