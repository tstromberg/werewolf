//! check-host-keys checks test/check-form's comparison of persistent SSH
//! host keys: a kernel message interrupting a fingerprint must not change
//! it, and a key that did change must still fail. It runs check-form with
//! itself standing in for test/boot, which writes each boot's host-key
//! record to the boot's log.

const std = @import("std");
const host = @import("host");
const Io = std.Io;
const mem = std.mem;

pub fn main(init: std.process.Init) void {
    var c = host.Check.init(
        init,
        "check-host-keys",
    ) catch |err| std.process.fatal("check-host-keys: {t}", .{err});
    if (mem.eql(u8, std.fs.path.basename(c.args[0]), "boot")) c.finish(boot(&c));
    c.finish(run(&c));
}

/// boot writes the record test/boot would find for boot NAME in LOG.
fn boot(c: *host.Check) !void {
    if (c.args.len < 4) return c.fail("usage: boot NAME CHECKS LOG", .{});
    const again = mem.endsWith(u8, c.args[1], "-again");
    const changed = mem.eql(u8, c.env.get("CHANGED") orelse "", "1");
    const fingerprint = if (!again)
        "abc123"
    else if (changed) "changed" else "abc[    1.551356] audit: denied\r\n123";
    try Io.Dir.cwd().writeFile(c.io, .{ .sub_path = c.args[3], .data = try c.gpa.print(
        "{{\"event\":\"host-key\",\"key\":\"/run/svc/sshd/host-key\"," ++
            "\"fingerprint\":\"SHA256:{s}\",\"detail\":\"kept in /data\"}}\n",
        .{fingerprint},
    ) });
}

fn run(c: *host.Check) !void {
    const io = c.io;
    const gpa = c.gpa;
    const self = try std.process.executablePathAlloc(io, gpa);
    const check_form = try c.absolute("test/check-form");
    const judge = try c.absolute("build/host/cloud-console");
    for ([_]bool{ false, true }) |changed| {
        var nonce: [6]u8 = undefined;
        io.random(&nonce);
        const root = try c.absolute(try gpa.print(
            "build/check-host-keys-{s}",
            .{&std.fmt.bytesToHex(nonce, .lower)},
        ));
        defer Io.Dir.cwd().deleteTree(io, root) catch {};
        for ([_][]const u8{ "test", "form/test", "check", "build/host" }) |d|
            try Io.Dir.cwd().createDirPath(io, try gpa.print("{s}/{s}", .{ root, d }));
        try Io.Dir.cwd().copyFile(
            check_form,
            .cwd(),
            try gpa.print("{s}/test/check-form", .{root}),
            io,
            .{},
        );
        try Io.Dir.cwd().symLink(
            io,
            judge,
            try gpa.print("{s}/build/host/cloud-console", .{root}),
            .{},
        );
        try Io.Dir.cwd().symLink(io, self, try gpa.print("{s}/test/boot", .{root}), .{});
        for ([_][]const u8{ "checks", "checks-again" }) |name|
            try Io.Dir.cwd().writeFile(
                io,
                .{ .sub_path = try gpa.print("{s}/test/{s}", .{ root, name }), .data = "" },
            );
        const howl = try gpa.print("{s}/howl", .{root});
        try Io.Dir.cwd().writeFile(io, .{
            .sub_path = howl,
            .data = "#!/bin/sh\nexit 0\n",
            .flags = .{ .permissions = .fromMode(0o700) },
        });
        var env = try c.env.clone(gpa);
        for ([_][2][]const u8{
            .{ "FORM", "fixture" },                            .{ "FORM_REF", "fixture" },
            .{
                "FORM_DIR",
                try gpa.print("{s}/form", .{root}),
            },
            .{ "CHECK", try gpa.print("{s}/check", .{root}) }, .{ "HOWL", howl },
            .{ "AGAIN", "1" },                                 .{ "SSH_PORT", "" },
            .{ "CMDLINE", "" },                                .{ "KERNEL", "/unused" },
            .{
                "OUT",
                "/unused",
            },
            .{ "CHANGED", if (changed) "1" else "0" },
        }) |kv| try env.put(kv[0], kv[1]);
        const r = try host.check.command(io, gpa, &.{ "sh", "test/check-form", "unused-qemu" }, .{
            .environ_map = &env,
            .cwd = root,
            .timeout = .fromSeconds(15),
        });
        if (r.ok() == changed) return c.fail(
            "changed={}: exit {f}: {s}{s}",
            .{ changed, r.term, r.stdout, r.stderr },
        );
        if (changed and mem.find(u8, r.stdout, "host key not kept") == null)
            return c.fail(
                "a changed key failed for another reason: {s}{s}",
                .{ r.stdout, r.stderr },
            );
    }
    c.say("check-host-keys: interleaving preserves fingerprints; changed keys still fail", .{});
}
