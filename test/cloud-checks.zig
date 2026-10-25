//! cloud-checks checks test/cloud's pass and fail decisions without a
//! cloud: it runs test/cloud against itself standing in for howl, aws,
//! gcloud, az, ssh, ssh-keygen and sleep, which answer as a good machine
//! would, or as one missing what CLOUD_TEST_BAD names. Both modes and both
//! users must pass; each missing protection, provider flag or wrong
//! identity must fail.

const std = @import("std");
const host = @import("host");
const form = @import("form");
const Io = std.Io;
const mem = std.mem;
const Environ = std.process.Environ;

const tools = [_][]const u8{ "howl", "aws", "gcloud", "az", "ssh", "ssh-keygen", "sleep" };

pub fn main(init: std.process.Init) void {
    var c = host.Check.init(
        init,
        "cloud-checks",
    ) catch |err| std.process.fatal("cloud-checks: {t}", .{err});
    const tool = std.fs.path.basename(c.args[0]);
    for (tools) |t| if (mem.eql(u8, tool, t)) {
        const code = stand(&c, tool) catch |err| {
            std.log.err("{s} stand-in: {t}", .{ tool, err });
            std.process.exit(1);
        };
        std.process.exit(code);
    };
    c.finish(run(&c));
}

fn run(c: *host.Check) !void {
    const io = c.io;
    const gpa = c.gpa;
    const runner = try c.absolute("test/cloud");
    const self = try std.process.executablePathAlloc(io, gpa);
    var nonce: [6]u8 = undefined;
    io.random(&nonce);
    const root = try c.absolute(try gpa.print(
        "build/cloud-checks-{s}",
        .{&std.fmt.bytesToHex(nonce, .lower)},
    ));
    try Io.Dir.cwd().createDirPath(io, try gpa.print("{s}/bin", .{root}));
    defer Io.Dir.cwd().deleteTree(io, root) catch {};
    try Io.Dir.cwd().createDirPath(io, try gpa.print("{s}/build/host", .{root}));
    for (tools) |t| try Io.Dir.cwd().symLink(
        io,
        self,
        try gpa.print("{s}/bin/{s}", .{ root, t }),
        .{},
    );
    // test/cloud runs the judges this checkout built.
    for ([_][]const u8{ "cloud-console", "azure-security", "cloud-posture" }) |judge|
        try Io.Dir.cwd().symLink(
            io,
            try c.absolute(try gpa.print("build/host/{s}", .{judge})),
            try gpa.print("{s}/build/host/{s}", .{ root, judge }),
            .{},
        );
    const provider = try gpa.print("{s}/test-sk.so", .{root});
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = provider, .data = "" });
    try c.env.put("PATH", try gpa.print("{s}/bin:{s}", .{ root, c.env.get("PATH") orelse "" }));
    try c.env.put("HOWL", try gpa.print("{s}/bin/howl", .{root}));
    try c.env.put("SSH_SK_PROVIDER", provider);
    try c.env.put("CLOUD_TEST_STATE", try gpa.print("{s}/hostname", .{root}));
    try c.env.put("CLOUD_NAME", "ww-cloud-test");
    try c.env.put("POSTURE_KNOWN", "");
    try c.env.put("CLOUD_KEEP", "0");
    try c.env.put("CLOUD_SIZE", "test-size");

    const want = [_][]const u8{
        "ssh-login-t",    "ssh-login-root", "tpm-floor",           "ipe-enforced", "secure-boot",
        "firmware-trust", "posture",        "runtime-protections", "reconfigure",  "delete",
    };
    for ([_][]const u8{ "aws", "azure", "gcp" }) |cloud| {
        for ([_][]const u8{ "build", "download" }) |mode| {
            const output = try cloudRun(c, runner, root, .{ .cloud = cloud, .mode = mode });
            for (want) |check| if (mem.find(
                u8,
                output,
                try gpa.print("ok     {s}", .{check}),
            ) == null)
                return c.fail("{s} {s}: no ok {s}:\n{s}", .{ cloud, mode, check, output });
        }
        if (mem.find(
            u8,
            try cloudRun(c, runner, root, .{ .cloud = cloud, .mode = "build", .bad = "provider" }),
            "FAIL",
        ) == null)
            return c.fail("{s}: a missing provider flag did not fail", .{cloud});
    }
    for ([_][]const u8{
        "verity",  "secureboot", "firmwaretrust", "tpm",      "ipe",       "sshd",
        "posture", "disabled",   "ssh-t",         "ssh-root", "t-is-root", "runtime",
    }) |bad| if (mem.find(
        u8,
        try cloudRun(c, runner, root, .{ .cloud = "aws", .mode = "build", .bad = bad }),
        "FAIL",
    ) == null)
        return c.fail("aws: missing {s} did not fail", .{bad});
    c.say(
        "pass   cloud-checks: both modes and users; missing protections, provider flags and " ++
            "wrong identities fail",
        .{},
    );
}

/// Case is one run of test/cloud: which cloud, which mode, missing what.
const Case = struct { cloud: []const u8, mode: []const u8, bad: []const u8 = "" };

fn cloudRun(c: *host.Check, runner: []const u8, root: []const u8, case: Case) ![]const u8 {
    var env = try c.env.clone(c.gpa);
    try env.put("CLOUD_MODE", case.mode);
    try env.put("CLOUD_TEST_PROVIDER", case.cloud);
    try env.put("CLOUD_TEST_BAD", case.bad);
    const r = try host.check.command(c.io, c.gpa, &.{
        "sh",
        runner,
        case.cloud,
        "prod-ssh",
        "aarch64",
    }, .{
        .environ_map = &env,
        .cwd = root,
        .timeout = .fromSeconds(30),
    });
    if (r.ok() != (case.bad.len == 0)) return c.fail("{s} {s} {s}: exit {f}:\n{s}{s}", .{
        case.cloud, case.mode, case.bad, r.term, r.stdout, r.stderr,
    });
    return r.stdout;
}

/// stand answers as tool would for a machine missing what CLOUD_TEST_BAD
/// names, and returns its exit status.
fn stand(c: *host.Check, tool: []const u8) !u8 {
    const io = c.io;
    const gpa = c.gpa;
    const args = c.args[1..];
    const bad = c.env.get("CLOUD_TEST_BAD") orelse "";
    const state = c.env.get("CLOUD_TEST_STATE") orelse "";
    var out_buf: [4096]u8 = undefined;
    var stdout = Io.File.stdout().writerStreaming(io, &out_buf);
    const w = &stdout.interface;
    defer w.flush() catch {};
    const has = struct {
        fn f(list: []const [:0]const u8, word: []const u8) bool {
            for (list) |a| if (mem.eql(u8, a, word)) return true;
            return false;
        }
    }.f;
    var words: std.ArrayList([]const u8) = .empty;
    for (args) |a| try words.append(gpa, a);
    const joined = try host.check.join(gpa, words.items);
    if (mem.eql(u8, tool, "sleep")) return 0;
    if (mem.eql(u8, tool, "ssh-keygen")) {
        if (mem.eql(u8, after(args, "-t"), "ed25519-sk") and
            !mem.eql(u8, after(args, "-O"), "verify-required"))
            return refuse("ssh-keygen: a security key without verify-required: {s}", .{joined});
        const key = after(args, "-f");
        try Io.Dir.cwd().writeFile(io, .{ .sub_path = key, .data = "disposable test key" });
        try Io.Dir.cwd().writeFile(
            io,
            .{
                .sub_path = try gpa.print("{s}.pub", .{key}),
                .data = "sk-ssh-ed25519@openssh.com fixture",
            },
        );
        return 0;
    }
    if (mem.eql(u8, tool, "howl")) {
        if (args.len == 0) return 1;
        if (mem.eql(u8, args[0], "create")) {
            const build = mem.eql(u8, c.env.get("CLOUD_MODE") orelse "", "build");
            if (has(
                args,
                "--build",
            ) != build) return refuse("howl create: --build in the wrong mode: {s}", .{joined});
            const config = after(args, "--config");
            const users = try Io.Dir.cwd().readFileAlloc(
                io,
                try gpa.print("{s}/users", .{config}),
                gpa,
                .limited(1 << 16),
            );
            if (!mem.startsWith(
                u8,
                users,
                "t admin sk-",
            )) return refuse("howl create: users is not t's security key", .{});
            const hostname = try Io.Dir.cwd().readFileAlloc(
                io,
                try gpa.print("{s}/hostname", .{config}),
                gpa,
                .limited(1 << 16),
            );
            try Io.Dir.cwd().writeFile(
                io,
                .{ .sub_path = state, .data = mem.trim(u8, hostname, " \t\r\n") },
            );
            try w.print("{s}\t192.0.2.1\tprod-ssh\n", .{args[1]});
        } else if (mem.eql(u8, args[0], "console")) {
            for ([_][2][]const u8{
                .{ "verity", "stage0: slot a: root.erofs, read-only, verified" },
                .{ "secureboot", "stage0: Secure Boot enforced outside setup mode" },
                .{ "firmwaretrust", "stage0: Secure Boot admits only this image's signer" },
                .{ "tpm", "stage0: TPM floor 1: release 1 admitted; reset authority sealed" },
                .{
                    "ipe",
                    "stage0: IPE: only this root image may execute; policy administration removed",
                },
                .{ "sshd", "Server listening on 0.0.0.0 port 22" },
            }) |marker| if (!mem.eql(u8, bad, marker[0])) try w.print("{s}\n", .{marker[1]});
            try w.print(
                "cloud-metadata: {{\"event\":\"config\",\"provider\":\"{s}\"}}\n",
                .{c.env.get("CLOUD_TEST_PROVIDER") orelse ""},
            );
            const hostname = Io.Dir.cwd().readFileAlloc(io, state, gpa, .limited(1 << 16)) catch "";
            try w.print("posture: fail={s} pass=100 {{\"host\":\"{s}\"}}\n", .{
                if (mem.eql(u8, bad, "posture")) "boot-rollback-protected" else "", hostname,
            });
            if (mem.eql(
                u8,
                bad,
                "disabled",
            )) try w.writeAll("posture: fail= pass=100 disabled=tpm {}\n");
        }
        return 0;
    }
    if (mem.eql(u8, tool, "ssh")) {
        const denied = "Permission denied (publickey)\n";
        if (mem.find(u8, joined, "SecurityKeyProvider=") == null or args.len < 2) {
            try Io.File.stderr().writeStreamingAll(io, denied);
            return 255;
        }
        const target = args[args.len - 2];
        const user = target[0 .. mem.findScalar(u8, target, '@') orelse target.len];
        if (mem.eql(u8, bad, try gpa.print("ssh-{s}", .{user}))) {
            try Io.File.stderr().writeStreamingAll(io, denied);
            return 255;
        }
        if (mem.eql(u8, args[args.len - 1], "cat /run/werewolf/posture.json")) {
            const hostname = Io.Dir.cwd().readFileAlloc(io, state, gpa, .limited(1 << 16)) catch "";
            try w.print(
                "{{\"host\":\"{s}\",\"root\":true,\"dev\":false,\"disabled\":[],\"checks\":[",
                .{hostname},
            );
            const table = try host.evidence.load(gpa, form);
            const result = if (mem.eql(u8, bad, "runtime")) "skip" else "pass";
            for (table.cloud, 0..) |id, i| {
                const comma = if (i > 0) "," else "";
                try w.print("{s}{{\"id\":\"{s}\",\"result\":\"{s}\"}}", .{ comma, id, result });
            }
            try w.writeAll("],\"known\":{\"unexpected\":[],\"now_passing\":[]}}\n");
        } else if (mem.eql(u8, user, "root") or mem.eql(u8, bad, "t-is-root"))
            try w.writeAll("root\n0\n")
        else
            try w.writeAll("t\n12345\n");
        return 0;
    }
    if (mem.eql(u8, tool, "aws")) {
        if (has(args, "describe-availability-zones")) try w.writeAll("us-west-2\n");
        if (has(args, "describe-images") and mem.find(u8, joined, "TpmSupport") != null)
            try w.writeAll(if (mem.eql(u8, bad, "provider")) "None\n" else "v2.0\n");
        if (has(args, "describe-instances") and
            mem.find(u8, joined, "ImageId") != null) try w.writeAll("ami-test\n");
        return 0;
    }
    if (mem.eql(u8, tool, "gcloud")) {
        if (has(args, "get-value")) {
            try w.writeAll("test-project\n");
        } else if (has(args, "describe") and has(args, "projects")) {
            try w.writeAll("test-project\n");
        } else if (has(args, "describe") and has(args, "instances"))
            try w.writeAll(if (mem.eql(u8, bad, "provider"))
                "True\tFalse\tTrue\n"
            else
                "True\tTrue\tTrue\n");
        return 0;
    }
    if (mem.eql(u8, tool, "az")) {
        if (has(args, "config")) {
            try w.writeAll("test-group\n");
        } else if (has(args, "group")) {
            try w.writeAll("westus2\n");
        } else if (has(args, "vm")) try w.print(
            "{{\"os\": null, \"security\": {{\"securityType\": \"TrustedLaunch\", " ++
                "\"uefiSettings\": {{\"secureBootEnabled\": true, \"vTpmEnabled\": {}}}}}}}\n",
            .{!mem.eql(u8, bad, "provider")},
        );
        return 0;
    }
    return refuse("unexpected command: {s} {s}", .{ tool, joined });
}

fn after(args: []const [:0]const u8, flag: []const u8) []const u8 {
    for (args, 0..) |a, i| if (mem.eql(u8, a, flag) and i + 1 < args.len) return args[i + 1];
    return "";
}

fn refuse(comptime fmt: []const u8, args: anytype) u8 {
    std.log.err(fmt, args);
    return 1;
}
