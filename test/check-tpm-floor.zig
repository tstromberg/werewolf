//! check-tpm-floor attacks lib/tpm.zig's release floor on swtpm, as guest
//! root holding the device would.
//!
//!     check-tpm-floor [TPM-FLOOR]
//!
//! TPM-FLOOR (tools/tpm-floor.zig, default build/host/tpm-floor) runs the
//! code stage0 and the mount broker run. Raw TPM2 commands then play root:
//! whatever would lower, lock, clear, redefine or take over the counter must
//! be refused, and incrementing it allowed. Enrollments cut short, command by
//! command, complete on the next boot; a TPM someone else owns is refused.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

const channel = "abababababababababababababababababababababababababababababababab";
const other = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
const owner: u32 = 0x40000001;
const lockout: u32 = 0x4000000a;
const platform: u32 = 0x4000000c;
const pw_session: u32 = 0x40000009;
const attributes: u32 = 0x02040014;
const counter = handle(channel);

fn handle(comptime hex: []const u8) u32 {
    var raw: [2]u8 = undefined;
    _ = std.fmt.hexToBytes(&raw, hex[0..4]) catch unreachable;
    return 0x01500000 | @as(u32, raw[0]) << 8 | raw[1];
}

pub fn main(init: std.process.Init) void {
    const io = init.io;
    const gpa = init.arena.allocator();
    const args = init.minimal.args.toSlice(gpa) catch fatal("arguments", .{});
    const probe = if (args.len > 1) args[1] else "build/host/tpm-floor";
    const swtpm = which(io, gpa, init.environ_map.get("PATH") orelse "", "swtpm") orelse
        fatal("needs swtpm", .{});
    var suffix: [8]u8 = undefined;
    io.random(&suffix);
    const root = gpa.print("{s}/ww-tpm-floor-{x}", .{
        init.environ_map.get("TMPDIR") orelse "/tmp",
        suffix,
    }) catch fatal("out of memory", .{});
    Io.Dir.cwd().createDirPath(io, root) catch |err| fatal("{s}: {t}", .{ root, err });
    var c: Check = .{ .io = io, .gpa = gpa, .probe = probe, .swtpm = swtpm, .root = root };
    const result = c.all();
    if (c.tpm) |*t| t.stop();
    Io.Dir.cwd().deleteTree(io, root) catch {};
    result catch |err| fatal("{s}", .{c.failure orelse @errorName(err)});
    std.debug.print("pass   tpm-floor: {d} checks\n", .{c.passed});
}

fn fatal(comptime format: []const u8, args: anytype) noreturn {
    std.debug.print("check-tpm-floor: " ++ format ++ "\n", args);
    std.process.exit(1);
}

fn which(io: Io, gpa: Allocator, path: []const u8, name: []const u8) ?[]const u8 {
    var dirs = std.mem.tokenizeScalar(u8, path, ':');
    while (dirs.next()) |dir| {
        const full = gpa.print("{s}/{s}", .{ dir, name }) catch return null;
        Io.Dir.cwd().access(io, full, .{ .execute = true }) catch continue;
        return full;
    }
    return null;
}

/// pack writes its arguments big-endian, as Python's struct.pack('>...')
/// would: each integer at its own width, each byte string as it is.
fn pack(gpa: Allocator, parts: anytype) ![]const u8 {
    var out: Io.Writer.Allocating = .init(gpa);
    inline for (parts) |p| switch (@TypeOf(p)) {
        u8 => try out.writer.writeByte(p),
        u16, u32, u64 => try out.writer.writeInt(@TypeOf(p), p, .big),
        else => try out.writer.writeAll(p),
    };
    return out.written();
}

fn sized(gpa: Allocator, data: []const u8) ![]const u8 {
    return pack(gpa, .{ @as(u16, @intCast(data.len)), data });
}

fn public(gpa: Allocator, h: u32, attrs: u32) ![]const u8 {
    return pack(gpa, .{ h, @as(u16, 0xb), attrs, try sized(gpa, ""), @as(u16, 8) });
}

const Reply = struct { rc: u32, data: []const u8 };

const Tpm = struct {
    io: Io,
    gpa: Allocator,
    swtpm: []const u8,
    work: []const u8,
    port: u16 = 0,
    child: ?std.process.Child = null,

    /// start is a power-on: Startup(CLEAR) re-enables the platform hierarchy.
    fn start(t: *Tpm) !void {
        // Take both ports at once: port + 1 may be anyone's.
        var server = try Io.net.IpAddress.listen(&.{ .ip4 = .loopback(0) }, t.io, .{});
        var ctrl = try Io.net.IpAddress.listen(&.{ .ip4 = .loopback(0) }, t.io, .{});
        t.port = server.socket.address.getPort();
        const ctrl_port = ctrl.socket.address.getPort();
        server.deinit(t.io);
        ctrl.deinit(t.io);
        t.child = try std.process.spawn(t.io, .{
            .argv = &.{
                t.swtpm,
                "socket",
                "--tpm2",
                "--tpmstate",
                try t.gpa.print("dir={s}", .{t.work}),
                "--server",
                try t.gpa.print("type=tcp,port={d}", .{t.port}),
                "--ctrl",
                try t.gpa.print("type=tcp,port={d}", .{ctrl_port}),
                "--flags",
                "not-need-init,startup-clear",
            },
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = .ignore,
        });
        // A loaded host can take seconds to start it.
        for (0..200) |_| {
            const address: Io.net.IpAddress = .{ .ip4 = .loopback(t.port) };
            if (address.connect(t.io, .{ .mode = .stream })) |stream| {
                stream.close(t.io);
                return;
            } else |_| try t.io.sleep(.fromMilliseconds(50), .awake);
        }
        return error.SwtpmDidNotStart;
    }

    /// stop pulls the plug. Child.kill's SIGTERM can leave swtpm spinning.
    fn stop(t: *Tpm) void {
        if (t.child) |*child| {
            std.posix.kill(child.id.?, .KILL) catch {};
            _ = child.wait(t.io) catch {};
        }
        t.child = null;
    }

    fn restart(t: *Tpm) !void {
        t.stop();
        try t.start();
    }

    /// call sends one command, with a password session when auth is set (""
    /// is the empty password), and returns its response code and parameters.
    /// swtpm serves one client at a time, so each call connects anew.
    fn call(
        t: *Tpm,
        code: u32,
        handles: []const u32,
        auth: ?[]const u8,
        params: []const u8,
    ) !Reply {
        const gpa = t.gpa;
        var body: Io.Writer.Allocating = .init(gpa);
        for (handles) |h| try body.writer.writeInt(u32, h, .big);
        if (auth) |secret| {
            const area = try pack(
                gpa,
                .{ pw_session, @as(u16, 0), @as(u8, 0), try sized(gpa, secret) },
            );
            try body.writer.writeAll(try pack(gpa, .{ @as(u32, @intCast(area.len)), area }));
        }
        try body.writer.writeAll(params);
        const tag: u16 = if (auth != null) 0x8002 else 0x8001;
        const size: u32 = @intCast(10 + body.written().len);
        const command = try pack(gpa, .{ tag, size, code, body.written() });
        const address: Io.net.IpAddress = .{ .ip4 = .loopback(t.port) };
        const stream = try address.connect(t.io, .{ .mode = .stream });
        defer stream.close(t.io);
        const timeout: std.posix.timeval = .{ .sec = 10, .usec = 0 };
        try std.posix.setsockopt(
            stream.socket.handle,
            std.posix.SOL.SOCKET,
            std.posix.SO.RCVTIMEO,
            std.mem.asBytes(&timeout),
        );
        var out_buf: [512]u8 = undefined;
        var writer = stream.writer(t.io, &out_buf);
        try writer.interface.writeAll(command);
        try writer.interface.flush();
        var in_buf: [4096]u8 = undefined;
        var reader = stream.reader(t.io, &in_buf);
        const r = &reader.interface;
        const reply_tag = try r.takeInt(u16, .big);
        const reply_size = try r.takeInt(u32, .big);
        const rc = try r.takeInt(u32, .big);
        if (reply_size < 10) return error.ShortResponse;
        var rest = try gpa.alloc(u8, reply_size - 10);
        try r.readSliceAll(rest);
        if (reply_tag == 0x8002 and rc == 0) {
            if (rest.len < 4) return error.ShortResponse;
            const n = std.mem.readInt(u32, rest[0..4], .big);
            if (n > rest.len - 4) return error.ShortResponse;
            rest = rest[4 .. 4 + n];
        }
        return .{ .rc = rc, .data = rest };
    }

    fn define(t: *Tpm, h: u32) !u32 {
        const area = try sized(t.gpa, try public(t.gpa, h, attributes));
        return (try t.call(
            0x12a,
            &.{owner},
            "",
            try pack(t.gpa, .{ try sized(t.gpa, ""), area }),
        )).rc;
    }

    fn increment(t: *Tpm, h: u32) !u32 {
        return (try t.call(0x134, &.{ h, h }, "", "")).rc;
    }

    fn value(t: *Tpm, h: u32) !u64 {
        const r = try t.call(0x14e, &.{ h, h }, "", try pack(t.gpa, .{ @as(u16, 8), @as(u16, 0) }));
        if (r.rc != 0 or r.data.len < 10) return error.ReadRefused;
        return std.mem.readInt(u64, r.data[2..10], .big);
    }

    fn changeAuth(t: *Tpm, hierarchy: u32, new: []const u8) !u32 {
        return (try t.call(0x129, &.{hierarchy}, "", try sized(t.gpa, new))).rc;
    }
};

const Check = struct {
    io: Io,
    gpa: Allocator,
    probe: []const u8,
    swtpm: []const u8,
    root: []const u8,
    tpm: ?Tpm = null,
    passed: usize = 0,
    /// failure says what failed, for main to report.
    failure: ?[]const u8 = null,

    fn check(c: *Check, label: []const u8, condition: bool) !void {
        if (!condition) {
            c.failure = label;
            return error.CheckFailed;
        }
        c.passed += 1;
    }

    /// fresh powers on a new, empty TPM in its own state directory.
    fn fresh(c: *Check, label: []const u8) !*Tpm {
        if (c.tpm) |*t| t.stop();
        const work = try c.gpa.print("{s}/{s}", .{ c.root, label });
        try Io.Dir.cwd().createDir(c.io, work, .default_dir);
        c.tpm = .{ .io = c.io, .gpa = c.gpa, .swtpm = c.swtpm, .work = work };
        try c.tpm.?.start();
        return &c.tpm.?;
    }

    /// run runs tpm-floor against t; ok says whether it must succeed. It
    /// returns what tpm-floor printed, stdout then stderr, trimmed.
    fn run(c: *Check, t: *Tpm, ok: bool, args: []const []const u8) ![]const u8 {
        const gpa = c.gpa;
        var argv: std.ArrayList([]const u8) = .empty;
        try argv.appendSlice(gpa, &.{ c.probe, args[0], try gpa.print("{d}", .{t.port}) });
        try argv.appendSlice(gpa, args[1..]);
        const result = try std.process.run(gpa, c.io, .{
            .argv = argv.items,
            .timeout = (Io.Timeout{ .duration = .{
                .raw = .fromSeconds(60),
                .clock = .awake,
            } }).toDeadline(c.io),
        });
        const succeeded = result.term == .exited and result.term.exited == 0;
        if (succeeded != ok) {
            c.failure = try gpa.print("{s}: {s}", .{
                try std.mem.join(gpa, " ", argv.items),
                if (ok) result.stderr else "succeeded",
            });
            return error.ProbeFailed;
        }
        const trim = " \t\r\n";
        return std.mem.concat(gpa, u8, &.{
            std.mem.trim(u8, result.stdout, trim),
            std.mem.trim(u8, result.stderr, trim),
        });
    }

    fn says(c: *Check, t: *Tpm, args: []const []const u8, want: []const u8) !bool {
        return std.mem.eql(u8, try c.run(t, true, args), want);
    }

    fn refused(c: *Check, t: *Tpm, args: []const []const u8, why: []const u8) !bool {
        return std.mem.find(u8, try c.run(t, false, args), why) != null;
    }

    fn all(c: *Check) !void {
        const gpa = c.gpa;
        const policy = try pack(gpa, .{ try sized(gpa, &@as([32]u8, @splat(1))), @as(u16, 0xb) });
        // A fresh TPM enrolls on first boot, at this release's index.
        var t = try c.fresh("enroll");
        try c.check(
            "first boot enrolls at its index",
            try c.says(t, &.{ "boot", channel, "5" }, "floor 5"),
        );
        try c.check(
            "the counter is written at its index",
            try c.says(t, &.{ "read", channel }, "written 5"),
        );
        const area = try t.call(0x169, &.{counter}, null, "");
        try c.check("the public area is exact", area.rc == 0 and area.data.len >= 16 and
            std.mem.eql(u8, area.data[2..16], try public(gpa, counter, attributes | 1 << 29)));
        // Guest root holds the device: nothing it sends may lower or take the counter.
        try t.restart();
        _ = try c.run(t, true, &.{ "boot", channel, "5" });
        const Refusal = struct { []const u8, u32, []const u32, []const u8 };
        const refusals = [_]Refusal{
            .{ "undefine as owner", 0x122, &.{ owner, counter }, "" },
            .{ "undefine as platform", 0x122, &.{ platform, counter }, "" },
            .{ "undefine special", 0x11f, &.{ counter, platform }, "" },
            .{ "clear as lockout", 0x126, &.{lockout}, "" },
            .{ "clear as platform", 0x126, &.{platform}, "" },
            .{ "enable clear as platform", 0x127, &.{platform}, "\x00" },
            .{ "enable clear as lockout", 0x127, &.{lockout}, "\x00" },
            .{
                "reopen the platform hierarchy",
                0x121,
                &.{platform},
                try pack(gpa, .{ platform, @as(u8, 1) }),
            },
            .{ "empty owner password", 0x129, &.{owner}, try sized(gpa, "") },
            .{ "empty lockout password", 0x129, &.{lockout}, try sized(gpa, "") },
            .{ "owner policy", 0x12e, &.{owner}, policy },
            .{
                "redefine the counter",
                0x12a,
                &.{owner},
                try pack(
                    gpa,
                    .{ try sized(gpa, ""), try sized(gpa, try public(gpa, counter, attributes)) },
                ),
            },
            .{ "write-lock the counter", 0x138, &.{ counter, counter }, "" },
            .{ "global write lock", 0x135, &.{owner}, "" },
            .{
                "write the counter",
                0x137,
                &.{ counter, counter },
                try pack(gpa, .{ try sized(gpa, &@as([8]u8, @splat(0))), @as(u16, 0) }),
            },
            .{ "read-lock the counter", 0x14f, &.{ counter, counter }, "" },
            .{ "change the counter password", 0x13b, &.{counter}, try sized(gpa, "x") },
        };
        for (refusals) |r| {
            const label, const code, const handles, const params = r;
            const reply = try t.call(code, handles, "", params);
            try c.check(try gpa.print("{s} is refused", .{label}), reply.rc != 0);
        }
        try c.check("refusals left the floor", try c.says(t, &.{ "read", channel }, "written 5"));
        try c.check(
            "anyone may increment",
            try t.increment(counter) == 0 and try t.value(counter) == 6,
        );
        try c.check(
            "the broker raises to an index",
            try c.says(t, &.{ "raise", channel, "9" }, "floor 9"),
        );
        try c.check("raising never lowers", try c.says(t, &.{ "raise", channel, "4" }, "floor 9"));
        // Boot refuses a release below the floor and admits one at or above it.
        try c.check(
            "a retired release is refused",
            try c.refused(t, &.{ "boot", channel, "8" }, "RollbackRefused"),
        );
        try c.check(
            "the floor release boots",
            try c.says(t, &.{ "boot", channel, "9" }, "floor 9"),
        );
        try c.check(
            "a later release boots without raising",
            try c.says(t, &.{ "boot", channel, "12" }, "floor 9"),
        );
        try c.check(
            "another channel finds no counter",
            try c.refused(t, &.{ "boot", other, "50" }, "ForeignTpm"),
        );
        // Power-on re-enables the platform hierarchy; boot closes it again.
        try t.restart();
        _ = try c.run(t, true, &.{ "boot", channel, "9" });
        try c.check(
            "platform clear after boot is refused",
            (try t.call(0x126, &.{platform}, "", "")).rc != 0,
        );

        // Enrollment cut at each step completes on the next boot, with the same result.
        for ([_][]const u8{ "defined", "incremented", "clear-disabled", "lockout-set" }) |cut| {
            t = try c.fresh(try gpa.print("cut-{s}", .{cut}));
            try c.check(try gpa.print("{s}: define", .{cut}), try t.define(counter) == 0);
            if (!std.mem.eql(u8, cut, "defined")) {
                for (0..3) |_| _ = try t.increment(counter);
            }
            if (std.mem.eql(u8, cut, "clear-disabled") or std.mem.eql(u8, cut, "lockout-set")) {
                const rc = (try t.call(0x127, &.{lockout}, "", "\x01")).rc;
                try c.check(try gpa.print("{s}: clear control", .{cut}), rc == 0);
            }
            if (std.mem.eql(u8, cut, "lockout-set")) {
                var secret: [32]u8 = undefined;
                c.io.random(&secret);
                try c.check(
                    try gpa.print("{s}: lockout", .{cut}),
                    try t.changeAuth(lockout, &secret) == 0,
                );
            }
            try t.restart();
            try c.check(
                try gpa.print("{s}: next boot completes", .{cut}),
                try c.says(t, &.{ "boot", channel, "3" }, "floor 3"),
            );
            try c.check(
                try gpa.print("{s}: owner is sealed", .{cut}),
                try t.changeAuth(owner, "") != 0,
            );
        }

        // A TPM someone else owns, or whose lockout they hold with clear enabled, is refused.
        t = try c.fresh("owned");
        _ = try t.changeAuth(owner, "someone");
        try c.check(
            "an owned TPM is refused",
            try c.refused(t, &.{ "boot", channel, "1" }, "ForeignTpm"),
        );
        t = try c.fresh("lockout");
        _ = try t.changeAuth(lockout, "someone");
        try c.check(
            "a foreign lockout is refused",
            try c.refused(t, &.{ "boot", channel, "1" }, "ForeignTpm"),
        );
        t = try c.fresh("policy");
        try c.check("owner policy set", (try t.call(0x12e, &.{owner}, "", policy)).rc == 0);
        try c.check(
            "an owner policy is refused",
            try c.refused(t, &.{ "boot", channel, "1" }, "UnprotectedTpmHierarchy"),
        );
        t = try c.fresh("squatter");
        const squat = try pack(
            gpa,
            .{ try sized(gpa, ""), try sized(gpa, try public(gpa, counter, attributes | 1 << 1)) },
        );
        try c.check(
            "a squatter defines the handle",
            (try t.call(0x12a, &.{owner}, "", squat)).rc == 0,
        );
        try c.check(
            "a different index at the handle is refused",
            try c.refused(t, &.{ "boot", channel, "1" }, "WrongTpmCounter"),
        );
        // A new counter starts above every counter undefined before it, so an undefined and
        // redefined counter never comes back lower: enrollment then admits only releases at
        // or above it.
        t = try c.fresh("ahead");
        const ahead = handle(other);
        _ = try t.define(ahead);
        for (0..7) |_| _ = try t.increment(ahead);
        try c.check(
            "an unowned TPM lets its counter go",
            (try t.call(0x122, &.{ owner, ahead }, "", "")).rc == 0,
        );
        try c.check(
            "a counter ahead of the release enrolls but refuses it",
            try c.refused(t, &.{ "boot", channel, "3" }, "RollbackRefused"),
        );
        try c.check("the TPM is sealed regardless", try t.changeAuth(owner, "") != 0);
        try c.check(
            "a release at the counter boots",
            try c.says(t, &.{ "boot", channel, "8" }, "floor 8"),
        );
    }
};
