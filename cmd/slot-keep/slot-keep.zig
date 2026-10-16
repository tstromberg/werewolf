//! slot-keep makes this boot's slot the loader's default once every service
//! has run for a minute, /data works, the updater is ready, and posture
//! fails nothing the image does not excuse. Until then stage0's deadman
//! reboots into the last good slot. See README.md.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const broker = @import("broker");
const cmdline = @import("cmdline");
const sandbox = @import("sandbox");
const linux = std.os.linux;
const keeper_id = 72;
var control_fd: i32 = -1;

const updater_ready = "/run/werewolf/updater-ready";
const posture_report = "/run/werewolf/posture.json";
const nodata = "/run/werewolf/nodata";
const wait = 15;

pub fn main(init: std.process.Init) !void {
    broker.keepOnlyClient(.keeper);
    const io = init.io;
    const gpa = init.arena.allocator();
    // The hardened kernel exposes boot arguments only to root. Keep the
    // immutable text before dropping identity; the keeper needs no later
    // access to procfs.
    const boot_line = readAll(io, gpa, "/proc/cmdline");
    if (boot_line.len == 0) return error.BootCommandLineUnavailable;
    control_fd = @intCast(try sandbox.sys(linux.open(
        "supervise/control",
        .{ .ACCMODE = .WRONLY, .NONBLOCK = true, .CLOEXEC = true },
        0,
    ), "open keeper control"));
    try sandbox.dropKeeping(keeper_id, 0);
    var rules: [3]sandbox.Rule = undefined;
    for ([_][:0]const u8{
        "/etc/sv",
        "/run/runit",
        "/run/werewolf",
    }, &rules) |path, *rule| {
        rule.* = .{
            .fd = @intCast(try sandbox.sys(
                linux.open(path, .{ .PATH = true, .CLOEXEC = true }, 0),
                "open keeper read path",
            )),
            .access = sandbox.read_file | sandbox.read_dir,
        };
    }
    try sandbox.landlock(&rules, &.{});
    for (rules) |rule| _ = linux.close(rule.fd);
    // Parse as stage0 does (lib/cmdline.zig).
    var refused: cmdline.Failure = .{};
    const cmd = cmdline.parse(boot_line, &refused) orelse {
        say(io, "the command line's {s}: {s}; not committing", .{ refused.word, refused.why });
        park(io);
    };
    if (cmd.esp == null or cmd.slot == null) park(io);
    const entry = try gpa.print("werewolf-{s}", .{@tagName(cmd.slot orelse .a)});

    var said_updater = false;
    var said_posture = false;
    // After two minutes, log the service that blocks the commit whenever it
    // changes. Otherwise a crash loop ends in a deadman rollback with nothing
    // on the console to say why.
    var waited: u32 = 0;
    var blocker_buf: [Dir.max_name_bytes]u8 = undefined;
    var blocker_said: [Dir.max_name_bytes]u8 = undefined;
    var blocker_said_len: usize = 0;
    while (true) : ({
        try io.sleep(.fromSeconds(wait), .awake);
        waited += wait;
    }) {
        if (unhealthy(io, &blocker_buf)) |blocker| {
            if (waited >= 120 and
                !std.mem.eql(u8, blocker, blocker_said[0..blocker_said_len]))
            {
                say(io, "{s} is not up and settled; not committing", .{blocker});
                @memcpy(blocker_said[0..blocker.len], blocker);
                blocker_said_len = blocker.len;
            }
            continue;
        }
        if (exists(io, "/etc/sv/autoupdate") and !exists(io, updater_ready)) {
            // A slot whose updater cannot run could never be updated away
            // from, so it is never kept. Log this once.
            if (!said_updater) say(
                io,
                "the updater has not said it can update; not committing",
                .{},
            );
            said_updater = true;
            continue;
        }
        // posture parks itself once it has written its report, so a healthy
        // posture service says nothing about what it found.
        if (!exists(io, "/etc/sv/posture")) break;
        switch (verdict(gpa, readAll(io, gpa, posture_report))) {
            .clean => break,
            .pending => {
                if (!said_posture) say(io, "posture has not reported; not committing", .{});
                said_posture = true;
            },
            .failing => |why| {
                say(io, "posture {s}; not committing", .{why});
                park(io);
            },
        }
    }

    try commitEsp(io, gpa, entry);
    park(io);
}

/// commitEsp commits for systemd-boot: the mount broker renames this
/// slot's counting entry to entry.conf on the EFI partition, which it
/// never lends as a mount.
fn commitEsp(io: Io, gpa: Allocator, entry: []const u8) !void {
    const status = broker.espStatus() catch |err|
        return say(
            io,
            "no EFI partition: {s} {s}; not committing",
            .{ @errorName(err), broker.refusal },
        );
    switch (status) {
        .already => {
            say(io, "{s} is already good", .{entry});
            return broker.espCommit();
        },
        .none => return say(io, "no entry for {s} on the EFI partition; not committing", .{entry}),
        .tried => {},
    }
    if (dataUnavailable(io, gpa)) return;
    broker.espCommit() catch |err|
        return say(
            io,
            "cannot commit {s}: {s} {s}; not committing",
            .{ entry, @errorName(err), broker.refusal },
        );
    say(io, "healthy for a minute; {s} is good", .{entry});
}

/// dataUnavailable reports, and logs, whether /data failed this boot. Such a
/// slot is not healthy whatever its services say, so it is left for the
/// deadman to roll back.
fn dataUnavailable(io: Io, gpa: Allocator) bool {
    if (!exists(io, nodata)) return false;
    say(io, "/data is unavailable ({s}); not committing", .{trim(readAll(io, gpa, nodata))});
    return true;
}

/// unhealthy returns the name, in name_buf, of the first other service that
/// serviceHealthy rejects or that has no readable supervise/status yet. It
/// returns null when every service is healthy.
fn unhealthy(io: Io, name_buf: *[Dir.max_name_bytes]u8) ?[]const u8 {
    var d = Dir.cwd().openDir(io, "/etc/sv", .{ .iterate = true }) catch return "/etc/sv";
    defer d.close(io);
    const now: u64 = @intCast(@max(
        0,
        @divFloor(Io.Timestamp.now(io, .real).nanoseconds, std.time.ns_per_s),
    ));
    var it = d.iterate();
    while (it.next(io) catch return "/etc/sv") |e| {
        if (std.mem.eql(u8, e.name, "slot-keep")) continue;
        const name = name_buf[0..e.name.len];
        @memcpy(name, e.name);
        var path_buf: [Dir.max_name_bytes + 32]u8 = undefined;
        const path = std.mem.print(&path_buf, "{s}/supervise/status", .{name}) catch return name;
        var f = d.openFile(io, path, .{}) catch return name;
        defer f.close(io);
        var status: [20]u8 = undefined;
        const n = f.readPositionalAll(io, &status, 0) catch return name;
        if (n != status.len or !serviceHealthy(status, now)) return name;
    }
    return null;
}

/// serviceHealthy reports whether a runsv supervise/status shows a service
/// running for 60 s, or down because it wants to be (parked). Down while
/// wanted up means between crashes; finish means leash-reap is clearing one.
/// The 20 bytes hold the last change as TAI64N (seconds since 1970 plus
/// 2^62 + 10), the pid, paused, want ('u' or 'd'), term, and state (0 down,
/// 1 run, 2 finish).
fn serviceHealthy(status: [20]u8, now: u64) bool {
    const since = std.mem.readInt(u64, status[0..8], .big) -| ((1 << 62) + 10);
    return switch (status[19]) {
        0 => status[17] == 'd',
        1 => now -| since >= 60,
        else => false,
    };
}

/// Verdict is what posture's report says about this slot.
const Verdict = union(enum) { pending, clean, failing: []const u8 };

/// verdict judges posture's report (cmd/posture, posture_report): pending
/// until it is written, failing with the checks the image does not excuse,
/// or with why the report cannot be read, else clean. A slot that fails a
/// protection its image did not declare is never kept, whatever its
/// services say: a kernel or program that lost a protection must not
/// become the slot every later update is measured against.
fn verdict(gpa: Allocator, text: []const u8) Verdict {
    if (text.len == 0) return .pending;
    const Report = struct {
        summary: struct { fail: usize = 0 } = .{},
        known: ?struct { unexpected: []const []const u8 = &.{} } = null,
    };
    const r = std.json.parseFromSliceLeaky(Report, gpa, text, .{
        .ignore_unknown_fields = true,
    }) catch |err| return .{
        .failing = gpa.print("wrote a report this cannot read: {s}", .{@errorName(err)}) catch
            "wrote a report this cannot read",
    };
    if (r.known) |k| {
        if (k.unexpected.len == 0) return .clean;
        return .{
            .failing = gpa.print(
                "fails {s}, which this image does not excuse",
                .{std.mem.join(gpa, " ", k.unexpected) catch "checks"},
            ) catch "fails checks this image does not excuse",
        };
    }
    if (r.summary.fail == 0) return .clean;
    return .{
        .failing = gpa.print(
            "fails {d} checks, and the image excuses none",
            .{r.summary.fail},
        ) catch
            "fails checks, and the image excuses none",
    };
}

/// park marks only this service down through the pipe opened before the drop.
fn park(io: Io) noreturn {
    _ = io;
    const rc = linux.write(control_fd, "d", 1);
    linux.exit_group(if (rc == 1) 0 else 1);
}

/// readAll returns path's contents, or "" on error. It reads to the end
/// because procfs reports a size of 0.
fn readAll(io: Io, gpa: Allocator, path: []const u8) []const u8 {
    var f = Dir.cwd().openFile(io, path, .{}) catch return "";
    defer f.close(io);
    var buf: [4096]u8 = undefined;
    var r = f.readerStreaming(io, &buf);
    return r.interface.allocRemaining(gpa, .limited(4 << 20)) catch "";
}

fn exists(io: Io, path: []const u8) bool {
    Dir.cwd().access(io, path, .{}) catch return false;
    return true;
}

fn trim(s: []const u8) []const u8 {
    return std.mem.trim(u8, s, " \r\n");
}

fn say(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const line = std.mem.print(&buf, "slot-keep: " ++ fmt ++ "\n", args) catch return;
    Io.File.stdout().writeStreamingAll(io, line) catch {};
}

// --- tests -------------------------------------------------------------------

const testing = std.testing;

/// statusOf builds a supervise/status with state, want, and the last change
/// ago seconds before 1000.
fn statusOf(state: u8, want: u8, ago: u64) [20]u8 {
    var st: [20]u8 = @splat(0);
    std.mem.writeInt(u64, st[0..8], (1 << 62) + 10 + 1000 - ago, .big);
    st[17] = want;
    st[19] = state;
    return st;
}

test verdict {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const gpa = a.allocator();
    try testing.expectEqual(Verdict.pending, verdict(gpa, ""));
    try testing.expectEqual(Verdict.clean, verdict(
        gpa,
        \\{"summary":{"pass":80,"fail":2,"skip":1},
        \\ "known":{"unexpected":[],"now_passing":["x"]},"checks":[]}
        ,
    ));
    try testing.expectEqualStrings(
        "fails kernel-lockdown processes-leash-attack, which this image does not excuse",
        verdict(
            gpa,
            \\{"summary":{"fail":2},"known":{"unexpected":["kernel-lockdown",
            \\ "processes-leash-attack"],"now_passing":[]}}
            ,
        ).failing,
    );
    // No weaknesses compared: every failure counts.
    try testing.expectEqual(Verdict.clean, verdict(gpa, "{\"summary\":{\"fail\":0}}"));
    try testing.expectEqualStrings(
        "fails 3 checks, and the image excuses none",
        verdict(gpa, "{\"summary\":{\"fail\":3}}").failing,
    );
    try testing.expectEqualStrings(
        "wrote a report this cannot read: UnexpectedEndOfInput",
        verdict(gpa, "{\"summary\":").failing,
    );
}

test serviceHealthy {
    try testing.expect(serviceHealthy(statusOf(1, 'u', 75), 1000));
    try testing.expect(!serviceHealthy(statusOf(1, 'u', 12), 1000));
    // Parked on purpose. The updater must also write updater_ready.
    try testing.expect(serviceHealthy(statusOf(0, 'd', 30), 1000));
    // Down between crashes, and finishing after one.
    try testing.expect(!serviceHealthy(statusOf(0, 'u', 1), 1000));
    try testing.expect(!serviceHealthy(statusOf(2, 'u', 600), 1000));
    try testing.expect(!serviceHealthy(statusOf(7, 'u', 600), 1000));
}
