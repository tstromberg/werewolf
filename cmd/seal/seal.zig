//! seal: say what the machine and each service promised, and what was
//! refused.
//!
//!     $ seal
//!     seal: enforcing; the machine promises stdio rpath wpath inet unix ...
//!     services:
//!       app          stdio rpath inet listen
//!       nginx        stdio rpath inet listen
//!       slot-keep    (werewolf's own: the machine's promises alone)
//!     refused this boot:
//!       keyctl         never   1 time, last by pid 97, first at 2026-10-07 01:14:03 UTC
//!     never allowed: bpf perf_event_open init_module ...
//!     never allowed for what they ask: socket (a family no promise names); ...
//!
//! A refusal's promise is the one that would have allowed the call. These
//! are the machine seal's: a leashed service holds itself to its pledge and
//! refuses the rest silently, so what is counted here is what werewolf's
//! own programs made outside the machine's promises
//! (docs/design/pledge.md, System calls: promises). It reads what init wrote
//! as it sealed the machine, the services' files as leash reads them, and
//! what seal-watch counts; it changes nothing, and anyone may run it.

const std = @import("std");
const seal = @import("seal");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();
    const policy = std.Io.Dir.cwd().readFileAlloc(
        io,
        seal.policy_path,
        gpa,
        .limited(64 << 10),
    ) catch {
        std.debug.print(
            "seal: no {s}: this machine was not sealed by werewolf's init\n",
            .{seal.policy_path},
        );
        std.process.exit(1);
    };
    const refused = std.Io.Dir.cwd().readFileAlloc(
        io,
        seal.refused_path,
        gpa,
        .limited(1 << 20),
    ) catch "";

    var services: std.ArrayList(Service) = .empty;
    if (std.Io.Dir.cwd().openDir(io, "/etc/sv", .{ .iterate = true })) |d| {
        var dir = d;
        defer dir.close(io);
        var it = dir.iterate();
        while (try it.next(io)) |e| {
            if (e.kind != .directory and e.kind != .sym_link) continue;
            const path = try gpa.print("{s}/service", .{e.name});
            const text = dir.readFileAlloc(io, path, gpa, .limited(64 << 10));
            try services.append(gpa, .{
                .name = try gpa.dupe(u8, e.name),
                .bound = if (text) |t|
                    try boundBy(gpa, t)
                else |err| switch (err) {
                    error.FileNotFound => "(werewolf's own: the machine's promises alone)",
                    else => try gpa.print("(cannot read its service file: {t})", .{err}),
                },
            });
        }
    } else |_| {}
    std.mem.sort(Service, services.items, {}, Service.less);

    var out: std.Io.Writer.Allocating = .init(gpa);
    const reported = report(&out.writer, policy, services.items, refused);
    try std.Io.File.stdout().writeStreamingAll(io, out.written());
    reported catch std.process.exit(1);
}

/// A service, and what binds it: its pledge, or why it has none.
const Service = struct {
    name: []const u8,
    bound: []const u8,

    fn less(_: void, a: Service, b: Service) bool {
        return std.mem.order(u8, a.name, b.name) == .lt;
    }
};

/// What binds a leashed service, from its service file: its pledge, or
/// that leash refuses the file and the service does not run.
fn boundBy(gpa: std.mem.Allocator, text: []const u8) ![]const u8 {
    const words = pledgeOf(text) orelse return "(no pledge: leash refuses it)";
    if (words.len == 0) return "(an empty pledge: leash refuses it)";
    var bad: []const u8 = "";
    _ = seal.parse(words, &bad) catch
        return try gpa.print("(no promise {s}: leash refuses it)", .{bad});
    return words;
}

/// The words of a service file's pledge line, as leash reads them: split by
/// spaces and tabs, and ended by a word that starts with #. null if there is
/// no pledge line.
fn pledgeOf(text: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        var words = std.mem.tokenizeAny(u8, line, " \t\r");
        const key = words.next() orelse continue;
        if (!std.mem.eql(u8, key, "pledge")) continue;
        var first: ?usize = null;
        var end: usize = 0;
        while (words.next()) |w| {
            if (w[0] == '#') break;
            const at = @intFromPtr(w.ptr) - @intFromPtr(line.ptr);
            if (first == null) first = at;
            end = at + w.len;
        }
        return if (first) |f| line[f..end] else "";
    }
    return null;
}

/// The rest of the line in text that starts with key and a space.
fn field(text: []const u8, key: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (std.mem.eql(u8, line, key)) return "";
        if (line.len > key.len and std.mem.startsWith(u8, line, key) and line[key.len] == ' ')
            return line[key.len + 1 ..];
    }
    return null;
}

fn report(
    w: *std.Io.Writer,
    policy: []const u8,
    services: []const Service,
    refused: []const u8,
) !void {
    // Enforcing only when init said so: an empty or unknown mode is a seal
    // this cannot vouch for, not one to call enforcing.
    const mode = field(policy, "mode") orelse "";
    const state = if (std.mem.eql(u8, mode, "enforce"))
        "enforcing"
    else if (std.mem.eql(u8, mode, "learn"))
        "learning: what no promise allows is allowed, and said"
    else {
        try w.print("seal: unknown mode \"{s}\" in {s}\n", .{ mode, seal.policy_path });
        return error.UnknownMode;
    };
    try w.print("seal: {s}; the machine promises {s}\n", .{
        state,
        field(policy, "promises") orelse "?",
    });
    if (services.len > 0) {
        try w.writeAll("services:\n");
        for (services) |s| try w.print("  {s:<12} {s}\n", .{ s.name, s.bound });
    }
    var lines = std.mem.tokenizeScalar(u8, refused, '\n');
    if (lines.peek() == null) {
        try w.writeAll("refused this boot: none\n");
    } else {
        try w.writeAll("refused this boot:\n");
        while (lines.next()) |line| {
            var f = std.mem.tokenizeScalar(u8, line, ' ');
            const name = f.next() orelse continue;
            const times = std.fmt.parseInt(u64, f.next() orelse "0", 10) catch 0;
            const pid = f.next() orelse "?";
            const first = std.fmt.parseInt(i64, f.next() orelse "0", 10) catch 0;
            const promise = f.next() orelse "?";
            try w.print("  {s:<16} {s:<9} {d} time{s}, last by pid {s}, first at ", .{
                name, promise, times, if (times == 1) "" else "s", pid,
            });
            try utc(w, first);
            try w.writeByte('\n');
        }
    }
    try w.writeAll("never allowed:");
    for (seal.never) |sys| try w.print(" {s}", .{@tagName(sys)});
    try w.writeAll("\nnever allowed for what they ask:");
    for (seal.by_argument, 0..) |what, i| try w.print("{s} {s}", .{ if (i > 0) ";" else "", what });
    try w.writeByte('\n');
}

/// Seconds since the epoch, as a UTC date and time.
fn utc(w: *std.Io.Writer, secs: i64) !void {
    if (secs <= 0) return w.writeAll("?");
    const es: std.time.epoch.EpochSeconds = .{ .secs = @intCast(secs) };
    const day = es.getEpochDay().calculateYearDay();
    const md = day.calculateMonthDay();
    const ds = es.getDaySeconds();
    try w.print("{d}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2} UTC", .{
        day.year,             md.month.numeric(),      md.day_index + 1,
        ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
    });
}

const testing = std.testing;

test pledgeOf {
    try testing.expectEqualStrings(
        "stdio rpath",
        pledgeOf("exec /a\npledge  stdio rpath # ok\nuser x\n").?,
    );
    try testing.expectEqual(null, pledgeOf("exec /a\n# pledge stdio\n"));
    // As leash reads it: # ends the line only where it starts a word.
    try testing.expectEqualStrings("stdio#x", pledgeOf("pledge stdio#x\n").?);
    try testing.expectEqualStrings("", pledgeOf("pledge # none\n").?);
}

test boundBy {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectEqualStrings("stdio inet", try boundBy(a, "pledge stdio inet\n"));
    try testing.expectEqualStrings("(no pledge: leash refuses it)", try boundBy(a, "exec /a\n"));
    try testing.expectEqualStrings(
        "(an empty pledge: leash refuses it)",
        try boundBy(a, "pledge\n"),
    );
    try testing.expectEqualStrings(
        "(no promise stdio#x: leash refuses it)",
        try boundBy(a, "pledge stdio#x\n"),
    );
}

test "report: only an enforce mode is enforcing" {
    var buf: [2048]u8 = undefined;
    for ([_][]const u8{
        "",
        "promises stdio\n",
        "mode\npromises stdio\n",
        "mode enforcing\n",
    }) |policy| {
        var w: std.Io.Writer = .fixed(&buf);
        try testing.expectError(error.UnknownMode, report(&w, policy, &.{}, ""));
        try testing.expect(std.mem.startsWith(u8, w.buffered(), "seal: unknown mode"));
        try testing.expect(std.mem.find(u8, w.buffered(), "enforcing;") == null);
    }
    var w: std.Io.Writer = .fixed(&buf);
    try report(&w, "mode learn\npromises stdio\n", &.{}, "");
    try testing.expect(std.mem.startsWith(u8, w.buffered(), "seal: learning:"));
}

test report {
    var buf: [2048]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try report(
        &w,
        "mode enforce\npromises stdio inet\n",
        &.{
            .{ .name = "app", .bound = "stdio inet listen" },
            .{ .name = "slot-keep", .bound = "(werewolf's own: the machine's promises alone)" },
        },
        "keyctl 1 97 1791335742 never\n",
    );
    const text = w.buffered();
    try testing.expect(std.mem.indexOf(
        u8,
        text,
        "seal: enforcing; the machine promises stdio inet\n",
    ) != null);
    try testing.expect(std.mem.indexOf(u8, text, "  app          stdio inet listen\n") != null);
    try testing.expect(std.mem.indexOf(u8, text, "  slot-keep    (werewolf's own") != null);
    try testing.expect(std.mem.indexOf(u8, text, "keyctl") != null);
    try testing.expect(std.mem.indexOf(
        u8,
        text,
        "never     1 time, last by pid 97, first at 2026-10-07 01:15:42 UTC",
    ) != null);
    try testing.expect(std.mem.indexOf(u8, text, "never allowed: bpf") != null);
    try testing.expect(std.mem.indexOf(
        u8,
        text,
        "never allowed for what they ask: socket (a family no promise names); setsockopt",
    ) != null);
}
