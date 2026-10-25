//! process reads what a service's members were started as, their comm or
//! cmdline, as one text a service step's matchers can judge: a line per
//! member, sorted, cmdline's arguments joined with spaces. Not environ:
//! another user's needs CAP_SYS_PTRACE, which the seal drops.
const std = @import("std");
const system = @import("system.zig");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const mem = std.mem;

pub const Field = enum { comm, cmdline };

pub const max_text = 1 << 20;

/// add puts each field expect names into a service probe's result.
pub fn add(io: Io, a: Allocator, got: *std.json.Value, expect: std.json.Value) !void {
    const members = got.object.get("members").?.array.items;
    const pids = try a.alloc(u32, members.len);
    for (members, pids) |member, *pid| pid.* = @intCast(member.object.get("pid").?.integer);
    for ([_]Field{ .comm, .cmdline }) |field| if (expect.object.contains(@tagName(field)))
        try got.object.put(a, @tagName(field), .{ .string = try text(io, a, pids, field) });
}

pub fn text(io: Io, a: Allocator, pids: []const u32, field: Field) ![]const u8 {
    var lines: std.ArrayList([]const u8) = .empty;
    for (pids) |pid| {
        const raw = system.read(io, a, try a.print("/proc/{d}/{t}", .{ pid, field })) catch |err|
            switch (err) {
                // A member that exited makes the observation incomplete; await retries it.
                error.FileNotFound => return error.ProcessSetChanged,
                else => return err,
            };
        try collect(a, &lines, field, raw);
    }
    return join(a, lines.items);
}

/// collect adds raw's line. A newline inside one would forge another
/// line, so it fails the probe.
fn collect(a: Allocator, lines: *std.ArrayList([]const u8), field: Field, raw: []const u8) !void {
    switch (field) {
        .comm => {
            const name = mem.trimEnd(u8, raw, "\n");
            if (mem.findScalar(u8, name, '\n') != null) return error.AmbiguousProcessText;
            try lines.append(a, name);
        },
        .cmdline => {
            const args = mem.trimEnd(u8, raw, "\x00");
            if (mem.findScalar(u8, args, '\n') != null) return error.AmbiguousProcessText;
            const line = try a.dupe(u8, args);
            mem.replaceScalar(u8, line, 0, ' ');
            try lines.append(a, line);
        },
    }
}

fn join(a: Allocator, lines: [][]const u8) ![]const u8 {
    mem.sort([]const u8, lines, {}, struct {
        fn less(_: void, x: []const u8, y: []const u8) bool {
            return mem.lessThan(u8, x, y);
        }
    }.less);
    const out = try mem.join(a, "\n", lines);
    if (out.len > max_text) return error.ProcessTextTooLong;
    return out;
}

const testing = std.testing;

test "members' commands become sorted lines, one per member" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var comm: std.ArrayList([]const u8) = .empty;
    try collect(a, &comm, .comm, "php8.4\n");
    try collect(a, &comm, .comm, "misp-serve\n");
    try testing.expectEqualStrings("misp-serve\nphp8.4", try join(a, comm.items));
    var cmdline: std.ArrayList([]const u8) = .empty;
    try collect(a, &cmdline, .cmdline, "/bin/bash\x00/usr/lib/werewolf/feed-run\x00");
    try collect(a, &cmdline, .cmdline, "nginx: worker process");
    try collect(a, &cmdline, .cmdline, "");
    try testing.expectEqualStrings(
        "\n/bin/bash /usr/lib/werewolf/feed-run\nnginx: worker process",
        try join(a, cmdline.items),
    );
}

test "a newline inside a value cannot forge a line" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var lines: std.ArrayList([]const u8) = .empty;
    try testing.expectError(
        error.AmbiguousProcessText,
        collect(a, &lines, .cmdline, "a\x00b\nc\x00"),
    );
    try testing.expectError(error.AmbiguousProcessText, collect(a, &lines, .comm, "a\nb\n"));
}

test "on Linux, a process's own command is readable text" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const pid: u32 = @intCast(std.os.linux.getpid());
    const got = try text(testing.io, arena.allocator(), &.{pid}, .cmdline);
    try testing.expect(got.len > 0);
}
