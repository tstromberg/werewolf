//! grub-setenv: set a variable in GRUB's environment block, in place.
//!
//!     grub-setenv FILE NAME VALUE
//!
//! The block is exactly 1024 bytes: a header line, name=value lines, then
//! '#' to the end. GRUB rewrites it in place, sector by sector, and reads it
//! without the filesystem's journal, so this writes the same bytes in the
//! same place rather than a new file: a data write the journal never holds.
//! slot-keep and slot-update use it on machines bite took over.

const std = @import("std");
const Io = std.Io;

const size = 1024;
const header = "# GRUB Environment Block\n";

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 4) fail("usage: grub-setenv FILE NAME VALUE", .{});
    const path = args[1];

    var f = Io.Dir.cwd().openFile(io, path, .{ .mode = .read_write }) catch |err|
        fail("grub-setenv: {s}: {s}", .{ path, @errorName(err) });
    defer f.close(io);
    var old: [size + 1]u8 = undefined;
    const n = f.readPositionalAll(
        io,
        &old,
        0,
    ) catch |err| fail("grub-setenv: {s}: {s}", .{ path, @errorName(err) });
    var new: [size]u8 = undefined;
    edit(old[0..n], args[2], args[3], &new) catch |err| switch (err) {
        error.NotABlock => fail("grub-setenv: {s} is not a GRUB environment block", .{path}),
        error.BadName,
        error.BadValue,
        => fail("grub-setenv: {s}={s} cannot be stored", .{ args[2], args[3] }),
        error.Overflow => fail("grub-setenv: {s} would overflow", .{path}),
    };
    f.writePositionalAll(
        io,
        &new,
        0,
    ) catch |err| fail("grub-setenv: {s}: {s}", .{ path, @errorName(err) });
    f.sync(io) catch |err| fail("grub-setenv: {s}: {s}", .{ path, @errorName(err) });
}

fn fail(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print(fmt ++ "\n", args);
    std.process.exit(1);
}

/// old, with name set to value: the header, every other variable in its
/// order, name=value last, and '#' to the end.
fn edit(old: []const u8, name: []const u8, value: []const u8, out: *[size]u8) !void {
    if (old.len != size or !std.mem.startsWith(u8, old, header)) return error.NotABlock;
    if (name.len == 0 or std.mem.indexOfAny(u8, name, "=\n#") != null or
        name[0] == '#') return error.BadName;
    if (std.mem.findScalar(u8, value, '\n') != null) return error.BadValue;

    var w: Io.Writer = .fixed(out);
    w.writeAll(header) catch return error.Overflow;
    var lines = std.mem.splitScalar(u8, old[header.len..], '\n');
    while (lines.next()) |line| {
        // Padding, comments and the variable being set are dropped; the
        // padding has no newline, so it is the last "line".
        if (line.len == 0 or line[0] == '#') continue;
        if (std.mem.startsWith(u8, line, name) and line.len > name.len and
            line[name.len] == '=') continue;
        w.print("{s}\n", .{line}) catch return error.Overflow;
    }
    w.print("{s}={s}\n", .{ name, value }) catch return error.Overflow;
    @memset(out[w.end..], '#');
}

// --- tests -------------------------------------------------------------------

const testing = std.testing;

fn block(vars: []const u8) [size]u8 {
    var b: [size]u8 = @splat('#');
    @memcpy(b[0..header.len], header);
    @memcpy(b[header.len..][0..vars.len], vars);
    return b;
}

test edit {
    var out: [size]u8 = undefined;
    const old = block("saved_entry=werewolf-a\nnext_entry=werewolf-b\n");

    try edit(&old, "saved_entry", "werewolf-b", &out);
    try testing.expectEqualSlices(
        u8,
        &block("next_entry=werewolf-b\nsaved_entry=werewolf-b\n"),
        &out,
    );

    // A new variable goes last; a name that is a prefix of another leaves it.
    try edit(&old, "saved", "x", &out);
    try testing.expectEqualSlices(
        u8,
        &block("saved_entry=werewolf-a\nnext_entry=werewolf-b\nsaved=x\n"),
        &out,
    );

    // An empty value clears it, as GRUB's own save_env does.
    try edit(&old, "next_entry", "", &out);
    try testing.expectEqualSlices(u8, &block("saved_entry=werewolf-a\nnext_entry=\n"), &out);
}

test "refusals" {
    var out: [size]u8 = undefined;
    const old = block("");
    try testing.expectError(error.NotABlock, edit(old[0 .. size - 1], "a", "b", &out));
    var bad = old;
    bad[0] = 'x';
    try testing.expectError(error.NotABlock, edit(&bad, "a", "b", &out));
    try testing.expectError(error.BadName, edit(&old, "a=b", "c", &out));
    try testing.expectError(error.BadName, edit(&old, "#a", "c", &out));
    try testing.expectError(error.BadName, edit(&old, "", "c", &out));
    try testing.expectError(error.BadValue, edit(&old, "a", "b\nc=d", &out));
    const long: [size]u8 = @splat('v');
    try testing.expectError(error.Overflow, edit(&old, "a", &long, &out));
}
