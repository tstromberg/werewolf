//! grub-setenv sets one variable in GRUB's environment block, in place.
//!
//!     grub-setenv FILE NAME VALUE
//!
//! See README.md.

const std = @import("std");
const Io = std.Io;
const linux = std.os.linux;

const size = 1024;
const header = "# GRUB Environment Block\n";

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 4) fail("usage: grub-setenv FILE NAME VALUE", .{});
    const path = args[1];

    var f = Io.Dir.cwd().openFile(
        io,
        path,
        .{ .mode = .read_write, .follow_symlinks = false },
    ) catch |err| fail("{s}: {s}", .{ path, @errorName(err) });
    defer f.close(io);
    const st = f.stat(io) catch |err| fail("{s}: {s}", .{ path, @errorName(err) });
    if (st.kind != .file) fail("{s} is not a regular file", .{path});
    var old: [size + 1]u8 = undefined;
    const n = f.readPositionalAll(io, &old, 0) catch |err|
        fail("{s}: {s}", .{ path, @errorName(err) });
    var new: [size]u8 = undefined;
    edit(old[0..n], args[2], args[3], &new) catch |err| switch (err) {
        error.NotABlock => fail("{s} is not a GRUB environment block", .{path}),
        error.BadName => fail("{s}: a name is letters, digits and _", .{args[2]}),
        error.BadValue => fail("{s}: a value has no newline or backslash", .{args[2]}),
        error.Overflow => fail("{s} would overflow", .{path}),
    };
    // GRUB reads the block's sectors directly, not through the journal, so
    // overwrite them in place rather than rename a new file over it.
    f.writePositionalAll(io, &new, 0) catch |err| fail("{s}: {s}", .{ path, @errorName(err) });
    // btrfs answers fsync from a log GRUB never replays; only syncfs commits
    // the block where GRUB reads it.
    f.sync(io) catch |err| fail("{s}: {s}", .{ path, @errorName(err) });
    if (linux.errno(linux.syscall1(.syncfs, @intCast(f.handle))) != .SUCCESS)
        fail("{s}: its filesystem could not be synced", .{path});
}

fn fail(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print("grub-setenv: " ++ fmt ++ "\n", args);
    std.process.exit(1);
}

/// edit writes old to out with name set to value. Like GRUB's save_env, it
/// keeps the variable's position, or appends it if absent, and keeps the
/// others byte for byte, so a same-length value changes only its own bytes.
/// It returns an error for a bad block, name or value, or if out overflows.
fn edit(old: []const u8, name: []const u8, value: []const u8, out: *[size]u8) !void {
    if (old.len != size or !std.mem.startsWith(u8, old, header)) return error.NotABlock;
    if (name.len == 0) return error.BadName;
    for (name) |c| if (!std.ascii.isAlphanumeric(c) and c != '_') return error.BadName;
    if (std.mem.findAny(u8, value, "\n\\") != null) return error.BadValue;

    var w: Io.Writer = .fixed(out);
    w.writeAll(header) catch return error.Overflow;
    var at: usize = header.len;
    var set = false;
    while (nextEntry(old, &at)) |entry| {
        // Drop comments and padding. The padding has no newline, so it is
        // the last entry.
        if (entry.len == 0 or entry[0] == '#') continue;
        if (std.mem.startsWith(u8, entry, name) and entry.len > name.len and
            entry[name.len] == '=')
        {
            // Set it at its first entry; drop any duplicate.
            if (!set) w.print("{s}={s}\n", .{ name, value }) catch return error.Overflow;
            set = true;
            continue;
        }
        w.print("{s}\n", .{entry}) catch return error.Overflow;
    }
    if (!set) w.print("{s}={s}\n", .{ name, value }) catch return error.Overflow;
    @memset(out[w.end..], '#');
}

/// nextEntry returns the entry at `at.*` in env, up to the next unescaped
/// newline, and moves `at.*` past it. It returns null at the end. A backslash
/// escapes the next byte, as GRUB reads it.
fn nextEntry(env: []const u8, at: *usize) ?[]const u8 {
    if (at.* >= env.len) return null;
    const start = at.*;
    var i = start;
    while (i < env.len) : (i += 1) {
        if (env[i] == '\\') {
            i += 1;
        } else if (env[i] == '\n') {
            at.* = i + 1;
            return env[start..i];
        }
    }
    at.* = env.len;
    return env[start..];
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

    // A same-length value changes only its own bytes.
    try edit(&old, "saved_entry", "werewolf-b", &out);
    try testing.expectEqualSlices(
        u8,
        &block("saved_entry=werewolf-b\nnext_entry=werewolf-b\n"),
        &out,
    );
    var changed: usize = 0;
    for (old, out) |a, b| changed += @intFromBool(a != b);
    try testing.expectEqual(1, changed);

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

    // Kernel arguments, as slot-update stores them for a slot.
    try edit(&old, "werewolf_args_b", "console=ttyS0 panic=10 werewolf.slot=b", &out);
    try testing.expect(std.mem.find(
        u8,
        &out,
        "werewolf_args_b=console=ttyS0 panic=10 werewolf.slot=b\n",
    ) != null);
}

test "a value GRUB escaped stays one variable" {
    var out: [size]u8 = undefined;
    // grub-editenv stores a newline in a value as a backslash and the newline.
    const old = block("kernelopts=a\\\nb\nsaved_entry=werewolf-a\n");
    // Setting another variable keeps the escaped value whole.
    try edit(&old, "next_entry", "werewolf-b", &out);
    try testing.expectEqualSlices(
        u8,
        &block("kernelopts=a\\\nb\nsaved_entry=werewolf-a\nnext_entry=werewolf-b\n"),
        &out,
    );
    // Setting that variable replaces its whole entry, not just the first line.
    try edit(&old, "kernelopts", "c", &out);
    try testing.expectEqualSlices(
        u8,
        &block("kernelopts=c\nsaved_entry=werewolf-a\n"),
        &out,
    );
    // A duplicate variable, which no writer should leave, is set once at
    // the first entry.
    const twice = block("a=1\nb=2\na=3\n");
    try edit(&twice, "a", "4", &out);
    try testing.expectEqualSlices(u8, &block("a=4\nb=2\n"), &out);
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
    try testing.expectError(error.BadName, edit(&old, "a b", "c", &out));
    try testing.expectError(error.BadName, edit(&old, "a\\", "c", &out));
    try testing.expectError(error.BadValue, edit(&old, "a", "b\nc=d", &out));
    // A trailing backslash would make GRUB read the next variable as this one.
    try testing.expectError(error.BadValue, edit(&old, "a", "b\\", &out));
    const long: [size]u8 = @splat('v');
    try testing.expectError(error.Overflow, edit(&old, "a", &long, &out));
}

test nextEntry {
    const b = "a=1\nb=x\\\ny\nc=\\\\\n###";
    var at: usize = 0;
    try testing.expectEqualStrings("a=1", nextEntry(b, &at).?);
    try testing.expectEqualStrings("b=x\\\ny", nextEntry(b, &at).?);
    try testing.expectEqualStrings("c=\\\\", nextEntry(b, &at).?);
    try testing.expectEqualStrings("###", nextEntry(b, &at).?);
    try testing.expectEqual(null, nextEntry(b, &at));
    // A trailing backslash escapes nothing and stays.
    at = 0;
    try testing.expectEqualStrings("x\\", nextEntry("x\\", &at).?);
}
