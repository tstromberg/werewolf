//! remote-qemu HOST QEMU ARG... runs QEMU on HOST, a Linux machine with KVM
//! that ssh reaches, as though it ran here: whoever starts it keeps QEMU's
//! standard input and output, its console (make QEMU_HOST=gandalf ARCH=x86_64
//! check-...). It first copies the files the arguments name (-kernel, -initrd,
//! -drive file=) to HOST's ~/.cache/werewolf-qemu, each only when it is not
//! what the copy came from, so a run's second boot finds on its data disk
//! what the first wrote there. A hostfwd to 127.0.0.1:PORT is forwarded on
//! from here, for host suites. QEMU runs on a terminal in raw mode, which
//! passes its bytes unchanged, and ends with the connection when its caller
//! stops ssh. Nothing but QEMU's console goes to standard output.
const std = @import("std");
const Io = std.Io;
const mem = std.mem;
const Allocator = mem.Allocator;

/// cache is where HOST keeps the copies, beneath the home ssh starts in.
const cache = ".cache/werewolf-qemu";

/// Copy is a file QEMU takes and its copy on HOST, NAME in cache, whose
/// NAME.from holds the line NAME FROM once the copy is whole.
const Copy = struct { local: []const u8, name: []const u8, from: []const u8 };

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(a);
    if (args.len < 3) std.process.fatal("usage: remote-qemu HOST QEMU ARG...", .{});
    const host = args[1];
    const qemu = try a.dupe([]const u8, args[2..]);
    var copies: std.ArrayList(Copy) = .empty;
    var i: usize = 1;
    while (i + 1 < qemu.len) : (i += 1) {
        const flag = qemu[i];
        if (mem.eql(u8, flag, "-kernel") or mem.eql(u8, flag, "-initrd")) {
            i += 1;
            qemu[i] = try copy(io, a, &copies, qemu[i]);
        } else if (mem.eql(u8, flag, "-drive")) {
            i += 1;
            const path = drivePath(qemu[i]) orelse continue;
            qemu[i] = try mem.replaceOwned(u8, a, qemu[i], path, try copy(io, a, &copies, path));
        }
    }
    const held = try ssh(io, a, host, try listing(a, copies.items));
    for (copies.items) |c| if (!holds(held, c)) try send(io, a, host, c);

    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(a, &.{ "ssh", "-tt", "-e", "none", "-o", "BatchMode=yes" });
    try argv.appendSlice(a, &.{ "-o", "ExitOnForwardFailure=yes", "-o", "LogLevel=ERROR" });
    for (qemu) |arg| {
        var rest = arg;
        while (forward(rest)) |f| : (rest = f.rest) {
            const local = try a.print("{s}:127.0.0.1:{s}", .{ f.port, f.port });
            try argv.appendSlice(a, &.{ "-L", local });
        }
    }
    var command: Io.Writer.Allocating = .init(a);
    try command.writer.writeAll("stty raw -echo && exec");
    for (qemu) |arg| {
        try command.writer.writeByte(' ');
        try quote(&command.writer, arg);
    }
    try argv.appendSlice(a, &.{ host, command.written() });
    return std.process.replace(io, .{ .argv = argv.items });
}

/// copy adds path to copies and returns where QEMU on HOST finds it: NAME
/// is a digest of the full path, so each file here has one copy there.
fn copy(io: Io, a: Allocator, copies: *std.ArrayList(Copy), path: []const u8) ![]const u8 {
    const full = try Io.Dir.cwd().realPathFileAlloc(io, path, a);
    const st = try Io.Dir.cwd().statFile(io, full, .{});
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(full, &digest, .{});
    const name = try a.print("{x}-{s}", .{ digest[0..8], std.fs.path.basename(full) });
    const there = try a.print("{s}/{s}", .{ cache, name });
    for (copies.items) |c| if (mem.eql(u8, c.name, name)) return there;
    const from = try a.print("{d}:{d}:{d}", .{ st.inode, st.size, st.mtime.toNanoseconds() });
    try copies.append(a, .{ .local = full, .name = name, .from = from });
    return there;
}

/// drivePath is the file a -drive's options name.
fn drivePath(options: []const u8) ?[]const u8 {
    var it = mem.splitScalar(u8, options, ',');
    while (it.next()) |option| if (mem.cutPrefix(u8, option, "file=")) |path| return path;
    return null;
}

/// listing is the command that prints the copies' .from lines.
fn listing(a: Allocator, copies: []const Copy) ![]const u8 {
    var out: Io.Writer.Allocating = .init(a);
    try out.writer.print("mkdir -p {s} && cd {s} && cat", .{ cache, cache });
    for (copies) |c| {
        try out.writer.writeByte(' ');
        try quote(&out.writer, try a.print("{s}.from", .{c.name}));
    }
    try out.writer.writeAll(" 2>/dev/null; true");
    return out.written();
}

fn holds(held: []const u8, c: Copy) bool {
    var lines = mem.splitScalar(u8, held, '\n');
    while (lines.next()) |line| {
        const name, const from = mem.cutScalar(u8, line, ' ') orelse continue;
        if (mem.eql(u8, name, c.name) and mem.eql(u8, from, c.from)) return true;
    }
    return false;
}

/// send copies c to HOST through zstd, which writes a disk's holes as holes.
fn send(io: Io, a: Allocator, host: []const u8, c: Copy) !void {
    var out: Io.Writer.Allocating = .init(a);
    const part = try a.print("{s}.part", .{c.name});
    try out.writer.print("cd {s} && rm -f ", .{cache});
    try quote(&out.writer, try a.print("{s}.from", .{c.name}));
    try out.writer.writeAll(" && zstd -q -d -f --sparse -o ");
    try quote(&out.writer, part);
    try out.writer.writeAll(" && mv -f ");
    try quote(&out.writer, part);
    try out.writer.writeByte(' ');
    try quote(&out.writer, c.name);
    try out.writer.writeAll(" && echo ");
    try quote(&out.writer, try a.print("{s} {s}", .{ c.name, c.from }));
    try out.writer.writeAll(" >");
    try quote(&out.writer, try a.print("{s}.from", .{c.name}));
    const start = Io.Clock.awake.now(io);
    var zstd = try std.process.spawn(io, .{
        .argv = &.{ "zstd", "-q", "-1", "-T0", "-c", c.local },
        .stdin = .ignore,
        .stdout = .pipe,
    });
    defer zstd.kill(io);
    var remote = try std.process.spawn(io, .{
        .argv = &.{ "ssh", "-o", "BatchMode=yes", host, out.written() },
        .stdin = .{ .file = zstd.stdout.? },
        .stdout = .ignore,
    });
    zstd.stdout.?.close(io);
    zstd.stdout = null;
    const sent = try remote.wait(io);
    const squeezed = try zstd.wait(io);
    if (sent != .exited or sent.exited != 0 or squeezed != .exited or squeezed.exited != 0)
        std.process.fatal("remote-qemu: could not copy {s} to {s}", .{ c.local, host });
    const took = start.durationTo(Io.Clock.awake.now(io)).toSeconds();
    std.debug.print("remote-qemu: copied {s} to {s} in {d}s\n", .{ c.local, host, took });
}

fn ssh(io: Io, a: Allocator, host: []const u8, command: []const u8) ![]const u8 {
    const r = try std.process.run(a, io, .{
        .argv = &.{ "ssh", "-o", "BatchMode=yes", host, command },
        .stdout_limit = .limited(1 << 20),
        .stderr_limit = .limited(64 << 10),
    });
    if (r.term != .exited or r.term.exited != 0)
        std.process.fatal("remote-qemu: {s}: {s}", .{ host, r.stderr });
    return r.stdout;
}

/// forward finds the next hostfwd to 127.0.0.1:PORT in arg.
fn forward(arg: []const u8) ?struct { port: []const u8, rest: []const u8 } {
    _, const after = mem.cut(u8, arg, "hostfwd=tcp:127.0.0.1:") orelse return null;
    const end = mem.findNone(u8, after, "0123456789") orelse after.len;
    if (end == 0) return forward(after);
    return .{ .port = after[0..end], .rest = after[end..] };
}

/// quote writes s as one word of a POSIX shell.
fn quote(w: *Io.Writer, s: []const u8) !void {
    try w.writeByte('\'');
    for (s) |c| if (c == '\'') try w.writeAll("'\\''") else try w.writeByte(c);
    try w.writeByte('\'');
}

test "a drive's file is the one QEMU opens" {
    const t = std.testing;
    try t.expectEqualStrings(
        "build/data.img",
        drivePath("file=build/data.img,format=raw,if=virtio").?,
    );
    try t.expectEqualStrings("p.tar", drivePath("format=raw,file=p.tar,readonly=on").?);
    try t.expectEqual(null, drivePath("if=none,id=d0"));
}

test "every forward to loopback is found" {
    const t = std.testing;
    const arg = "user,id=n0,hostfwd=tcp:127.0.0.1:24200-:22,hostfwd=tcp:127.0.0.1:8443-:443";
    const first = forward(arg).?;
    try t.expectEqualStrings("24200", first.port);
    try t.expectEqualStrings("8443", forward(first.rest).?.port);
    try t.expectEqual(null, forward(forward(first.rest).?.rest));
    try t.expectEqual(null, forward("user,id=n0,hostfwd=tcp::2222-:22"));
}

test "quoted words survive a shell" {
    const t = std.testing;
    var out: Io.Writer.Allocating = .init(t.allocator);
    defer out.deinit();
    try quote(&out.writer, "console=ttyS0 it's");
    try t.expectEqualStrings("'console=ttyS0 it'\\''s'", out.written());
}

test "a copy is held only as it came" {
    const c: Copy = .{ .local = "/x/data.img", .name = "ab-data.img", .from = "7:4096:1" };
    try std.testing.expect(holds("ab-other 1:1:1\nab-data.img 7:4096:1\n", c));
    try std.testing.expect(!holds("ab-data.img 7:4096:2\n", c));
    try std.testing.expect(!holds("", c));
}
