//! popen-shim.so: popen(3), pclose(3) and system(3) without a shell, for
//! PostgreSQL's initdb alone.
//!
//! initdb starts the server it is setting up through popen and system,
//! which glibc runs as `/bin/sh -c COMMAND`; werewolf has no /bin/sh.
//! pg-init (forms/postgresql/cmd/pg-init/pg-init.zig) loads this library into initdb with
//! LD_PRELOAD. It takes the commands initdb builds, of one shape only:
//!
//!     "/usr/libexec/postgresql17/postgres" --boot -F -c log_checkpoints=false
//!     "/usr/libexec/postgresql17/postgres" --single -F -O -j template1 >/dev/null
//!     "/usr/libexec/postgresql17/postgres" --check -c max_connections=100 < "/dev/null" >
//! "/dev/null" 2>&1
//!
//! that is, an absolute program and plain words, either of which may be in
//! double quotes, and then the redirections </dev/null, >/dev/null and 2>&1,
//! the one file initdb ever names, so the library never creates a file. It runs
//! the program itself, with no shell between, with the words a shell would
//! have given it. A command with anything else (a pipe, a ;, a $ or ` or \
//! even in double quotes, a glob outside them, a quote of the other kind)
//! is not run: popen returns NULL and system -1, with errno ENOEXEC, and the
//! command is said on stderr, so initdb fails where it can be seen.
//!
//! The servers initdb starts keep the library: setting up the cluster, one
//! of them runs `locale -a` through popen, to import the system's locales
//! as collations. There are none here (PostgreSQL's own C and POSIX need
//! no import), so that one command reads as empty. The server leash starts
//! afterwards is not one of them, and never has the library.

const std = @import("std");
const linux = std.os.linux;

const FILE = opaque {}; // ziglint-ignore: Z032
extern "c" fn fdopen(fd: c_int, mode: [*:0]const u8) ?*FILE;
extern "c" fn fclose(stream: *FILE) c_int;
extern "c" fn fileno(stream: *FILE) c_int;
extern "c" var environ: [*:null]?[*:0]u8;

const max_words = 64;
const max_command = 4096;

/// A command, parsed: argv, whether stdin and stdout are /dev/null, and
/// whether stderr follows stdout.
const Command = struct {
    buf: [max_command + 1]u8 = undefined,
    argv: [max_words + 1]?[*:0]const u8 = @splat(null),
    in: bool = false,
    out: bool = false,
    err_to_out: bool = false,
};

/// command into c, or false if it is not of the one shape taken.
fn parse(command: []const u8, c: *Command) bool {
    if (command.len > max_command) return false;
    var n: usize = 0; // words
    var used: usize = 0; // bytes of c.buf
    var i: usize = 0;
    // What the next word is: an argument, or a file to redirect from or to.
    var next: enum { arg, in, out } = .arg;
    while (true) {
        while (i < command.len and (command[i] == ' ' or command[i] == '\t')) i += 1;
        if (i == command.len) break;
        if (next == .arg) {
            if (std.mem.startsWith(u8, command[i..], "2>&1")) {
                if (!c.out) return false; // only after >/dev/null, as initdb writes it
                c.err_to_out = true;
                i += 4;
                continue;
            }
            if (command[i] == '<' or command[i] == '>') {
                next = if (command[i] == '<') .in else .out;
                i += 1;
                continue;
            }
            if (c.in or c.out) return false; // words after a redirection
        }
        // A word: in double quotes, or plain.
        var word: []const u8 = undefined;
        if (command[i] == '"') {
            const end = std.mem.findScalarPos(u8, command, i + 1, '"') orelse return false;
            word = command[i + 1 .. end];
            i = end + 1;
            if (i < command.len and command[i] != ' ' and command[i] != '\t') return false;
        } else {
            const begin = i;
            while (i < command.len and command[i] != ' ' and command[i] != '\t') : (i += 1) {
                if (!isPlain(command[i])) return false;
            }
            word = command[begin..i];
        }
        // What a shell reads specially even in double quotes, and controls.
        for (word) |ch| switch (ch) {
            0...0x1f, 0x7f, '"', '$', '`', '\\' => return false,
            else => {},
        };
        switch (next) {
            .arg => {
                if (n == max_words or used + word.len + 1 > c.buf.len) return false;
                @memcpy(c.buf[used..][0..word.len], word);
                c.buf[used + word.len] = 0;
                c.argv[n] = @ptrCast(&c.buf[used]);
                used += word.len + 1;
                n += 1;
            },
            // Only the file initdb names, once each.
            .in, .out => {
                const seen = if (next == .in) &c.in else &c.out;
                if (seen.* or !std.mem.eql(u8, word, "/dev/null")) return false;
                seen.* = true;
            },
        }
        next = .arg;
    }
    if (next != .arg or n == 0) return false;
    // The program by its full path: no PATH to search, as no shell would.
    // span's slice ends in its NUL, so an empty program reads as 0 here.
    return std.mem.span(c.argv[0].?)[0] == '/';
}

/// What a plain word may hold: none of what a shell would read as more
/// than a character.
fn isPlain(ch: u8) bool {
    return switch (ch) {
        '|',
        '&',
        ';',
        '<',
        '>',
        '(',
        ')',
        '$',
        '`',
        '\\',
        '\'',
        '"',
        '*',
        '?',
        '[',
        ']',
        '{',
        '}',
        '~',
        '#',
        '!',
        '\n',
        '\r',
        => false,
        else => ch > 0x20 and ch < 0x7f,
    };
}

/// Start c, with stdin or stdout (which) on the pipe end fd, if any.
/// The child's pid, or null with errno set.
fn start(c: *const Command, pipe_end: ?struct { fd: i32, which: i32 }) ?linux.pid_t {
    const pid = linux.fork();
    if (linux.errno(pid) != .SUCCESS) {
        setErrno(linux.errno(pid));
        return null;
    }
    if (pid == 0) {
        // The child: only system calls until it becomes the command. A pipe
        // end that is already the descriptor it should be (the caller had
        // closed it) only loses close-on-exec.
        if (pipe_end) |p| {
            if (p.fd == p.which)
                _ = linux.fcntl(p.fd, linux.F.SETFD, 0)
            else
                _ = linux.dup3(p.fd, p.which, 0);
        }
        if (c.in) toNull(.RDONLY, 0);
        if (c.out) toNull(.WRONLY, 1);
        if (c.err_to_out) _ = linux.dup3(1, 2, 0);
        _ = linux.execve(c.argv[0].?, @ptrCast(&c.argv), @ptrCast(environ));
        linux.exit_group(127);
    }
    return @intCast(pid);
}

/// /dev/null opened onto descriptor to, or the child ends as a shell's
/// would. Opened as the lowest free descriptor, it may be to already.
fn toNull(mode: @FieldType(linux.O, "ACCMODE"), to: i32) void {
    const rc = linux.open("/dev/null", .{ .ACCMODE = mode }, 0);
    if (linux.errno(rc) != .SUCCESS) linux.exit_group(127);
    const fd: i32 = @intCast(rc);
    if (fd == to) return;
    _ = linux.dup3(fd, to, 0);
    _ = linux.close(fd);
}

fn wait(pid: linux.pid_t) c_int {
    var status: i32 = 0;
    while (true) {
        const rc = linux.wait4(pid, &status, 0, null);
        switch (linux.errno(rc)) {
            .SUCCESS => return status,
            .INTR => continue,
            else => |e| {
                setErrno(e);
                return -1;
            },
        }
    }
}

fn setErrno(e: linux.E) void {
    std.c._errno().* = @backingInt(e);
}

/// Say on stderr that command was not run, its first max_command bytes
/// with every control character as ?, so a command cannot write to the
/// terminal or log it is shown on; and set errno.
fn refuse(command: [*:0]const u8) void {
    const prefix = "popen-shim: not run, not a command of initdb's shape: ";
    var buf: [prefix.len + max_command + 1]u8 = undefined;
    const cmd = std.mem.span(command);
    const shown = cmd[0..@min(cmd.len, max_command)];
    @memcpy(buf[0..prefix.len], prefix);
    for (shown, buf[prefix.len..][0..shown.len]) |ch, *o| o.* = if (ch < 0x20 or ch == 0x7f)
        '?'
    else
        ch;
    buf[prefix.len + shown.len] = '\n';
    _ = linux.write(2, &buf, prefix.len + shown.len + 1);
    setErrno(.NOEXEC);
}

/// The streams popen has open, and the children behind them: none, pid 0,
/// for `locale -a`.
var open_streams: [8]struct { stream: ?*FILE = null, pid: linux.pid_t = 0 } = @splat(.{});

export fn popen(command: [*:0]const u8, mode: [*:0]const u8) ?*FILE {
    const reading = mode[0] == 'r';
    if (!reading and mode[0] != 'w') {
        setErrno(.INVAL);
        return null;
    }
    const slot = for (&open_streams) |*s| {
        if (s.stream == null) break s;
    } else {
        setErrno(.MFILE);
        return null;
    };
    // The system's locales, of which there are none.
    if (reading and std.mem.eql(u8, std.mem.span(command), "locale -a")) {
        const fd = linux.open("/dev/null", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
        if (linux.errno(fd) != .SUCCESS) {
            setErrno(linux.errno(fd));
            return null;
        }
        const stream = fdopen(@intCast(fd), "r") orelse {
            _ = linux.close(@intCast(fd));
            return null;
        };
        slot.* = .{ .stream = stream, .pid = 0 };
        return stream;
    }
    var c: Command = .{};
    if (!parse(std.mem.span(command), &c)) {
        refuse(command);
        return null;
    }
    var fds: [2]i32 = undefined;
    const piped = linux.pipe2(&fds, .{ .CLOEXEC = true });
    if (linux.errno(piped) != .SUCCESS) {
        setErrno(linux.errno(piped));
        return null;
    }
    // Reading: the child writes stdout into fds[1]. Writing: it reads
    // stdin from fds[0].
    const theirs = if (reading) fds[1] else fds[0];
    const ours = if (reading) fds[0] else fds[1];
    const pid = start(&c, .{ .fd = theirs, .which = if (reading) 1 else 0 }) orelse {
        _ = linux.close(fds[0]);
        _ = linux.close(fds[1]);
        return null;
    };
    _ = linux.close(theirs);
    const stream = fdopen(ours, if (reading) "r" else "w") orelse {
        _ = linux.close(ours);
        _ = wait(pid);
        return null;
    };
    slot.* = .{ .stream = stream, .pid = pid };
    return stream;
}

export fn pclose(stream: *FILE) c_int {
    for (&open_streams) |*s| {
        if (s.stream != stream) continue;
        const pid = s.pid;
        s.* = .{};
        _ = fclose(stream);
        // `locale -a`, which ran nothing, ends as a command that succeeded.
        return if (pid == 0) 0 else wait(pid);
    }
    // Not a stream popen opened: as glibc, ECHILD, and the stream untouched.
    setErrno(.CHILD);
    return -1;
}

export fn system(command: ?[*:0]const u8) c_int {
    const cmd = command orelse return 1; // a command processor is here
    var c: Command = .{};
    if (!parse(std.mem.span(cmd), &c)) {
        refuse(cmd);
        return -1;
    }
    const pid = start(&c, null) orelse return -1;
    return wait(pid);
}

// --- tests -------------------------------------------------------------------

const testing = std.testing;

fn argvOf(c: *const Command) []const [*:0]const u8 {
    var n: usize = 0;
    while (c.argv[n] != null) n += 1;
    return @ptrCast(c.argv[0..n]);
}

test "initdb's commands" {
    var c: Command = .{};
    try testing.expect(parse(
        "\"/usr/libexec/postgresql17/postgres\" --boot -F -c log_checkpoints=false",
        &c,
    ));
    const a = argvOf(&c);
    try testing.expectEqual(5, a.len);
    try testing.expectEqualStrings("/usr/libexec/postgresql17/postgres", std.mem.span(a[0]));
    try testing.expectEqualStrings("log_checkpoints=false", std.mem.span(a[4]));

    c = .{};
    try testing.expect(parse("\"/usr/bin/postgres\" --single -F -O -j template1 >/dev/null", &c));
    try testing.expect(c.out and !c.in);
    try testing.expect(!c.err_to_out);

    c = .{};
    try testing.expect(parse(
        "\"/usr/bin/postgres\" --check -c max_connections=100 -c dynamic_shared_memory_type=posi" ++
            "x < \"/dev/null\" > \"/dev/null\" 2>&1",
        &c,
    ));
    try testing.expect(c.in and c.out);
    try testing.expect(c.err_to_out);

    c = .{};
    try testing.expect(parse("\"/usr/bin/postgres\" -V", &c));
}

test "anything else is not run" {
    const refused = [_][]const u8{
        "postgres -V", // no full path
        "\"/usr/bin/postgres\" -V | /usr/bin/x",
        "\"/usr/bin/postgres\" -V; /usr/bin/x",
        "\"/usr/bin/postgres\" $HOME",
        "\"/usr/bin/postgres\" `x`",
        "\"/usr/bin/postgres\" 'a b'",
        "\"/usr/bin/postgres\" *",
        "\"/usr/bin/postgres\" -V && /usr/bin/x",
        "\"/usr/bin/postgres\" > /dev/null extra",
        "\"/usr/bin/postgres\" 2>&1", // stderr into a stdout never redirected
        "\"/usr/bin/postgres\" > a > b",
        "\"/usr/bin/postgres\" >",
        "\"/usr/bin/post\"gres\"",
        "\"/usr/bin/postgres",
        "",
        "   ",
        "/usr/bin/postgres\n/usr/bin/x",
        // What a shell reads even in double quotes.
        "\"/usr/bin/postgres\" \"$HOME\"",
        "\"/usr/bin/postgres\" \"`id`\"",
        "\"/usr/bin/postgres\" \"a\\b\"",
        "\"/usr/bin/$x\"",
        // No program, or not by its full path.
        "\"\"",
        "\"\" -V",
        "./postgres",
        "usr/bin/postgres",
        // Redirections initdb never writes.
        "/usr/bin/postgres >>/tmp/x",
        "/usr/bin/postgres 2>/tmp/x",
        "/usr/bin/postgres 2>&1 >/tmp/x",
        "/usr/bin/postgres >/tmp/x 2>&1 -V",
        "/usr/bin/postgres </tmp/a </tmp/b",
        "/usr/bin/postgres <",
        "/usr/bin/postgres < >/tmp/x",
        "/usr/bin/postgres >/tmp/x <",
        // Any file but /dev/null: none to create, truncate or read.
        "/usr/bin/postgres >/tmp/x",
        "/usr/bin/postgres </etc/shadow",
        "/usr/bin/postgres >\"/tmp/x\"",
        "/usr/bin/postgres >/dev/null/",
        "/usr/bin/postgres >/dev/null2",
        "/usr/bin/postgres >dev/null",
        "/usr/bin/postgres >/dev/./null",
        "/usr/bin/postgres </dev/null </dev/null",
        "/usr/bin/postgres >/dev/null >/dev/null",
        // Quotes that a shell would join or read otherwise.
        "/usr/bin/postgres a\"b\"",
        "/usr/bin/postgres \"a\"b",
        "/usr/bin/postgres 'a'",
        // Globs, groups, expansions, comments, history, background.
        "/usr/bin/postgres a?",
        "/usr/bin/postgres [a]",
        "/usr/bin/postgres {a,b}",
        "/usr/bin/postgres (a)",
        "/usr/bin/postgres ~",
        "/usr/bin/postgres #c",
        "/usr/bin/postgres a!",
        "/usr/bin/postgres a &",
        // Controls and what is not ASCII, outside quotes or in them.
        "/usr/bin/postgres a\rb",
        "/usr/bin/postgres \"a\x01b\"",
        "/usr/bin/postgres \"a\x7fb\"",
        "/usr/bin/postgres \x7f",
        "/usr/bin/postgres \xc3\xa9",
    };
    for (refused) |cmd| {
        var c: Command = .{};
        testing.expect(!parse(cmd, &c)) catch |err| {
            std.debug.print("accepted: {s}\n", .{cmd});
            return err;
        };
    }
}

test "accepted commands, word for word" {
    const Case = struct {
        cmd: []const u8,
        argv: []const []const u8,
        in: bool = false,
        out: bool = false,
        err: bool = false,
    };
    const cases = [_]Case{
        .{ .cmd = "/bin/x a\tb  c", .argv = &.{ "/bin/x", "a", "b", "c" } },
        .{ .cmd = "\"/bin/x\" \"a b\" \"\"", .argv = &.{ "/bin/x", "a b", "" } },
        .{ .cmd = "/bin/x >/dev/null", .argv = &.{"/bin/x"}, .out = true },
        .{ .cmd = "/bin/x </dev/null", .argv = &.{"/bin/x"}, .in = true },
        .{
            .cmd = "/bin/x > \"/dev/null\" < \"/dev/null\" 2>&1",
            .argv = &.{"/bin/x"},
            .in = true,
            .out = true,
            .err = true,
        },
        .{ .cmd = "/bin/x -c=1,2:3@4%5+6^7.8_9/", .argv = &.{ "/bin/x", "-c=1,2:3@4%5+6^7.8_9/" } },
        // In double quotes a shell takes these as they are.
        .{
            .cmd = "/bin/x \"a|b;c&d*e?f[g]h{i}~#!'(j)<k>\"",
            .argv = &.{ "/bin/x", "a|b;c&d*e?f[g]h{i}~#!'(j)<k>" },
        },
        .{ .cmd = "/bin/x \"\xc3\xa9\"", .argv = &.{ "/bin/x", "\xc3\xa9" } },
    };
    for (cases) |k| {
        var c: Command = .{};
        testing.expect(parse(k.cmd, &c)) catch |err| {
            std.debug.print("refused: {s}\n", .{k.cmd});
            return err;
        };
        const a = argvOf(&c);
        try testing.expectEqual(k.argv.len, a.len);
        for (k.argv, a) |want, got| try testing.expectEqualStrings(want, std.mem.span(got));
        try testing.expectEqual(k.in, c.in);
        try testing.expectEqual(k.out, c.out);
        try testing.expectEqual(k.err, c.err_to_out);
    }
}

test "as many words and bytes as there is room for, and no more" {
    var cmd: std.ArrayList(u8) = .empty;
    defer cmd.deinit(testing.allocator);
    try cmd.appendSlice(testing.allocator, "/bin/x");
    for (1..max_words) |_| try cmd.appendSlice(testing.allocator, " a");
    var c: Command = .{};
    try testing.expect(parse(cmd.items, &c));
    try testing.expectEqual(max_words, argvOf(&c).len);
    try cmd.appendSlice(testing.allocator, " a");
    c = .{};
    try testing.expect(!parse(cmd.items, &c));

    cmd.clearRetainingCapacity();
    try cmd.appendSlice(testing.allocator, "/bin/x ");
    try cmd.appendNTimes(testing.allocator, 'a', max_command - cmd.items.len);
    c = .{};
    try testing.expect(parse(cmd.items, &c));
    try cmd.append(testing.allocator, 'a');
    c = .{};
    try testing.expect(!parse(cmd.items, &c));
}

/// Pieces random commands are made of: what initdb writes, and what a
/// shell would read as more than a character.
const pieces = [_][]const u8{
    "a",  "b", "-c", "=", "/",  ".",  " ",    " ",    "\t",       "\"",     "\"", "'", "$", "`",
    "\\", "|", ";",  "&", "<",  ">",  "2>&1", "(",    ")",        "*",      "?",  "[", "]", "{",
    "}",  "~", "#",  "!", "\n", "\r", "\x01", "\x7f", "\xc3\xa9", "/tmp/f",
};

/// A random command of pieces, most after a program as initdb writes one;
/// the length of that program, or 0 for none.
fn randomCommand(r: std.Random, buf: *std.ArrayList(u8)) !usize {
    buf.clearRetainingCapacity();
    const program: []const u8 = switch (r.int(u2)) {
        0 => "",
        1 => "/bin/x",
        else => "\"/bin/x\"",
    };
    try buf.appendSlice(testing.allocator, program);
    for (0..r.uintLessThan(
        usize,
        14,
    )) |_| try buf.appendSlice(testing.allocator, pieces[r.uintLessThan(usize, pieces.len)]);
    return program.len;
}

test "random commands: never a crash, and nothing a shell would read specially" {
    var prng: std.Random.DefaultPrng = .init(0x9e3779b97f4a7c15);
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    var accepted: usize = 0;
    for (0..50_000) |_| {
        _ = try randomCommand(prng.random(), &buf);
        var c: Command = .{};
        if (!parse(buf.items, &c)) continue;
        accepted += 1;
        const a = argvOf(&c);
        try testing.expect(a.len > 0 and std.mem.span(a[0])[0] == '/');
        for (a) |w| for (std.mem.span(
            w,
        )) |ch| try testing.expect(
            ch >= 0x20 and ch != 0x7f and ch != '"' and ch != '$' and ch != '`' and ch != '\\',
        );
    }
    // The generator reaches both sides.
    try testing.expect(accepted > 1000 and accepted < 49_000);
}

// --- on Linux: against a shell, and the functions themselves -----------------
//
// These run where the shim does, and are skipped elsewhere (macOS).

const builtin = @import("builtin");
extern "c" fn fread(ptr: [*]u8, size: usize, n: usize, stream: *FILE) usize;
extern "c" fn fwrite(ptr: [*]const u8, size: usize, n: usize, stream: *FILE) usize;
extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;

fn onLinux() !void {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
}

/// /tmp/popen-shim-test-PID-NAME.
fn scratch(buf: *[256]u8, name: []const u8) [:0]const u8 {
    const s = std.mem.print(
        buf[0..255],
        "/tmp/popen-shim-test-{d}-{s}",
        .{ linux.getpid(), name },
    ) catch unreachable;
    buf[s.len] = 0;
    return buf[0..s.len :0];
}

fn writeAll(path: [:0]const u8, data: []const u8) !void {
    const fd = linux.open(
        path,
        .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true, .CLOEXEC = true },
        0o600,
    );
    if (linux.errno(fd) != .SUCCESS) return error.Open;
    defer _ = linux.close(@intCast(fd));
    if (linux.write(@intCast(fd), data.ptr, data.len) != data.len) return error.Write;
}

fn readAll(path: [:0]const u8, buf: []u8) ![]const u8 {
    const fd = linux.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(fd) != .SUCCESS) return error.Open;
    defer _ = linux.close(@intCast(fd));
    var n: usize = 0;
    while (n < buf.len) {
        const rc = linux.read(@intCast(fd), buf[n..].ptr, buf.len - n);
        if (linux.errno(rc) != .SUCCESS) return error.Read;
        if (rc == 0) break;
        n += rc;
    }
    return buf[0..n];
}

fn exists(path: [:0]const u8) bool {
    return linux.errno(linux.access(path, linux.F_OK)) == .SUCCESS;
}

/// What stream gives until its end.
fn drain(stream: *FILE, buf: []u8) []const u8 {
    var n: usize = 0;
    while (n < buf.len) {
        const got = fread(buf[n..].ptr, 1, buf.len - n, stream);
        if (got == 0) break;
        n += got;
    }
    return buf[0..n];
}

fn errno() linux.E {
    return @fromBackingInt(@intCast(std.c._errno().*));
}

test "random commands: the words /bin/sh gives" {
    try onLinux();
    if (!exists("/bin/sh")) return error.SkipZigTest;
    var pb: [256]u8 = undefined;
    var ob: [256]u8 = undefined;
    const script = scratch(&pb, "words.sh");
    const out = scratch(&ob, "words.out");
    defer _ = linux.unlink(script);
    defer _ = linux.unlink(out);

    // Each accepted command without redirections, its program swapped for
    // a function that prints its arguments, each ended by a NUL, and then
    // a record's end.
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(testing.allocator);
    try text.appendSlice(
        testing.allocator,
        "p() { for a; do printf '%s\\0' \"$a\"; done; printf '\\001\\0'; }\n",
    );
    var want: std.ArrayList(u8) = .empty;
    defer want.deinit(testing.allocator);
    var prng: std.Random.DefaultPrng = .init(0x2545f4914f6cdd1d);
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    var compared: usize = 0;
    while (compared < 3000) {
        const program_end = try randomCommand(prng.random(), &buf);
        var c: Command = .{};
        if (program_end == 0 or !parse(buf.items, &c) or c.in or c.out or c.err_to_out) continue;
        // A piece run on into the program makes another program: /bin/x-c.
        if (!std.mem.eql(u8, std.mem.span(c.argv[0].?), "/bin/x")) continue;
        try text.print(testing.allocator, "p{s}\n", .{buf.items[program_end..]});
        for (argvOf(&c)[1..]) |w| try want.print(testing.allocator, "{s}\x00", .{std.mem.span(w)});
        try want.appendSlice(testing.allocator, "\x01\x00");
        compared += 1;
    }
    try writeAll(script, text.items);

    const pid = linux.fork();
    if (pid == 0) {
        const fd = linux.open(out, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o600);
        _ = linux.dup3(@intCast(fd), 1, 0);
        const argv = [_:null]?[*:0]const u8{ "/bin/sh", script };
        _ = linux.execve("/bin/sh", &argv, @ptrCast(environ));
        linux.exit_group(127);
    }
    var status: i32 = 0;
    _ = linux.wait4(@intCast(pid), &status, 0, null);
    try testing.expectEqual(0, status);
    const got = try readAll(out, try testing.allocator.alloc(u8, want.items.len + 4096));
    defer testing.allocator.free(got.ptr[0 .. want.items.len + 4096]);
    try testing.expectEqualSlices(u8, want.items, got);
}

test "popen: a program's output, and its status" {
    try onLinux();
    var b: [256]u8 = undefined;
    const s = popen("/bin/echo hello \"two words\"", "r") orelse return error.NotRun;
    try testing.expectEqualStrings("hello two words\n", drain(s, &b));
    try testing.expectEqual(0, pclose(s));

    const f = popen("/bin/false", "r") orelse return error.NotRun;
    _ = drain(f, &b);
    try testing.expectEqual(1 << 8, pclose(f));
}

test "popen: a program's input" {
    try onLinux();
    var pb: [256]u8 = undefined;
    const out = scratch(&pb, "input");
    defer _ = linux.unlink(out);
    var cmd: [300]u8 = undefined;
    const c = try std.mem.printSentinel(&cmd, "/usr/bin/tee {s} >/dev/null", .{out}, 0);
    const s = popen(c, "w") orelse return error.NotRun;
    try testing.expectEqual(5, fwrite("data\n", 1, 5, s));
    try testing.expectEqual(0, pclose(s));
    var b: [64]u8 = undefined;
    try testing.expectEqualStrings("data\n", try readAll(out, &b));
}

test "system: statuses, redirections, and a program not there" {
    try onLinux();
    try testing.expectEqual(1, system(null));
    try testing.expectEqual(0, system("/bin/true"));
    try testing.expectEqual(1 << 8, system("/bin/false"));
    try testing.expectEqual(127 << 8, system("/nonexistent/popen-shim-test"));

    var ob: [256]u8 = undefined;
    var eb: [256]u8 = undefined;
    const out = scratch(&ob, "out");
    const err = scratch(&eb, "err");
    defer _ = linux.unlink(out);
    defer _ = linux.unlink(err);
    var b: [256]u8 = undefined;
    // Without a redirection, cat copies its stdin to its stdout; with
    // one, /dev/null takes the place of either.
    try testing.expect(try systemWith("/bin/cat", out, err));
    try testing.expectEqualStrings("abc\n", try readAll(out, &b));
    try testing.expect(try systemWith("/bin/cat </dev/null", out, err));
    try testing.expectEqualStrings("", try readAll(out, &b));
    try testing.expect(try systemWith("/bin/cat >/dev/null", out, err));
    try testing.expectEqualStrings("", try readAll(out, &b));

    // 2>&1: what the program says on stderr follows stdout to /dev/null.
    try testing.expect(!try systemWith("/bin/ls /nonexistent/popen-shim-test", out, err));
    try testing.expect((try readAll(err, &b)).len > 0);
    try testing.expect(!try systemWith(
        "/bin/ls /nonexistent/popen-shim-test >/dev/null 2>&1",
        out,
        err,
    ));
    try testing.expectEqualStrings("", try readAll(err, &b));
    try testing.expectEqualStrings("", try readAll(out, &b));
    // A file other than /dev/null is not opened: the command is not run.
    try testing.expectEqual(-1, system("/bin/cat </nonexistent/popen-shim-test"));
}

/// Whether system(cmd) succeeded, run in a child whose stdin holds "abc\n"
/// and whose stdout and stderr are the files out and err.
fn systemWith(cmd: [*:0]const u8, out: [:0]const u8, err: [:0]const u8) !bool {
    var p: [2]i32 = undefined;
    if (linux.errno(linux.pipe2(&p, .{})) != .SUCCESS) return error.Pipe;
    _ = linux.write(p[1], "abc\n", 4);
    _ = linux.close(p[1]);
    const pid = linux.fork();
    if (pid == 0) {
        _ = linux.dup3(p[0], 0, 0);
        const flags: linux.O = .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true };
        _ = linux.dup3(@intCast(linux.open(out, flags, 0o600)), 1, 0);
        _ = linux.dup3(@intCast(linux.open(err, flags, 0o600)), 2, 0);
        linux.exit_group(if (system(cmd) == 0) 0 else 1);
    }
    _ = linux.close(p[0]);
    var status: i32 = 0;
    _ = linux.wait4(@intCast(pid), &status, 0, null);
    return status == 0;
}

test "refused: nothing runs, ENOEXEC, and a line on stderr" {
    try onLinux();
    var sb: [256]u8 = undefined;
    const sentinel = scratch(&sb, "sentinel");
    defer _ = linux.unlink(sentinel);
    var cmd: [600]u8 = undefined;
    const bad = try std.mem.printSentinel(
        &cmd,
        "/usr/bin/touch {s}; /usr/bin/touch {s}",
        .{ sentinel, sentinel },
        0,
    );

    // stderr into a pipe, for the line.
    var p: [2]i32 = undefined;
    try testing.expectEqual(.SUCCESS, linux.errno(linux.pipe2(&p, .{ .CLOEXEC = true })));
    const saved: i32 = @intCast(linux.dup(2));
    _ = linux.dup3(p[1], 2, 0);
    const rc = system(bad);
    const e1 = errno();
    const s = popen(bad, "r");
    const e2 = errno();
    // A command that would set the terminal's title and colour.
    _ = system("/bin/x \x1b]0;owned\x07 \x1b[31m");
    _ = linux.dup3(saved, 2, 0);
    _ = linux.close(saved);
    _ = linux.close(p[1]);
    try testing.expectEqual(-1, rc);
    try testing.expectEqual(.NOEXEC, e1);
    try testing.expectEqual(null, s);
    try testing.expectEqual(.NOEXEC, e2);
    try testing.expect(!exists(sentinel));
    var b: [4096]u8 = undefined;
    const n = linux.read(p[0], &b, b.len);
    _ = linux.close(p[0]);
    try testing.expect(std.mem.startsWith(
        u8,
        b[0..n],
        "popen-shim: not run, not a command of initdb's shape: /usr/bin/touch",
    ));
    try testing.expectEqual(3, std.mem.count(u8, b[0..n], "\n"));
    try testing.expect(std.mem.indexOfAny(u8, b[0..n], "\x1b\x07") == null);
    try testing.expect(std.mem.indexOf(u8, b[0..n], "/bin/x ?]0;owned? ?[31m\n") != null);
}

test "popen: locale -a reads as empty and closes as a success" {
    try onLinux();
    var b: [64]u8 = undefined;
    const s = popen("locale -a", "r") orelse return error.NotRun;
    try testing.expectEqual(0, drain(s, &b).len);
    try testing.expectEqual(0, pclose(s));
    // Written to, it is a command of the wrong shape.
    try testing.expectEqual(null, popen("locale -a", "w"));
    try testing.expectEqual(.NOEXEC, errno());
    try testing.expectEqual(null, popen("/bin/true", "x"));
    try testing.expectEqual(.INVAL, errno());
}

test "popen: eight streams at once, and no more" {
    try onLinux();
    var streams: [8]*FILE = undefined;
    for (&streams) |*s| s.* = popen("/bin/true", "r") orelse return error.NotRun;
    try testing.expectEqual(null, popen("/bin/true", "r"));
    try testing.expectEqual(.MFILE, errno());
    try testing.expectEqual(null, popen("locale -a", "r"));
    try testing.expectEqual(0, pclose(streams[3]));
    streams[3] = popen("/bin/true", "r") orelse return error.NotRun;
    for (streams) |s| try testing.expectEqual(0, pclose(s));
}

test "pclose: a stream popen did not open" {
    try onLinux();
    const fd = linux.open("/dev/null", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    const s = fdopen(@intCast(fd), "r") orelse return error.NoStream;
    try testing.expectEqual(-1, pclose(s));
    try testing.expectEqual(.CHILD, errno());
    _ = fclose(s);
}

test "children keep the environment" {
    try onLinux();
    try testing.expectEqual(0, setenv("POPEN_SHIM_TEST", "kept", 1));
    var b: [65536]u8 = undefined;
    const s = popen("/usr/bin/env", "r") orelse return error.NotRun;
    const got = drain(s, &b);
    try testing.expectEqual(0, pclose(s));
    try testing.expect(std.mem.indexOf(u8, got, "POPEN_SHIM_TEST=kept\n") != null);
}

test "a caller with stdin closed" {
    try onLinux();
    var ob: [256]u8 = undefined;
    const out = scratch(&ob, "closed-out");
    defer _ = linux.unlink(out);
    var cmd: [300]u8 = undefined;
    const redirected = try std.mem.printSentinel(
        &cmd,
        "/usr/bin/tee {s} </dev/null >/dev/null",
        .{out},
        0,
    );
    var cmd2: [300]u8 = undefined;
    const written = try std.mem.printSentinel(&cmd2, "/usr/bin/tee {s} >/dev/null", .{out}, 0);

    // In a child, so the test's own stdin is left alone: the /dev/null
    // </dev/null opens, and the pipe popen makes, each take descriptor 0
    // itself. tee fails on a stdin it cannot read.
    for ([_]bool{ false, true }) |use_popen| {
        _ = linux.unlink(out);
        const pid = linux.fork();
        if (pid == 0) {
            _ = linux.close(0);
            if (use_popen) {
                const s = popen(written, "w") orelse linux.exit_group(2);
                _ = fwrite("through\n", 1, 8, s);
                linux.exit_group(if (pclose(s) == 0) 0 else 1);
            }
            linux.exit_group(if (system(redirected) == 0) 0 else 1);
        }
        var status: i32 = 0;
        _ = linux.wait4(@intCast(pid), &status, 0, null);
        try testing.expectEqual(0, status);
        var b: [64]u8 = undefined;
        try testing.expectEqualStrings(if (use_popen) "through\n" else "", try readAll(out, &b));
    }
}
