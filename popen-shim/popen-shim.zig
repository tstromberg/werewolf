//! popen-shim.so: popen(3), pclose(3) and system(3) without a shell, for
//! PostgreSQL's initdb alone.
//!
//! initdb starts the server it is setting up through popen and system,
//! which glibc runs as `/bin/sh -c COMMAND`; werewolf has no /bin/sh.
//! pg-init (pg-init/pg-init.zig) loads this library into initdb with
//! LD_PRELOAD. It takes the commands initdb builds, of one shape only:
//!
//!     "/usr/libexec/postgresql17/postgres" --boot -F -c log_checkpoints=false
//!     "/usr/libexec/postgresql17/postgres" --single -F -O -j template1 >/dev/null
//!     "/usr/libexec/postgresql17/postgres" --check -c max_connections=100 < "/dev/null" >
//! "/dev/null" 2>&1
//!
//! that is, an absolute program and plain words, either of which may be in
//! double quotes, and then the redirections <FILE, >FILE and 2>&1. It runs
//! the program itself, with no shell between. A command with anything else
//! (a pipe, a ;, a $, a glob, a quote of the other kind) is not run: popen
//! returns NULL and system -1, with errno ENOEXEC, and the command is said
//! on stderr, so initdb fails where it can be seen.
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

/// A command, parsed: argv, and where stdin and stdout come from, and
/// whether stderr follows stdout.
const Command = struct {
    buf: [max_command + 1]u8 = undefined,
    argv: [max_words + 1]?[*:0]const u8 = @splat(null),
    in: ?[*:0]const u8 = null,
    out: ?[*:0]const u8 = null,
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
                if (c.out == null) return false; // only after >FILE, as initdb writes it
                c.err_to_out = true;
                i += 4;
                continue;
            }
            if (command[i] == '<' or command[i] == '>') {
                next = if (command[i] == '<') .in else .out;
                i += 1;
                continue;
            }
            if (c.in != null or c.out != null) return false; // words after a redirection
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
        for (word) |ch| if (ch < 0x20 or ch == '"' or ch == 0x7f) return false;
        if (used + word.len + 1 > c.buf.len) return false;
        @memcpy(c.buf[used..][0..word.len], word);
        c.buf[used + word.len] = 0;
        const z: [*:0]const u8 = @ptrCast(&c.buf[used]);
        used += word.len + 1;
        switch (next) {
            .arg => {
                if (n == max_words) return false;
                c.argv[n] = z;
                n += 1;
            },
            .in => c.in = if (c.in == null) z else return false,
            .out => c.out = if (c.out == null) z else return false,
        }
        next = .arg;
    }
    if (next != .arg or n == 0) return false;
    // The program by its full path: no PATH to search, as no shell would.
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
    if (linux.errno(pid) != .SUCCESS) return fail(linux.errno(pid));
    if (pid == 0) {
        // The child: only system calls until it becomes the command.
        if (pipe_end) |p| _ = linux.dup3(p.fd, p.which, 0);
        if (c.in) |path| redirect(path, .{ .ACCMODE = .RDONLY }, 0);
        if (c.out) |path| redirect(path, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 1);
        if (c.err_to_out) _ = linux.dup3(1, 2, 0);
        _ = linux.execve(c.argv[0].?, @ptrCast(&c.argv), @ptrCast(environ));
        linux.exit_group(127);
    }
    return @intCast(pid);
}

fn redirect(path: [*:0]const u8, flags: linux.O, to: i32) void {
    const fd = linux.open(path, flags, 0o600);
    if (linux.errno(fd) != .SUCCESS) linux.exit_group(127);
    _ = linux.dup3(@intCast(fd), to, 0);
    _ = linux.close(@intCast(fd));
}

fn wait(pid: linux.pid_t) c_int {
    var status: i32 = 0;
    while (true) {
        const rc = linux.wait4(pid, &status, 0, null);
        switch (linux.errno(rc)) {
            .SUCCESS => return status,
            .INTR => continue,
            else => |e| {
                _ = fail(e);
                return -1;
            },
        }
    }
}

fn fail(e: linux.E) ?linux.pid_t {
    std.c._errno().* = @intCast(@backingInt(e));
    return null;
}

fn refuse(command: [*:0]const u8) void {
    var buf: [max_command + 64]u8 = undefined;
    const line = std.mem.print(
        &buf,
        "popen-shim: not run, not a command of initdb's shape: {s}\n",
        .{std.mem.span(command)},
    ) catch "popen-shim: not run\n";
    _ = linux.write(2, line.ptr, line.len);
    std.c._errno().* = @backingInt(linux.E.NOEXEC);
}

/// The streams popen has open, and the children behind them.
var open_streams: [8]struct { stream: ?*FILE = null, pid: linux.pid_t = 0 } = @splat(.{});

export fn popen(command: [*:0]const u8, mode: [*:0]const u8) ?*FILE {
    // The system's locales, of which there are none.
    if (std.mem.eql(u8, std.mem.span(command), "locale -a") and mode[0] == 'r') {
        const fd = linux.open("/dev/null", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
        if (linux.errno(fd) != .SUCCESS) return null;
        return fdopen(@intCast(fd), "r");
    }
    var c: Command = .{};
    if (!parse(std.mem.span(command), &c)) {
        refuse(command);
        return null;
    }
    const reading = mode[0] == 'r';
    if (!reading and mode[0] != 'w') {
        std.c._errno().* = @backingInt(linux.E.INVAL);
        return null;
    }
    const slot = for (&open_streams) |*s| {
        if (s.stream == null) break s;
    } else {
        std.c._errno().* = @backingInt(linux.E.MFILE);
        return null;
    };
    var fds: [2]i32 = undefined;
    if (linux.errno(linux.pipe2(&fds, .{ .CLOEXEC = true })) != .SUCCESS) {
        std.c._errno().* = @backingInt(linux.E.MFILE);
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
        return wait(pid);
    }
    // `locale -a`, which ran nothing, ends as a command that succeeded.
    _ = fclose(stream);
    return 0;
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
    try testing.expectEqualStrings("/dev/null", std.mem.span(c.out.?));
    try testing.expect(!c.err_to_out);

    c = .{};
    try testing.expect(parse(
        "\"/usr/bin/postgres\" --check -c max_connections=100 -c dynamic_shared_memory_type=posi" ++
            "x < \"/dev/null\" > \"/dev/null\" 2>&1",
        &c,
    ));
    try testing.expectEqualStrings("/dev/null", std.mem.span(c.in.?));
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
    };
    for (refused) |cmd| {
        var c: Command = .{};
        try testing.expect(!parse(cmd, &c));
    }
}
