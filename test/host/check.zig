//! check is what one run of a host-side check carries: its name, the
//! directory its logs go to, the environment its commands get, and why it
//! failed. run runs a command with a deadline and keeps what it said.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const mem = std.mem;
const Environ = std.process.Environ;
const Child = std.process.Child;

pub const Check = struct {
    io: Io,
    /// gpa is the process's arena: a check is short and frees nothing.
    gpa: Allocator,
    /// name starts the lines the check prints.
    name: []const u8,
    args: []const [:0]const u8,
    /// env is what commands run with: the check's own, as edited.
    env: Environ.Map,
    /// work is the absolute directory logs go to, once set.
    work: []const u8 = ".",
    why: []const u8 = "",

    pub fn init(process: std.process.Init, name: []const u8) !Check {
        const gpa = process.arena.allocator();
        // A command that exits without reading its input must not end the check.
        const ignore: std.posix.Sigaction = .{
            .handler = .{ .handler = std.posix.SIG.IGN },
            .mask = std.posix.sigemptyset(),
            .flags = 0,
        };
        std.posix.sigaction(.PIPE, &ignore, null);
        return .{
            .io = process.io,
            .gpa = gpa,
            .name = name,
            .args = try process.minimal.args.toSlice(gpa),
            .env = try process.environ_map.clone(gpa),
        };
    }

    /// say prints one line on standard output, at once.
    pub fn say(c: *Check, comptime fmt: []const u8, args: anytype) void {
        var buf: [4096]u8 = undefined;
        var out = Io.File.stdout().writerStreaming(c.io, &buf);
        out.interface.print(fmt ++ "\n", args) catch return;
        out.interface.flush() catch {};
    }

    /// fail keeps why the check failed for finish, and returns its error.
    pub fn fail(c: *Check, comptime fmt: []const u8, args: anytype) error{CheckFailed} {
        c.why = c.gpa.print(fmt, args) catch "(out of memory saying why)";
        return error.CheckFailed;
    }

    /// finish exits: 0 on success, else 1 after saying why on standard error.
    pub fn finish(c: *Check, result: anyerror!void) noreturn {
        result catch |err| {
            var buf: [8192]u8 = undefined;
            var out = Io.File.stderr().writerStreaming(c.io, &buf);
            if (err == error.CheckFailed)
                out.interface.print("FAIL   {s}: {s}\n", .{ c.name, c.why }) catch {}
            else
                out.interface.print("FAIL   {s}: {t}{s}{s}\n", .{
                    c.name,
                    err,
                    if (c.why.len > 0) ": " else "",
                    c.why,
                }) catch {};
            out.interface.flush() catch {};
            std.process.exit(1);
        };
        std.process.exit(0);
    }

    /// setWork makes dir if need be, and logs there from now on.
    pub fn setWork(c: *Check, dir: []const u8) !void {
        try Io.Dir.cwd().createDirPath(c.io, dir);
        c.work = try Io.Dir.cwd().realPathFileAlloc(c.io, dir, c.gpa);
    }

    /// path is name inside work.
    pub fn path(c: *Check, name: []const u8) ![]const u8 {
        return std.fs.path.join(c.gpa, &.{ c.work, name });
    }

    /// absolute is p from the current directory, which need not exist.
    pub fn absolute(c: *Check, p: []const u8) ![]const u8 {
        return absolutePath(c.io, c.gpa, p);
    }

    /// run runs argv, appending its command line, output and exit to
    /// work/label.log unless label is empty.
    pub fn run(c: *Check, argv: []const []const u8, label: []const u8, o: Options) !Result {
        var options = o;
        if (options.environ_map == null) options.environ_map = &c.env;
        const result = command(c.io, c.gpa, argv, options);
        if (label.len > 0) c.keep(label, argv, result) catch {};
        return result;
    }

    /// must runs argv as run does, and fails the check unless it exits 0.
    pub fn must(c: *Check, argv: []const []const u8, label: []const u8, o: Options) !Result {
        const r = c.run(argv, label, o) catch |err| return c.fail(
            "{s}: {s}: {t}",
            .{ if (label.len > 0) label else argv[0], argv[0], err },
        );
        if (!r.ok()) return c.fail("{s}: {f}: {s}", .{
            if (label.len > 0) label else argv[0],
            r.term,
            tail(r.stderr, 3000),
        });
        return r;
    }

    fn keep(c: *Check, label: []const u8, argv: []const []const u8, result: anyerror!Result) !void {
        var text: Io.Writer.Allocating = .init(c.gpa);
        const w = &text.writer;
        try w.print("$ {s}\n", .{try join(c.gpa, argv)});
        if (result) |r| {
            try w.writeAll(r.stdout);
            try w.writeAll(r.stderr);
            try w.print("({f})\n", .{r.term});
        } else |err| try w.print("({t})\n", .{err});
        try append(c.io, try c.path(try c.gpa.print("{s}.log", .{label})), text.written());
    }
};

/// absolutePath is p from the current directory, which need not exist.
pub fn absolutePath(io: Io, gpa: Allocator, p: []const u8) ![]const u8 {
    if (std.fs.path.isAbsolute(p)) return p;
    const here = try std.process.currentPathAlloc(io, gpa);
    return std.fs.path.join(gpa, &.{ here, p });
}

/// append adds data to the end of the file at path, making it if need be.
pub fn append(io: Io, path: []const u8, data: []const u8) !void {
    const file = try Io.Dir.cwd().createFile(io, path, .{ .truncate = false });
    defer file.close(io);
    try file.writePositionalAll(io, data, try file.length(io));
}

/// copyTree copies the directory from to to, which must not exist:
/// directories, files with their modes, and symbolic links as links.
pub fn copyTree(io: Io, gpa: Allocator, from: []const u8, to: []const u8) !void {
    var source = try Io.Dir.cwd().openDir(io, from, .{ .iterate = true });
    defer source.close(io);
    try Io.Dir.cwd().createDir(io, to, .default_dir);
    var target = try Io.Dir.cwd().openDir(io, to, .{});
    defer target.close(io);
    var walker = try source.walk(gpa);
    defer walker.deinit();
    while (try walker.next(io)) |e| switch (e.kind) {
        .directory => try target.createDir(io, e.path, .default_dir),
        .sym_link => {
            var buf: [std.fs.max_path_bytes]u8 = undefined;
            const n = try source.readLink(io, e.path, &buf);
            try target.symLink(io, buf[0..n], e.path, .{});
        },
        .file => try source.copyFile(e.path, target, e.path, io, .{}),
        else => return error.UnsupportedFileKind,
    };
}

/// digest is the SHA-256 of the file at path.
pub fn digest(io: Io, path: []const u8) ![32]u8 {
    const file = try Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    var h: std.crypto.hash.sha2.Sha256 = .init(.{});
    var buf: [64 << 10]u8 = undefined;
    while (true) {
        const n = file.readStreaming(io, &.{&buf}) catch |err| switch (err) {
            error.EndOfStream => break,
            else => |e| return e,
        };
        if (n == 0) break;
        h.update(buf[0..n]);
    }
    return h.finalResult();
}

/// hexDigest is digest in lowercase hex.
pub fn hexDigest(io: Io, path: []const u8) ![64]u8 {
    return std.fmt.bytesToHex(try digest(io, path), .lower);
}

/// freePort is a TCP port on loopback that nothing listened on a moment ago.
pub fn freePort(io: Io) !u16 {
    const address: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try address.listen(io, .{});
    defer server.deinit(io);
    return server.socket.address.getPort();
}

/// Why holds the reason a decision refused, for its caller to report.
pub const Why = struct {
    buf: [2048]u8 = undefined,
    text: []const u8 = "",

    pub fn refuse(w: *Why, comptime fmt: []const u8, args: anytype) error{Refused} {
        w.text = std.mem.print(&w.buf, fmt, args) catch "(too long to say)";
        return error.Refused;
    }
};

pub const Options = struct {
    environ_map: ?*const Environ.Map = null,
    cwd: ?[]const u8 = null,
    /// input is the command's standard input; without it, /dev/null.
    input: ?[]const u8 = null,
    /// timeout ends the command, killed, with error.Timeout.
    timeout: Io.Duration = .fromSeconds(900),
};

pub const Result = struct {
    term: Child.Term,
    stdout: []const u8,
    stderr: []const u8,

    pub fn ok(r: Result) bool {
        return r.term.success();
    }

    /// code is the exit status, or null if a signal ended it.
    pub fn code(r: Result) ?u8 {
        return if (r.term == .exited) r.term.exited else null;
    }
};

/// command runs argv and returns what it said and how it ended.
pub fn command(io: Io, gpa: Allocator, argv: []const []const u8, o: Options) !Result {
    var child = try std.process.spawn(io, .{
        .argv = argv,
        .cwd = if (o.cwd) |d| .{ .path = d } else .inherit,
        .environ_map = o.environ_map,
        .stdin = if (o.input != null) .pipe else .ignore,
        .stdout = .pipe,
        .stderr = .pipe,
    });
    defer child.kill(io);
    if (o.input) |input| {
        const in = child.stdin.?;
        child.stdin = null;
        defer in.close(io);
        in.writeStreamingAll(io, input) catch |err| switch (err) {
            // A command may exit without reading all it was given.
            error.BrokenPipe => {},
            else => |e| return e,
        };
    }
    var streams: Io.File.MultiReader.Buffer(2) = undefined;
    var multi: Io.File.MultiReader = undefined;
    multi.init(gpa, io, streams.toStreams(), &.{ child.stdout.?, child.stderr.? });
    defer multi.deinit();
    const deadline: Io.Timeout = .{ .deadline = .fromNow(
        io,
        .{ .raw = o.timeout, .clock = .awake },
    ) };
    while (multi.fill(4096, deadline)) |_| {} else |err| switch (err) {
        error.EndOfStream => {},
        else => |e| return e,
    }
    try multi.checkAnyError();
    const term = try child.wait(io);
    return .{
        .term = term,
        .stdout = try multi.toOwnedSlice(0),
        .stderr = try multi.toOwnedSlice(1),
    };
}

/// tail is at most the last n bytes of text.
pub fn tail(text: []const u8, n: usize) []const u8 {
    return text[text.len -| n..];
}

/// quote is word as a POSIX shell reads it back: unchanged if it holds
/// only safe bytes, else in single quotes.
pub fn quote(gpa: Allocator, word: []const u8) ![]const u8 {
    const plain = word.len > 0 and for (word) |b| {
        if (!std.ascii.isAlphanumeric(b) and
            mem.findScalar(u8, "@%+=:,./-_", b) == null) break false;
    } else true;
    if (plain) return word;
    var out: std.ArrayList(u8) = .empty;
    try out.append(gpa, '\'');
    for (word) |b| if (b == '\'') try out.appendSlice(gpa, "'\"'\"'") else try out.append(gpa, b);
    try out.append(gpa, '\'');
    return out.items;
}

/// join is argv as one shell command line.
pub fn join(gpa: Allocator, argv: []const []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (argv, 0..) |a, i| {
        if (i > 0) try out.append(gpa, ' ');
        try out.appendSlice(gpa, try quote(gpa, a));
    }
    return out.items;
}

test "join quotes what a shell would split or expand" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    try std.testing.expectEqualStrings(
        "cp -r /a/b.c 'x y' '' 'it'\"'\"'s' '$HOME' a=b,c:d@e%f+g",
        try join(gpa, &.{ "cp", "-r", "/a/b.c", "x y", "", "it's", "$HOME", "a=b,c:d@e%f+g" }),
    );
}

test "command gives input, keeps output, and ends a command past its timeout" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = std.testing.io;
    const r = try command(io, gpa, &.{ "/bin/sh", "-c", "cat; echo err >&2; exit 3" }, .{
        .input = "hello\n",
    });
    try std.testing.expectEqualStrings("hello\n", r.stdout);
    try std.testing.expectEqualStrings("err\n", r.stderr);
    try std.testing.expectEqual(3, r.code().?);
    try std.testing.expect(!r.ok());
    try std.testing.expectError(error.Timeout, command(io, gpa, &.{ "/bin/sleep", "30" }, .{
        .timeout = .fromMilliseconds(100),
    }));
}

test "copyTree keeps directories, modes and links" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realPathFileAlloc(io, ".", gpa);
    try tmp.dir.createDirPath(io, "from/a/b");
    try tmp.dir.writeFile(io, .{
        .sub_path = "from/a/b/run",
        .data = "#!/bin/sh\n",
        .flags = .{ .permissions = .fromMode(0o755) },
    });
    try tmp.dir.symLink(io, "/usr/bin/false", "from/a/false", .{});
    try copyTree(io, gpa, try gpa.print("{s}/from", .{dir}), try gpa.print("{s}/to", .{dir}));
    const st = try tmp.dir.statFile(io, "to/a/b/run", .{});
    try std.testing.expectEqual(0o755, st.permissions.toMode() & 0o777);
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings(
        "/usr/bin/false",
        buf[0..try tmp.dir.readLink(io, "to/a/false", &buf)],
    );
    try append(io, try gpa.print("{s}/log", .{dir}), "one\n");
    try append(io, try gpa.print("{s}/log", .{dir}), "two\n");
    try std.testing.expectEqualStrings(
        "one\ntwo\n",
        try tmp.dir.readFileAlloc(io, "log", gpa, .unlimited),
    );
}
