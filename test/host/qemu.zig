//! qemu runs a machine for a host-side check: QEMU from an argv, its
//! console read from a pipe into a log as it arrives, waits bounded by a
//! deadline, and a stop that leaves no process behind. clean rejoins the
//! userspace records kernel console messages split.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const mem = std.mem;
const posix = std.posix;

/// Machine is a running QEMU. Its standard output, the console, and its
/// standard error, QEMU's own complaints, are read as they come into one
/// log and one console text, so a machine never stalls on a full pipe.
pub const Machine = struct {
    io: Io,
    gpa: Allocator,
    child: std.process.Child,
    log: Io.File,
    readers: Io.Group = .init,
    mutex: Io.Mutex = .init,
    changed: Io.Condition = .init,
    text: std.ArrayList(u8) = .empty,
    open: u8 = 2,
    /// term is how QEMU ended, once it has closed its output.
    term: ?std.process.Child.Term = null,

    pub const Options = struct {
        /// log is created afresh and receives everything QEMU writes.
        log: []const u8,
        environ_map: ?*const std.process.Environ.Map = null,
        /// input makes QEMU's standard input a pipe for send: the console,
        /// and with -nographic the monitor behind Ctrl-A c.
        input: bool = false,
    };

    /// start runs argv. m must not move until stop; gpa, safe to use
    /// from several threads, keeps the console.
    pub fn start(m: *Machine, io: Io, gpa: Allocator, argv: []const []const u8, o: Options) !void {
        const log = try Io.Dir.cwd().createFile(io, o.log, .{});
        errdefer log.close(io);
        m.* = .{
            .io = io,
            .gpa = gpa,
            .log = log,
            .child = try std.process.spawn(io, .{
                .argv = argv,
                .environ_map = o.environ_map,
                .stdin = if (o.input) .pipe else .ignore,
                .stdout = .pipe,
                .stderr = .pipe,
            }),
        };
        for ([_]Io.File{ m.child.stdout.?, m.child.stderr.? }) |pipe|
            m.readers.concurrent(io, drain, .{ m, pipe }) catch m.drain(pipe);
    }

    fn drain(m: *Machine, pipe: Io.File) void {
        var buf: [16 << 10]u8 = undefined;
        while (true) {
            const n = pipe.readStreaming(m.io, &.{&buf}) catch 0;
            m.mutex.lockUncancelable(m.io);
            defer m.mutex.unlock(m.io);
            if (n == 0) {
                m.open -= 1;
                // The last reader to see the end reaps QEMU.
                if (m.open == 0) m.term = m.child.wait(m.io) catch .{ .unknown = 0 };
                m.changed.broadcast(m.io);
                return;
            }
            m.log.writeStreamingAll(m.io, buf[0..n]) catch {};
            m.text.appendSlice(m.gpa, buf[0..n]) catch {};
            m.changed.broadcast(m.io);
        }
    }

    /// until waits until done(context, console) is true, and refuses with
    /// error.MachineExited if QEMU ends first, or error.Timeout at
    /// deadline. done sees all the console so far, and may refuse too.
    pub fn until(m: *Machine, deadline: Io.Clock.Timestamp, context: anytype) !void {
        m.mutex.lockUncancelable(m.io);
        defer m.mutex.unlock(m.io);
        while (!try context.done(m.text.items)) {
            if (m.term != null) return error.MachineExited;
            m.changed.waitTimeout(
                m.io,
                &m.mutex,
                .{ .deadline = deadline },
            ) catch |err| switch (err) {
                error.Timeout => if (deadline.compare(.lte, .now(m.io, deadline.clock)))
                    return error.Timeout,
                else => |e| return e,
            };
        }
    }

    /// waitFor waits until the console holds needle.
    pub fn waitFor(m: *Machine, needle: []const u8, deadline: Io.Clock.Timestamp) !void {
        const Holds = struct {
            needle: []const u8,
            pub fn done(h: @This(), text: []const u8) !bool {
                return mem.find(u8, text, h.needle) != null;
            }
        };
        return m.until(deadline, Holds{ .needle = needle });
    }

    /// send writes bytes to the machine's standard input, if it has one.
    pub fn send(m: *Machine, bytes: []const u8) !void {
        const in = m.child.stdin orelse return error.NoInput;
        try in.writeStreamingAll(m.io, bytes);
    }

    /// note adds text to the log, between what QEMU writes, not to the console.
    pub fn note(m: *Machine, text: []const u8) void {
        m.mutex.lockUncancelable(m.io);
        defer m.mutex.unlock(m.io);
        m.log.writeStreamingAll(m.io, text) catch {};
    }

    /// console is a copy of all the machine has written so far.
    pub fn console(m: *Machine, gpa: Allocator) ![]u8 {
        m.mutex.lockUncancelable(m.io);
        defer m.mutex.unlock(m.io);
        return gpa.dupe(u8, m.text.items);
    }

    /// exited is whether QEMU has ended.
    pub fn exited(m: *Machine) bool {
        m.mutex.lockUncancelable(m.io);
        defer m.mutex.unlock(m.io);
        return m.term != null;
    }

    /// stop asks QEMU to end, waits up to grace for it, kills it if it has
    /// not, and reaps it.
    pub fn stop(m: *Machine, grace: Io.Duration) void {
        const Ended = struct {
            pub fn done(_: @This(), _: []const u8) !bool {
                return false;
            }
        };
        if (!m.exited()) if (m.child.id) |pid| {
            posix.kill(pid, .TERM) catch {};
            const deadline: Io.Clock.Timestamp = .fromNow(m.io, .{ .raw = grace, .clock = .awake });
            m.until(deadline, Ended{}) catch |err| if (err == error.Timeout) {
                // Still running, and not yet reaped: the pid is QEMU's.
                if (!m.exited()) posix.kill(pid, .KILL) catch {};
            };
        };
        m.readers.await(m.io) catch {};
        if (m.child.stdin) |in| in.close(m.io);
        m.child.stdin = null;
        m.log.close(m.io);
    }
};

/// after is the moment seconds from now, a deadline.
pub fn after(io: Io, seconds: i64) Io.Clock.Timestamp {
    return .fromNow(io, .{ .raw = .fromSeconds(seconds), .clock = .awake });
}

/// clean drops carriage returns and every kernel record, "[" seconds "]"
/// to the end of its line, wherever on the line it starts: a userspace
/// record it interrupted reads whole again.
pub fn clean(gpa: Allocator, data: []const u8) ![]u8 {
    var plain: std.ArrayList(u8) = try .initCapacity(gpa, data.len);
    defer plain.deinit(gpa);
    for (data) |c| if (c != '\r') plain.appendAssumeCapacity(c);
    const text = plain.items;
    var out: std.ArrayList(u8) = try .initCapacity(gpa, text.len);
    var i: usize = 0;
    while (i < text.len) {
        if (kernelRecord(text[i..], .any_space) orelse dropped(text[i..])) |len| {
            i += len;
            continue;
        }
        out.appendAssumeCapacity(text[i]);
        i += 1;
    }
    return out.items;
}

pub const Spacing = enum {
    /// any_space takes any whitespace before the seconds.
    any_space,
    /// spaces takes only spaces before them, and needs one after "]".
    spaces,
};

/// kernelRecord is the length of the kernel record text starts with,
/// through its newline, or null: "[", spacing, digits "." digits "]".
pub fn kernelRecord(text: []const u8, spacing: Spacing) ?usize {
    if (text.len == 0 or text[0] != '[') return null;
    var i: usize = 1;
    while (i < text.len) : (i += 1) switch (spacing) {
        .any_space => if (!std.ascii.isWhitespace(text[i])) break,
        .spaces => if (text[i] != ' ') break,
    };
    i = digits(text, i) orelse return null;
    if (i == text.len or text[i] != '.') return null;
    i = digits(text, i + 1) orelse return null;
    if (i == text.len or text[i] != ']') return null;
    i += 1;
    if (spacing == .spaces) {
        if (i == text.len or text[i] != ' ') return null;
        i += 1;
    }
    const end = mem.findScalarPos(u8, text, i, '\n') orelse return null;
    return end + 1;
}

/// dropped is the length of the kernel's "** N printk messages dropped **"
/// line at the start of text, which has no time but lands inside a record
/// as a kernel record does, or null.
fn dropped(text: []const u8) ?usize {
    if (!mem.startsWith(u8, text, "** ")) return null;
    const end = mem.findScalar(u8, text, '\n') orelse return null;
    const line = mem.trimEnd(u8, text[0..end], "\r");
    return if (mem.endsWith(u8, line, " printk messages dropped **")) end + 1 else null;
}

fn digits(text: []const u8, start: usize) ?usize {
    var i = start;
    while (i < text.len and std.ascii.isDigit(text[i])) i += 1;
    return if (i == start) null else i;
}

test "clean rejoins userspace records split by kernel messages" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const wanted = "posture: fail= pass=90 {\"tool\":\"posture\",\"host\":\"new-host\"}\n";
    try std.testing.expectEqualStrings(wanted, try clean(gpa, "posture: fail= pass=90 " ++
        "{\"tool\":\"posture\",\"[ 5.125] audit: syscall denied\r\nhost\":\"new-host\"}\r\n"));
    try std.testing.expectEqualStrings(wanted, try clean(gpa, wanted));
    try std.testing.expectEqualStrings(
        "ordinary [1, 2] data\n",
        try clean(gpa, "ordinary [1, 2] data\n"),
    );
    // A flood of kernel messages drops some, and says so where it was.
    try std.testing.expectEqualStrings("werewolf-test: {\"a\":1}\n", try clean(
        gpa,
        "werewolf-test: {\"a\":1}[ 1.43] audit: seccomp\r\n** 9 printk messages dropped **\r\n\r\n",
    ));
    const key = "{\"event\":\"host-key\",\"key\":\"/run/svc/sshd/host-key\"," ++
        "\"fingerprint\":\"SHA256:abc123\",\"detail\":\"kept in /data\"}\n";
    const split_key = try mem.replaceOwned(
        u8,
        gpa,
        key,
        "abc123",
        "abc[    1.551356] audit: type=1423 blockers=fs.write_file path=\r\n123",
    );
    try std.testing.expectEqualStrings(key, try clean(gpa, split_key));
    const refusal = "werewolf: people: unregistered data failed; not handing over\r\n";
    const split_refusal = try mem.replaceOwned(
        u8,
        gpa,
        refusal,
        "data",
        "d[    0.408051] Kernel panic - not syncing: Attempted to kill init!\r\nata",
    );
    try std.testing.expectEqualStrings(
        "werewolf: people: unregistered data failed; not handing over\n",
        try clean(gpa, split_refusal),
    );
    // A record with no newline yet is not a whole record.
    try std.testing.expectEqualStrings("a[ 1.0] b", try clean(gpa, "a[ 1.0] b"));
}

test "kernelRecord spacing" {
    try std.testing.expectEqual(9, kernelRecord("[ 1.0] x\nrest", .spaces).?);
    try std.testing.expectEqual(null, kernelRecord("[\t1.0] x\n", .spaces));
    try std.testing.expectEqual(9, kernelRecord("[\t1.0] x\n", .any_space).?);
    try std.testing.expectEqual(null, kernelRecord("[ 1.0]x\n", .spaces));
    try std.testing.expectEqual(8, kernelRecord("[ 1.0]x\n", .any_space).?);
    try std.testing.expectEqual(null, kernelRecord("[ 1] x\n", .any_space));
}

test "a machine's console is read and logged, and stop leaves nothing running" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realPathFileAlloc(io, ".", gpa);
    const log = try gpa.print("{s}/console.log", .{dir});
    var m: Machine = undefined;
    try m.start(io, gpa, &.{
        "/bin/sh", "-c", "echo booting; echo oops >&2; echo 'up in 1s'; exec sleep 60",
    }, .{ .log = log });
    try m.waitFor("up in ", after(io, 10));
    m.stop(.fromSeconds(5));
    try std.testing.expect(m.term.? != .exited);
    const written = try tmp.dir.readFileAlloc(io, "console.log", gpa, .unlimited);
    try std.testing.expect(mem.find(u8, written, "booting\n") != null);
    try std.testing.expect(mem.find(u8, written, "oops\n") != null);

    try m.start(io, gpa, &.{ "/bin/sh", "-c", "echo bye" }, .{ .log = log });
    try std.testing.expectError(error.MachineExited, m.waitFor("never", after(io, 10)));
    try std.testing.expectEqual(0, m.term.?.exited);
    m.stop(.fromSeconds(5));

    // A machine that ignores the request to stop is killed.
    try m.start(
        io,
        gpa,
        &.{ "/bin/sh", "-c", "trap '' TERM; echo ready; while :; do sleep 1; done" },
        .{ .log = log },
    );
    try m.waitFor("ready", after(io, 10));
    try std.testing.expectError(error.Timeout, m.waitFor("never", after(io, 0)));
    m.stop(.fromMilliseconds(200));
    try std.testing.expect(m.term.? == .signal);
}
