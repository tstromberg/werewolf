//! leash: start a service someone else wrote, as its own user, on a leash.
//!
//! On a machine without a shell, runsv can only run ./run, with no
//! arguments, as root. For our own programs that is enough: they give root
//! up themselves. A program someone else wrote (nginx, postgres, grype) needs
//! its user, arguments and environment given to it, and cannot confine
//! itself. /etc/sv/NAME/run is a link to leash, which reads
//! /etc/sv/NAME/service and starts the service as that file says:
//!
//!     # nginx, as its own user, serving the status page.
//!     exec    /usr/bin/nginx
//!     before  /usr/bin/nginx -t -q
//!     user    nginx
//!     listen  tcp/80
//!     read    /etc/nginx /data/svc/status/www
//!
//! One directive a line: a key, then words. Double quotes around a whole
//! word let it hold spaces (env "GREETING=hello world"); there are no
//! escapes, variables or expansions. A # that starts a word starts a
//! comment.
//!
//!     exec PROGRAM ARG...     what runs; required, once
//!     before PROGRAM ARG...   run first, in order, leashed; each must exit 0
//!     user NAME               whom it runs as; required, once; never root
//!     listen tcp/PORT...      ports it may bind; one below 1024 brings
//!                             CAP_NET_BIND_SERVICE, and no other capability
//!     connect tcp/PORT...     ports it may reach; without it, none
//!     read PATH...            read beyond the floor (below)
//!     write PATH...           read and write beyond its own directories
//!     run PROGRAM...          other programs it may start
//!     requires PATH...        stay down unless each exists
//!     env NAME=VALUE          its environment, otherwise only PATH
//!     secret NAME PATH        a variable read from a file; never logged
//!     nofile N                its limit on open files
//!
//! Every service also gets /run/svc/NAME and, while /data is usable,
//! /data/svc/NAME, owned by its user and its working directory; and the
//! floor: read /usr, /proc, /sys/devices/system/cpu (how many CPUs there
//! are), /etc/ssl and the few files in /etc that every
//! program reads (passwd, group, hosts, resolv.conf, nsswitch.conf,
//! ld.so.cache, localtime), and the console and /dev/null, /dev/zero and
//! /dev/urandom.
//!
//! leash reads nothing from outside the image but the secrets it is told
//! of. It checks the whole file before it does anything. As root, it then
//! checks requirements, reads secrets, makes the service's directories and
//! sets its limits; builds a Landlock ruleset of the paths, programs and
//! ports above; and gives root up for good: groups, gid and uid, every
//! capability but the one a low port needs, no_new_privs, and a check that
//! root cannot be had back. Then the ruleset applies, with Landlock's
//! scoping (no signals or abstract UNIX sockets outside the service), and
//! leash runs each `before` and becomes the service. Nothing of leash runs
//! after that, so the service pays nothing for it.
//!
//! What cannot change by waiting, a bad line, a missing requirement or a
//! `before` that fails, parks the service: one line on the console says
//! why, and runsv is told to keep it down. A path another service has not
//! made yet is not that: leash exits, and runsv tries again in a second.
//! The system calls a service may make are the seal's business, for every
//! process at once (design/lockdown.md), not leash's.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const linux = std.os.linux;

const path_env = "/usr/sbin:/usr/bin:/sbin:/bin";
const max_file = 64 << 10;
const max_secret = 4 << 10;

/// What failed, for the line that says so.
var why_buf: [512]u8 = undefined;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();

    // Whatever runsv left open goes at exec; leash's own files close too.
    _ = linux.close_range(3, std.math.maxInt(linux.fd_t), .{ .UNSHARE = false, .CLOEXEC = true });
    // runsv's control pipe, opened while root, so a service can be parked
    // from any step, before or after root is given up.
    const ctl_rc = linux.open("supervise/control", .{ .ACCMODE = .WRONLY, .NONBLOCK = true, .CLOEXEC = true }, 0);
    const ctl: ?linux.fd_t = if (linux.errno(ctl_rc) == .SUCCESS) @intCast(ctl_rc) else null;

    var cwd_buf: [Dir.max_path_bytes]u8 = undefined;
    const cwd_len = std.process.currentPath(io, &cwd_buf) catch 0;
    const name = std.fs.path.basename(cwd_buf[0..cwd_len]);
    if (!isName(name)) fail(io, ctl, .park, "?", "run from /etc/sv/NAME, not {s}", .{cwd_buf[0..cwd_len]});

    const text = Dir.cwd().readFileAlloc(io, "service", gpa, .limited(max_file)) catch |err|
        fail(io, ctl, .park, name, "./service: {s}", .{@errorName(err)});
    var bad: Bad = .{};
    const s = parse(gpa, text, &bad) catch fail(io, ctl, .park, name, "./service, line {d}: {s}", .{ bad.line, bad.why });

    const user = lookupUser(readOr(io, gpa, "/etc/passwd"), s.user) orelse
        fail(io, ctl, .park, name, "no user {s} in /etc/passwd", .{s.user});
    if (user.uid == 0 or user.gid == 0) fail(io, ctl, .park, name, "{s} is root's", .{s.user});

    // --- as root ------------------------------------------------------------

    const nodata = exists("/run/werewolf/nodata");
    for (s.requires) |p| {
        if (!exists(try gpa.dupeSentinel(u8, p, 0))) fail(io, ctl, .park, name, "requires {s}, which is not there", .{p});
    }
    var env: std.process.Environ.Map = .init(gpa);
    try env.put("PATH", path_env);
    for (s.env) |e| try env.put(e[0], e[1]);
    for (s.secrets) |sec| {
        const value = readSecret(io, gpa, sec[1]) catch |err| fail(io, ctl, .park, name, "secret {s}: {s}: {s}", .{ sec[0], sec[1], @errorName(err) });
        try env.put(sec[0], value);
    }

    const run_dir = try std.fmt.allocPrintSentinel(gpa, "/run/svc/{s}", .{name}, 0);
    const data_dir = try std.fmt.allocPrintSentinel(gpa, "/data/svc/{s}", .{name}, 0);
    _ = linux.mkdir("/run/svc", 0o755);
    own(io, ctl, name, run_dir, user);
    if (!nodata) {
        _ = linux.mkdir("/data/svc", 0o755);
        own(io, ctl, name, data_dir, user);
    }
    if (s.nofile) |n| {
        if (linux.errno(linux.setrlimit(.NOFILE, &.{ .cur = n, .max = n })) != .SUCCESS) fail(io, ctl, .park, name, "nofile {d}: refused", .{n});
    }

    var rules = Ruleset.init() catch |err| fail(io, ctl, .park, name, "Landlock: {s}; this kernel cannot leash a service", .{@errorName(err)});
    if ((s.listen.len > 0 or s.connect.len > 0) and rules.abi < 4) fail(io, ctl, .park, name, "Landlock ABI {d} has no TCP rules", .{rules.abi});
    for (floor) |f| rules.allow(f.path, f.access, .optional) catch {};
    for ([_][:0]const u8{ "/proc/self/fd/1", "/proc/self/fd/2" }) |fd| rules.allow(fd, write_file, .optional) catch {};
    rules.allow(run_dir, write_dir, .own) catch |err| fail(io, ctl, .park, name, "{s}: {s}", .{ run_dir, @errorName(err) });
    if (!nodata) rules.allow(data_dir, write_dir, .own) catch |err| fail(io, ctl, .park, name, "{s}: {s}", .{ data_dir, @errorName(err) });
    for (s.read) |p| allowPath(io, ctl, name, &rules, gpa, p, read_dir, nodata);
    for (s.write) |p| allowPath(io, ctl, name, &rules, gpa, p, write_dir, nodata);
    for (s.run) |p| allowProgram(io, ctl, name, &rules, gpa, p);
    allowProgram(io, ctl, name, &rules, gpa, s.exec[0]);
    for (s.before) |b| allowProgram(io, ctl, name, &rules, gpa, b[0]);
    for (s.listen) |port| rules.port(port, bind_tcp) catch |err| fail(io, ctl, .park, name, "listen tcp/{d}: {s}", .{ port, @errorName(err) });
    for (s.connect) |port| rules.port(port, connect_tcp) catch |err| fail(io, ctl, .park, name, "connect tcp/{d}: {s}", .{ port, @errorName(err) });

    _ = linux.chdir(if (nodata) run_dir else data_dir);
    const low_port = for (s.listen) |p| {
        if (p < 1024) break true;
    } else false;
    dropTo(user, low_port) catch |err| fail(io, ctl, .park, name, "giving root up: {s}", .{@errorName(err)});

    // --- leashed --------------------------------------------------------------

    rules.restrict() catch |err| fail(io, ctl, .park, name, "Landlock: {s}", .{@errorName(err)});
    record(io, .{ .event = "start", .service = name, .user = s.user, .exec = s.exec[0], .listen = s.listen, .connect = s.connect, .landlock = rules.abi });

    for (s.before) |argv| {
        var child = std.process.spawn(io, .{ .argv = argv, .environ_map = &env, .stdin = .ignore }) catch |err|
            fail(io, ctl, .park, name, "before {s}: {s}", .{ argv[0], @errorName(err) });
        const term = child.wait(io) catch |err| fail(io, ctl, .park, name, "before {s}: {s}", .{ argv[0], @errorName(err) });
        if (term != .exited or term.exited != 0) fail(io, ctl, .park, name, "before {s} failed", .{argv[0]});
    }
    const err = std.process.replace(io, .{ .argv = s.exec, .environ_map = &env });
    fail(io, ctl, .park, name, "exec {s}: {s}", .{ s.exec[0], @errorName(err) });
}

// --- the service file ----------------------------------------------------------

const Service = struct {
    exec: []const []const u8 = &.{},
    before: []const []const []const u8 = &.{},
    user: []const u8 = "",
    listen: []const u16 = &.{},
    connect: []const u16 = &.{},
    read: []const []const u8 = &.{},
    write: []const []const u8 = &.{},
    run: []const []const u8 = &.{},
    requires: []const []const u8 = &.{},
    env: []const [2][]const u8 = &.{},
    secrets: []const [2][]const u8 = &.{},
    nofile: ?u32 = null,
};

/// Where the file is wrong, and how.
const Bad = struct { line: usize = 0, why: []const u8 = "" };

/// A service file, checked whole: an error sets bad and returns
/// error.Invalid, and nothing has been done.
fn parse(gpa: Allocator, text: []const u8, bad: *Bad) !Service {
    var exec: ?[]const []const u8 = null;
    var user: ?[]const u8 = null;
    var nofile: ?u32 = null;
    var before: std.ArrayList([]const []const u8) = .empty;
    var listen: std.ArrayList(u16) = .empty;
    var connect: std.ArrayList(u16) = .empty;
    var read: std.ArrayList([]const u8) = .empty;
    var write: std.ArrayList([]const u8) = .empty;
    var run: std.ArrayList([]const u8) = .empty;
    var requires: std.ArrayList([]const u8) = .empty;
    var env: std.ArrayList([2][]const u8) = .empty;
    var secrets: std.ArrayList([2][]const u8) = .empty;

    var lines = std.mem.splitScalar(u8, text, '\n');
    var n: usize = 0;
    while (lines.next()) |line| {
        n += 1;
        bad.line = n;
        const words = try split(gpa, line, bad);
        if (words.len == 0) continue;
        const key = words[0];
        const args = words[1..];
        if (std.mem.eql(u8, key, "exec")) {
            if (exec != null) return invalid(bad, "exec twice");
            exec = try program(args, bad);
        } else if (std.mem.eql(u8, key, "before")) {
            try before.append(gpa, try program(args, bad));
        } else if (std.mem.eql(u8, key, "user")) {
            if (user != null) return invalid(bad, "user twice");
            if (args.len != 1 or !isName(args[0])) return invalid(bad, "user takes one plain name");
            if (std.mem.eql(u8, args[0], "root")) return invalid(bad, "user root: a service runs as a user of its own");
            user = args[0];
        } else if (std.mem.eql(u8, key, "listen") or std.mem.eql(u8, key, "connect")) {
            if (args.len == 0) return invalid(bad, "no ports");
            for (args) |a| try (if (key[0] == 'l') &listen else &connect).append(gpa, try tcpPort(a, bad));
        } else if (std.mem.eql(u8, key, "read") or std.mem.eql(u8, key, "write") or
            std.mem.eql(u8, key, "run") or std.mem.eql(u8, key, "requires"))
        {
            if (args.len == 0) return invalid(bad, "no paths");
            const list = switch (key[0]) {
                'w' => &write,
                'r' => if (key[1] == 'u') &run else if (key[2] == 'a') &read else &requires,
                else => unreachable,
            };
            for (args) |a| {
                if (!isCleanPath(a)) return invalid(bad, "a path must be absolute, without . or .. or //");
                try list.append(gpa, a);
            }
        } else if (std.mem.eql(u8, key, "env")) {
            if (args.len != 1) return invalid(bad, "env takes one NAME=VALUE");
            const eq = std.mem.indexOfScalar(u8, args[0], '=') orelse return invalid(bad, "env takes NAME=VALUE");
            if (!isVariable(args[0][0..eq])) return invalid(bad, "not a variable name");
            try env.append(gpa, .{ args[0][0..eq], args[0][eq + 1 ..] });
        } else if (std.mem.eql(u8, key, "secret")) {
            if (args.len != 2 or !isVariable(args[0])) return invalid(bad, "secret takes NAME and PATH");
            if (!isCleanPath(args[1])) return invalid(bad, "a path must be absolute, without . or .. or //");
            try secrets.append(gpa, .{ args[0], args[1] });
        } else if (std.mem.eql(u8, key, "nofile")) {
            if (nofile != null) return invalid(bad, "nofile twice");
            if (args.len != 1) return invalid(bad, "nofile takes one number");
            nofile = std.fmt.parseInt(u32, args[0], 10) catch return invalid(bad, "nofile takes a number");
            if (nofile.? == 0 or nofile.? > 1 << 20) return invalid(bad, "nofile is 1 to 1048576");
        } else return invalid(bad, "unknown key");
    }
    bad.line = 0;
    return .{
        .exec = exec orelse return invalid(bad, "no exec"),
        .user = user orelse return invalid(bad, "no user"),
        .before = before.items,
        .listen = listen.items,
        .connect = connect.items,
        .read = read.items,
        .write = write.items,
        .run = run.items,
        .requires = requires.items,
        .env = env.items,
        .secrets = secrets.items,
        .nofile = nofile,
    };
}

fn invalid(bad: *Bad, why: []const u8) error{Invalid} {
    bad.why = why;
    return error.Invalid;
}

/// A line's words: separated by spaces or tabs, grouped by double quotes,
/// ended by a # that starts a word.
fn split(gpa: Allocator, line: []const u8, bad: *Bad) ![]const []const u8 {
    var words: std.ArrayList([]const u8) = .empty;
    var i: usize = 0;
    while (i < line.len) {
        const c = line[i];
        if (c == ' ' or c == '\t' or c == '\r') {
            i += 1;
        } else if (c == '#') {
            break;
        } else if (c == '"') {
            const end = std.mem.indexOfScalarPos(u8, line, i + 1, '"') orelse return invalid(bad, "a quote is not closed");
            if (end + 1 < line.len and line[end + 1] != ' ' and line[end + 1] != '\t') return invalid(bad, "a quote ends inside a word");
            try words.append(gpa, line[i + 1 .. end]);
            i = end + 1;
        } else {
            var end = i;
            while (end < line.len and line[end] != ' ' and line[end] != '\t' and line[end] != '\r') : (end += 1) {
                if (line[end] == '"') return invalid(bad, "a quote inside a word");
            }
            try words.append(gpa, line[i..end]);
            i = end;
        }
    }
    for (words.items) |w| for (w) |c| if (c < 0x20 or c == 0x7f) return invalid(bad, "a control character");
    return words.items;
}

fn program(args: []const []const u8, bad: *Bad) ![]const []const u8 {
    if (args.len == 0) return invalid(bad, "no program");
    if (!isCleanPath(args[0])) return invalid(bad, "a program is an absolute path, without . or .. or //");
    return args;
}

fn tcpPort(word: []const u8, bad: *Bad) !u16 {
    if (!std.mem.startsWith(u8, word, "tcp/")) return invalid(bad, "a port is tcp/PORT: Landlock cannot restrict UDP");
    const p = std.fmt.parseInt(u16, word[4..], 10) catch return invalid(bad, "a port is 1 to 65535");
    if (p == 0) return invalid(bad, "a port is 1 to 65535");
    return p;
}

/// Absolute, with no empty, . or .. part, and no trailing slash but "/".
fn isCleanPath(p: []const u8) bool {
    if (p.len == 0 or p[0] != '/') return false;
    if (p.len == 1) return true;
    var parts = std.mem.splitScalar(u8, p[1..], '/');
    while (parts.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) return false;
    }
    return true;
}

/// A user's or service's name: [a-z_][a-z0-9_-]*, at most 32.
fn isName(s: []const u8) bool {
    if (s.len == 0 or s.len > 32) return false;
    if (!std.ascii.isLower(s[0]) and s[0] != '_') return false;
    for (s[1..]) |c| if (!std.ascii.isLower(c) and !std.ascii.isDigit(c) and c != '_' and c != '-') return false;
    return true;
}

/// An environment variable's name: [A-Za-z_][A-Za-z0-9_]*.
fn isVariable(s: []const u8) bool {
    if (s.len == 0 or std.ascii.isDigit(s[0])) return false;
    for (s) |c| if (!std.ascii.isAlphanumeric(c) and c != '_') return false;
    return true;
}

// --- as root ---------------------------------------------------------------------

/// dir, made if need be, a directory of the user's own, 0755. A directory
/// someone else owns becomes the user's, but only itself: what is inside
/// stays as it is, since a recursive chown as root is how a user is handed
/// a file it should not have.
fn own(io: Io, ctl: ?linux.fd_t, name: []const u8, dir: [:0]const u8, user: User) void {
    _ = linux.mkdir(dir, 0o755);
    var st: linux.Statx = undefined;
    if (linux.errno(linux.statx(linux.AT.FDCWD, dir, linux.AT.SYMLINK_NOFOLLOW, .{ .TYPE = true, .UID = true, .GID = true }, &st)) != .SUCCESS or
        st.mode & linux.S.IFMT != linux.S.IFDIR)
        fail(io, ctl, .park, name, "{s} is not a directory", .{dir});
    if (st.uid != user.uid or st.gid != user.gid) {
        if (linux.errno(linux.fchownat(linux.AT.FDCWD, dir, user.uid, user.gid, linux.AT.SYMLINK_NOFOLLOW)) != .SUCCESS)
            fail(io, ctl, .park, name, "cannot give {s} to its user", .{dir});
    }
}

/// A secret: one line, at most 4 KiB, without its newline.
fn readSecret(io: Io, gpa: Allocator, path: []const u8) ![]const u8 {
    const text = try Dir.cwd().readFileAlloc(io, path, gpa, .limited(max_secret));
    const value = std.mem.trimEnd(u8, text, "\n");
    if (value.len == 0) return error.Empty;
    for (value) |c| if (c == 0 or c == '\n') return error.NotOneLine;
    return value;
}

fn allowPath(io: Io, ctl: ?linux.fd_t, name: []const u8, rules: *Ruleset, gpa: Allocator, path: []const u8, access: u64, nodata: bool) void {
    const z = gpa.dupeSentinel(u8, path, 0) catch fail(io, ctl, .park, name, "out of memory", .{});
    rules.allow(z, access, .follow) catch |err| switch (err) {
        // Another service makes it; runsv starts this one again in a
        // second. Not while /data is unavailable: it would not appear.
        error.FileNotFound => fail(io, ctl, if (nodata and std.mem.startsWith(u8, path, "/data/")) .park else .retry, name, "{s} is not there yet", .{path}),
        else => fail(io, ctl, .park, name, "{s}: {s}", .{ path, @errorName(err) }),
    };
}

/// A program it may start, and the ELF interpreter that loads it, which
/// the kernel opens for execution too.
fn allowProgram(io: Io, ctl: ?linux.fd_t, name: []const u8, rules: *Ruleset, gpa: Allocator, path: []const u8) void {
    const z = gpa.dupeSentinel(u8, path, 0) catch fail(io, ctl, .park, name, "out of memory", .{});
    rules.allow(z, run_file, .follow) catch |err| fail(io, ctl, .park, name, "{s}: {s}", .{ path, @errorName(err) });
    var head: [4096]u8 = undefined;
    const fd = linux.open(z, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(fd) != .SUCCESS) fail(io, ctl, .park, name, "{s}: cannot read it", .{path});
    defer _ = linux.close(@intCast(fd));
    const n = linux.pread(@intCast(fd), &head, head.len, 0);
    if (linux.errno(n) != .SUCCESS) fail(io, ctl, .park, name, "{s}: cannot read it", .{path});
    const interp = interpreter(head[0..n]) catch fail(io, ctl, .park, name, "{s}: not an ELF program leash can read", .{path});
    if (interp) |i| {
        const iz = gpa.dupeSentinel(u8, i, 0) catch fail(io, ctl, .park, name, "out of memory", .{});
        rules.allow(iz, run_file, .follow) catch |err| fail(io, ctl, .park, name, "{s}'s loader {s}: {s}", .{ path, i, @errorName(err) });
    }
}

/// The ELF interpreter a 64-bit little-endian program names (PT_INTERP),
/// or null for a static one, from the program's first bytes.
fn interpreter(head: []const u8) !?[]const u8 {
    if (head.len < 64 or !std.mem.eql(u8, head[0..4], "\x7fELF") or head[4] != 2 or head[5] != 1) return error.NotElf;
    const phoff = std.mem.readInt(u64, head[0x20..0x28], .little);
    const phentsize = std.mem.readInt(u16, head[0x36..0x38], .little);
    const phnum = std.mem.readInt(u16, head[0x38..0x3a], .little);
    if (phentsize < 56) return error.NotElf;
    for (0..phnum) |i| {
        const at = std.math.add(u64, phoff, std.math.mul(u64, i, phentsize) catch return error.NotElf) catch return error.NotElf;
        if (at + 56 > head.len) return error.NotElf;
        const ph = head[@intCast(at)..][0..56];
        if (std.mem.readInt(u32, ph[0..4], .little) != 3) continue; // PT_INTERP
        const off = std.mem.readInt(u64, ph[8..16], .little);
        const size = std.mem.readInt(u64, ph[32..40], .little);
        if (size < 2 or size > 256 or off + size > head.len) return error.NotElf;
        const path = head[@intCast(off)..][0..@intCast(size)];
        const end = std.mem.indexOfScalar(u8, path, 0) orelse return error.NotElf;
        if (!isCleanPath(path[0..end])) return error.NotElf;
        return path[0..end];
    }
    return null;
}

/// Become user for good: no groups but its own, no capability but
/// CAP_NET_BIND_SERVICE where a low port needs it, now or in anything it
/// runs, and no way back to root.
fn dropTo(user: User, bind_low: bool) !void {
    var cap: usize = 0;
    while (cap < 64) : (cap += 1) {
        if (!(bind_low and cap == linux.CAP.NET_BIND_SERVICE)) _ = linux.prctl(@backingInt(linux.PR.CAPBSET_DROP), cap, 0, 0, 0);
    }
    if (bind_low) try check(linux.prctl(@backingInt(linux.PR.SET_KEEPCAPS), 1, 0, 0, 0));
    try check(linux.setgroups(0, &[_]linux.gid_t{}));
    try check(linux.setresgid(user.gid, user.gid, user.gid));
    try check(linux.setresuid(user.uid, user.uid, user.uid));
    const keep: u32 = if (bind_low) 1 << linux.CAP.NET_BIND_SERVICE else 0;
    var hdr: CapHeader = .{};
    const caps = [2]CapData{ .{ .effective = keep, .permitted = keep, .inheritable = keep }, .{} };
    try check(linux.syscall2(.capset, @intFromPtr(&hdr), @intFromPtr(&caps)));
    // Ambient, so it survives exec into a program with no file capabilities.
    if (bind_low) try check(linux.prctl(@backingInt(linux.PR.CAP_AMBIENT), linux.PR.CAP_AMBIENT_RAISE, linux.CAP.NET_BIND_SERVICE, 0, 0));
    try check(linux.prctl(@backingInt(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0));
    if (linux.errno(linux.setresuid(0, 0, 0)) == .SUCCESS) return error.StillRoot;
}

fn check(rc: usize) !void {
    if (linux.errno(rc) != .SUCCESS) return error.SystemCall;
}

/// The kernel's struct __user_cap_header_struct (dhcp/dhcp.zig).
const CapHeader = extern struct {
    version: u32 = 0x20080522, // _LINUX_CAPABILITY_VERSION_3
    pid: i32 = 0,
};
const CapData = extern struct {
    effective: u32 = 0,
    permitted: u32 = 0,
    inheritable: u32 = 0,
};

// --- Landlock -------------------------------------------------------------------

// Access rights, from linux/landlock.h.
const execute: u64 = 1 << 0;
const write_file: u64 = 1 << 1;
const read_file: u64 = 1 << 2;
const read_dir: u64 = read_file | 1 << 3;
const write_dir: u64 = read_dir | write_file | 1 << 4 | 1 << 5 | 1 << 7 | 1 << 8 | 1 << 9 | 1 << 10 | 1 << 12 | 1 << 13 | 1 << 14; // not MAKE_CHAR or MAKE_BLOCK
const run_file: u64 = execute | read_file;
/// The rights a rule on a file, not a directory, may hold.
const file_rights: u64 = execute | write_file | read_file | 1 << 14 | 1 << 15;
const bind_tcp: u64 = 1 << 0;
const connect_tcp: u64 = 1 << 1;

const Floor = struct { path: [:0]const u8, access: u64 };
const floor = [_]Floor{
    .{ .path = "/usr", .access = read_dir },
    .{ .path = "/proc", .access = read_dir },
    .{ .path = "/sys/devices/system/cpu", .access = read_dir },
    .{ .path = "/etc/passwd", .access = read_file },
    .{ .path = "/etc/group", .access = read_file },
    .{ .path = "/etc/hosts", .access = read_file },
    .{ .path = "/etc/resolv.conf", .access = read_file },
    .{ .path = "/etc/nsswitch.conf", .access = read_file },
    .{ .path = "/etc/ld.so.cache", .access = read_file },
    .{ .path = "/etc/localtime", .access = read_file },
    .{ .path = "/etc/ssl", .access = read_dir },
    .{ .path = "/dev/null", .access = read_file | write_file },
    .{ .path = "/dev/zero", .access = read_file },
    .{ .path = "/dev/urandom", .access = read_file },
};

const Ruleset = struct {
    fd: linux.fd_t,
    abi: usize,
    fs: u64,

    /// A ruleset handling every access this kernel's Landlock knows, so
    /// what no rule grants is refused.
    fn init() !Ruleset {
        const abi = linux.syscall3(.landlock_create_ruleset, 0, 0, 1); // LANDLOCK_CREATE_RULESET_VERSION
        if (linux.errno(abi) != .SUCCESS) return error.Unsupported;
        const fs: u64 = if (abi >= 5) 0xffff else if (abi >= 3) 0x7fff else if (abi >= 2) 0x3fff else 0x1fff;
        const attr: [3]u64 = .{ fs, if (abi >= 4) bind_tcp | connect_tcp else 0, if (abi >= 6) 0x3 else 0 }; // scoped: abstract UNIX sockets, signals
        const size: usize = if (abi >= 6) 24 else if (abi >= 4) 16 else 8;
        const fd = linux.syscall3(.landlock_create_ruleset, @intFromPtr(&attr), size, 0);
        if (linux.errno(fd) != .SUCCESS) return error.Unsupported;
        return .{ .fd = @intCast(fd), .abi = abi, .fs = fs };
    }

    const How = enum { follow, optional, own };

    /// access beneath path: on a directory, all of it; on a file, the
    /// file's rights alone. own refuses a link.
    fn allow(r: *Ruleset, path: [:0]const u8, access: u64, how: How) !void {
        const fd = linux.open(path, .{ .PATH = true, .CLOEXEC = true, .NOFOLLOW = how == .own }, 0);
        switch (linux.errno(fd)) {
            .SUCCESS => {},
            .NOENT => return error.FileNotFound,
            else => return error.CannotOpen,
        }
        defer _ = linux.close(@intCast(fd));
        var st: linux.Statx = undefined;
        if (linux.errno(linux.statx(@intCast(fd), "", linux.AT.EMPTY_PATH, .{ .TYPE = true }, &st)) != .SUCCESS) return error.CannotOpen;
        const is_dir = st.mode & linux.S.IFMT == linux.S.IFDIR;
        var beneath: [12]u8 = undefined; // struct landlock_path_beneath_attr, packed
        std.mem.writeInt(u64, beneath[0..8], access & r.fs & (if (is_dir) ~@as(u64, 0) else file_rights), .little);
        std.mem.writeInt(i32, beneath[8..12], @intCast(fd), .little);
        if (linux.errno(linux.syscall4(.landlock_add_rule, @intCast(r.fd), 1, @intFromPtr(&beneath), 0)) != .SUCCESS) return error.RuleRefused;
    }

    fn port(r: *Ruleset, p: u16, access: u64) !void {
        const attr: [2]u64 = .{ access, p }; // struct landlock_net_port_attr
        if (linux.errno(linux.syscall4(.landlock_add_rule, @intCast(r.fd), 2, @intFromPtr(&attr), 0)) != .SUCCESS) return error.RuleRefused;
    }

    fn restrict(r: *Ruleset) !void {
        if (linux.errno(linux.syscall2(.landlock_restrict_self, @intCast(r.fd), 0)) != .SUCCESS) return error.Refused;
        _ = linux.close(r.fd);
    }
};

// --- small things ------------------------------------------------------------------

const User = struct { uid: linux.uid_t, gid: linux.gid_t };

/// name's uid and gid in an /etc/passwd.
fn lookupUser(passwd: []const u8, name: []const u8) ?User {
    var lines = std.mem.tokenizeScalar(u8, passwd, '\n');
    while (lines.next()) |line| {
        var f = std.mem.splitScalar(u8, line, ':');
        if (!std.mem.eql(u8, f.next() orelse continue, name)) continue;
        _ = f.next() orelse return null;
        const uid = std.fmt.parseInt(linux.uid_t, f.next() orelse return null, 10) catch return null;
        const gid = std.fmt.parseInt(linux.gid_t, f.next() orelse return null, 10) catch return null;
        return .{ .uid = uid, .gid = gid };
    }
    return null;
}

fn readOr(io: Io, gpa: Allocator, path: []const u8) []const u8 {
    return Dir.cwd().readFileAlloc(io, path, gpa, .limited(1 << 20)) catch "";
}

fn exists(path: [:0]const u8) bool {
    return linux.errno(linux.access(path, linux.F_OK)) == .SUCCESS;
}

const Outcome = enum { park, retry };

/// Say why on the console, then stop: parked, or for runsv to try again.
fn fail(io: Io, ctl: ?linux.fd_t, how: Outcome, name: []const u8, comptime fmt: []const u8, args: anytype) noreturn {
    const why = std.fmt.bufPrint(&why_buf, fmt, args) catch fmt;
    record(io, .{ .event = if (how == .park) "down" else "retry", .service = name, .why = why });
    if (how == .park) if (ctl) |fd| {
        _ = linux.write(fd, "d", 1);
    };
    std.process.exit(1);
}

/// One JSON line on the console.
fn record(io: Io, fields: anytype) void {
    var buf: [2048]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    w.writeAll("leash: ") catch return;
    std.json.Stringify.value(fields, .{}, &w) catch return;
    w.writeByte('\n') catch return;
    Io.File.stdout().writeStreamingAll(io, w.buffered()) catch {};
}

// --- tests ---------------------------------------------------------------------------

const testing = std.testing;

test parse {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var bad: Bad = .{};
    const s = try parse(arena.allocator(),
        \\# nginx
        \\exec    /usr/bin/nginx -c "/etc/nginx/nginx.conf"
        \\before  /usr/bin/nginx -t -q   # check first
        \\user    nginx
        \\listen  tcp/80 tcp/443
        \\connect tcp/443
        \\read    /etc/nginx /data/svc/status/www
        \\write   /var/lib/nginx
        \\run     /usr/bin/grype
        \\requires /run/config/nginx/cert.pem
        \\env     "GREETING=hello world"
        \\secret  TOKEN /run/config/x/token
        \\nofile  65536
    , &bad);
    try testing.expectEqualStrings("/etc/nginx/nginx.conf", s.exec[2]);
    try testing.expectEqual(3, s.before[0].len);
    try testing.expectEqualSlices(u16, &.{ 80, 443 }, s.listen);
    try testing.expectEqualSlices(u16, &.{443}, s.connect);
    try testing.expectEqual(2, s.read.len);
    try testing.expectEqualStrings("/var/lib/nginx", s.write[0]);
    try testing.expectEqualStrings("/usr/bin/grype", s.run[0]);
    try testing.expectEqualStrings("/run/config/nginx/cert.pem", s.requires[0]);
    try testing.expectEqualStrings("hello world", s.env[0][1]);
    try testing.expectEqualStrings("TOKEN", s.secrets[0][0]);
    try testing.expectEqual(65536, s.nofile.?);
}

test "parse refuses" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const cases = [_]struct { text: []const u8, line: usize }{
        .{ .text = "exec /a\nuser x\nfrobnicate 1", .line = 3 },
        .{ .text = "exec /a\nexec /b\nuser x", .line = 2 },
        .{ .text = "exec a\nuser x", .line = 1 },
        .{ .text = "exec /a/../b\nuser x", .line = 1 },
        .{ .text = "exec /a\nuser root", .line = 2 },
        .{ .text = "exec /a\nuser x\nlisten udp/53", .line = 3 },
        .{ .text = "exec /a\nuser x\nlisten tcp/0", .line = 3 },
        .{ .text = "exec /a\nuser x\nread /etc//x", .line = 3 },
        .{ .text = "exec /a\nuser x\nenv 1X=y", .line = 3 },
        .{ .text = "exec /a \"b\nuser x", .line = 1 },
        .{ .text = "exec /a b\"c\"\nuser x", .line = 1 },
        .{ .text = "exec /a\nuser x\nnofile 0", .line = 3 },
        .{ .text = "user x", .line = 0 },
        .{ .text = "exec /a", .line = 0 },
        .{ .text = "exec /a\x07\nuser x", .line = 1 },
    };
    for (cases) |c| {
        var bad: Bad = .{};
        try testing.expectError(error.Invalid, parse(arena.allocator(), c.text, &bad));
        try testing.expectEqual(c.line, bad.line);
    }
}

test isCleanPath {
    try testing.expect(isCleanPath("/"));
    try testing.expect(isCleanPath("/data/svc/status"));
    try testing.expect(!isCleanPath("data"));
    try testing.expect(!isCleanPath("/data/"));
    try testing.expect(!isCleanPath("/data/./x"));
    try testing.expect(!isCleanPath("/data/../etc"));
    try testing.expect(!isCleanPath(""));
}

test interpreter {
    var elf: [512]u8 = @splat(0);
    @memcpy(elf[0..6], "\x7fELF\x02\x01");
    std.mem.writeInt(u64, elf[0x20..0x28], 64, .little); // e_phoff
    std.mem.writeInt(u16, elf[0x36..0x38], 56, .little); // e_phentsize
    std.mem.writeInt(u16, elf[0x38..0x3a], 2, .little); // e_phnum
    std.mem.writeInt(u32, elf[64..68], 6, .little); // PT_PHDR
    std.mem.writeInt(u32, elf[120..124], 3, .little); // PT_INTERP
    std.mem.writeInt(u64, elf[128..136], 300, .little);
    std.mem.writeInt(u64, elf[152..160], 27, .little);
    @memcpy(elf[300..327], "/lib/ld-linux-aarch64.so.1\x00");
    try testing.expectEqualStrings("/lib/ld-linux-aarch64.so.1", (try interpreter(&elf)).?);
    std.mem.writeInt(u32, elf[120..124], 1, .little); // PT_LOAD: a static program
    try testing.expectEqual(null, try interpreter(&elf));
    std.mem.writeInt(u16, elf[0x38..0x3a], 60, .little); // headers past what was read
    try testing.expectError(error.NotElf, interpreter(&elf));
    try testing.expectError(error.NotElf, interpreter("#!/bin/sh\n"));
}

test lookupUser {
    try testing.expectEqual(User{ .uid = 200, .gid = 200 }, lookupUser("root:x:0:0::/:/x\nnginx:x:200:200::/var/empty:/sbin/nologin\n", "nginx").?);
    try testing.expectEqual(null, lookupUser("nginx2:x:1:1::/:/x\n", "nginx"));
}
