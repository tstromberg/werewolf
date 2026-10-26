//! clsi-confine runs one Overleaf compile on a leash of its own. TeX runs
//! what its users write, and TeX Live 2026 made openin_any a no-op, so
//! nothing in TeX keeps a document from reading another project's files:
//! every compile is clsi's user's. clsi starts latexmk through it
//! (clsi-settings.cjs) as clsi-confine DIR PROGRAM ARG..., DIR the
//! compile's directory. It enters a Landlock domain that reads and runs
//! /usr, reads the loader's cache, fonts and devices, reads and writes DIR
//! and a TeX cache of that compile's own, makes no link and connects
//! nowhere; then it becomes PROGRAM, found by PATH. The domain stacks on
//! clsi's leash, which still names what may run. See its README.
const std = @import("std");
const linux = std.os.linux;
const mem = std.mem;
const sandbox = @import("sandbox");

const compiles = "/var/lib/overleaf/data/compiles/";
/// caches holds a TeX cache (TEXMFVAR: the fonts and formats TeX makes)
/// per compile. One all compiles wrote would let a document leave a font
/// cache, Lua that luaotfload loads, for another project's compile.
const caches = "/var/lib/overleaf/tmp/texmf-var/";

const read_tree = sandbox.read_file | sandbox.read_dir;
/// own is a compile's rights in its directory and its cache: no link, no
/// device, no socket, and nothing to run.
const own = sandbox.own_dir | sandbox.refer;

/// floor is what TeX reads besides its project, as a narrowed program's
/// (docs/design/narrow.md), but beneath clsi's root: TeX Live, perl and
/// their libraries, which it may also run; the loader's cache; fontconfig's
/// files; the CPU list; and the devices. Not /etc as a whole, /proc, /tmp
/// or /var/lib/overleaf, where every other project's compile is.
const floor = [_]struct { path: [:0]const u8, access: u64 }{
    .{ .path = "/usr", .access = read_tree | sandbox.execute },
    .{ .path = "/etc/ld.so.cache", .access = sandbox.read_file },
    .{ .path = "/etc/localtime", .access = sandbox.read_file },
    .{ .path = "/etc/fonts", .access = read_tree },
    .{ .path = "/sys/devices/system/cpu", .access = read_tree },
    .{ .path = "/dev/null", .access = sandbox.read_file | sandbox.write_file },
    .{ .path = "/dev/zero", .access = sandbox.read_file },
    .{ .path = "/dev/random", .access = sandbox.read_file },
    .{ .path = "/dev/urandom", .access = sandbox.read_file },
};

pub fn main(init: std.process.Init) void {
    confine(init.arena.allocator(), init.minimal) catch |why| refuse(why);
}

fn refuse(why: anyerror) noreturn {
    var buf: [256]u8 = undefined;
    const text = std.mem.print(
        &buf,
        "clsi-confine: {{\"event\":\"refused\",\"reason\":\"{s}\"}}\n",
        .{@errorName(why)},
    ) catch unreachable;
    _ = linux.write(2, text.ptr, text.len);
    std.process.exit(1);
}

fn confine(a: mem.Allocator, m: std.process.Init.Minimal) !noreturn {
    const args = m.args.vector;
    if (args.len < 3) return error.Usage;
    const dir = mem.span(args[1]);
    const name = mem.cutPrefix(u8, dir, compiles) orelse return error.NotACompile;
    if (!isName(name)) return error.NotACompile;
    const cache = try a.printSentinel(caches ++ "{s}", .{name}, 0);
    switch (linux.errno(linux.mkdir(cache, 0o700))) {
        .SUCCESS, .EXIST => {},
        else => return error.NoCache,
    }

    const rules = try sandbox.Ruleset.init(.{ .sockets = true });
    for (floor) |f| allow(rules, f.path, f.access, false) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
    try allow(rules, args[1], own, true);
    try allow(rules, cache, own, true);
    _ = try sandbox.sys(
        linux.prctl(@backingInt(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0),
        "no_new_privs",
    );
    // TeX compiles nothing as it runs, unlike clsi's Node.
    try sandbox.refuseExecGain();
    try rules.restrict();

    const env = try environment(a, m.environ.block.slice, cache);
    const argv = try a.allocSentinel(?[*:0]const u8, args.len - 2, null);
    for (args[2..], argv) |arg, *p| p.* = arg;
    return exec(a, mem.span(args[2]), argv.ptr, env.ptr, search(env));
}

/// isName reports whether name is a compile's: a project ID, and a user's
/// after a dash, in hex. Nothing else may name a directory to grant.
fn isName(name: []const u8) bool {
    if (name.len == 0 or name.len > 64 or name[0] == '-') return false;
    for (name) |c| if (!std.ascii.isDigit(c) and !(c >= 'a' and c <= 'f') and c != '-')
        return false;
    return true;
}

/// allow grants access beneath path: file rights alone for a file. own
/// paths lie under clsi's writable directory, so no link may lead there.
fn allow(rules: sandbox.Ruleset, path: [*:0]const u8, access: u64, own_path: bool) !void {
    const open_how: extern struct { flags: u64, mode: u64, resolve: u64 } = .{
        .flags = @as(u32, @bitCast(linux.O{ .PATH = true, .CLOEXEC = true })),
        .mode = 0,
        // RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS
        .resolve = if (own_path) 0x04 | 0x02 else 0,
    };
    const fd = linux.syscall4(
        .openat2,
        @bitCast(@as(isize, linux.AT.FDCWD)),
        @intFromPtr(path),
        @intFromPtr(&open_how),
        @sizeOf(@TypeOf(open_how)),
    );
    switch (linux.errno(fd)) {
        .SUCCESS => {},
        .NOENT => return error.FileNotFound,
        .LOOP => return error.ThroughALink,
        else => return error.CannotOpen,
    }
    defer _ = linux.close(@intCast(fd));
    var st: linux.Statx = undefined;
    if (linux.errno(linux.statx(@intCast(fd), "", linux.AT.EMPTY_PATH, .{ .TYPE = true }, &st)) !=
        .SUCCESS) return error.CannotOpen;
    const is_dir = st.mode & linux.S.IFMT == linux.S.IFDIR;
    if (own_path and !is_dir) return error.NotADirectory;
    try rules.add(@intCast(fd), if (is_dir) access else access & sandbox.file_rights);
}

/// environment is env with TEXMFVAR the compile's own cache.
fn environment(
    a: mem.Allocator,
    env: []const ?[*:0]const u8,
    cache: []const u8,
) ![:null]?[*:0]const u8 {
    var out: std.ArrayList(?[*:0]const u8) = .empty;
    for (env) |e| {
        const v = e orelse continue;
        if (!mem.startsWith(u8, mem.span(v), "TEXMFVAR=")) try out.append(a, v);
    }
    try out.append(a, try a.printSentinel("TEXMFVAR={s}", .{cache}, 0));
    return out.toOwnedSliceSentinel(a, null);
}

/// search is env's PATH, or the empty string.
fn search(env: [:null]const ?[*:0]const u8) []const u8 {
    for (env) |e| if (mem.cutPrefix(u8, mem.span(e.?), "PATH=")) |p| return p;
    return "";
}

/// exec becomes program, by each directory in path unless it names one.
fn exec(
    a: mem.Allocator,
    program: []const u8,
    argv: [*:null]const ?[*:0]const u8,
    envp: [*:null]const ?[*:0]const u8,
    path: []const u8,
) !noreturn {
    if (mem.findScalar(u8, program, '/') != null)
        return execErr(linux.execve(try a.dupeSentinel(u8, program, 0), argv, envp));
    var dirs = mem.tokenizeScalar(u8, path, ':');
    while (dirs.next()) |d| {
        const full = try a.printSentinel("{s}/{s}", .{ d, program }, 0);
        const why = execErr(linux.execve(full, argv, envp));
        if (why != error.FileNotFound and why != error.AccessDenied) return why;
    }
    return error.FileNotFound;
}

fn execErr(rc: usize) anyerror {
    return switch (linux.errno(rc)) {
        .NOENT, .NOTDIR => error.FileNotFound,
        .ACCES, .PERM => error.AccessDenied,
        else => error.CannotRun,
    };
}

const testing = std.testing;

test "only a compile's name, in hex, names a directory to grant" {
    try testing.expect(isName("6ade5affb59aa473294a296a-6ade5a96335293d172ecb7e3"));
    try testing.expect(isName("6ade5affb59aa473294a296a"));
    const long: [65]u8 = @splat('a');
    for ([_][]const u8{ "", "-6ade", "..", "6ade/../x", "6ADE", "6ade 5aff", &long }) |bad|
        try testing.expect(!isName(bad));
}

test "the compile's cache replaces any TEXMFVAR, and PATH is found" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const env = try environment(a, &.{
        "PATH=/usr/local/texlive/2026/bin/x86_64-linux:/usr/bin",
        "TEXMFVAR=/var/lib/overleaf/tmp/texmf-var",
        "HOME=/data",
    }, caches ++ "6ade");
    try testing.expectEqual(@as(usize, 3), env.len);
    try testing.expectEqualStrings("HOME=/data", mem.span(env[1].?));
    try testing.expectEqualStrings("TEXMFVAR=" ++ caches ++ "6ade", mem.span(env[2].?));
    try testing.expectEqualStrings(
        "/usr/local/texlive/2026/bin/x86_64-linux:/usr/bin",
        search(env),
    );
}
