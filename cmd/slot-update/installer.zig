//! Offline apk's runtime and confinement; see docs/design/implemented/updater-installer.md.
const std = @import("std");
const sandbox = @import("sandbox");
const linux = std.os.linux;
const Io = std.Io;
const Dir = Io.Dir;

pub const interpreter = switch (@import("builtin").cpu.arch) {
    .x86_64 => "/lib64/ld-linux-x86-64.so.2",
    .aarch64 => "/lib/ld-linux-aarch64.so.1",
    else => @compileError("werewolf builds for x86_64 and aarch64"),
};

const runtime = [_][]const u8{ "lib", "lib64", "etc" };

/// clean removes only trust-file copies and aliases, never the read-only bind.
pub fn clean(io: Io, gpa: std.mem.Allocator, state: []const u8) !void {
    for (runtime) |name| try Dir.cwd().deleteTree(
        io,
        try gpa.print("{s}/{s}", .{ state, name }),
    );
}

/// prepare copies trust files and names the broker's immutable /usr bind.
pub fn prepare(io: Io, gpa: std.mem.Allocator, state: []const u8) !void {
    try clean(io, gpa, state);
    try Dir.cwd().createDirPath(io, try gpa.print("{s}/usr", .{state}));
    // Wolfi's loader searches these aliases on both architectures.
    for ([_]struct { []const u8, []const u8 }{
        .{ "lib", "usr/lib" }, .{ "lib64", "usr/lib" },
    }) |link| try Dir.cwd().symLink(
        io,
        link[1],
        try gpa.print("{s}/{s}", .{ state, link[0] }),
        .{},
    );
    for ([_][]const u8{ "/etc/apk/keys", "/etc/werewolf/kernel-keys" }) |path| {
        var keys = try Dir.cwd().openDir(io, path, .{ .iterate = true });
        defer keys.close(io);
        var names = keys.iterate();
        while (try names.next(io)) |entry| {
            if (entry.kind != .file) return error.UnsafeInstallerKey;
            try copy(io, gpa, state, try gpa.print("{s}/{s}", .{ path, entry.name }));
        }
    }
    try copy(io, gpa, state, "/etc/apk/repositories");
}

fn copy(io: Io, gpa: std.mem.Allocator, state: []const u8, from: []const u8) !void {
    const to = try gpa.print("{s}{s}", .{ state, from });
    try Dir.cwd().createDirPath(io, std.fs.path.dirname(to).?);
    try Dir.cwd().copyFile(from, Dir.cwd(), to, io, .{ .replace = false });
}

pub const Destination = struct { root: [:0]const u8, cache: [:0]const u8 };

/// destination accepts the two installation roots, with their matching cache.
pub fn destination(argv: [:null]const ?[*:0]const u8) !Destination {
    if (argv.len < 8 or !is(argv[0], "/usr/bin/apk") or !is(argv[1], "--root") or
        !is(argv[3], "--arch") or !is(argv[5], "--cache-dir") or !is(argv[7], "--no-network"))
        return error.BadInstallerArguments;
    for ([_]Destination{
        .{ .root = "/work/root", .cache = "/cache/root" },
        .{ .root = "/work/kernel", .cache = "/cache/kernel" },
    }) |d| if (is(argv[2], d.root) and is(argv[6], d.cache)) return d;
    return error.BadInstallerArguments;
}

fn is(arg: ?[*:0]const u8, value: []const u8) bool {
    return if (arg) |a| std.mem.eql(u8, std.mem.span(a), value) else false;
}

/// confine must run after closing inherited descriptors and before dropping
/// SYS_CHROOT. No pathname metadata operation can reach the running machine.
pub fn confine(state: ?[*:0]const u8, d: Destination) !void {
    // Metadata capabilities also apply to inherited descriptors. Keep only
    // anonymous pipes, never the host's /dev/null, across the chroot.
    var input: [2]i32 = undefined;
    _ = try sandbox.sys(linux.pipe2(&input, .{ .CLOEXEC = true }), "installer input pipe");
    defer _ = linux.close(input[1]);
    if (input[0] != 0) {
        defer _ = linux.close(input[0]);
        _ = try sandbox.sys(linux.dup3(input[0], 0, 0), "installer input");
    } else {
        _ = try sandbox.sys(linux.fcntl(0, linux.F.SETFD, 0), "installer input flags");
    }
    for ([_]i32{ 1, 2 }) |fd| {
        var st: linux.Statx = undefined;
        _ = try sandbox.sys(
            linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .TYPE = true }, &st),
            "installer output",
        );
        if (st.mode & linux.S.IFMT != linux.S.IFIFO) return error.UnsafeInstallerOutput;
    }
    if (state) |root| {
        _ = try sandbox.sys(linux.chdir(root), "enter installer state");
        _ = try sandbox.sys(linux.chroot("."), "chroot installer");
    }
    _ = try sandbox.sys(linux.chdir("/"), "enter installer root");
    for ([_][:0]const u8{ "/", "/usr", "/etc" }) |dir| try requireRootOwnedDir(dir);
    var rules: [7]sandbox.Rule = undefined;
    var n: usize = 0;
    const readable = sandbox.read_file | sandbox.read_dir;
    const writable = sandbox.own_dir | sandbox.make_sym | sandbox.make_fifo |
        sandbox.refer;
    for ([_]struct { [:0]const u8, u64 }{
        .{ "/usr", readable },
        .{ "/etc", readable },
        .{ interpreter, sandbox.read_file | sandbox.execute },
        .{ "/usr/bin/apk", sandbox.read_file | sandbox.execute },
        .{ d.cache, readable },
        .{ d.root, writable },
    }) |grant| {
        const fd = linux.open(grant[0], .{ .PATH = true, .CLOEXEC = true, .NOFOLLOW = true }, 0);
        rules[n] = .{
            .fd = @intCast(try sandbox.sys(fd, "open installer grant")),
            .access = grant[1],
        };
        n += 1;
    }
    defer for (rules[0..n]) |rule| {
        _ = linux.close(rule.fd);
    };
    try sandbox.landlock(rules[0..n], &.{});
}

fn requireRootOwnedDir(path: [:0]const u8) !void {
    var st: linux.Statx = undefined;
    _ = try sandbox.sys(
        linux.statx(
            linux.AT.FDCWD,
            path,
            linux.AT.SYMLINK_NOFOLLOW,
            .{ .TYPE = true, .MODE = true, .UID = true, .GID = true },
            &st,
        ),
        "stat installer root directory",
    );
    if (st.mode & linux.S.IFMT != linux.S.IFDIR or st.uid != 0 or st.gid != 0 or
        st.mode & 0o022 != 0)
        return error.UnsafeInstallerRoot;
}

/// filter admits offline extraction and the dynamic loader, without sockets,
/// identity changes, mounts or a way to obtain another process's descriptors.
pub fn filter() !void {
    var f: sandbox.Filter = .{};
    inline for (.{
        "read",            "readv",        "pread64",         "write",
        "writev",          "pwrite64",     "open",            "openat",
        "close",           "fstat",        "newfstatat",      "stat",
        "lstat",           "statx",        "fstatfs",         "statfs",
        "lseek",           "getdents64",   "faccessat",       "faccessat2",
        "access",          "readlink",     "readlinkat",      "mkdir",
        "mkdirat",         "rename",       "renameat",        "renameat2",
        "unlink",          "unlinkat",     "rmdir",           "link",
        "linkat",          "symlink",      "symlinkat",       "utimensat",
        "ftruncate",       "truncate",     "chmod",           "fchmod",
        "fchmodat",        "fchmodat2",    "chown",           "lchown",
        "fchown",          "fchownat",     "fsync",           "fdatasync",
        "fcntl",           "flock",        "dup",             "dup2",
        "dup3",            "umask",        "mmap",            "munmap",
        "mprotect",        "mremap",       "madvise",         "brk",
        "futex",           "getpid",       "gettid",          "getuid",
        "geteuid",         "getgid",       "getegid",         "poll",
        "ppoll",           "pselect6",     "select",          "rt_sigaction",
        "rt_sigprocmask",  "rt_sigreturn", "getrandom",       "clock_gettime",
        "gettimeofday",    "nanosleep",    "clock_nanosleep", "set_tid_address",
        "set_robust_list", "rseq",         "prlimit64",       "uname",
        "execve",          "exit_group",   "exit",            "restart_syscall",
        "arch_prctl",      "getcwd",       "sendfile",        "fallocate",
        "fgetxattr",       "fsetxattr",    "flistxattr",      "getxattr",
        "lgetxattr",       "setxattr",     "lsetxattr",       "listxattr",
        "llistxattr",      "mknod",        "mknodat",
    }) |call| f.allow(call);
    for ([_]u32{ 0x541b, 0x5401, 0x802c542a }) |req| f.allowArg("ioctl", 1, req);
    inline for (.{ "socket", "socketpair", "mount", "umount2" }) |call|
        f.refuse(call);
    try f.install();
}

test "installer destinations cannot select another root or cache" {
    const good = [_:null]?[*:0]const u8{
        "/usr/bin/apk", "--root",      "/work/root",   "--arch", "aarch64",
        "--cache-dir",  "/cache/root", "--no-network",
    };
    try std.testing.expectEqualStrings("/work/root", (try destination(&good)).root);
    var bad = good;
    bad[2] = "/";
    try std.testing.expectError(error.BadInstallerArguments, destination(&bad));
    bad = good;
    bad[6] = "/cache/kernel";
    try std.testing.expectError(error.BadInstallerArguments, destination(&bad));
    const short = [_:null]?[*:0]const u8{"/usr/bin/apk"};
    try std.testing.expectError(error.BadInstallerArguments, destination(&short));
}

test "offline installer confines contents, metadata, descriptors and sockets" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    if (linux.geteuid() != 0) return error.SkipZigTest;
    const t = std.testing;
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = t.io;
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    for ([_][]const u8{ "state/usr/bin", "state/etc", "state/cache/root", "state/work/root" }) |d|
        try tmp.dir.createDirPath(io, d);
    try tmp.dir.createDirPath(io, try gpa.print("state{s}", .{std.fs.path.dirname(interpreter).?}));
    for ([_][]const u8{
        "state/usr/bin/apk",     try gpa.print("state{s}", .{interpreter}),
        "state/cache/root/kept", "outside",
    }) |p| try tmp.dir.writeFile(io, .{ .sub_path = p, .data = "kept" });
    const outside = try tmp.dir.realPathFileAlloc(io, "outside", gpa);
    const external = try tmp.dir.openFile(io, "outside", .{ .mode = .read_write });
    defer external.close(io);
    try tmp.dir.symLink(io, outside, "state/work/root/escape", .{});
    const base = try gpa.dupeSentinel(u8, try tmp.dir.realPathFileAlloc(io, "state", gpa), 0);
    var pipe: [2]i32 = undefined;
    _ = try sandbox.sys(linux.pipe2(&pipe, .{ .CLOEXEC = true }), "pipe installer test");
    defer _ = linux.close(pipe[0]);
    const pid = try sandbox.sys(linux.fork(), "fork installer test");
    if (pid == 0) {
        installerProbe(base, pipe[1], external.handle) catch |err| {
            var message: [256]u8 = undefined;
            const line = std.mem.print(&message, "installer probe: {s} ({s}, {s})\n", .{
                @errorName(err), sandbox.failed, sandbox.errnoName(sandbox.failed_errno),
            }) catch "installer probe failed\n";
            _ = linux.write(pipe[1], line.ptr, line.len);
            linux.exit_group(1);
        };
        linux.exit_group(0);
    }
    _ = linux.close(pipe[1]);
    const result = try sandbox.collect(gpa, @intCast(pid), pipe[0], 1024, 10);
    if (result.code != 0) std.debug.print("{s}", .{result.out});
    try t.expectEqual(@as(u8, 0), result.code);
    try t.expectEqualStrings("kept", try tmp.dir.readFileAlloc(io, "outside", gpa, .unlimited));
    try t.expectEqualStrings(
        "new",
        try tmp.dir.readFileAlloc(io, "state/work/root/new", gpa, .unlimited),
    );
}

fn installerProbe(base: [*:0]const u8, report: i32, external: i32) !void {
    try sandbox.closeAllBut(&.{report});
    for ([_]i32{
        1,
        2,
    }) |fd| _ = try sandbox.sys(linux.dup3(report, fd, 0), "installer test output");
    try confine(base, .{ .root = "/work/root", .cache = "/cache/root" });
    try sandbox.keepOnly((1 << linux.CAP.CHOWN) | (1 << linux.CAP.FOWNER));
    try filter();
    var input: [1]u8 = undefined;
    if (linux.read(0, &input, input.len) != 0) return error.NotEofInput;
    var stdin_stat: linux.Statx = undefined;
    _ = try sandbox.sys(
        linux.statx(0, "", linux.AT.EMPTY_PATH, .{ .TYPE = true }, &stdin_stat),
        "stat installer input",
    );
    if (stdin_stat.mode & linux.S.IFMT != linux.S.IFIFO) return error.HostInputDescriptor;
    if (linux.errno(linux.write(external, "out", 3)) != .BADF)
        return error.InheritedOutsideDescriptor;
    const raw = try sandbox.sys(linux.open("/work/root/new", .{
        .ACCMODE = .WRONLY,
        .CREAT = true,
        .EXCL = true,
    }, 0o600), "create candidate file");
    const fd: i32 = @intCast(raw);
    _ = try sandbox.sys(linux.write(fd, "new", 3), "write candidate file");
    _ = try sandbox.sys(linux.fchown(fd, 1234, 1234), "preserve package ownership");
    _ = try sandbox.sys(linux.fchmod(fd, 0o640), "preserve package mode");
    _ = linux.close(fd);
    _ = try sandbox.sys(
        testNode("/work/root/fifo", linux.S.IFIFO | 0o600, 0),
        "create package FIFO",
    );
    const device = testNode("/work/root/device", linux.S.IFCHR | 0o600, 0x103);
    if (linux.errno(device) == .SUCCESS) return error.DeviceCreated;
    const cache = linux.open("/cache/root/kept", .{ .ACCMODE = .WRONLY }, 0);
    if (linux.errno(cache) != .ACCES) return error.WritableCache;
    if (linux.errno(linux.open("/work/root/escape", .{}, 0)) == .SUCCESS)
        return error.ReadOutside;
    if (linux.errno(linux.fchmodat(linux.AT.FDCWD, "/work/root/escape", 0o777)) == .SUCCESS)
        return error.ChmodOutside;
    if (linux.errno(linux.fchownat(linux.AT.FDCWD, "/work/root/escape", 1234, 1234, 0)) == .SUCCESS)
        return error.ChownOutside;
    if (linux.errno(linux.open("/usr/bin/apk", .{ .ACCMODE = .WRONLY }, 0)) != .ACCES)
        return error.WritableRuntime;
    for ([_]u32{ linux.AF.INET, linux.AF.INET6, linux.AF.UNIX, linux.AF.NETLINK }) |family|
        if (linux.errno(linux.socket(family, linux.SOCK.STREAM, 0)) != .PERM)
            return error.SocketAllowed;
}

fn testNode(path: [*:0]const u8, mode: u32, dev: u32) usize {
    const at: usize = @bitCast(@as(isize, linux.AT.FDCWD));
    return linux.syscall4(.mknodat, at, @intFromPtr(path), mode, dev);
}

test "the image's offline apk initializes a database inside its jail" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    if (linux.geteuid() != 0 or
        linux.faccessat(linux.AT.FDCWD, "/usr/bin/apk", linux.X_OK, 0) != 0 or
        linux.faccessat(linux.AT.FDCWD, "/etc/werewolf/kernel-keys", linux.F_OK, 0) != 0)
        return error.SkipZigTest;
    const t = std.testing;
    const io = t.io;
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "state/work/root");
    try tmp.dir.createDirPath(io, "state/cache/root");
    const base = try gpa.dupeSentinel(u8, try tmp.dir.realPathFileAlloc(io, "state", gpa), 0);
    try prepare(io, gpa, base);
    const usr = try gpa.printSentinel("{s}/usr", .{base}, 0);
    var pipe: [2]i32 = undefined;
    _ = try sandbox.sys(linux.pipe2(&pipe, .{ .CLOEXEC = true }), "pipe apk test");
    defer _ = linux.close(pipe[0]);
    const pid = try sandbox.sys(linux.fork(), "fork apk test");
    if (pid == 0) {
        apkProbe(base, usr, pipe[1]) catch linux.exit_group(1);
        linux.exit_group(1);
    }
    _ = linux.close(pipe[1]);
    const result = try sandbox.collect(gpa, @intCast(pid), pipe[0], 4096, 15);
    if (result.code != 0) std.debug.print("{s}", .{result.out});
    try t.expectEqual(@as(u8, 0), result.code);
    try tmp.dir.access(io, "state/work/root/lib/apk/db/installed", .{});
}

fn apkProbe(base: [*:0]const u8, usr: [*:0]const u8, output: i32) !noreturn {
    // The test's bind must never propagate outside this disposable namespace.
    _ = try sandbox.sys(linux.syscall1(.unshare, 0x20000), "unshare apk test mounts");
    _ = try sandbox.sys(
        linux.mount(null, "/", null, linux.MS.REC | linux.MS.PRIVATE, 0),
        "private apk test mounts",
    );
    _ = try sandbox.sys(linux.mount("/usr", usr, null, linux.MS.BIND, 0), "bind apk test runtime");
    _ = try sandbox.sys(linux.mount(null, usr, null, linux.MS.BIND | linux.MS.REMOUNT |
        linux.MS.RDONLY | linux.MS.NOSUID |
        linux.MS.NODEV, 0), "read-only apk test runtime");
    try sandbox.closeAllBut(&.{output});
    for ([_]i32{ 1, 2 }) |fd| _ = try sandbox.sys(linux.dup3(output, fd, 0), "apk test output");
    try confine(base, .{ .root = "/work/root", .cache = "/cache/root" });
    try sandbox.keepOnly(0);
    try filter();
    const arch = if (@import("builtin").cpu.arch == .aarch64) "aarch64" else "x86_64";
    const args = [_:null]?[*:0]const u8{
        "/usr/bin/apk",  "--root",      "/work/root",   "--arch",       arch,
        "--cache-dir",   "/cache/root", "--no-network", "--no-scripts", "--quiet",
        "--no-progress", "--initdb",    "add",
    };
    const env = [_:null]?[*:0]const u8{};
    _ = try sandbox.sys(linux.execve("/usr/bin/apk", &args, &env), "execute offline apk test");
    unreachable;
}

test "requireRootOwnedDir rejects coordinator-owned and writable directories" {
    if (@import("builtin").os.tag != .linux or linux.geteuid() != 0) return error.SkipZigTest;
    const t = std.testing;
    const io = t.io;
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "etc");
    const path = try gpa.dupeSentinel(u8, try tmp.dir.realPathFileAlloc(io, "etc", gpa), 0);
    _ = try sandbox.sys(linux.fchownat(linux.AT.FDCWD, path, 0, 0, 0), "own test etc");
    _ = try sandbox.sys(linux.fchmodat(linux.AT.FDCWD, path, 0o755), "chmod test etc");
    try requireRootOwnedDir(path);
    _ = try sandbox.sys(linux.fchmodat(linux.AT.FDCWD, path, 0o775), "writable test etc");
    try t.expectError(error.UnsafeInstallerRoot, requireRootOwnedDir(path));
    _ = try sandbox.sys(linux.fchmodat(linux.AT.FDCWD, path, 0o755), "restore test etc");
    _ = try sandbox.sys(linux.fchownat(linux.AT.FDCWD, path, 77, 77, 0), "foreign test etc");
    try t.expectError(error.UnsafeInstallerRoot, requireRootOwnedDir(path));
}
