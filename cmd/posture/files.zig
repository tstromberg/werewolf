//! posture's filesystem checks: mounts, what runs from where, shared
//! places, and the account files.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const linux = std.os.linux;
const testing = std.testing;

const posture = @import("posture.zig");
const Posture = posture.Posture;
const exists = posture.exists;
const hasOption = posture.hasOption;
const missingOption = posture.missingOption;
const mountType = posture.mountType;
const statx = posture.statx;

/// How opening path for writing, and nothing more, ends.
fn writeOpen(path: [:0]const u8) linux.E {
    const rc = linux.open(path, .{ .ACCMODE = .WRONLY, .CLOEXEC = true, .NOFOLLOW = true }, 0);
    if (linux.errno(rc) == .SUCCESS) _ = linux.close(@intCast(rc));
    return linux.errno(rc);
}

/// How opening path for reading, and nothing more, ends.
fn readOpen(path: [:0]const u8) linux.E {
    const rc = linux.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true, .NOFOLLOW = true }, 0);
    if (linux.errno(rc) == .SUCCESS) _ = linux.close(@intCast(rc));
    return linux.errno(rc);
}

/// The first whole disk, /dev/vda say: not a loop, RAM or mapped device.
fn firstDisk(buf: *[64]u8) [:0]const u8 {
    const dir = linux.open(
        "/sys/block",
        .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true },
        0,
    );
    if (linux.errno(dir) != .SUCCESS) return "";
    defer _ = linux.close(@intCast(dir));
    var ents: [2048]u8 align(8) = undefined;
    const n = linux.getdents64(@intCast(dir), &ents, ents.len);
    if (linux.errno(n) != .SUCCESS) return "";
    var off: usize = 0;
    while (off < n) {
        const ent: *align(1) const linux.dirent64 = @ptrCast(&ents[off]);
        off += ent.reclen;
        const name = std.mem.sliceTo(@as([*:0]const u8, @ptrCast(&ent.name)), 0);
        const virtual = [_][]const u8{ ".", "loop", "ram", "dm-", "zram" };
        for (virtual) |v| {
            if (std.mem.startsWith(u8, name, v)) break;
        } else return std.mem.printSentinel(buf, "/dev/{s}", .{name}, 0) catch "";
    }
    return "";
}

pub fn check(p: *Posture) !void {
    const mounts = p.read("/proc/self/mounts");
    try p.add(.{
        .id = "files-root-readonly",
        .area = "files",
        .name = "Read-only root",
        .why = "Nothing can change the running system's programs.",
        .how = "/ is mounted ro",
        .result = if (hasOption(mounts, "/", "ro")) .pass else .fail,
    });
    const nosuid = try missingOption(p.gpa, mounts, "nosuid", &.{});
    try p.add(.{
        .id = "files-nosuid-everywhere",
        .area = "files",
        .name = "setuid ignored everywhere",
        .why = "No filesystem, the root included, honours a setuid or setgid bit.",
        .how = "every mount in /proc/self/mounts is nosuid",
        .result = if (nosuid.len == 0) .pass else .fail,
        .detail = nosuid,
    });
    const noexec = try missingOption(p.gpa, mounts, "noexec", &.{"/"});
    try p.add(.{
        .id = "files-noexec-everywhere",
        .area = "files",
        .name = "Only the system's programs run",
        .why = "Every filesystem but the root refuses to run programs from it.",
        .how = "every mount in /proc/self/mounts but / is noexec",
        .result = if (noexec.len == 0) .pass else .fail,
        .detail = noexec,
    });
    // /dev and /dev/pts hold device nodes, terminals among them.
    const nodev = try missingOption(p.gpa, mounts, "nodev", &.{ "/dev", "/dev/pts" });
    try p.add(.{
        .id = "files-nodev-everywhere",
        .area = "files",
        .name = "Device files only in /dev",
        .why = "A device file made anywhere else is not honoured.",
        .how = "every mount in /proc/self/mounts but /dev and /dev/pts is nodev",
        .result = if (nodev.len == 0) .pass else .fail,
        .detail = nodev,
    });

    // The proof: a program put in each place does not start.
    var ran: std.ArrayList(u8) = .empty;
    var tried: std.ArrayList(u8) = .empty;
    for ([_][]const u8{
        "/tmp",
        "/var/tmp",
        "/run",
        "/dev/shm",
        "/dev/mqueue",
        "/data",
    }) |dir| {
        if (!exists(p.io, dir)) continue;
        try tried.print(p.gpa, "{s}{s}", .{ if (tried.items.len > 0) ", " else "", dir });
        if (runsFrom(p, dir)) try ran.print(
            p.gpa,
            "{s}{s}",
            .{ if (ran.items.len > 0) ", " else "", dir },
        );
    }
    try p.add(.{
        .id = "files-exec-refused",
        .area = "files",
        .name = "A program written there does not run",
        .why = "Malware dropped into a temporary or data directory cannot be started.",
        .how = try p.gpa.print(
            "a copy of this program, put in each of {s}, fails to start (or cannot be put " ++
                "there)",
            .{tried.items},
        ),
        .result = if (ran.items.len == 0) .pass else .fail,
        .detail = if (ran.items.len > 0)
            try p.gpa.print("ran from {s}", .{ran.items})
        else
            "",
    });

    const sealed = std.mem.eql(u8, p.sysctl("vm/memfd_noexec"), "2");
    const memfd_ran = runsFromMemfd(p);
    try p.add(.{
        .id = "files-memfd-exec",
        .area = "files",
        .name = "No programs from memory",
        .why = "Code cannot run from an anonymous memory file, the usual way to run malware " ++
            "without writing it to disk.",
        .how = "vm.memfd_noexec is 2, and a copy of this program in a memfd fails to start",
        .result = if (sealed and !memfd_ran) .pass else .fail,
        .detail = if (memfd_ran)
            "a memfd program ran"
        else if (!sealed)
            try p.gpa.print("vm.memfd_noexec is {s}", .{p.sysctl("vm/memfd_noexec")})
        else
            "",
    });
    try p.sysctls("files-link" ++
        "s", "files", "Link and FIFO tricks " ++
        "blocked", "Symlinks, hard links and FIFOs in shared directories cannot be turned " ++
        "against another user.", &.{
        .{
            "fs/protected_symlinks",
            "1",
        },
        .{ "fs/protected_hardlinks", "1" },
        .{ "fs/protected_fifos", "2" },
        .{ "fs/protected_regular", "2" },
    });
    const open = try worldWritable(p);
    try p.add(.{
        .id = "files-world-writable",
        .area = "files",
        .name = "Shared places are sticky",
        .why = "Where everyone may write, no one can remove or replace another's files, and " ++
            "outside the temporary directories there is no file anyone may change.",
        .how = try p.gpa.print(
            "in {s}, every directory anyone may write is sticky, and outside /tmp, /var/tmp " ++
                "and /dev/shm no file is writable by anyone",
            .{open.tried},
        ),
        .result = if (open.found.len == 0) .pass else .fail,
        .detail = open.found,
    });
    const loose = try accountFiles(p);
    try p.add(.{
        .id = "files-account-db",
        .area = "files",
        .name = "Account files root's alone",
        .why = "No one but root can add an account, change a password or read a password hash.",
        .how = "/etc/passwd, group, shadow and gshadow, and the directories their links " ++
            "lead to, are root's and writable by no one else, and shadow and gshadow are " ++
            "not readable by everyone",
        .result = if (loose.len == 0) .pass else .fail,
        .detail = loose,
    });
    const shadow = p.read("/etc/shadow");
    const unread = shadow.len == 0 and exists(p.io, "/etc/shadow");
    const accounts = try accountProblems(p.gpa, p.read("/etc/passwd"), shadow);
    try p.add(.{
        .id = "files-accounts",
        .area = "files",
        .name = "One root, and no empty passwords",
        .why = "No account but root has root's powers, and none can be logged into without " ++
            "a password or key.",
        .how = "only root has uid 0 in /etc/passwd, and no account in /etc/shadow has an " ++
            "empty password",
        .result = if (accounts.len > 0) .fail else if (unread) .skip else .pass,
        .detail = if (accounts.len > 0)
            accounts
        else if (unread)
            "cannot read /etc/shadow"
        else
            "",
    });
    if (mountType(mounts, "/victim") != null) try p.add(.{
        .id = "files-victim-readonly",
        .area = "files",
        .name = "Old system read-only",
        .why = "The system this machine replaced stays readable, not writable.",
        .how = "/victim is mounted ro",
        .result = if (hasOption(mounts, "/victim", "ro")) .pass else .fail,
    });
    if (p.root) {
        var disk_buf: [64]u8 = undefined;
        const disk = firstDisk(&disk_buf);
        var writable: std.ArrayList(u8) = .empty;
        const places = [_][:0]const u8{
            "/proc/sys/kernel/printk",
            "/sys/kernel/mm/transparent_hugepage/enabled",
            disk,
        };
        for (places) |path| {
            if (path.len == 0) continue;
            switch (writeOpen(path)) {
                .ACCES, .NOENT => {},
                else => try writable.print(
                    p.gpa,
                    "{s}{s}",
                    .{ if (writable.items.len > 0) ", " else "", path },
                ),
            }
        }
        try p.add(.{
            .id = "files-system-writes",
            .area = "files",
            .name = "Kernel settings and disks not writable",
            .why = "Not even root can change a sysctl, a sysfs setting or a disk underneath " ++
                "its filesystem, until the machine reboots.",
            .how = "opening a sysctl, a sysfs setting and the first disk for writing, " ++
                "without writing, is refused with EACCES (Landlock, from fence)",
            .result = if (writable.items.len == 0) .pass else .fail,
            .detail = if (writable.items.len == 0)
                ""
            else
                try p.gpa.print("opened for writing: {s}", .{writable.items}),
        });
        // /dev is closed but for the devices werewolf names: a disk, and
        // the device mapper's and loop devices' controls, open for no one.
        var readable: std.ArrayList(u8) = .empty;
        const devices = [_][:0]const u8{ disk, "/dev/mapper/control", "/dev/loop-control" };
        for (devices) |path| {
            if (path.len == 0) continue;
            switch (readOpen(path)) {
                .ACCES, .NOENT => {},
                else => try readable.print(
                    p.gpa,
                    "{s}{s}",
                    .{ if (readable.items.len > 0) ", " else "", path },
                ),
            }
        }
        try p.add(.{
            .id = "files-device-reads",
            .area = "files",
            .name = "Devices closed",
            .why = "Not even root can open a disk underneath its filesystem, or any device " ++
                "the machine does not use, even to read it: /dev is closed but for the " ++
                "devices werewolf names.",
            .how = "opening the first disk, /dev/mapper/control and /dev/loop-control for " ++
                "reading is refused with EACCES (Landlock, from fence)",
            .result = if (readable.items.len == 0) .pass else .fail,
            .detail = if (readable.items.len == 0)
                ""
            else
                try p.gpa.print("opened for reading: {s}", .{readable.items}),
        });
    }
}

/// Whether a copy of this program, put in dir, starts. A place it
/// cannot be put is one it cannot start from.
fn runsFrom(p: *Posture, dir: []const u8) bool {
    // A name no one can know first: a fixed one, planted as a directory
    // by anyone in /tmp, would make the copy fail and the check pass.
    var nonce: [8]u8 = undefined;
    p.io.random(&nonce);
    const path = p.gpa.print(
        "{s}/.posture-exec-{x}",
        .{ dir, std.mem.readInt(u64, &nonce, .little) },
    ) catch return true;
    defer Dir.cwd().deleteFile(p.io, path) catch {};
    Dir.cwd().copyFile(
        "/proc/self/exe",
        Dir.cwd(),
        path,
        p.io,
        .{ .permissions = .fromMode(0o755) },
    ) catch return false;
    return starts(p, path);
}

/// Whether a copy of this program in a memfd starts. memfd_create's flags
/// are none but close-on-exec, as malware's would be.
fn runsFromMemfd(p: *Posture) bool {
    const rc = linux.memfd_create("posture", linux.MFD.CLOEXEC);
    if (linux.errno(rc) != .SUCCESS) return false;
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    const self = Dir.cwd().readFileAlloc(
        p.io,
        "/proc/self/exe",
        p.gpa,
        .limited(64 << 20),
    ) catch return false;
    var off: usize = 0;
    while (off < self.len) {
        const n = linux.write(fd, self[off..].ptr, self.len - off);
        if (linux.errno(n) != .SUCCESS or n == 0) return false;
        off += n;
    }
    // The child reaches the memfd through this process's fd table.
    const path = p.gpa.print(
        "/proc/{d}/fd/{d}",
        .{ linux.getpid(), fd },
    ) catch return false;
    return starts(p, path);
}

/// Whether path starts, run with --noop, and exits 0.
fn starts(p: *Posture, path: []const u8) bool {
    var child = std.process.spawn(
        p.io,
        .{
            .argv = &.{ path, "--noop" },
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = .ignore,
        },
    ) catch return false;
    const term = child.wait(p.io) catch return false;
    return switch (term) {
        .exited => |code| code == 0,
        else => false,
    };
}

/// Files on the root filesystem with setuid or setgid, as a list. It
/// does not cross into other filesystems (/proc, /data and the like).
pub fn findSetid(p: *Posture) ![]const u8 {
    var found: std.ArrayList(u8) = .empty;
    const root = statx(p.gpa, "/") orelse return "cannot stat /";
    var d = Dir.cwd().openDir(p.io, "/", .{ .iterate = true }) catch return "cannot open /";
    defer d.close(p.io);
    try walk(p, d, "/", root, .setid, &found, 0);
    return found.items;
}

/// The files under dir, open at path, on top's filesystem, that find
/// looks for, added to found. Each entry is looked at, and each
/// directory opened, from its parent's descriptor, links not followed:
/// a directory swapped for a link while it is walked, by whoever may
/// write there, leads nowhere.
fn walk(
    p: *Posture,
    dir: Dir,
    path: []const u8,
    top: linux.Statx,
    find: Find,
    found: *std.ArrayList(u8),
    depth: usize,
) !void {
    if (depth > 40) return;
    const sep = if (std.mem.endsWith(u8, path, "/")) "" else "/";
    var it = dir.iterate();
    while (it.next(p.io) catch null) |e| {
        var name_buf: [256]u8 = undefined;
        const name = std.mem.printSentinel(&name_buf, "{s}", .{e.name}, 0) catch continue;
        var st: linux.Statx = undefined;
        if (linux.errno(linux.statx(
            dir.handle,
            name,
            linux.AT.SYMLINK_NOFOLLOW,
            .{ .TYPE = true, .MODE = true },
            &st,
        )) != .SUCCESS) continue;
        if (st.dev_major != top.dev_major or st.dev_minor != top.dev_minor) continue;
        if (isFound(find, st.mode)) try found.print(
            p.gpa,
            "{s}{s}{s}{s}",
            .{ if (found.items.len > 0) ", " else "", path, sep, e.name },
        );
        if (st.mode & linux.S.IFMT != linux.S.IFDIR) continue;
        var sub = dir.openDir(
            p.io,
            e.name,
            .{ .iterate = true, .follow_symlinks = false },
        ) catch continue;
        defer sub.close(p.io);
        try walk(
            p,
            sub,
            try p.gpa.print("{s}{s}{s}", .{ path, sep, e.name }),
            top,
            find,
            found,
            depth + 1,
        );
    }
}

/// Where everyone may write, a directory must be sticky; outside the
/// temporary directories, no file may be writable by everyone.
fn worldWritable(p: *Posture) !struct { found: []const u8, tried: []const u8 } {
    var found: std.ArrayList(u8) = .empty;
    var tried: std.ArrayList(u8) = .empty;
    for ([_][]const u8{
        "/run",
        "/tmp",
        "/var/tmp",
        "/dev/shm",
        "/dev/mqueue",
        "/data",
    }) |dir| {
        const top = statx(p.gpa, dir) orelse continue;
        if (top.mode & linux.S.IFMT != linux.S.IFDIR) continue;
        try tried.print(p.gpa, "{s}{s}", .{ if (tried.items.len > 0) ", " else "", dir });
        const temporary = std.mem.eql(u8, dir, "/tmp") or std.mem.eql(u8, dir, "/var/tmp") or
            std.mem.eql(u8, dir, "/dev/shm");
        const find: Find = if (temporary) .open_dirs else .open;
        if (isFound(
            .open_dirs,
            top.mode,
        )) try found.print(p.gpa, "{s}{s}", .{ if (found.items.len > 0) ", " else "", dir });
        var d = Dir.cwd().openDir(p.io, dir, .{ .iterate = true }) catch continue;
        defer d.close(p.io);
        try walk(p, d, dir, top, find, &found, 0);
    }
    return .{ .found = found.items, .tried = tried.items };
}

/// Who could change the account files, wherever their links lead:
/// each must be root's and writable by no one else, in a directory
/// that is the same, and the shadow files readable by root's group at
/// most.
fn accountFiles(p: *Posture) ![]const u8 {
    var loose: std.ArrayList(u8) = .empty;
    for ([_][]const u8{ "/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow" }) |path| {
        const real = realPath(p, path) orelse continue;
        const st = statx(p.gpa, real) orelse continue;
        const dir = std.fs.path.dirname(real) orelse "/";
        const sep = if (loose.items.len > 0) ", " else "";
        if (st.uid != 0 or st.mode & 0o022 != 0) {
            try loose.print(p.gpa, "{s}{s} is not root's alone", .{ sep, real });
        } else if (std.mem.endsWith(u8, path, "shadow") and st.mode & 0o004 != 0) {
            try loose.print(p.gpa, "{s}{s} is readable by everyone", .{ sep, real });
        } else if (statx(p.gpa, dir)) |d| if (d.uid != 0 or d.mode & 0o022 != 0) {
            try loose.print(
                p.gpa,
                "{s}{s}, which holds {s}, is not root's alone",
                .{ sep, dir, std.fs.path.basename(real) },
            );
        };
    }
    return loose.items;
}

/// The real path of path, every link followed, or null if it is not there.
fn realPath(p: *Posture, path: []const u8) ?[]const u8 {
    const z = p.gpa.printSentinel("{s}", .{path}, 0) catch return null;
    const rc = linux.open(z, .{ .PATH = true, .CLOEXEC = true }, 0);
    if (linux.errno(rc) != .SUCCESS) return null;
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    const link = p.gpa.printSentinel(
        "/proc/self/fd/{d}",
        .{fd},
        0,
    ) catch return null;
    var buf: [4096]u8 = undefined;
    const n = linux.readlink(link, &buf, buf.len);
    if (linux.errno(n) != .SUCCESS) return null;
    return p.gpa.dupe(u8, buf[0..n]) catch null;
}

/// What a walk looks for: setuid and setgid programs; anything anyone may
/// write, but a sticky directory; or only directories anyone may write that
/// are not sticky.
const Find = enum { setid, open, open_dirs };

fn isFound(find: Find, mode: u16) bool {
    const kind = mode & linux.S.IFMT;
    const open_dir = kind == linux.S.IFDIR and mode & linux.S.IWOTH != 0 and
        mode & linux.S.ISVTX == 0;
    return switch (find) {
        .setid => kind == linux.S.IFREG and mode & (linux.S.ISUID | linux.S.ISGID) != 0,
        .open => open_dir or (kind == linux.S.IFREG and mode & linux.S.IWOTH != 0),
        .open_dirs => open_dir,
    };
}

/// Accounts other than root with uid 0 in passwd, and accounts with an
/// empty password in shadow, as a list.
fn accountProblems(gpa: Allocator, passwd: []const u8, shadow: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var lines = std.mem.tokenizeScalar(u8, passwd, '\n');
    while (lines.next()) |line| {
        var f = std.mem.splitScalar(u8, line, ':');
        const name = f.next() orelse continue;
        _ = f.next() orelse continue;
        const uid = f.next() orelse continue;
        if (std.mem.eql(u8, uid, "0") and
            !std.mem.eql(
                u8,
                name,
                "root",
            )) try out.print(
            gpa,
            "{s}{s} has uid 0",
            .{ if (out.items.len > 0) ", " else "", name },
        );
    }
    lines = std.mem.tokenizeScalar(u8, shadow, '\n');
    while (lines.next()) |line| {
        var f = std.mem.splitScalar(u8, line, ':');
        const name = f.next() orelse continue;
        const hash = f.next() orelse continue;
        if (hash.len == 0) try out.print(
            gpa,
            "{s}{s} has no password",
            .{ if (out.items.len > 0) ", " else "", name },
        );
    }
    return out.items;
}

test accountProblems {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const passwd = "root:x:0:0:root:/root:/sbin/nologin\ntoor:x:0:0::/:/bin/sh\nnobody:x:65534:6" ++
        "5534::/:/sbin/nologin\n";
    const shadow = "root:*:19000::::::\ntoor::19000::::::\nnobody:!:19000::::::\n";
    try testing.expectEqualStrings(
        "toor has uid 0, toor has no password",
        try accountProblems(a, passwd, shadow),
    );
    try testing.expectEqualStrings(
        "",
        try accountProblems(a, "root:x:0:0::/:/x\n", "root:!::::::::\n"),
    );
}

test isFound {
    const S = linux.S;
    try testing.expect(isFound(.setid, S.IFREG | S.ISUID | 0o755));
    try testing.expect(!isFound(.setid, S.IFDIR | S.ISGID | 0o755));
    try testing.expect(isFound(.open, S.IFDIR | 0o777));
    try testing.expect(!isFound(.open, S.IFDIR | S.ISVTX | 0o777)); // /tmp
    try testing.expect(isFound(.open, S.IFREG | 0o666));
    try testing.expect(!isFound(.open, S.IFLNK | 0o777));
    try testing.expect(!isFound(.open_dirs, S.IFREG | 0o666));
    try testing.expect(isFound(.open_dirs, S.IFDIR | 0o773));
}

test "walk: from descriptors, links not followed" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "open", .fromMode(0o755));
    try tmp.dir.createDir(io, "closed", .fromMode(0o755));
    try tmp.dir.writeFile(io, .{ .sub_path = "closed/anyones", .data = "" });
    try tmp.dir.writeFile(io, .{ .sub_path = "mine", .data = "" });
    // chmod past the umask: a directory and a file anyone may write.
    var path_buf: [Dir.max_path_bytes]u8 = undefined;
    const base = path_buf[0..try tmp.dir.realPath(io, &path_buf)];
    for ([_][]const u8{ "open", "closed/anyones" }, [_]linux.mode_t{ 0o777, 0o666 }) |name, mode| {
        const z = try testing.allocator.printSentinel("{s}/{s}", .{ base, name }, 0);
        defer testing.allocator.free(z);
        try testing.expectEqual(.SUCCESS, linux.errno(linux.chmod(z, mode)));
    }
    // A link to a tree with its own world-writable places, never entered.
    try tmp.dir.symLink(io, "/tmp", "elsewhere", .{ .is_directory = true });

    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var p: Posture = .{ .io = io, .gpa = arena.allocator(), .root = false };
    const top = statx(p.gpa, base) orelse return error.NoStat;
    var found: std.ArrayList(u8) = .empty;
    try walk(&p, tmp.dir, "T", top, .open, &found, 0);
    // Order is the directory's; both, and nothing through the link.
    try testing.expect(std.mem.find(u8, found.items, "T/open") != null);
    try testing.expect(std.mem.find(u8, found.items, "T/closed/anyones") != null);
    try testing.expectEqual(1, std.mem.count(u8, found.items, ", "));
}
