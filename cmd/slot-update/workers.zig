//! Private, chrooted worker launcher. See docs/design/implemented/updater-coordinator.md.
const std = @import("std");
const linux = std.os.linux;
const sandbox = @import("sandbox");
const broker = @import("broker");
const m = @import("slot-update.zig");
const slot = @import("slot.zig");
const installer = @import("installer.zig");
const cve = @import("cve.zig");
const Dir = std.Io.Dir;

pub const coordinator_id: u32 = 77;
pub var channel: i32 = -1;
pub var jailed = false;
pub var console: i32 = -1;
pub var boot_line: []const u8 = "";
pub var owner_channel: @import("owner.zig").Channel = .{};
pub var ipe_policy: ?std.Io.File = null;
pub var ipe_active: ?std.Io.File = null;
pub var ipe_enforce: ?std.Io.File = null;
var service_control: i32 = -1;
const maximum = 16 << 20;
const Kind = enum(u8) { reset, packages, build, fetch, read };
pub const Packages = struct {
    kernel: bool,
    arch: []const u8,
    repository: ?[]const u8 = null,
    packages: []const []const u8,
};
const Build = struct { kernel: []const u8, host: []const u8 };
const Fetch = struct { url: []const u8, maximum: usize };
const Read = struct { job: cve.Job, size: usize };

pub fn start(io: std.Io) !void {
    service_control = @intCast(try sandbox.sys(linux.open("/etc/sv/autoupdate/supervise/control", .{
        .ACCMODE = .WRONLY,
        .NONBLOCK = true,
        .NOFOLLOW = true,
        .CLOEXEC = true,
    }, 0), "open update service control"));
    var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    owner_channel = try @import("owner.zig").Channel.open();
    try prepare(io, gpa);
    const command = try Dir.cwd().openFile(io, "/proc/cmdline", .{});
    defer command.close(io);
    var boot: [64 << 10]u8 = undefined;
    const length = try command.readPositionalAll(io, &boot, 0);
    if (length == 0 or length == boot.len) return error.BootCommandLineUnavailable;
    boot_line = try std.heap.page_allocator.dupe(u8, boot[0..length]);
    Dir.cwd().deleteFile(io, "/run/werewolf/updater-ready") catch |err| {
        if (err != error.FileNotFound) return err;
    };
    ipe_policy = try protectedFile(io, @import("ipe").policy_path);
    ipe_active = try protectedFile(io, @import("ipe").active);
    ipe_enforce = try protectedFile(io, @import("ipe").base ++ "/enforce");
    try configAccess("/run/config");
    console = @intCast(try sandbox.sys(linux.open("/dev/console", .{
        .ACCMODE = .WRONLY,
        .CLOEXEC = true,
        .NOCTTY = true,
        .NONBLOCK = true,
    }, 0), "open update console"));
    // The broker raises the TPM floor; the updater never holds the device.
    var refused: @import("cmdline").Failure = .{};
    _ = @import("cmdline").parse(boot_line, &refused) orelse return error.BadCommandLine;
    var pair: [2]i32 = undefined;
    _ = try sandbox.sys(
        linux.socketpair(linux.AF.UNIX, linux.SOCK.SEQPACKET | linux.SOCK.CLOEXEC, 0, &pair),
        "worker channel",
    );
    const parent = linux.getpid();
    const pid = try sandbox.sys(linux.fork(), "fork worker launcher");
    if (pid == 0) {
        sandbox.tieTo(parent);
        serve(pair[1]) catch |err| {
            reportFailure(pair[1], err);
            linux.exit_group(1);
        };
        linux.exit_group(0);
    }
    _ = linux.close(pair[1]);
    channel = pair[0];
    const ready = try receive(channel);
    defer ready.close();
    if (ready.kind != 0 or ready.count != 0) {
        if (ready.count == 1) {
            const detail = try contents(io, gpa, ready.fds[0], 1024);
            std.debug.print("autoupdate: launcher: {s}\n", .{detail});
        }
        return error.WorkerSetup;
    }
    try sandbox.dropWith(coordinator_id, null, &.{5});
    _ = try sandbox.sys(
        linux.prctl(@backingInt(linux.PR.SET_DUMPABLE), 0, 0, 0, 0),
        "update dumpable",
    );
    const status_file = try Dir.cwd().openFile(io, "/proc/self/status", .{});
    defer status_file.close(io);
    var status_bytes: [8192]u8 = undefined;
    const status = status_bytes[0..try status_file.readPositionalAll(io, &status_bytes, 0)];
    if (!validCoordinatorStatus(status)) {
        std.debug.print("autoupdate: credentials: {s}\n", .{status});
        return error.PrivilegedCoordinator;
    }
    try coordinatorDomain();
    std.debug.print("autoupdate: coordinator uid=77 gid=77 caps=0 nnp=1\n", .{});
}

fn protectedFile(io: std.Io, path: []const u8) !?std.Io.File {
    return Dir.cwd().openFile(io, path, .{}) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
}

fn configAccess(path: [:0]const u8) !void {
    const dir = linux.open(
        path,
        .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true },
        0,
    );
    if (linux.errno(dir) == .NOENT) return;
    const fd: i32 = @intCast(try sandbox.sys(dir, "open operator config directory"));
    defer _ = linux.close(fd);
    _ = try sandbox.sys(linux.fchown(fd, 0, coordinator_id), "config traversal group");
    _ = try sandbox.sys(linux.fchmod(fd, 0o710), "config traversal access");
    // Only the operator's policy belongs to the coordinator. Other config,
    // including secrets, stays root-only.
    try configReadAccess(fd, "update-policy.json");
}

fn configReadAccess(dir: i32, name: [:0]const u8) !void {
    const raw = linux.openat(
        dir,
        name,
        .{ .NOFOLLOW = true, .NONBLOCK = true, .CLOEXEC = true },
        0,
    );
    if (linux.errno(raw) == .NOENT) return;
    const file: i32 = @intCast(try sandbox.sys(raw, "open updater config"));
    defer _ = linux.close(file);
    var st: linux.Statx = undefined;
    _ = try sandbox.sys(
        linux.statx(
            file,
            "",
            linux.AT.EMPTY_PATH,
            .{ .TYPE = true, .UID = true, .MODE = true, .NLINK = true },
            &st,
        ),
        "stat updater config",
    );
    if (st.mode & linux.S.IFMT != linux.S.IFREG or st.nlink != 1 or st.uid != 0 or
        st.mode & 0o022 != 0)
        return error.UnsafeUpdateConfig;
    _ = try sandbox.sys(linux.fchown(file, 0, coordinator_id), "updater config group");
    _ = try sandbox.sys(linux.fchmod(file, 0o640), "updater config read access");
}

pub fn park() noreturn {
    while (true) {
        const rc = linux.write(service_control, "d", 1);
        if (linux.errno(rc) == .INTR) continue;
        linux.exit_group(if (rc == 1) 0 else 1);
    }
}

fn prepare(io: std.Io, gpa: std.mem.Allocator) !void {
    try Dir.cwd().createDirPath(io, m.state_dir);
    var state = try Dir.cwd().openDir(
        io,
        m.state_dir,
        .{ .iterate = true, .follow_symlinks = false },
    );
    defer state.close(io);
    _ = try sandbox.sys(linux.fchown(state.handle, 0, 0), "own updater jail root");
    _ = try sandbox.sys(linux.fchmod(state.handle, 0o755), "updater jail root mode");
    for ([_][]const u8{ "state", "reports" }) |name| {
        try state.createDirPath(io, name);
        var sub = try state.openDir(io, name, .{ .iterate = true, .follow_symlinks = false });
        defer sub.close(io);
        _ = try sandbox.sys(
            linux.fchown(sub.handle, coordinator_id, coordinator_id),
            "own coordinator directory",
        );
        _ = try sandbox.sys(linux.fchmod(sub.handle, 0o755), "coordinator directory mode");
        try migrateDir(io, sub);
    }
    var coord = try state.openDir(io, "state", .{ .follow_symlinks = false });
    defer coord.close(io);
    try migrateRootState(io, state, coord.handle);
    try ensureLogFile(state.handle);
    try installer.prepare(io, gpa, m.state_dir);
    for ([_][]const u8{
        "/etc/apk/arch",
        "/etc/apk/world",
        "/etc/ssl/certs/ca-certificates.crt",
    }) |path| {
        const to = try gpa.print("{s}{s}", .{ m.state_dir, path });
        try Dir.cwd().createDirPath(io, std.fs.path.dirname(to).?);
        try Dir.cwd().copyFile(path, Dir.cwd(), to, io, .{});
    }
    try state.deleteTree(io, "data");
    for ([_][]const u8{ "host", "work", "cache", "data/svc" }) |path|
        try state.createDirPath(io, path);
    for ([_][:0]const u8{ "usr", "etc", "host", "cache", "data", "data/svc" }) |name|
        try setRootDir(state.handle, name);
    {
        var work = try state.openDir(io, "work", .{ .follow_symlinks = false });
        defer work.close(io);
        _ = try sandbox.sys(
            linux.fchown(work.handle, coordinator_id, coordinator_id),
            "own updater work",
        );
        _ = try sandbox.sys(linux.fchmod(work.handle, 0o755), "updater work mode");
    }
    for ([_]struct { []const u8, []const u8 }{
        .{ "/", "data/svc/autoupdate" },
        .{ "/work/tmp", "tmp" },
        .{ "/work/net/etc/resolv.conf", "etc/resolv.conf" },
        .{ "/work/net/etc/hosts", "etc/hosts" },
        .{ "certs/ca-certificates.crt", "etc/ssl/cert.pem" },
        .{ "state/held", "held" },
    }) |link| {
        state.deleteFile(io, link[1]) catch |err| if (err != error.FileNotFound) return err;
        try state.symLink(io, link[0], link[1], .{});
    }
    try broker.installerRuntime();
}

fn setRootDir(parent: i32, name: [:0]const u8) !void {
    const fd: i32 = @intCast(try sandbox.sys(linux.openat(parent, name, .{
        .DIRECTORY = true,
        .NOFOLLOW = true,
        .CLOEXEC = true,
    }, 0), "open jail root directory"));
    defer _ = linux.close(fd);
    _ = try sandbox.sys(linux.fchown(fd, 0, 0), "own jail root directory");
    _ = try sandbox.sys(linux.fchmod(fd, 0o755), "jail root directory mode");
}

fn ensureLogFile(state_fd: i32) !void {
    const fd: i32 = @intCast(try sandbox.sys(linux.openat(state_fd, "log", .{
        .ACCMODE = .WRONLY,
        .CREAT = true,
        .NOFOLLOW = true,
        .NONBLOCK = true,
        .CLOEXEC = true,
    }, 0o644), "open updater log"));
    defer _ = linux.close(fd);
    var st: linux.Statx = undefined;
    _ = try sandbox.sys(
        linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .TYPE = true, .NLINK = true }, &st),
        "stat updater log",
    );
    if (st.mode & linux.S.IFMT != linux.S.IFREG or st.nlink != 1)
        return error.UnsafeUpdateState;
    _ = try sandbox.sys(
        linux.fchown(fd, coordinator_id, coordinator_id),
        "own updater log",
    );
    _ = try sandbox.sys(linux.fchmod(fd, 0o644), "updater log mode");
}

// Migrate top-level regular state files into state/ while keeping log in place.
// Never follow links or change an inode shared with another name.
fn migrateRootState(io: std.Io, dir: Dir, coord_fd: i32) !void {
    var moved: std.ArrayList([256]u8) = .empty;
    var lens: std.ArrayList(usize) = .empty;
    defer moved.deinit(std.heap.page_allocator);
    defer lens.deinit(std.heap.page_allocator);
    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        if (entry.kind != .file) continue;
        var buf: [256]u8 = undefined;
        const name = try std.mem.printSentinel(&buf, "{s}", .{entry.name}, 0);
        try ownStateFile(dir.handle, name);
        if (!std.mem.eql(u8, entry.name, "log")) {
            var copy: [256]u8 = @splat(0);
            @memcpy(copy[0..entry.name.len], entry.name);
            try moved.append(std.heap.page_allocator, copy);
            try lens.append(std.heap.page_allocator, entry.name.len);
        }
    }
    for (moved.items, lens.items) |*item, len| {
        const name: [:0]const u8 = item[0..len :0];
        _ = try sandbox.sys(
            linux.renameat(dir.handle, name, coord_fd, name),
            "move old update state",
        );
    }
}

fn migrateDir(io: std.Io, dir: Dir) !void {
    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        if (entry.kind != .file) continue;
        var buf: [256]u8 = undefined;
        const name = try std.mem.printSentinel(&buf, "{s}", .{entry.name}, 0);
        try ownStateFile(dir.handle, name);
    }
}

fn ownStateFile(dir_fd: i32, name: [:0]const u8) !void {
    const fd: i32 = @intCast(try sandbox.sys(linux.openat(dir_fd, name, .{
        .NOFOLLOW = true,
        .NONBLOCK = true,
        .CLOEXEC = true,
    }, 0), "open old update state"));
    defer _ = linux.close(fd);
    var st: linux.Statx = undefined;
    _ = try sandbox.sys(
        linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .TYPE = true, .NLINK = true }, &st),
        "stat old update state",
    );
    if (st.mode & linux.S.IFMT != linux.S.IFREG or
        st.nlink != 1) return error.UnsafeUpdateState;
    _ = try sandbox.sys(
        linux.fchown(fd, coordinator_id, coordinator_id),
        "own old update state",
    );
}

fn reportFailure(fd: i32, err: anyerror) void {
    var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    var output: [2]i32 = undefined;
    if (linux.errno(linux.pipe2(&output, .{ .CLOEXEC = true })) != .SUCCESS) return;
    defer _ = linux.close(output[1]);
    defer _ = linux.close(output[0]);
    send(fd, 1, &.{output[0]}) catch return;
    writeAll(output[1], sandbox.whyNot(arena.allocator(), err)) catch {};
}

fn confineLauncher(fd: i32, root: [*:0]const u8) !void {
    try sandbox.closeAllButAnonymous(&.{fd});
    _ = try sandbox.sys(linux.chdir(root), "enter worker state");
    _ = try sandbox.sys(linux.chroot("."), "worker chroot");
    _ = try sandbox.sys(linux.chdir("/"), "worker cwd");
    // SYS_CHROOT must be gone even in the launcher: nested chroots can escape.
    try m.keepDaemonCaps(m.apk_caps | (1 << linux.CAP.SETUID) |
        (1 << linux.CAP.SETGID) | (1 << linux.CAP.SETPCAP));
    jailed = true;
    channel = -1;
}

fn serve(fd: i32) !void {
    try confineLauncher(fd, m.state_dir);
    try launcherDomain();
    try send(fd, 0, &.{});
    while (true) {
        const request = try receive(fd);
        defer request.close();
        const kind = std.enums.fromInt(Kind, request.kind) orelse return error.BadWorkerKind;
        const has_body = kind == .fetch or kind == .read;
        if (request.count != @as(usize, if (has_body) 2 else 1)) return error.BadWorkerDescriptors;
        try anonymousPipe(request.fds[0]);
        var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
        defer arena.deinit();
        const gpa = arena.allocator();
        var u: m.Update = .{ .io = undefined, .gpa = gpa };
        const result = u.child(
            run,
            .{ kind, request.fds[0], if (has_body) request.fds[1] else -1 },
            4 << 20,
            switch (kind) {
                .reset, .read => 300,
                .fetch => 600,
                .packages => 3 * m.apk_seconds + 300,
                .build => 2 * m.tool_seconds + 600,
            },
        ) catch |err| sandbox.Exit{
            .code = 1,
            .out = sandbox.whyNot(gpa, err),
        };
        var output: [2]i32 = undefined;
        _ = try sandbox.sys(linux.pipe2(&output, .{ .CLOEXEC = true }), "worker output pipe");
        defer _ = linux.close(output[1]);
        try send(fd, result.code, &.{output[0]});
        _ = linux.close(output[0]);
        try writeAll(output[1], result.out);
    }
}

fn run(kind: Kind, input: i32, body: i32, out: i32, parent: linux.pid_t) noreturn {
    sandbox.tieTo(parent);
    var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    runJob(arena.allocator(), kind, input, body, out, parent) catch |err|
        sandbox.say(out, 1, sandbox.whyNot(arena.allocator(), err), "");
    linux.exit_group(0);
}

fn runJob(
    gpa: std.mem.Allocator,
    kind: Kind,
    input: i32,
    body: i32,
    out: i32,
    parent: linux.pid_t,
) !void {
    try sandbox.closeAllButAnonymous(if (body >= 0) &.{ input, body, out } else &.{ input, out });
    for ([_]i32{ 1, 2 }) |fd| _ = try sandbox.sys(linux.dup3(out, fd, 0), "worker output");
    if (kind == .fetch or kind == .read) try sandbox.dropTo(m.update_id, null);
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const data = try contents(io, gpa, input, maximum);
    _ = linux.close(input);
    const uts = std.posix.uname();
    var u: m.Update = .{ .io = io, .gpa = gpa, .host = std.mem.sliceTo(&uts.nodename, 0) };
    errdefer if (u.detail.len > 0) {
        writeAll(out, u.detail) catch {};
        writeAll(out, "\n") catch {};
    };
    if (kind == .packages or kind == .build) try constructionDomain(kind);
    switch (kind) {
        .reset => {
            var work = try Dir.cwd().openDir(
                io,
                "/work",
                .{ .iterate = true, .follow_symlinks = false },
            );
            defer work.close(io);
            var entries = work.iterate();
            while (try entries.next(io)) |entry| try work.deleteTree(io, entry.name);
            _ = try sandbox.sys(
                linux.fchown(work.handle, coordinator_id, coordinator_id),
                "own updater work",
            );
            _ = try sandbox.sys(linux.fchmod(work.handle, 0o755), "updater work mode");
        },
        .packages => {
            const args = try std.json.parseFromSliceLeaky(Packages, gpa, data, .{});
            if (args.kernel) {
                try slot.apkAdd(&u, m.work_dir ++
                    "/kernel", args.arch, "/etc/werewolf/kernel-keys", &.{
                    "--repository",
                    args.repository orelse return error.MissingKernelRepository,
                }, args.packages);
            } else {
                try slot.apkAdd(
                    &u,
                    m.work_dir ++ "/root",
                    args.arch,
                    "/etc/apk/keys",
                    &.{ "--repositories-file", "/etc/apk/repositories" },
                    args.packages,
                );
            }
        },
        .build => {
            const args = try std.json.parseFromSliceLeaky(Build, gpa, data, .{});
            u.host = args.host;
            try buildScratch(io);
            try slot.buildSlot(&u, args.kernel);
            const dir = try Dir.cwd().openDir(
                io,
                m.work_dir ++ "/slot",
                .{ .iterate = true, .follow_symlinks = false },
            );
            defer dir.close(io);
            _ = try sandbox.sys(
                linux.fchown(dir.handle, coordinator_id, coordinator_id),
                "own staged slot",
            );
            _ = try sandbox.sys(linux.fchmod(dir.handle, 0o750), "staged slot mode");
            for ([_][:0]const u8{ "root.erofs", "vmlinuz", "stage0.zst", "uki.efi" }) |name| {
                const rc = linux.fchownat(
                    dir.handle,
                    name,
                    coordinator_id,
                    coordinator_id,
                    linux.AT.SYMLINK_NOFOLLOW,
                );
                if (linux.errno(rc) != .NOENT) _ = try sandbox.sys(rc, "own staged artifact");
            }
        },
        .fetch => {
            const args = try std.json.parseFromSliceLeaky(Fetch, gpa, data, .{});
            if (args.maximum > 16 << 30) return error.TooBig;
            cve.fetcherBounded(m.update_id, null, args.url, body, args.maximum, out, parent);
        },
        .read => {
            const args = try std.json.parseFromSliceLeaky(Read, gpa, data, .{});
            if (args.size > m.max_read) return error.TooBig;
            cve.reader(
                m.update_id,
                null,
                args.job,
                .{ .fd = body, .size = args.size },
                out,
                parent,
            );
        },
    }
}

fn buildScratch(io: std.Io) !void {
    var tmp = try Dir.cwd().createDirPathOpen(io, "/work/tmp", .{
        .open_options = .{ .iterate = true, .follow_symlinks = false },
    });
    defer tmp.close(io);
    _ = try sandbox.sys(linux.fchown(tmp.handle, 0, 0), "construction temporary owner");
    _ = try sandbox.sys(linux.fchmod(tmp.handle, 0o700), "construction temporary mode");
}

fn launcherDomain() !void {
    const root: i32 = @intCast(try sandbox.sys(
        linux.open("/", .{ .PATH = true, .DIRECTORY = true }, 0),
        "worker domain root",
    ));
    defer _ = linux.close(root);
    // A separate signal/abstract-socket scope keeps root in the jail from
    // signalling host processes, including PID 1 and its own coordinator.
    const domain = try sandbox.Ruleset.init(.{});
    errdefer _ = linux.close(domain.fd);
    if (domain.abi < 6) return error.WorkerScopeRequired;
    try domain.add(
        root,
        sandbox.own_dir | sandbox.make_sym | sandbox.make_fifo | sandbox.refer | sandbox.execute,
    );
    try domain.port(sandbox.connect_tcp, 443);
    try domain.port(sandbox.connect_tcp, 53);
    var threaded: std.Io.Threaded = .init_single_threaded;
    var buf: [16]u8 = undefined;
    if (Dir.cwd().readFile(threaded.io(), "/usr/share/werewolf/image-update/port", &buf)) |text| {
        const port = try std.fmt.parseUnsigned(u16, std.mem.trim(u8, text, "\n"), 10);
        if (port == 0) return error.BadWorkerPort;
        try domain.port(sandbox.connect_tcp, port);
    } else |_| {}
    try domain.restrict();
}

fn constructionDomain(kind: Kind) !void {
    var rules: [10]sandbox.Rule = undefined;
    var count: usize = 0;
    for ([_]struct { [:0]const u8, u64 }{
        .{ "/usr", sandbox.read_file | sandbox.read_dir },
        .{ "/etc", sandbox.read_file | sandbox.read_dir },
        .{ "/host", sandbox.read_file | sandbox.read_dir },
        .{ "/work", sandbox.own_dir | sandbox.make_sym | sandbox.make_fifo | sandbox.refer },
        .{ "/cache", sandbox.own_dir | sandbox.make_sym | sandbox.refer },
        .{ "/log", sandbox.read_file | sandbox.write_file },
        .{ installer.interpreter, sandbox.read_file | sandbox.execute },
        .{
            if (kind == .build) "/usr/bin/mkfs.erofs" else "/usr/bin/apk",
            sandbox.read_file | sandbox.execute,
        },
        .{
            if (kind == .build) "/usr/bin/zstd" else "/usr/bin/apk",
            sandbox.read_file | sandbox.execute,
        },
    }) |grant| {
        rules[count] = .{
            .fd = @intCast(try sandbox.sys(
                linux.open(grant[0], .{ .PATH = true, .CLOEXEC = true }, 0),
                "construction grant",
            )),
            .access = grant[1],
        };
        count += 1;
    }
    defer {
        for (rules[0..count]) |rule| _ = linux.close(rule.fd);
    }
    // Only package jobs start fetch children. Builders need no TCP access.
    try sandbox.landlock(rules[0..count], if (kind == .packages) &.{ 443, 53 } else &.{});
}

fn coordinatorDomain() !void {
    var rules: [16]sandbox.Rule = undefined;
    var count: usize = 0;
    for ([_]struct { [:0]const u8, u64 }{
        .{ "/usr", sandbox.read_file | sandbox.read_dir },
        .{ "/etc", sandbox.read_file | sandbox.read_dir },
        .{ "/proc", sandbox.read_file | sandbox.read_dir },
        .{ "/sys", sandbox.read_file | sandbox.read_dir },
        .{ "/boot", sandbox.read_file | sandbox.read_dir },
        .{ "/run/config", sandbox.read_file | sandbox.read_dir },
        .{ "/run/werewolf", sandbox.read_file | sandbox.read_dir },
        .{ m.state_dir, sandbox.read_file | sandbox.read_dir },
        .{ m.coord_dir, sandbox.own_dir | sandbox.refer },
        .{ m.work_dir, sandbox.own_dir | sandbox.make_sym | sandbox.refer },
        .{ m.state_dir ++ "/reports", sandbox.own_dir | sandbox.refer },
        .{ m.log_path, sandbox.read_file | sandbox.write_file },
        .{ "/dev/pts", sandbox.read_dir | sandbox.write_file },
    }) |grant| {
        const rc = linux.open(grant[0], .{ .PATH = true, .CLOEXEC = true }, 0);
        if (linux.errno(rc) == .NOENT) continue;
        rules[count] = .{
            .fd = @intCast(try sandbox.sys(rc, "coordinator grant")),
            .access = grant[1],
        };
        count += 1;
    }
    defer {
        for (rules[0..count]) |rule| _ = linux.close(rule.fd);
    }
    try sandbox.landlock(rules[0..count], &.{});
    var filter = coordinatorFilter();
    try filter.install();
}

fn coordinatorFilter() sandbox.Filter {
    var filter: sandbox.Filter = .{};
    inline for (.{
        "copy_file_range", "sendfile",
        "read",            "readv",
        "pread64",         "preadv",
        "write",           "writev",
        "pwrite64",        "pwritev",
        "openat",          "openat2",
        "close",           "fstat",
        "newfstatat",      "statx",
        "stat",            "lstat",
        "fstatfs",         "statfs",
        "lseek",           "getdents64",
        "faccessat",       "faccessat2",
        "readlinkat",      "mkdirat",
        "mkdir",           "renameat",
        "renameat2",       "unlinkat",
        "unlink",          "fchmod",
        "fchmodat",        "fchmodat2",
        "ftruncate",       "fsync",
        "fdatasync",       "sync",
        "flock",           "fcntl",
        "sendmsg",         "recvmsg",
        "sendto",          "recvfrom",
        "bind",            "listen",
        "accept4",         "getsockopt",
        "poll",            "ppoll",
        "mmap",            "munmap",
        "mremap",          "mprotect",
        "madvise",         "brk",
        "futex",           "clock_gettime",
        "nanosleep",       "clock_nanosleep",
        "getrandom",       "uname",
        "getpid",          "gettid",
        "getuid",          "geteuid",
        "getgid",          "getegid",
        "rt_sigaction",    "rt_sigprocmask",
        "rt_sigreturn",    "pipe2",
        "exit_group",      "exit",
        "restart_syscall", "sched_yield",
        "sigaltstack",
    }) |name| filter.allow(name);
    filter.allowArg("socket", 0, linux.AF.UNIX);
    // Zig's I/O probes pipe availability and terminal settings. These
    // read-only requests grant no device-changing ioctls.
    for ([_]u32{ 0x541b, 0x5401, 0x802c542a, 0x5413 }) |request|
        filter.allowArg("ioctl", 1, request);
    return filter;
}

pub fn alive() bool {
    var item: linux.pollfd = .{ .fd = channel, .events = linux.POLL.IN, .revents = 0 };
    const rc = linux.poll(@ptrCast(&item), 1, 0);
    return linux.errno(rc) == .INTR or (linux.errno(rc) == .SUCCESS and item.revents == 0);
}

pub fn reset(u: *m.Update) !void {
    try checked(u, .reset, .{}, null);
}
pub fn packages(u: *m.Update, args: Packages) !void {
    try checked(u, .packages, args, null);
}
pub fn build(
    u: *m.Update,
    kernel: []const u8,
) !void {
    try checked(u, .build, Build{ .kernel = kernel, .host = u.host }, null);
}
pub fn fetch(u: *m.Update, url: []const u8, body: i32, max: usize) !sandbox.Exit {
    return call(u, .fetch, Fetch{ .url = url, .maximum = max }, body);
}

pub fn read(u: *m.Update, job: cve.Job, body: cve.Body) !sandbox.Exit {
    return call(u, .read, Read{ .job = job, .size = body.size }, body.fd);
}

fn checked(u: *m.Update, kind: Kind, args: anytype, body: ?i32) !void {
    const result = try call(u, kind, args, body);
    if (result.code != 0) {
        u.detail = result.out;
        return error.WorkerFailed;
    }
    if (result.out.len > 0) try std.Io.File.stdout().writeStreamingAll(u.io, result.out);
}

fn call(u: *m.Update, kind: Kind, args: anytype, body: ?i32) !sandbox.Exit {
    const data = try std.json.Stringify.valueAlloc(u.gpa, args, .{});
    if (data.len > maximum) return error.TooBig;
    var input: [2]i32 = undefined;
    _ = try sandbox.sys(linux.pipe2(&input, .{ .CLOEXEC = true }), "worker input pipe");
    send(
        channel,
        @backingInt(kind),
        if (body) |b| &.{ input[0], b } else &.{input[0]},
    ) catch |err| {
        _ = linux.close(input[0]);
        _ = linux.close(input[1]);
        return err;
    };
    _ = linux.close(input[0]);
    writeAll(input[1], data) catch |err| {
        _ = linux.close(input[1]);
        return err;
    };
    _ = linux.close(input[1]);
    const response = try receive(channel);
    defer response.close();
    if (response.count != 1) return error.BadWorkerResponse;
    try anonymousPipe(response.fds[0]);
    return .{ .code = response.kind, .out = try contents(u.io, u.gpa, response.fds[0], 4 << 20) };
}

fn writeAll(fd: i32, data: []const u8) !void {
    var off: usize = 0;
    while (off < data.len) {
        const n = linux.write(fd, data[off..].ptr, data.len - off);
        if (linux.errno(n) == .INTR) continue;
        off += try sandbox.sys(n, "worker pipe write");
    }
}

fn anonymousPipe(fd: i32) !void {
    var st: [32]usize = undefined;
    _ = try sandbox.sys(
        linux.syscall2(.fstatfs, @intCast(fd), @intFromPtr(&st)),
        "worker pipe filesystem",
    );
    if (st[0] != 0x50495045) return error.NotAnonymousWorkerPipe;
}

fn contents(io: std.Io, gpa: std.mem.Allocator, fd: i32, max: usize) ![]const u8 {
    _ = io;
    const data = try gpa.alloc(u8, max + 1);
    var got: usize = 0;
    while (true) {
        const n = linux.read(fd, data[got..].ptr, data.len - got);
        if (linux.errno(n) == .INTR) continue;
        const count = try sandbox.sys(n, "worker pipe read");
        if (count == 0) return data[0..got];
        got += count;
        if (got > max) return error.TooBig;
    }
}

const Packet = struct {
    kind: u8,
    fds: [2]i32 = .{ -1, -1 },
    count: usize = 0,
    fn close(p: Packet) void {
        for (p.fds[0..p.count]) |fd| _ = linux.close(fd);
    }
};

fn send(fd: i32, kind: u8, fds: []const i32) !void {
    const e = @import("builtin").cpu.arch.endian();
    var ancillary: [24]u8 align(8) = @splat(0);
    const size = 16 + 4 * fds.len;
    std.mem.writeInt(usize, ancillary[0..8], size, e);
    std.mem.writeInt(i32, ancillary[8..12], linux.SOL.SOCKET, e);
    std.mem.writeInt(i32, ancillary[12..16], linux.SCM.RIGHTS, e);
    for (fds, 0..) |value, i| std.mem.writeInt(i32, ancillary[16 + i * 4 ..][0..4], value, e);
    const bytes = [1]u8{kind};
    const iov = [_]std.posix.iovec_const{.{ .base = &bytes, .len = 1 }};
    const msg: linux.msghdr_const = .{
        .name = null,
        .namelen = 0,
        .iov = &iov,
        .iovlen = 1,
        .control = if (fds.len == 0) null else &ancillary,
        .controllen = if (fds.len == 0) 0 else ancillary.len,
        .flags = 0,
    };
    if (try sandbox.sys(
        linux.sendmsg(fd, &msg, linux.MSG.NOSIGNAL),
        "worker send",
    ) != 1) return error.WorkerSend;
}

fn receive(fd: i32) !Packet {
    var bytes: [2]u8 = undefined;
    var ancillary: [1040]u8 align(8) = undefined;
    var iov = [_]std.posix.iovec{.{ .base = &bytes, .len = bytes.len }};
    var msg: linux.msghdr = .{
        .name = null,
        .namelen = 0,
        .iov = &iov,
        .iovlen = 1,
        .control = &ancillary,
        .controllen = ancillary.len,
        .flags = 0,
    };
    const n = try sandbox.sys(linux.recvmsg(fd, &msg, linux.MSG.CMSG_CLOEXEC), "worker receive");
    var packet: Packet = .{ .kind = if (n > 0) bytes[0] else 0 };
    var valid = n == 1 and msg.flags & (linux.MSG.TRUNC | linux.MSG.CTRUNC) == 0;
    var at: usize = 0;
    while (at + @sizeOf(linux.cmsghdr) <= msg.controllen) {
        const h: *align(1) const linux.cmsghdr = @ptrCast(&ancillary[at]);
        if (h.len < 16 or h.len > msg.controllen - at) {
            valid = false;
            break;
        }
        if (h.level != linux.SOL.SOCKET or h.type != linux.SCM.RIGHTS or (h.len - 16) % 4 != 0) {
            valid = false;
        } else {
            var pos = at + 16;
            while (pos < at + h.len) : (pos += 4) {
                const value = std.mem.readInt(
                    i32,
                    ancillary[pos..][0..4],
                    @import("builtin").cpu.arch.endian(),
                );
                if (packet.count < packet.fds.len) {
                    packet.fds[packet.count] = value;
                    packet.count += 1;
                } else {
                    _ = linux.close(value);
                    valid = false;
                }
            }
        }
        at += std.mem.alignForward(usize, h.len, 8);
    }
    if (!valid) {
        packet.close();
        return error.BadWorkerPacket;
    }
    return packet;
}

fn validCoordinatorStatus(status: []const u8) bool {
    var seen: u16 = 0;
    var lines = std.mem.tokenizeScalar(u8, status, '\n');
    while (lines.next()) |line| {
        inline for (.{
            "Uid:",
            "Gid:",
            "CapInh:",
            "CapPrm:",
            "CapEff:",
            "CapBnd:",
            "CapAmb:",
            "NoNewPrivs:",
            "Threads:",
        }, 0..) |key, index| {
            if (std.mem.startsWith(u8, line, key)) {
                if (seen & (@as(u16, 1) << index) != 0) return false;
                seen |= @as(u16, 1) << index;
                var fields = std.mem.tokenizeAny(u8, line[key.len..], " \t");
                var count: usize = 0;
                while (fields.next()) |field| {
                    const value = std.fmt.parseUnsigned(
                        u64,
                        field,
                        if (index >= 2 and index <= 6) 16 else 10,
                    ) catch return false;
                    const want: u64 = if (index < 2) coordinator_id else if (index >= 7) 1 else 0;
                    if (value != want) return false;
                    count += 1;
                }
                if (count != @as(usize, if (index < 2) 4 else 1)) return false;
            }
        }
    }
    return seen == 0x1ff;
}

test "coordinator reads its policy without reading secrets or writing config" {
    if (@import("builtin").os.tag != .linux or linux.geteuid() != 0) return error.SkipZigTest;
    const t = std.testing;
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    for ([_][]const u8{ "update-policy.json", "secret" }) |name| {
        const file = try tmp.dir.createFile(t.io, name, .{ .permissions = .fromMode(0o600) });
        defer file.close(t.io);
        try file.writeStreamingAll(t.io, "fixture");
    }
    const path = try tmp.dir.realPathFileAlloc(t.io, ".", t.allocator);
    defer t.allocator.free(path);
    const z = try t.allocator.printSentinel("{s}", .{path}, 0);
    defer t.allocator.free(z);
    try configAccess(z);
    var output: [2]i32 = undefined;
    _ = try sandbox.sys(linux.pipe2(&output, .{ .CLOEXEC = true }), "config probe pipe");
    defer _ = linux.close(output[0]);
    const pid = try sandbox.sys(linux.fork(), "fork config probe");
    if (pid == 0) {
        _ = linux.close(output[0]);
        sandbox.dropTo(coordinator_id, null) catch linux.exit_group(1);
        for ([_][:0]const u8{"update-policy.json"}) |name| {
            const raw = linux.openat(tmp.dir.handle, name, .{ .CLOEXEC = true }, 0);
            if (linux.errno(raw) != .SUCCESS) linux.exit_group(2);
            const fd: i32 = @intCast(raw);
            var buf: [7]u8 = undefined;
            const n = linux.read(fd, &buf, buf.len);
            _ = linux.close(fd);
            if (n != buf.len or !std.mem.eql(u8, &buf, "fixture")) linux.exit_group(3);
            if (linux.errno(linux.openat(
                tmp.dir.handle,
                name,
                .{ .ACCMODE = .WRONLY },
                0,
            )) != .ACCES)
                linux.exit_group(4);
        }
        if (linux.errno(linux.openat(tmp.dir.handle, "secret", .{}, 0)) != .ACCES)
            linux.exit_group(5);
        if (linux.errno(linux.openat(
            tmp.dir.handle,
            "new-file",
            .{ .CREAT = true },
            0o600,
        )) != .ACCES)
            linux.exit_group(6);
        linux.exit_group(0);
    }
    _ = linux.close(output[1]);
    const result = try sandbox.collect(arena.allocator(), @intCast(pid), output[0], 1024, 5);
    try t.expectEqual(@as(u8, 0), result.code);
}

test "coordinator refuses writable, shared, linked and foreign config files" {
    if (@import("builtin").os.tag != .linux or linux.geteuid() != 0) return error.SkipZigTest;
    const t = std.testing;
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    const file = try tmp.dir.createFile(t.io, "file", .{ .permissions = .fromMode(0o600) });
    defer file.close(t.io);
    _ = try sandbox.sys(linux.fchmod(file.handle, 0o666), "writable config fixture");
    try t.expectError(error.UnsafeUpdateConfig, configReadAccess(tmp.dir.handle, "file"));
    _ = try sandbox.sys(linux.fchmod(file.handle, 0o600), "private config fixture");
    _ = try sandbox.sys(
        linux.fchown(file.handle, coordinator_id, coordinator_id),
        "foreign config fixture",
    );
    try t.expectError(error.UnsafeUpdateConfig, configReadAccess(tmp.dir.handle, "file"));
    _ = try sandbox.sys(linux.fchown(file.handle, 0, 0), "root config fixture");
    _ = try sandbox.sys(
        linux.linkat(tmp.dir.handle, "file", tmp.dir.handle, "shared", 0),
        "shared config fixture",
    );
    try t.expectError(error.UnsafeUpdateConfig, configReadAccess(tmp.dir.handle, "shared"));
    try tmp.dir.symLink(t.io, "file", "linked", .{});
    if (configReadAccess(tmp.dir.handle, "linked")) |_|
        return error.TestUnexpectedResult
    else |_| {}
    var st: linux.Statx = undefined;
    _ = try sandbox.sys(
        linux.statx(file.handle, "", linux.AT.EMPTY_PATH, .{ .UID = true }, &st),
        "config fixture owner",
    );
    try t.expectEqual(@as(u32, 0), st.uid);
    try t.expectEqual(@as(u32, 0o600), (try file.stat(t.io)).permissions.toMode() & 0o777);
}

test "coordinator copies files, probes I/O and rejects device-changing ioctls" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    const t = std.testing;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    const payload = "copy probe";
    try tmp.dir.writeFile(t.io, .{ .sub_path = "source", .data = payload });
    const source = try tmp.dir.openFile(t.io, "source", .{});
    defer source.close(t.io);
    const copied = try tmp.dir.createFile(t.io, "copied", .{ .read = true });
    defer copied.close(t.io);
    var output: [2]i32 = undefined;
    _ = try sandbox.sys(linux.pipe2(&output, .{ .CLOEXEC = true }), "coordinator I/O probe");
    defer _ = linux.close(output[0]);
    const pid = try sandbox.sys(linux.fork(), "fork coordinator I/O probe");
    if (pid == 0) {
        _ = linux.close(output[0]);
        _ = linux.dup3(output[1], 2, 0);
        var filter = coordinatorFilter();
        filter.install() catch linux.exit_group(1);
        var buffer: [256]u8 align(8) = @splat(0);
        for ([_]u32{ 0x541b, 0x5401, 0x802c542a }) |request|
            _ = linux.ioctl(2, request, @intFromPtr(&buffer));
        if (linux.copy_file_range(source.handle, null, copied.handle, null, payload.len, 0) !=
            payload.len) linux.exit_group(2);
        var offset: i64 = 0;
        if (linux.sendfile(copied.handle, source.handle, &offset, payload.len) != payload.len)
            linux.exit_group(3);
        std.debug.print("coordinator I/O ready\n", .{});
        linux.exit_group(0);
    }
    _ = linux.close(output[1]);
    const result = try sandbox.collect(arena.allocator(), @intCast(pid), output[0], 1024, 5);
    try t.expectEqual(@as(u8, 0), result.code);
    try t.expectEqualStrings("coordinator I/O ready\n", result.out);
    var copied_bytes: [payload.len * 2]u8 = undefined;
    const length = try copied.readPositionalAll(t.io, &copied_bytes, 0);
    try t.expectEqualStrings(payload ++ payload, copied_bytes[0..length]);
    const blocked = try sandbox.sys(linux.fork(), "fork coordinator ioctl refusal");
    if (blocked == 0) {
        var filter = coordinatorFilter();
        filter.install() catch linux.exit_group(1);
        var buffer: [256]u8 align(8) = @splat(0);
        // TCSETS changes settings.
        _ = linux.ioctl(2, 0x5402, @intFromPtr(&buffer));
        linux.exit_group(0);
    }
    var status: i32 = 0;
    while (true) {
        const rc = linux.wait4(@intCast(blocked), &status, 0, null);
        if (linux.errno(rc) == .INTR) continue;
        _ = try sandbox.sys(rc, "wait coordinator ioctl refusal");
        break;
    }
    const termination: u32 = @bitCast(status);
    try t.expect(linux.W.IFSIGNALED(termination));
    try t.expectEqual(linux.SIG.SYS, linux.W.TERMSIG(termination));
}

test "coordinator requires all credentials and capability sets to be dropped" {
    const good = "Uid:\t77\t77\t77\t77\nGid:\t77\t77\t77\t77\n" ++
        "CapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapBnd:\t0\nCapAmb:\t0\nNoNewPrivs:\t1\nThreads:\t1\n";
    try std.testing.expect(validCoordinatorStatus(good));
    try std.testing.expect(!validCoordinatorStatus("Uid:\t77\t77\t0\t77\n"));
    try std.testing.expect(!validCoordinatorStatus(good ++ "CapPrm:\t1\n"));
    try std.testing.expect(!validCoordinatorStatus(good[0 .. good.len - 14]));
    const privileged = try std.mem.replaceOwned(
        u8,
        std.testing.allocator,
        good,
        "CapEff:\t0",
        "CapEff:\t200000",
    );
    defer std.testing.allocator.free(privileged);
    try std.testing.expect(!validCoordinatorStatus(privileged));
}

test "coordinator worker messages carry anonymous pipes and reject excess descriptors" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    var pair: [2]i32 = undefined;
    _ = try sandbox.sys(
        linux.socketpair(linux.AF.UNIX, linux.SOCK.SEQPACKET | linux.SOCK.CLOEXEC, 0, &pair),
        "test worker socketpair",
    );
    defer {
        for (pair) |fd| _ = linux.close(fd);
    }
    var input: [2]i32 = undefined;
    _ = try sandbox.sys(linux.pipe2(&input, .{ .CLOEXEC = true }), "test worker pipe");
    defer _ = linux.close(input[0]);
    try writeAll(input[1], "bounded job");
    _ = linux.close(input[1]);
    try send(pair[0], @backingInt(Kind.reset), &.{input[0]});
    const packet = try receive(pair[1]);
    defer packet.close();
    try std.testing.expectEqual(@as(usize, 1), packet.count);
    try anonymousPipe(packet.fds[0]);
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const data = try contents(std.testing.io, arena.allocator(), packet.fds[0], 32);
    try std.testing.expectEqualStrings("bounded job", data);
    var large: [2]i32 = undefined;
    _ = try sandbox.sys(linux.pipe2(&large, .{ .CLOEXEC = true }), "test bounded worker pipe");
    defer _ = linux.close(large[0]);
    try writeAll(large[1], "too big");
    _ = linux.close(large[1]);
    try std.testing.expectError(
        error.TooBig,
        contents(std.testing.io, arena.allocator(), large[0], 2),
    );
    const too_many = [_]i32{ input[0], input[0], input[0] };
    var control: [32]u8 align(8) = @splat(0);
    const endian = @import("builtin").cpu.arch.endian();
    std.mem.writeInt(usize, control[0..8], 28, endian);
    std.mem.writeInt(i32, control[8..12], linux.SOL.SOCKET, endian);
    std.mem.writeInt(i32, control[12..16], linux.SCM.RIGHTS, endian);
    for (too_many, 0..) |fd, i| std.mem.writeInt(i32, control[16 + i * 4 ..][0..4], fd, endian);
    const bytes = [1]u8{0};
    const iov = [_]std.posix.iovec_const{.{ .base = &bytes, .len = bytes.len }};
    const msg: linux.msghdr_const = .{
        .name = null,
        .namelen = 0,
        .iov = &iov,
        .iovlen = 1,
        .control = &control,
        .controllen = control.len,
        .flags = 0,
    };
    _ = try sandbox.sys(
        linux.sendmsg(pair[0], &msg, linux.MSG.NOSIGNAL),
        "send excessive worker rights",
    );
    try std.testing.expectError(error.BadWorkerPacket, receive(pair[1]));
}

test "coordinator launcher closes host FDs and cannot mount, chroot or change source files" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    if (linux.geteuid() != 0) return error.SkipZigTest;
    const t = std.testing;
    const io = t.io;
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "state/host");
    try tmp.dir.writeFile(io, .{ .sub_path = "outside", .data = "kept" });
    try tmp.dir.writeFile(io, .{ .sub_path = "state/host/kept", .data = "" });
    const base = try gpa.dupeSentinel(u8, try tmp.dir.realPathFileAlloc(io, "state", gpa), 0);
    const outside = try gpa.dupeSentinel(u8, try tmp.dir.realPathFileAlloc(io, "outside", gpa), 0);
    const target = try gpa.printSentinel("{s}/host/kept", .{base}, 0);
    const external = try tmp.dir.openFile(io, "outside", .{ .mode = .read_write });
    defer external.close(io);
    var output: [2]i32 = undefined;
    _ = try sandbox.sys(linux.pipe2(&output, .{ .CLOEXEC = true }), "launcher probe pipe");
    defer _ = linux.close(output[0]);
    const pid = try sandbox.sys(linux.fork(), "fork launcher probe");
    if (pid == 0) {
        launcherProbe(base, outside, target, external.handle, output[1]) catch |err|
            sandbox.say(output[1], 1, sandbox.whyNot(gpa, err), "");
        linux.exit_group(0);
    }
    _ = linux.close(output[1]);
    const result = try sandbox.collect(gpa, @intCast(pid), output[0], 1024, 15);
    if (result.code != 0) std.debug.print("launcher probe: {s}\n", .{result.out});
    try t.expectEqual(@as(u8, 0), result.code);
    try t.expectEqualStrings("kept", try tmp.dir.readFileAlloc(io, "outside", gpa, .unlimited));
}

fn launcherProbe(
    base: [*:0]const u8,
    outside: [*:0]const u8,
    target: [*:0]const u8,
    external: i32,
    report: i32,
) !void {
    _ = try sandbox.sys(linux.syscall1(.unshare, 0x20000), "private launcher probe mounts");
    _ = try sandbox.sys(
        linux.mount(null, "/", null, linux.MS.REC | linux.MS.PRIVATE, 0),
        "private launcher propagation",
    );
    _ = try sandbox.sys(
        linux.mount(outside, target, null, linux.MS.BIND, 0),
        "launcher source bind",
    );
    _ = try sandbox.sys(
        linux.mount(
            null,
            target,
            null,
            linux.MS.BIND | linux.MS.REMOUNT | linux.MS.RDONLY | linux.MS.NOSUID | linux.MS.NODEV,
            0,
        ),
        "read-only launcher source",
    );
    _ = try sandbox.sys(linux.dup3(external, 60, 0), "test broker descriptor");
    try confineLauncher(report, base);
    if (linux.errno(linux.fcntl(60, linux.F.GETFD, 0)) != .BADF) return error.InheritedBroker;
    if (linux.errno(linux.chroot("/")) != .PERM) return error.CanChrootAgain;
    if (linux.errno(linux.mount(
        null,
        "/",
        null,
        linux.MS.REMOUNT,
        0,
    )) != .PERM) return error.CanMount;
    if (linux.errno(linux.fchmodat(
        linux.AT.FDCWD,
        "/host/kept",
        0o777,
    )) != .ROFS) return error.CanChmodSource;
    if (linux.errno(linux.fchownat(
        linux.AT.FDCWD,
        "/host/kept",
        1234,
        1234,
        0,
    )) != .ROFS) return error.CanChownSource;
    if (linux.errno(linux.open(outside, .{}, 0)) != .NOENT) return error.CanReadOutside;
    launcherDomain() catch |err| {
        // Older fixture kernels must fail closed; production requires scope.
        if (err == error.WorkerScopeRequired) return;
        return err;
    };
    if (linux.errno(linux.kill(linux.getppid(), .CONT)) != .PERM) return error.CanSignalOutside;
}

test "coordinator builds an EROFS image with private scratch inside the jail" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    if (linux.geteuid() != 0) return error.SkipZigTest;
    const t = std.testing;
    const io = t.io;
    Dir.cwd().access(io, "/usr/bin/mkfs.erofs", .{}) catch return error.SkipZigTest;
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    for ([_][]const u8{ "usr", "etc", "host", "work/root", "cache" }) |path|
        try tmp.dir.createDirPath(io, path);
    try tmp.dir.writeFile(io, .{ .sub_path = "log", .data = "" });
    try tmp.dir.writeFile(io, .{ .sub_path = "work/root/kept", .data = "image content\n" });
    try tmp.dir.symLink(io, "usr/lib", "lib", .{});
    try tmp.dir.symLink(io, "usr/lib", "lib64", .{});
    try tmp.dir.symLink(io, "/work/tmp", "tmp", .{});
    const base = try gpa.dupeSentinel(u8, try tmp.dir.realPathFileAlloc(io, ".", gpa), 0);
    const runtime = try gpa.printSentinel("{s}/usr", .{base}, 0);
    var output: [2]i32 = undefined;
    _ = try sandbox.sys(linux.pipe2(&output, .{ .CLOEXEC = true }), "construction probe pipe");
    defer _ = linux.close(output[0]);
    const pid = try sandbox.sys(linux.fork(), "fork construction probe");
    if (pid == 0) {
        constructionProbe(gpa, base, runtime, output[1]) catch |err|
            sandbox.say(output[1], 1, sandbox.whyNot(gpa, err), "");
        linux.exit_group(0);
    }
    _ = linux.close(output[1]);
    const result = try sandbox.collect(gpa, @intCast(pid), output[0], 4096, 30);
    if (result.code != 0) std.debug.print("construction probe: {s}\n", .{result.out});
    try t.expectEqual(@as(u8, 0), result.code);
    const image = try tmp.dir.openFile(io, "work/root.erofs", .{});
    defer image.close(io);
    try t.expect(try image.length(io) > 0);
    const scratch = try tmp.dir.statFile(io, "work/tmp", .{});
    try t.expectEqual(@as(u32, 0o700), scratch.permissions.toMode() & 0o7777);
}

fn constructionProbe(
    gpa: std.mem.Allocator,
    base: [*:0]const u8,
    runtime: [*:0]const u8,
    report: i32,
) !void {
    _ = try sandbox.sys(linux.syscall1(.unshare, 0x20000), "private construction mounts");
    _ = try sandbox.sys(
        linux.mount(null, "/", null, linux.MS.REC | linux.MS.PRIVATE, 0),
        "private propagation",
    );
    _ = try sandbox.sys(
        linux.mount("/usr", runtime, null, linux.MS.BIND, 0),
        "construction runtime",
    );
    _ = try sandbox.sys(linux.mount(null, runtime, null, linux.MS.BIND | linux.MS.REMOUNT |
        linux.MS.RDONLY | linux.MS.NOSUID | linux.MS.NODEV, 0), "read-only runtime");
    try confineLauncher(report, base);
    try constructionDomain(.build);
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    try buildScratch(io);
    var u: m.Update = .{ .io = io, .gpa = gpa };
    errdefer writeAll(report, u.detail) catch {};
    try u.run(&.{
        "/usr/bin/mkfs.erofs",
        "-b",
        "4096",
        "-zzstd,level=5",
        "-C65536",
        "-Efragments",
        "-x-1",
        "--all-root",
        "/work/root.erofs",
        "/work/root",
    });
}

test "jail root keeps skeleton root-owned while migrating coordinator state into state/" {
    if (@import("builtin").os.tag != .linux or linux.geteuid() != 0) return error.SkipZigTest;
    const t = std.testing;
    const io = t.io;
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "jail/state");
    try tmp.dir.createDirPath(io, "jail/etc/apk/keys");
    try tmp.dir.writeFile(io, .{ .sub_path = "jail/log", .data = "old-log\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "jail/checked", .data = "" });
    try tmp.dir.writeFile(io, .{ .sub_path = "jail/etc/apk/keys/trusted.pub", .data = "key" });
    var jail = try tmp.dir.openDir(io, "jail", .{ .iterate = true, .follow_symlinks = false });
    defer jail.close(io);
    _ = try sandbox.sys(linux.fchown(jail.handle, 0, 0), "own test jail");
    _ = try sandbox.sys(linux.fchmod(jail.handle, 0o755), "test jail mode");
    try setRootDir(jail.handle, "etc");
    try setRootDir(jail.handle, "etc/apk");
    try setRootDir(jail.handle, "etc/apk/keys");
    var coord = try jail.openDir(io, "state", .{ .follow_symlinks = false });
    defer coord.close(io);
    _ = try sandbox.sys(
        linux.fchown(coord.handle, coordinator_id, coordinator_id),
        "own test coord",
    );
    _ = try sandbox.sys(linux.fchmod(coord.handle, 0o755), "test coord mode");
    try migrateRootState(io, jail, coord.handle);
    try ensureLogFile(jail.handle);
    try jail.access(io, "log", .{});
    try jail.access(io, "state/checked", .{});
    try t.expectError(error.FileNotFound, jail.access(io, "checked", .{}));

    var output: [2]i32 = undefined;
    _ = try sandbox.sys(linux.pipe2(&output, .{ .CLOEXEC = true }), "jail skeleton probe pipe");
    defer _ = linux.close(output[0]);
    const pid = try sandbox.sys(linux.fork(), "fork jail skeleton probe");
    if (pid == 0) {
        _ = linux.close(output[0]);
        sandbox.dropTo(coordinator_id, null) catch linux.exit_group(1);
        if (linux.errno(linux.unlinkat(jail.handle, "etc/apk/keys/trusted.pub", 0)) != .ACCES)
            linux.exit_group(2);
        if (linux.errno(linux.renameat(jail.handle, "etc", coord.handle, "stolen")) != .ACCES)
            linux.exit_group(3);
        if (linux.errno(linux.symlinkat("/tmp", jail.handle, "lib")) != .ACCES)
            linux.exit_group(4);
        const fd = linux.openat(
            coord.handle,
            "pending",
            .{ .ACCMODE = .WRONLY, .CREAT = true },
            0o600,
        );
        if (linux.errno(fd) != .SUCCESS) linux.exit_group(5);
        _ = linux.close(@intCast(fd));
        linux.exit_group(0);
    }
    _ = linux.close(output[1]);
    const result = try sandbox.collect(arena.allocator(), @intCast(pid), output[0], 1024, 5);
    try t.expectEqual(@as(u8, 0), result.code);
}
