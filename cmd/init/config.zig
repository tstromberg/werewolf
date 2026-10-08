//! init's config: the victim's filesystem, one config tar, a NoCloud seed,
//! or the cloud's metadata; extracted by a confined child, and checked.

const std = @import("std");
const seal_lib = @import("seal");
const sandbox = @import("sandbox");
const settings = @import("settings");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const linux = std.os.linux;
const testing = std.testing;
const init = @import("init.zig");
const Machine = init.Machine;
const executable = init.executable;
const exists = init.exists;
const firstLine = init.firstLine;
const isBlockDevice = init.isBlockDevice;
const lastField = init.lastField;
const mount_bin = init.mount_bin;
const say = init.say;
const trim = init.trim;

const max_config_file = 1 << 20;

/// What a config tar may hold in all, so one from a disk cannot fill /run.
const max_config_total = 16 << 20;

const max_config_entries = 256;

/// On a machine with slots, the filesystem holding them also holds, in
/// one directory, config.tar and data/ for /data. stage0 has mounted it
/// already, to read root.erofs.
pub fn victim(m: *Machine) void {
    const v = m.cmd.victim orelse return;
    // stage0 mounts it before it hands over, or the machine never gets
    // here (werewolf.victim comes only with werewolf.slot). Its device
    // is the kernel's word, from the mount table, not a second search
    // of every disk that could name a different one.
    const dev = m.mountSource("/victim") orelse
        return say("victim's filesystem {s} is not on /victim", .{v.uuid});
    m.victim_dir = m.fmt("/victim{s}", .{v.path});
    say("victim's filesystem {s} on /victim, werewolf in {s}", .{ dev, m.victim_dir });
}

/// One config tar: the victim's config.tar, or else the first block
/// device holding one ("ustar" at byte 257). Never a merge: any other is
/// said and ignored, so a disk someone attached cannot quietly replace
/// root's keys. Then a NoCloud seed, but only an ISO9660 volume labelled
/// cidata, found in the same pass by its volume descriptor alone, so no
/// other disk is ever mounted to look, and no blkid probes every
/// superblock of every disk (85 ms on GCP's network disks, where there
/// is never a seed); the first, and any other said and ignored, as a
/// second tar is. Before the network, as the tar may hold its address.
pub fn config(m: *Machine) void {
    var tar: ?[]const u8 = null;
    if (m.victim_dir.len > 0) {
        const t = m.fmt("{s}/config.tar", .{m.victim_dir});
        if (exists(m.z(t))) {
            say("config tar in {s}", .{m.victim_dir});
            tar = t;
        }
    }
    var seed_dev: ?[:0]const u8 = null;
    for (m.list("/sys/class/block")) |name| {
        const dev = m.fmtZ("/dev/{s}", .{name});
        if (!isBlockDevice(dev)) continue;
        if (isNoCloud(dev)) {
            if (seed_dev) |s|
                say("NoCloud seed on {s} ignored: the seed is {s}", .{ dev, s })
            else
                seed_dev = dev;
            continue;
        }
        if (!hasUstar(dev)) continue;
        if (tar) |t| {
            say("config tar on {s} ignored: the config is {s}", .{ dev, t });
            continue;
        }
        say("config tar on {s}", .{dev});
        tar = dev;
    }
    if (tar) |t| extract(m, t);

    var seeded = false;
    if (seed_dev) |cidata| {
        if (m.runQuiet(&.{ mount_bin, "-t", "iso9660", "-o", "ro", cidata, "/mnt" })) {
            if (exists("/mnt/user-data")) {
                say("NoCloud user-data on {s}", .{cidata});
                seeded = true;
                nocloud(m);
            }
            _ = linux.umount2("/mnt", 0);
        }
    }
    m.configured = tar != null or seeded;
}

/// Where no disk held a config and the form has werewolf's cloud
/// program, the config from the cloud's metadata server, checked and
/// rewritten by that program first (docs/cloud.md); a network file in
/// it comes too late, the network being up to fetch it. Then the
/// hostname and root's keys, from whichever config there is.
pub fn metadata(m: *Machine) void {
    if (!m.configured and executable("/usr/lib/werewolf/cloud-metadata") and
        m.run(&.{"/usr/lib/werewolf/cloud-metadata"}) and
        exists("/run/werewolf/cloud/config.tar"))
    {
        say("config tar from the cloud's metadata server", .{});
        extract(m, "/run/werewolf/cloud/config.tar");
        if (exists("/run/config/network"))
            say(
                "network: the cloud's network file is not read: the network was up to fetch it",
                .{},
            );
    }

    const name = if (exists("/run/config/hostname"))
        trim(firstLine(m.read("/run/config/hostname")))
    else
        "werewolf";
    const host = if (settings.isHostname(name)) name else blk: {
        var buf: [64]u8 = undefined;
        say("hostname '{s}' refused: not a hostname of at most 64 bytes", .{shown(&buf, name)});
        break :blk "werewolf";
    };
    m.write("/run/werewolf/hostname", m.fmt("{s}\n", .{host}), 0o644);
    // The machine's own name resolves, to itself, with no DNS: programs
    // that look it up (Java's getLocalHost) need it, and a lookup that
    // left the machine would say its name to the network.
    m.write("/run/werewolf/hosts", m.fmt(
        "127.0.0.1\tlocalhost {s}\n::1\t\tlocalhost {s}\n",
        .{ host, host },
    ), 0o644);
    _ = linux.syscall2(.sethostname, @intFromPtr(host.ptr), host.len);
    if (exists("/run/config/authorized_keys"))
        keys(m, "root", m.read("/run/config/authorized_keys"));
}

/// The first user in a NoCloud cloud-config and every ssh key in it,
/// which is what Lima provides. The name and uid come from outside the
/// machine: plain ones only. Written directly, since /etc is read-only:
/// "*" is no password, without the lock "!" that sshd reads as refusing
/// even a key. Home is on /data.
fn nocloud(m: *Machine) void {
    limaConfig(m);
    const nc = parseNoCloud(m.gpa, m.readRegular("/mnt/user-data")) catch return;
    if (nc.user.len > 0) {
        const passwd = m.read("/run/werewolf/passwd");
        const group = m.read("/run/werewolf/group");
        // The name must be new to the group file too: the image's has
        // groups no account owns (wheel, disk, shadow), and a second line
        // with one of their names would be a name meaning two groups.
        if (isPlainUser(nc.user) and isPlainUid(nc.uid) and !hasEntry(passwd, nc.user) and
            !hasEntry(group, nc.user) and !idInUse(passwd, nc.uid) and !idInUse(group, nc.uid))
        {
            m.append(
                "/run/werewolf/passwd",
                m.fmt(
                    "{s}:x:{s}:{s}::/data/home/{s}:/bin/ash\n",
                    .{ nc.user, nc.uid, nc.uid, nc.user },
                ),
            );
            m.append("/run/werewolf/group", m.fmt("{s}:x:{s}:\n", .{ nc.user, nc.uid }));
            m.append("/run/werewolf/shadow", m.fmt("{s}:*:0:0:99999:7:::\n", .{nc.user}));
            keys(m, nc.user, nc.keys);
            m.nocloud_user = nc.user;
        } else {
            var user_buf: [64]u8 = undefined;
            var uid_buf: [16]u8 = undefined;
            say(
                "NoCloud user '{s}' (uid {s}) refused: not a plain name, or a uid from 500 " ++
                    "to 60000 no account has",
                .{ shown(&user_buf, nc.user), shown(&uid_buf, nc.uid) },
            );
        }
    }
    // Lima's readiness probe reads the instance-id back from here; it is
    // what cloud-init's boot scripts would have written.
    const id = instanceId(m.readRegular("/mnt/meta-data"));
    m.write("/run/lima-boot-done", if (id.len > 0) m.fmt("{s}\n", .{id}) else "", 0o644);
}

/// Import only Lima's data provisioning into root-private /run/config.
/// Treat lima.env as data, never source it or run any cidata script.
fn limaConfig(m: *Machine) void {
    var cidata = Dir.cwd().openDir(m.io, "/mnt", .{ .follow_symlinks = false }) catch return;
    defer cidata.close(m.io);
    const env = readLimaFile(m.gpa, m.io, cidata, "lima.env") catch |err| switch (err) {
        error.FileNotFound => return,
        else => return say("Lima config refused: {s}", .{@errorName(err)}),
    };
    const files = limaDataFiles(m.gpa, env) catch |err|
        return say("Lima config refused: {s}", .{@errorName(err)});
    if (files.len == 0) return;
    // Read and check every source before writing any destination.
    const values = readLimaData(m.gpa, m.io, cidata, files) catch |err|
        return say("Lima config refused: {s}", .{@errorName(err)});
    var n: usize = 0;
    for (files, values) |file, value| {
        const dest = m.fmt("/run/config/{s}", .{file.name});
        // The config tar's word stands: Lima's adds, never replaces.
        if (exists(m.z(dest))) {
            say("Lima config: {s} kept, as the config tar gave it", .{file.name});
            continue;
        }
        if (std.fs.path.dirname(dest)) |parent| m.mkdirAll(m.z(parent));
        m.write(dest, value, 0o600);
        n += 1;
    }
    say("Lima config: imported {d} data files", .{n});
}

/// user's ssh keys, where sshd looks (AuthorizedKeysFile).
fn keys(m: *Machine, user: []const u8, text: []const u8) void {
    const path = m.fmtZ("/run/werewolf/keys/{s}", .{user});
    m.write(path, text, 0o600);
    const ids = lookupIds(m.read("/run/werewolf/passwd"), user) orelse return;
    _ = linux.fchownat(linux.AT.FDCWD, path, ids.uid, ids.gid, 0);
}

/// A config tar into /run/config, by a child that can do nothing else:
/// root's uid with no capabilities, Landlock letting it write beneath
/// /run/config alone and read nothing else, and a filter of file calls
/// alone. It reads the whole tar once to check its size, then extracts
/// it, or nothing: at most 256 entries and 16 MiB. Regular files and
/// directories only, each name relative and plain, no file over 1 MiB;
/// files 0600 and directories 0700, root's.
fn extract(m: *Machine, path: []const u8) void {
    // A regular file or a disk, no link followed: on a victim's
    // filesystem a FIFO at the name would hold PID 1 in open for good, a
    // link would lead it elsewhere.
    const src = linux.open(m.z(path), .{
        .ACCMODE = .RDONLY,
        .CLOEXEC = true,
        .NOFOLLOW = true,
        .NONBLOCK = true,
        .NOCTTY = true,
    }, 0);
    if (linux.errno(src) != .SUCCESS)
        return say("config: {s}: {t}", .{ path, linux.errno(src) });
    defer _ = linux.close(@intCast(src));
    const kind = init.fileType(@intCast(src));
    if (kind != linux.S.IFREG and kind != linux.S.IFBLK)
        return say("config: {s} refused: not a file or a disk", .{path});
    const dir = linux.open(
        "/run/config",
        .{ .PATH = true, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true },
        0,
    );
    if (linux.errno(dir) != .SUCCESS)
        return say("config: /run/config: {t}", .{linux.errno(dir)});
    defer _ = linux.close(@intCast(dir));
    const pid = linux.fork();
    if (linux.errno(pid) != .SUCCESS) return say("config: fork: {t}", .{linux.errno(pid)});
    if (pid == 0) extractChild(m, @intCast(src), @intCast(dir), path);
    var status: i32 = 0;
    while (linux.errno(linux.wait4(@intCast(pid), &status, 0, null)) == .INTR) {}
    const st: u32 = @bitCast(status);
    if (!linux.W.IFEXITED(st) or linux.W.EXITSTATUS(st) != 0)
        say("config: {s} not extracted", .{path});
}

/// The child of extract: confined, then the tar checked whole, then
/// written.
fn extractChild(m: *Machine, src: i32, dir: i32, path: []const u8) noreturn {
    confineExtract(dir) catch {
        say("config: cannot confine the extraction: {s} {s}", .{
            sandbox.failed, sandbox.errnoName(sandbox.failed_errno),
        });
        linux.exit_group(1);
    };
    const f: Io.File = .{ .handle = src, .flags = .{ .nonblocking = false } };
    const out: Dir = .{ .handle = dir };
    sizeUp(m, f) catch |err| {
        say("config: {s} refused: {s}", .{ path, @errorName(err) });
        linux.exit_group(1);
    };
    if (linux.errno(linux.lseek(src, 0, linux.SEEK.SET)) != .SUCCESS) linux.exit_group(1);
    writeOut(m, f, out) catch |err| {
        say("config: {s}: {s}", .{ path, @errorName(err) });
        linux.exit_group(1);
    };
    linux.exit_group(0);
}

/// The tar's entries and file bytes counted, before anything is written.
fn sizeUp(m: *Machine, f: Io.File) !void {
    var rbuf: [8192]u8 = undefined;
    var r = f.readerStreaming(m.io, &rbuf);
    var name_buf: [Dir.max_path_bytes]u8 = undefined;
    var link_buf: [Dir.max_path_bytes]u8 = undefined;
    var it: std.tar.Iterator = .init(
        &r.interface,
        .{ .file_name_buffer = &name_buf, .link_name_buffer = &link_buf },
    );
    var entries: usize = 0;
    var total: u64 = 0;
    while (try it.next()) |e| {
        entries += 1;
        if (e.kind == .file) total += e.size;
        if (entries > max_config_entries) return error.TooManyEntries;
        if (total > max_config_total) return error.TooLarge;
    }
}

/// Each entry written beneath out: what is not plain is said and left.
fn writeOut(m: *Machine, f: Io.File, out: Dir) !void {
    var rbuf: [8192]u8 = undefined;
    var r = f.readerStreaming(m.io, &rbuf);
    var name_buf: [Dir.max_path_bytes]u8 = undefined;
    var link_buf: [Dir.max_path_bytes]u8 = undefined;
    var it: std.tar.Iterator = .init(
        &r.interface,
        .{ .file_name_buffer = &name_buf, .link_name_buffer = &link_buf },
    );
    // The caps sizeUp held the tar to, held again on this pass: a disk's
    // bytes are the hypervisor's to change between the two reads.
    var entries: usize = 0;
    var total: u64 = 0;
    while (try it.next()) |e| {
        entries += 1;
        if (e.kind == .file) total += e.size;
        if (entries > max_config_entries) return error.TooManyEntries;
        if (total > max_config_total) return error.TooLarge;
        const name = settings.entryName(e.name) orelse {
            var buf: [64]u8 = undefined;
            say(
                "config: {s} refused: not a plain relative name of letters, digits and . _ - /",
                .{shown(&buf, e.name)},
            );
            continue;
        };
        if (name.len == 0) continue;
        switch (e.kind) {
            .directory => out.createDirPath(m.io, name) catch |err|
                say("config: {s}: {s}", .{ name, @errorName(err) }),
            .sym_link => say("config: {s} refused: a link", .{name}),
            .file => {
                if (e.size > max_config_file) {
                    say("config: {s} refused: over 1 MiB", .{name});
                    continue;
                }
                if (std.fs.path.dirname(name)) |parent| out.createDirPath(m.io, parent) catch {};
                var file = out.createFile(
                    m.io,
                    name,
                    .{ .permissions = .fromMode(0o600) },
                ) catch |err| {
                    say("config: {s}: {s}", .{ name, @errorName(err) });
                    continue;
                };
                defer file.close(m.io);
                var wbuf: [8192]u8 = undefined;
                var w = file.writer(m.io, &wbuf);
                try it.streamRemaining(e, &w.interface);
                try w.interface.flush();
            },
        }
    }
}

/// What a config tar's extraction may do: write beneath /run/config, which
/// dir names, and nothing else; root's uid with no capabilities, so no
/// other file it could not reach as an owner; no socket, process or mount
/// call, refused as if the kernel had none.
fn confineExtract(dir: i32) !void {
    try sandbox.keepOnly(0);
    try sandbox.landlock(&.{.{ .fd = dir, .access = sandbox.own_dir }}, &.{});
    var buf: [seal_lib.max_filter]seal_lib.Filter = undefined;
    const filter = seal_lib.buildFilter(&buf, .initMany(&.{ .stdio, .rpath, .wpath }), true);
    _ = seal_lib.install(filter, false) catch {
        sandbox.failed = "seccomp";
        return error.SystemCall;
    };
}

const NoCloud = struct { user: []const u8 = "", uid: []const u8 = "1000", keys: []const u8 = "" };

const LimaFile = struct { id: []const u8, name: []const u8 };

fn readLimaData(gpa: Allocator, io: Io, cidata: Dir, files: []const LimaFile) ![]const []const u8 {
    var payloads = try cidata.openDir(io, "provision.data", .{ .follow_symlinks = false });
    defer payloads.close(io);
    const values = try gpa.alloc([]const u8, files.len);
    for (files, values) |file, *value|
        value.* = try readLimaFile(gpa, io, payloads, file.id);
    return values;
}

fn readLimaFile(gpa: Allocator, io: Io, dir: Dir, name: []const u8) ![]const u8 {
    // cidata is read-only. Refuse special files before opening: a FIFO
    // could otherwise wait forever for a writer before f.stat sees it.
    const entry = try dir.statFile(io, name, .{ .follow_symlinks = false });
    if (entry.kind != .file or entry.size > 32 * 1024) return error.InvalidLimaDataFile;
    var f = try dir.openFile(io, name, .{ .follow_symlinks = false });
    defer f.close(io);
    const st = try f.stat(io);
    if (st.kind != .file or st.size > 32 * 1024) return error.InvalidLimaDataFile;
    var buf: [4096]u8 = undefined;
    var reader = f.readerStreaming(io, &buf);
    return reader.interface.allocRemaining(gpa, .limited(32 * 1024));
}

test "Lima data is bounded and never follows links" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    const files = [_]LimaFile{.{ .id = "00000000", .name = "service/key" }};
    try tmp.dir.createDir(io, "provision.data", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "provision.data/00000000", .data = "private\n" });
    const values = try readLimaData(arena.allocator(), io, tmp.dir, &files);
    try std.testing.expectEqualStrings("private\n", values[0]);
    const large = try arena.allocator().alloc(u8, 32 * 1024 + 1);
    @memset(large, 'x');
    try tmp.dir.writeFile(io, .{ .sub_path = "provision.data/00000000", .data = large });
    try std.testing.expectError(
        error.InvalidLimaDataFile,
        readLimaData(arena.allocator(), io, tmp.dir, &files),
    );
    try tmp.dir.deleteFile(io, "provision.data/00000000");
    try tmp.dir.writeFile(io, .{ .sub_path = "victim", .data = "must not be imported" });
    try tmp.dir.symLink(io, "../victim", "provision.data/00000000", .{});
    if (readLimaData(arena.allocator(), io, tmp.dir, &files)) |_|
        return error.FollowedSymlink
    else |_| {}
    try tmp.dir.deleteFile(io, "provision.data/00000000");
    try tmp.dir.deleteDir(io, "provision.data");
    try tmp.dir.createDir(io, "other", .default_dir);
    try std.testing.expectError(
        error.InvalidLimaDataFile,
        readLimaFile(arena.allocator(), io, tmp.dir, "other"),
    );
    try tmp.dir.writeFile(io, .{ .sub_path = "other/00000000", .data = "outside" });
    try tmp.dir.symLink(io, "other", "provision.data", .{});
    if (readLimaData(arena.allocator(), io, tmp.dir, &files)) |_|
        return error.FollowedSymlink
    else |_| {}
}

fn limaDataFiles(gpa: Allocator, env: []const u8) ![]const LimaFile {
    var files: std.ArrayList(LimaFile) = .empty;
    var lines = std.mem.splitScalar(u8, env, '\n');
    while (lines.next()) |line| {
        const prefix = "LIMA_CIDATA_DATAFILE_";
        if (!std.mem.startsWith(u8, line, prefix)) continue;
        const rest = line[prefix.len..];
        if (rest.len < 14 or !std.mem.startsWith(u8, rest[8..], "_PATH=")) continue;
        const id = rest[0..8];
        for (id) |c| if (!std.ascii.isDigit(c)) return error.InvalidLimaDataId;
        const path = std.mem.trimEnd(u8, rest[14..], "\r");
        if (!std.mem.startsWith(u8, path, "/run/config/")) continue;
        const relative = path["/run/config/".len..];
        const name = settings.entryName(relative) orelse return error.InvalidLimaConfigPath;
        if (name.len == 0 or !std.mem.eql(u8, name, relative)) return error.InvalidLimaConfigPath;
        if (files.items.len == 32) return error.TooManyLimaConfigFiles;
        for (files.items) |f| {
            if (std.mem.eql(u8, f.id, id) or
                std.mem.eql(u8, f.name, name)) return error.DuplicateLimaConfigFile;
            // Prevent file/directory conflicts between destinations.
            if ((std.mem.startsWith(u8, name, f.name) and name.len > f.name.len and
                name[f.name.len] == '/') or
                (std.mem.startsWith(u8, f.name, name) and f.name.len > name.len and
                    f.name[name.len] == '/'))
                return error.ConflictingLimaConfigPaths;
        }
        try files.append(gpa, .{ .id = id, .name = name });
    }
    return files.items;
}

test "Lima data imports only plain config paths" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const files = try limaDataFiles(gpa,
        \\LIMA_CIDATA_DATAFILE_00000000_PATH=/run/config/bastion/settings.json
        \\LIMA_CIDATA_DATAFILE_00000001_PATH=/etc/ssh/sshd_config
        \\LIMA_CIDATA_DATAFILE_00000002_PATH=/run/config/tailscale/auth-key
        \\LIMA_CIDATA_YQ_PROVISION_00000003_PATH=/run/config/ignored
        \\LIMA_CIDATA_DATAFILE_00000004_OWNER=root:root
    );
    try std.testing.expectEqual(@as(usize, 2), files.len);
    try std.testing.expectEqualStrings("00000000", files[0].id);
    try std.testing.expectEqualStrings("bastion/settings.json", files[0].name);
    for ([_][]const u8{
        "/run/config/../etc/shadow",
        "/run/config/a//b",
        "/run/config/",
        "/run/config/a;echo",
    }) |path| {
        const line = try gpa.print("LIMA_CIDATA_DATAFILE_00000000_PATH={s}", .{path});
        try std.testing.expectError(error.InvalidLimaConfigPath, limaDataFiles(gpa, line));
    }
    try std.testing.expectError(
        error.InvalidLimaDataId,
        limaDataFiles(gpa, "LIMA_CIDATA_DATAFILE_../../.._PATH=/run/config/key"),
    );
    try std.testing.expectError(error.DuplicateLimaConfigFile, limaDataFiles(gpa,
        \\LIMA_CIDATA_DATAFILE_00000000_PATH=/run/config/key
        \\LIMA_CIDATA_DATAFILE_00000001_PATH=/run/config/key
    ));
    try std.testing.expectError(error.ConflictingLimaConfigPaths, limaDataFiles(gpa,
        \\LIMA_CIDATA_DATAFILE_00000000_PATH=/run/config/key
        \\LIMA_CIDATA_DATAFILE_00000001_PATH=/run/config/key/child
    ));
}

/// The first user's name and uid in a cloud-config, quotes dropped, and
/// every ssh public key in it, one a line.
fn parseNoCloud(gpa: Allocator, text: []const u8) !NoCloud {
    var nc: NoCloud = .{};
    var user_found = false;
    var uid_found = false;
    var found_keys: std.ArrayList(u8) = .empty;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        const t = std.mem.trimStart(u8, line, " ");
        if (!user_found and std.mem.startsWith(u8, t, "-")) {
            const rest = std.mem.trimStart(u8, t[1..], " ");
            if (std.mem.startsWith(u8, rest, "name:")) {
                nc.user = try std.mem.replaceOwned(u8, gpa, lastField(rest), "\"", "");
                user_found = true;
            }
        }
        if (!uid_found and std.mem.startsWith(u8, t, "uid:")) {
            nc.uid = try std.mem.replaceOwned(u8, gpa, lastField(t), "\"", "");
            uid_found = true;
        }
        try sshKeys(gpa, line, &found_keys);
    }
    nc.keys = found_keys.items;
    return nc;
}

/// Every ssh public key on line, one a line into out: a type, a space, the
/// base64 body, and an optional comment to the end of the line or a quote.
fn sshKeys(gpa: Allocator, line: []const u8, out: *std.ArrayList(u8)) !void {
    var i: usize = 0;
    while (i < line.len) {
        const start = i;
        const kind_end = keyTypeEnd(line[i..]) orelse {
            i += 1;
            continue;
        };
        var j = start + kind_end;
        const body = j;
        while (j < line.len and isBase64(line[j])) j += 1;
        if (j == body) {
            i += 1;
            continue;
        }
        if (j < line.len and line[j] == ' ') {
            const q = std.mem.findScalarPos(u8, line, j, '"') orelse line.len;
            j = q;
        }
        try out.print(gpa, "{s}\n", .{std.mem.trimEnd(u8, line[start..j], " \r")});
        i = j;
    }
}

/// Where the key type at the start of s ends, with its space: ssh-ed25519,
/// ssh-rsa, ecdsa-sha2-nistpN, sk-...@openssh.com.
fn keyTypeEnd(s: []const u8) ?usize {
    if (std.mem.startsWith(u8, s, "ssh-ed25519 ")) return "ssh-ed25519 ".len;
    if (std.mem.startsWith(u8, s, "ssh-rsa ")) return "ssh-rsa ".len;
    if (std.mem.startsWith(u8, s, "ecdsa-sha2-nistp")) {
        var k: usize = "ecdsa-sha2-nistp".len;
        while (k < s.len and std.ascii.isDigit(s[k])) k += 1;
        if (k == "ecdsa-sha2-nistp".len or k >= s.len or s[k] != ' ') return null;
        return k + 1;
    }
    if (std.mem.startsWith(u8, s, "sk-")) {
        const at = std.mem.indexOf(u8, s, "@openssh.com ") orelse return null;
        for (s[3..at]) |c| if (!std.ascii.isLower(c) and !std.ascii.isDigit(c) and
            c != '-') return null;
        return at + "@openssh.com ".len;
    }
    return null;
}

fn isBase64(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '+' or c == '/' or c == '=';
}

/// A NoCloud name: [a-z_][a-z0-9_-]{0,31}.
fn isPlainUser(s: []const u8) bool {
    if (s.len == 0 or s.len > 32) return false;
    if (!std.ascii.isLower(s[0]) and s[0] != '_') return false;
    for (s[1..]) |c| if (!std.ascii.isLower(c) and !std.ascii.isDigit(c) and c != '_' and
        c != '-') return false;
    return true;
}

/// A NoCloud uid: 500 to 60000, written plainly, so macOS's users (501
/// and up, which Lima passes on) fit and root's never does. Taking a system
/// account's is stopped by idInUse, not by the range.
fn isPlainUid(s: []const u8) bool {
    if (s.len == 0 or s.len > 5 or s[0] == '0') return false;
    for (s) |c| if (!std.ascii.isDigit(c)) return false;
    const n = std.fmt.parseInt(u32, s, 10) catch return false;
    return n >= 500 and n <= 60000;
}

/// Whether an /etc/passwd- or /etc/group-like file already has id as an
/// entry's third field: its uid, or its gid.
fn idInUse(text: []const u8, id: []const u8) bool {
    var it = std.mem.tokenizeScalar(u8, text, '\n');
    while (it.next()) |line| {
        var f = std.mem.splitScalar(u8, line, ':');
        _ = f.next();
        _ = f.next();
        if (std.mem.eql(u8, f.next() orelse continue, id)) return true;
    }
    return false;
}

/// Whether an /etc/passwd-like file has an entry for name.
fn hasEntry(text: []const u8, name: []const u8) bool {
    var it = std.mem.tokenizeScalar(u8, text, '\n');
    while (it.next()) |line| {
        if (std.mem.startsWith(u8, line, name) and line.len > name.len and
            line[name.len] == ':') return true;
    }
    return false;
}

pub const Ids = struct { uid: u32, gid: u32 };

/// name's uid and gid in an /etc/passwd.
pub fn lookupIds(passwd: []const u8, name: []const u8) ?Ids {
    var it = std.mem.tokenizeScalar(u8, passwd, '\n');
    while (it.next()) |line| {
        var f = std.mem.splitScalar(u8, line, ':');
        if (!std.mem.eql(u8, f.next() orelse continue, name)) continue;
        _ = f.next() orelse return null;
        const uid = std.fmt.parseInt(u32, f.next() orelse return null, 10) catch return null;
        const gid = std.fmt.parseInt(u32, f.next() orelse return null, 10) catch return null;
        return .{ .uid = uid, .gid = gid };
    }
    return null;
}

/// Text from outside as the console may show it: at most buf.len bytes,
/// each control byte a "?", so a name refused for holding one cannot put
/// an escape sequence or a false line on the console log.
fn shown(buf: []u8, s: []const u8) []const u8 {
    const n = @min(s.len, buf.len);
    for (s[0..n], buf[0..n]) |c, *o| o.* = if (c < 0x20 or c == 0x7f) '?' else c;
    return buf[0..n];
}

test "shown hides control bytes and bounds the text" {
    var buf: [8]u8 = undefined;
    try testing.expectEqualStrings("a?b?c", shown(&buf, "a\x1bb\x7fc"));
    try testing.expectEqualStrings("12345678", shown(&buf, "123456789"));
}

/// instance-id's value in a NoCloud meta-data.
fn instanceId(text: []const u8) []const u8 {
    var it = std.mem.tokenizeScalar(u8, text, '\n');
    while (it.next()) |line| {
        if (!std.mem.startsWith(u8, line, "instance-id:")) continue;
        var f = std.mem.tokenizeAny(u8, line["instance-id:".len..], " \t\r");
        return f.next() orelse "";
    }
    return "";
}

/// Whether dev holds a tar: "ustar" at byte 257.
pub fn hasUstar(dev: [:0]const u8) bool {
    const fd = linux.open(dev, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(fd) != .SUCCESS) return false;
    defer _ = linux.close(@intCast(fd));
    var magic: [5]u8 = undefined;
    const n = linux.pread(@intCast(fd), &magic, magic.len, 257);
    return linux.errno(n) == .SUCCESS and n == 5 and std.mem.eql(u8, &magic, "ustar");
}

/// Whether dev is an ISO9660 volume labelled cidata (or CIDATA), as a
/// NoCloud seed is: its primary volume descriptor, at 32 KiB, says CD001,
/// and its volume identifier, from byte 40, is the label: padded with
/// spaces, as the standard says, or with NULs, as Lima's and macOS's are.
fn isNoCloud(dev: [:0]const u8) bool {
    const fd = linux.open(dev, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(fd) != .SUCCESS) return false;
    defer _ = linux.close(@intCast(fd));
    var pvd: [72]u8 = undefined;
    const n = linux.pread(@intCast(fd), &pvd, pvd.len, 0x8000);
    return linux.errno(n) == .SUCCESS and n == pvd.len and isCidata(&pvd);
}

fn isCidata(pvd: *const [72]u8) bool {
    if (pvd[0] != 1 or !std.mem.eql(u8, pvd[1..6], "CD001")) return false;
    const volume = std.mem.trimEnd(u8, pvd[40..72], " \x00");
    return std.mem.eql(u8, volume, "cidata") or std.mem.eql(u8, volume, "CIDATA");
}

test parseNoCloud {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const ud =
        \\#cloud-config
        \\users:
        \\  - name: "t"
        \\    uid: "501"
        \\    ssh-authorized-keys:
        \\      - "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabc t@mac"
        \\      - ecdsa-sha2-nistp256 AAAAE2VjZHNh= other
        \\  - name: second
        \\    uid: 1002
    ;
    const nc = try parseNoCloud(arena.allocator(), ud);
    try testing.expectEqualStrings("t", nc.user);
    try testing.expectEqualStrings("501", nc.uid);
    try testing.expectEqualStrings(
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabc t@mac\necdsa-sha2-nistp256 AAAAE2VjZHNh= other\n",
        nc.keys,
    );
    try testing.expect(isPlainUid(nc.uid)); // 501: macOS's first user, through Lima
    const none = try parseNoCloud(arena.allocator(), "#cloud-config\n");
    try testing.expectEqualStrings("1000", none.uid);
    try testing.expectEqualStrings("", none.user);
}

test sshKeys {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var out: std.ArrayList(u8) = .empty;
    try sshKeys(arena.allocator(), "  - sk-ssh-ed25519@openssh.com AAAAGnNr comment here", &out);
    try sshKeys(arena.allocator(), "ssh-rsa AAAAB3Nza", &out);
    try sshKeys(arena.allocator(), "ssh-dss AAAA not ours; ssh-rsa  no-body", &out);
    try testing.expectEqualStrings(
        "sk-ssh-ed25519@openssh.com AAAAGnNr comment here\nssh-rsa AAAAB3Nza\n",
        out.items,
    );
}

test "validation" {
    try testing.expect(isPlainUser("lima"));
    try testing.expect(isPlainUser("_svc-1"));
    try testing.expect(!isPlainUser("Root"));
    try testing.expect(!isPlainUser("a:b"));
    try testing.expect(!isPlainUser("../x"));
    try testing.expect(isPlainUid("1000"));
    try testing.expect(isPlainUid("500"));
    try testing.expect(isPlainUid("60000"));
    try testing.expect(!isPlainUid("499"));
    try testing.expect(!isPlainUid("60001"));
    try testing.expect(!isPlainUid("0"));
    try testing.expect(!isPlainUid("0100"));
    try testing.expect(!isPlainUid("+501"));
    try testing.expect(!isPlainUid("1234567890"));
    try testing.expect(idInUse("root:x:0:0::/root:/bin/sh\n_dhcp:x:501:501::/:/x\n", "501"));
    try testing.expect(idInUse("_update:x:69:\n", "69"));
    try testing.expect(!idInUse("root:x:0:0::/root:/bin/sh\nt:x:5010:5010::/:/x\n", "501"));
    try testing.expect(hasEntry("root:x:0:0::/root:/bin/sh\nt:x:501:501::/:/x\n", "t"));
    try testing.expect(!hasEntry("tt:x:1:1::/:/x\n", "t"));
    try testing.expectEqual(
        Ids{ .uid = 200, .gid = 201 },
        lookupIds("nginx:x:200:201::/:/x\n", "nginx").?,
    );
}

test instanceId {
    try testing.expectEqualStrings(
        "i-0123",
        instanceId("local-hostname: x\ninstance-id: i-0123\n"),
    );
}

test isCidata {
    var pvd: [72]u8 = @splat(' ');
    pvd[0] = 1;
    @memcpy(pvd[1..6], "CD001");
    @memcpy(pvd[40..46], "cidata");
    try testing.expect(isCidata(&pvd));
    @memcpy(pvd[40..46], "CIDATA");
    try testing.expect(isCidata(&pvd));
    // Lima's seed, and macOS's hdiutil's, pad with NULs.
    @memset(pvd[46..72], 0);
    try testing.expect(isCidata(&pvd));
    @memset(pvd[46..72], ' ');
    // Another label, a label that only starts so, or no ISO9660 at all.
    @memcpy(pvd[40..46], "config");
    try testing.expect(!isCidata(&pvd));
    @memcpy(pvd[40..47], "cidata2");
    try testing.expect(!isCidata(&pvd));
    @memcpy(pvd[40..47], "cidata ");
    pvd[0] = 2; // a supplementary descriptor, not the primary
    try testing.expect(!isCidata(&pvd));
    pvd[0] = 1;
    @memcpy(pvd[1..6], "BEA01");
    try testing.expect(!isCidata(&pvd));
}
