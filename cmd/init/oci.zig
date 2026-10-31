//! init's image roots phase: it mounts what each OCI image root needs
//! (proc, devices, its own /tmp, /run, /data) before fence forbids
//! mounting. See docs/design/implemented/adhoc.md.
//!
//! The build lists the roots in /usr/share/werewolf/oci:
//!
//!     root web /oci/web _oci-web
//!     write web /var/cache/web
//!     data feed /data/share/gvm/vt /var/lib/openvas/plugins write
//!
//! Every directory under /data and /run is walked component-by-component
//! through openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV)
//! and bound directly by descriptor, so persistent data on /data can never
//! redirect init's chown, chmod, ACLs or bind mounts.

const std = @import("std");
const linux = std.os.linux;
const init = @import("init.zig");
const Machine = init.Machine;
const phase_config = @import("config.zig");
const exists = init.exists;
const say = init.say;

const list = "/usr/share/werewolf/oci";
const devices = [_][]const u8{ "null", "zero", "full", "random", "urandom" };

const O_RDONLY: u64 = 0;
const O_PATH: u64 = 0o10000000;
const O_DIRECTORY: u64 = 0o200000;
const O_NOFOLLOW: u64 = 0o400000;
const O_CLOEXEC: u64 = 0o2000000;
const RESOLVE_NO_XDEV: u64 = 0x01;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;
const AT_EMPTY_PATH: u32 = 0x1000;
const OPEN_TREE_CLONE: u32 = 1;
const MOVE_MOUNT_F_EMPTY_PATH: u32 = 0x04;
const MOVE_MOUNT_T_EMPTY_PATH: u32 = 0x40;

const ATTR = struct {
    const RDONLY: u64 = 0x1;
    const NOSUID: u64 = 0x2;
    const NODEV: u64 = 0x4;
    const NOEXEC: u64 = 0x8;
    const NOSYMFOLLOW: u64 = 0x200000;
};

const OpenHow = extern struct { flags: u64, mode: u64, resolve: u64 };
const MountAttr = extern struct { set: u64, clr: u64, propagation: u64, userns_fd: u64 };

const root_ids: phase_config.Ids = .{ .uid = 0, .gid = 0 };

/// oci mounts what the listed image roots need, and reports whether there
/// were any.
pub fn oci(m: *Machine) bool {
    const text = m.read(list);
    if (text.len == 0) return false;
    const nodata = exists("/run/werewolf/nodata");
    const passwd = m.read("/etc/passwd");

    const run_root = openMountRoot("/run") catch |err| {
        say("oci: /run: {s}", .{@errorName(err)});
        return true;
    };
    defer _ = linux.close(run_root);
    const run_svc = ensureSubdir(run_root, "svc", root_ids, 0o755, true) catch |err| {
        say("oci: /run/svc: {s}", .{@errorName(err)});
        return true;
    };
    defer _ = linux.close(run_svc);

    var data_root: ?i32 = null;
    defer if (data_root) |fd| {
        _ = linux.close(fd);
    };
    var data_svc: ?i32 = null;
    defer if (data_svc) |fd| {
        _ = linux.close(fd);
    };
    if (!nodata) {
        if (openMountRoot("/data")) |dfd| {
            data_root = dfd;
            _ = linux.fchown(dfd, 0, 0);
            _ = linux.fchmod(dfd, 0o755);
            if (ensureSubdir(dfd, "svc", root_ids, 0o755, true)) |sfd| {
                data_svc = sfd;
            } else |err| say("oci: /data/svc: {s}", .{@errorName(err)});
        } else |err| say("oci: /data: {s}", .{@errorName(err)});
    }

    var name: []const u8 = "";
    var dir: []const u8 = "";
    var ids: ?phase_config.Ids = null;
    var roots: [max_roots]Root = undefined;
    var nroot: usize = 0;
    var shares: [max_shares]Share = undefined;
    var nshare: usize = 0;
    var lines = std.mem.tokenizeScalar(u8, text, '\n');
    while (lines.next()) |line| {
        var words = std.mem.tokenizeScalar(u8, line, ' ');
        const key = words.next() orelse continue;
        if (std.mem.eql(u8, key, "root")) {
            name = words.next() orelse "";
            dir = words.next() orelse "";
            const user = words.next() orelse "";
            ids = phase_config.lookupIds(passwd, user);
            if (name.len == 0 or !isPlainComponent(name) or dir.len == 0 or ids == null) {
                say("oci: {s}: not a root line the build writes", .{line});
                name = "";
                continue;
            }
            root(m, run_svc, data_svc, name, dir, ids.?);
            if (nroot < max_roots) {
                roots[nroot] = .{ .name = name, .dir = dir, .ids = ids.? };
                nroot += 1;
            }
        } else if (std.mem.eql(u8, key, "write") and name.len > 0 and
            std.mem.eql(u8, words.next() orelse "", name))
        {
            const path = words.next() orelse continue;
            const sfd = data_svc orelse continue;
            bindWriteSubpath(m, sfd, name, dir, path, ids.?);
        } else if (std.mem.eql(u8, key, "data")) {
            const svc = words.next() orelse "";
            const host = words.next() orelse "";
            const image = words.next() orelse "";
            const access = words.next() orelse "";
            const write = std.mem.eql(u8, access, "write");
            if (words.next() != null or nshare == max_shares or svc.len == 0 or
                !shareHost(host) or image.len < 2 or image[0] != '/' or
                (!write and !std.mem.eql(u8, access, "read")))
            {
                say("oci: {s}: not a data line the build writes", .{line});
                continue;
            }
            shares[nshare] = .{ .name = svc, .host = host, .image = image, .write = write };
            nshare += 1;
        } else say("oci: {s}: not a line the build writes", .{line});
    }
    if (data_root) |dfd| shareMounts(m, dfd, passwd, shares[0..nshare], roots[0..nroot]);
    return true;
}

/// root mounts into dir a private procfs, the CPU list, five devices and
/// the resolver, and binds the service's own /tmp, /run and /data by
/// verified file descriptor.
fn root(
    m: *Machine,
    run_svc: i32,
    data_svc: ?i32,
    name: []const u8,
    dir: []const u8,
    ids: phase_config.Ids,
) void {
    m.mount(&.{ "-t", "proc", "-o", "hidepid=invisible", "proc", m.fmt("{s}/proc", .{dir}) });
    m.mount(&.{
        "--bind",
        "-o",
        "ro",
        "/sys/devices/system/cpu",
        m.fmt("{s}/sys/devices/system/cpu", .{dir}),
    });
    for (devices) |d| m.mount(&.{
        "--bind",
        m.fmt("/dev/{s}", .{d}),
        m.fmt("{s}/dev/{s}", .{ dir, d }),
    });
    const network = "/run/werewolf/network";
    const target = m.fmtZ("{s}/etc/werewolf-network", .{dir});
    if (exists(target)) {
        m.mount(&.{ "--bind", "-o", "ro", network, target });
    } else if (exists(m.fmtZ("{s}/resolv.conf", .{network}))) {
        m.mount(&.{
            "--bind",
            "-o",
            "ro",
            m.fmt("{s}/resolv.conf", .{network}),
            m.fmt("{s}/etc/resolv.conf", .{dir}),
        });
    }

    const root_fd = openMountRoot(m.z(dir)) catch |err| {
        say("oci: {s}: {s}", .{ dir, @errorName(err) });
        return;
    };
    defer _ = linux.close(root_fd);

    if (ensureSubdir(run_svc, name, ids, 0o700, true)) |svc_run| {
        defer _ = linux.close(svc_run);
        if (mountTargetAt(root_fd, "/tmp", ids)) |dst| {
            defer _ = linux.close(dst);
            bindFd(svc_run, dst, false) catch |err|
                say("oci: {s}/tmp: {s}", .{ dir, @errorName(err) });
        } else |err| say("oci: {s}/tmp: {s}", .{ dir, @errorName(err) });

        if (ensureSubdir(svc_run, "run", ids, 0o755, true)) |svc_run_run| {
            defer _ = linux.close(svc_run_run);
            if (mountTargetAt(root_fd, "/run", ids)) |dst| {
                defer _ = linux.close(dst);
                bindFd(svc_run_run, dst, false) catch |err|
                    say("oci: {s}/run: {s}", .{ dir, @errorName(err) });
            } else |err| say("oci: {s}/run: {s}", .{ dir, @errorName(err) });
            if (openMountRoot("/run/syslog")) |syslog_src| {
                defer _ = linux.close(syslog_src);
                if (mountTargetAt(root_fd, "/run/syslog", root_ids)) |syslog_dst| {
                    defer _ = linux.close(syslog_dst);
                    bindFd(syslog_src, syslog_dst, true) catch |err|
                        say("oci: {s}/run/syslog: {s}", .{ dir, @errorName(err) });
                } else |err| say("oci: {s}/run/syslog: {s}", .{ dir, @errorName(err) });
            } else |_| {}
        } else |err| say("oci: /run/svc/{s}/run: {s}", .{ name, @errorName(err) });
    } else |err| say("oci: /run/svc/{s}: {s}", .{ name, @errorName(err) });

    const sfd = data_svc orelse return;
    const svc_data = ensureSubdir(sfd, name, ids, 0o700, true) catch |err| {
        say("oci: /data/svc/{s}: {s}", .{ name, @errorName(err) });
        return;
    };
    defer _ = linux.close(svc_data);
    const data_dst = mountTargetAt(root_fd, "/data", ids) catch |err| {
        say("oci: {s}/data: {s}", .{ dir, @errorName(err) });
        return;
    };
    defer _ = linux.close(data_dst);
    bindFd(svc_data, data_dst, false) catch |err|
        say("oci: {s}/data: {s}", .{ dir, @errorName(err) });
}

fn bindWriteSubpath(
    m: *Machine,
    data_svc: i32,
    name: []const u8,
    dir: []const u8,
    path: []const u8,
    ids: phase_config.Ids,
) void {
    const svc_data = ensureSubdir(data_svc, name, ids, 0o700, true) catch |err| {
        say("oci: /data/svc/{s}: {s}", .{ name, @errorName(err) });
        return;
    };
    defer _ = linux.close(svc_data);
    const src = ensureWalk(svc_data, path, ids, 0o755) catch |err| {
        say("oci: /data/svc/{s}{s}: {s}", .{ name, path, @errorName(err) });
        return;
    };
    defer _ = linux.close(src);
    const root_fd = openMountRoot(m.z(dir)) catch |err| {
        say("oci: {s}: {s}", .{ dir, @errorName(err) });
        return;
    };
    defer _ = linux.close(root_fd);
    const dst = mountTargetAt(root_fd, path, ids) catch |err| {
        say("oci: {s}{s}: {s}", .{ dir, path, @errorName(err) });
        return;
    };
    defer _ = linux.close(dst);
    bindFd(src, dst, false) catch |err|
        say("oci: {s}{s}: {s}", .{ dir, path, @errorName(err) });
}

const max_roots = 16;
const max_shares = 32;
const max_host_writers = 32;
const max_acl_writers = 16;

const Root = struct { name: []const u8, dir: []const u8, ids: phase_config.Ids };
const Share = struct { name: []const u8, host: []const u8, image: []const u8, write: bool };
const HostWriter = struct { name: []const u8, host: []const u8, uid: u32 };

/// shareMounts binds each data directory into the image that named it.
/// /data/share is root-owned (0:0), mode 0711: traversable and not listable.
/// The first writer of a path owns it, mode 02750, so the group may read and
/// the world may not. Later writers (both OCI data writers and host services
/// with write /data/share/...) get per-user POSIX ACL entries on the verified
/// directory descriptor.
fn shareMounts(
    m: *Machine,
    data_root: i32,
    passwd: []const u8,
    shares: []const Share,
    roots: []const Root,
) void {
    if (shares.len == 0) return;
    const share_root = ensureSubdir(data_root, "share", root_ids, 0o711, true) catch |err| {
        say("oci: /data/share: {s}", .{@errorName(err)});
        return;
    };
    defer _ = linux.close(share_root);

    var host_writers: [max_host_writers]HostWriter = undefined;
    var nhost: usize = 0;
    for (m.list("/etc/sv")) |svc| {
        const svc_text = m.read(m.fmt("/etc/sv/{s}/service", .{svc}));
        nhost += parseHostShareWriters(svc, svc_text, passwd, host_writers[nhost..]);
    }

    for (shares) |s| {
        const owner = ownerOf(shares, s.host) orelse {
            say("oci: {s}: no service writes it", .{s.host});
            continue;
        };
        if (!std.mem.eql(u8, s.name, owner)) continue;
        const ids = idsOf(roots, owner) orelse {
            say("oci: {s}: {s} is not a root", .{ s.host, owner });
            continue;
        };
        const rel = s.host["/data/share/".len..];
        const fd = ensureWalk(share_root, rel, ids, 0o2750) catch |err| {
            say("oci: {s}: {s}", .{ s.host, @errorName(err) });
            continue;
        };
        defer _ = linux.close(fd);
        var extra: [max_acl_writers]u32 = undefined;
        const n = extraWriters(
            shares,
            roots,
            host_writers[0..nhost],
            s.host,
            owner,
            ids.uid,
            &extra,
        );
        if (n > 0) shareAclFd(fd, s.host, extra[0..n]);
    }

    for (shares) |s| {
        const owner = ownerOf(shares, s.host) orelse continue;
        const owner_ids = idsOf(roots, owner) orelse continue;
        const at = for (roots) |r| {
            if (std.mem.eql(u8, r.name, s.name)) break r;
        } else {
            say("oci: {s}: {s} is not a root", .{ s.host, s.name });
            continue;
        };
        const rel = s.host["/data/share/".len..];
        const src = openWalk(share_root, rel) catch |err| {
            say("oci: {s}: {s}", .{ s.host, @errorName(err) });
            continue;
        };
        defer _ = linux.close(src);
        var st: linux.Statx = undefined;
        if (linux.errno(linux.statx(
            src,
            "",
            AT_EMPTY_PATH,
            .{ .TYPE = true, .UID = true },
            &st,
        )) != .SUCCESS or st.mode & linux.S.IFMT != linux.S.IFDIR or st.uid != owner_ids.uid) {
            say("oci: {s}: unexpected owner", .{s.host});
            continue;
        }
        const root_fd = openMountRoot(m.z(at.dir)) catch |err| {
            say("oci: {s}: {s}", .{ at.dir, @errorName(err) });
            continue;
        };
        defer _ = linux.close(root_fd);
        const dst = mountTargetAt(root_fd, s.image, at.ids) catch |err| {
            say("oci: {s}{s}: mount point: {s}", .{ at.dir, s.image, @errorName(err) });
            continue;
        };
        defer _ = linux.close(dst);
        bindFd(src, dst, !s.write) catch |err|
            say("oci: {s}{s}: {s}", .{ at.dir, s.image, @errorName(err) });
    }
}

fn isPlainComponent(part: []const u8) bool {
    return part.len > 0 and part.len <= 255 and
        !std.mem.eql(u8, part, ".") and !std.mem.eql(u8, part, "..") and
        std.mem.findScalar(u8, part, '/') == null and
        std.mem.findScalar(u8, part, 0) == null;
}

fn openMountRoot(path: [:0]const u8) !i32 {
    var how: OpenHow = .{
        .flags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC,
        .mode = 0,
        .resolve = RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
    };
    const rc = linux.syscall4(
        .openat2,
        @bitCast(@as(isize, linux.AT.FDCWD)),
        @intFromPtr(path.ptr),
        @intFromPtr(&how),
        @sizeOf(OpenHow),
    );
    if (linux.errno(rc) != .SUCCESS) return error.OpenRoot;
    const fd: i32 = @intCast(rc);
    var st: linux.Statx = undefined;
    if (linux.errno(linux.statx(fd, "", AT_EMPTY_PATH, .{ .TYPE = true }, &st)) != .SUCCESS or
        st.mode & linux.S.IFMT != linux.S.IFDIR)
    {
        _ = linux.close(fd);
        return error.NotDirectory;
    }
    return fd;
}

fn openChildDir(parent_fd: i32, z: [:0]const u8, no_xdev: bool) usize {
    var how: OpenHow = .{
        .flags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC,
        .mode = 0,
        .resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS |
            (if (no_xdev) RESOLVE_NO_XDEV else 0),
    };
    return linux.syscall4(
        .openat2,
        @bitCast(@as(isize, parent_fd)),
        @intFromPtr(z.ptr),
        @intFromPtr(&how),
        @sizeOf(OpenHow),
    );
}

fn ensureSubdir(
    parent_fd: i32,
    part: []const u8,
    ids: phase_config.Ids,
    mode: u32,
    no_xdev: bool,
) !i32 {
    if (!isPlainComponent(part)) return error.InvalidPath;
    var name: [256]u8 = undefined;
    @memcpy(name[0..part.len], part);
    name[part.len] = 0;
    const z = name[0..part.len :0];
    const mk = linux.mkdirat(parent_fd, z, mode);
    switch (linux.errno(mk)) {
        .SUCCESS, .EXIST => {},
        else => return error.CreateDir,
    }
    const opened = openChildDir(parent_fd, z, no_xdev);
    if (linux.errno(opened) != .SUCCESS) return error.UnsafePath;
    const fd: i32 = @intCast(opened);
    errdefer _ = linux.close(fd);
    var st: linux.Statx = undefined;
    if (linux.errno(linux.statx(
        fd,
        "",
        AT_EMPTY_PATH,
        .{ .TYPE = true, .MODE = true, .UID = true, .GID = true },
        &st,
    )) != .SUCCESS or st.mode & linux.S.IFMT != linux.S.IFDIR)
        return error.UnsafePath;
    if ((st.uid != ids.uid or st.gid != ids.gid) and
        linux.errno(linux.fchown(fd, ids.uid, ids.gid)) != .SUCCESS)
        return error.OwnDir;
    if (st.mode & 0o7777 != mode and linux.errno(linux.fchmod(fd, mode)) != .SUCCESS)
        return error.ModeDir;
    return fd;
}

/// ensureWalk creates and verifies every component of path beneath base_fd
/// without following symlinks or crossing mount points, returning the leaf
/// directory descriptor.
fn ensureWalk(base_fd: i32, path: []const u8, ids: phase_config.Ids, mode: u32) !i32 {
    var cur = try dupDir(base_fd);
    errdefer _ = linux.close(cur);
    var saw_any = false;
    var at: usize = 0;
    while (at < path.len) {
        while (at < path.len and path[at] == '/') : (at += 1) {}
        if (at == path.len) break;
        const end = std.mem.findScalarPos(u8, path, at, '/') orelse path.len;
        const part = path[at..end];
        if (!isPlainComponent(part)) return error.InvalidPath;
        const next = try ensureSubdir(cur, part, ids, mode, true);
        _ = linux.close(cur);
        cur = next;
        saw_any = true;
        at = end;
    }
    if (!saw_any) return error.InvalidPath;
    return cur;
}

fn openWalk(base_fd: i32, path: []const u8) !i32 {
    var cur = try dupDir(base_fd);
    errdefer _ = linux.close(cur);
    var saw_any = false;
    var at: usize = 0;
    while (at < path.len) {
        while (at < path.len and path[at] == '/') : (at += 1) {}
        if (at == path.len) break;
        const end = std.mem.findScalarPos(u8, path, at, '/') orelse path.len;
        const part = path[at..end];
        if (!isPlainComponent(part)) return error.InvalidPath;
        var name: [256]u8 = undefined;
        @memcpy(name[0..part.len], part);
        name[part.len] = 0;
        const z = name[0..part.len :0];
        const next = openChildDir(cur, z, true);
        if (linux.errno(next) != .SUCCESS) return error.UnsafePath;
        _ = linux.close(cur);
        cur = @intCast(next);
        saw_any = true;
        at = end;
    }
    if (!saw_any) return error.InvalidPath;
    return cur;
}

fn dupDir(fd: i32) !i32 {
    const rc = linux.fcntl(fd, linux.F.DUPFD_CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return error.DupDir;
    return @intCast(rc);
}

fn mountTarget(root_dir: [:0]const u8, path: []const u8, ids: phase_config.Ids) !void {
    const root_fd = try openMountRoot(root_dir);
    defer _ = linux.close(root_fd);
    const dst = try mountTargetAt(root_fd, path, ids);
    _ = linux.close(dst);
}

fn mountTargetAt(root_fd: i32, path: []const u8, ids: phase_config.Ids) !i32 {
    var parent = try dupDir(root_fd);
    errdefer _ = linux.close(parent);
    var saw_any = false;
    var at: usize = 0;
    while (at < path.len) {
        while (at < path.len and path[at] == '/') : (at += 1) {}
        if (at == path.len) break;
        const end = std.mem.findScalarPos(u8, path, at, '/') orelse path.len;
        const part = path[at..end];
        if (!isPlainComponent(part)) return error.InvalidPath;
        var name: [256]u8 = undefined;
        @memcpy(name[0..part.len], part);
        name[part.len] = 0;
        const z = name[0..part.len :0];
        // A writable parent bind mount (such as gvmd's /var/lib/gvm) crosses a
        // mount boundary inside root_fd, so RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS
        // holds without RESOLVE_NO_XDEV.
        var next = openChildDir(parent, z, false);
        if (linux.errno(next) == .NOENT) {
            if (linux.errno(linux.mkdirat(parent, z, 0o755)) != .SUCCESS)
                return error.CreateMountPoint;
            next = openChildDir(parent, z, false);
            if (linux.errno(next) != .SUCCESS) return error.OpenMountPoint;
            if (linux.errno(linux.fchown(@intCast(next), ids.uid, ids.gid)) != .SUCCESS) {
                _ = linux.close(@intCast(next));
                return error.OwnMountPoint;
            }
        } else if (linux.errno(next) != .SUCCESS) return error.UnsafeMountPoint;
        _ = linux.close(parent);
        parent = @intCast(next);
        saw_any = true;
        at = end;
    }
    if (!saw_any) return error.InvalidPath;
    return parent;
}

fn bindFd(src_fd: i32, dst_fd: i32, read_only: bool) !void {
    const tree_rc = linux.syscall3(
        .open_tree,
        @bitCast(@as(isize, src_fd)),
        @intFromPtr(""),
        OPEN_TREE_CLONE | @as(u32, @truncate(O_CLOEXEC)) | AT_EMPTY_PATH,
    );
    if (linux.errno(tree_rc) != .SUCCESS) return error.OpenTree;
    const tree: i32 = @intCast(tree_rc);
    defer _ = linux.close(tree);

    var set: u64 = ATTR.NOSUID | ATTR.NODEV | ATTR.NOEXEC | ATTR.NOSYMFOLLOW;
    if (read_only) set |= ATTR.RDONLY;
    var attr: MountAttr = .{ .set = set, .clr = 0, .propagation = 0, .userns_fd = 0 };
    if (linux.errno(linux.syscall5(
        .mount_setattr,
        @bitCast(@as(isize, tree)),
        @intFromPtr(""),
        AT_EMPTY_PATH,
        @intFromPtr(&attr),
        @sizeOf(MountAttr),
    )) != .SUCCESS) return error.MountSetattr;

    if (linux.errno(linux.syscall5(
        .move_mount,
        @bitCast(@as(isize, tree)),
        @intFromPtr(""),
        @bitCast(@as(isize, dst_fd)),
        @intFromPtr(""),
        MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH,
    )) != .SUCCESS) return error.MoveMount;
}

/// ownerOf returns the first service that writes host, or null.
fn ownerOf(shares: []const Share, host: []const u8) ?[]const u8 {
    for (shares) |s| if (s.write and std.mem.eql(u8, s.host, host)) return s.name;
    return null;
}

fn idsOf(roots: []const Root, name: []const u8) ?phase_config.Ids {
    for (roots) |r| if (std.mem.eql(u8, r.name, name)) return r.ids;
    return null;
}

/// parseHostShareWriters scans a host service file (/etc/sv/NAME/service) for
/// write grants under /data/share/ and records its service uid. OCI roots have
/// a `root` line and are already accounted for in shares.
fn parseHostShareWriters(
    svc_name: []const u8,
    svc_text: []const u8,
    passwd: []const u8,
    out: []HostWriter,
) usize {
    var user: ?[]const u8 = null;
    var paths: [8][]const u8 = undefined;
    var npath: usize = 0;
    var lines = std.mem.tokenizeScalar(u8, svc_text, '\n');
    while (lines.next()) |raw| {
        const line = raw[0 .. std.mem.findScalar(u8, raw, '#') orelse raw.len];
        var words = std.mem.tokenizeAny(u8, line, " \t\r");
        const key = words.next() orelse continue;
        if (std.mem.eql(u8, key, "root")) return 0;
        if (std.mem.eql(u8, key, "user")) {
            user = words.next();
        } else if (std.mem.eql(u8, key, "write")) {
            while (words.next()) |w| {
                if (std.mem.startsWith(u8, w, "/data/share/") and npath < paths.len) {
                    paths[npath] = w;
                    npath += 1;
                }
            }
        }
    }
    if (npath == 0) return 0;
    const uname = user orelse return 0;
    const ids = phase_config.lookupIds(passwd, uname) orelse return 0;
    if (ids.uid <= 65535) return 0;
    var n: usize = 0;
    for (paths[0..npath]) |p| {
        if (n == out.len) break;
        out[n] = .{ .name = svc_name, .host = p, .uid = ids.uid };
        n += 1;
    }
    return n;
}

/// extraWriters lists sorted, unique uids (other than owner_uid) that write
/// host across both OCI data shares and host services.
fn extraWriters(
    shares: []const Share,
    roots: []const Root,
    host_writers: []const HostWriter,
    host: []const u8,
    owner: []const u8,
    owner_uid: u32,
    out: *[max_acl_writers]u32,
) usize {
    var n: usize = 0;
    for (shares) |s| {
        if (!s.write or !std.mem.eql(u8, s.host, host) or std.mem.eql(u8, s.name, owner))
            continue;
        const ids = idsOf(roots, s.name) orelse continue;
        if (ids.uid == owner_uid) continue;
        if (n == out.len) break;
        out[n] = ids.uid;
        n += 1;
    }
    for (host_writers) |hw| {
        if (std.mem.eql(u8, hw.name, owner) or hw.uid == owner_uid) continue;
        const matches = std.mem.eql(u8, hw.host, host) or
            (std.mem.startsWith(u8, host, hw.host) and host[hw.host.len] == '/');
        if (!matches) continue;
        if (n == out.len) break;
        out[n] = hw.uid;
        n += 1;
    }
    std.mem.sort(u32, out[0..n], {}, struct {
        fn less(_: void, a: u32, b: u32) bool {
            return a < b;
        }
    }.less);
    var unique: usize = 0;
    for (out[0..n]) |uid| {
        if (unique == 0 or out[unique - 1] != uid) {
            out[unique] = uid;
            unique += 1;
        }
    }
    return unique;
}

/// shareHost reports whether host is /data/share/NAME/ and a directory
/// beneath it, so a data line cannot bind /data/share itself or /etc.
fn shareHost(host: []const u8) bool {
    const prefix = "/data/share/";
    if (!std.mem.startsWith(u8, host, prefix)) return false;
    var parts = std.mem.splitScalar(u8, host[1..], '/');
    while (parts.next()) |p| if (!isPlainComponent(p)) return false;
    const rest = host[prefix.len..];
    const slash = std.mem.findScalar(u8, rest, '/') orelse return false;
    return slash > 0 and slash + 1 < rest.len;
}

/// shareAclFd lets each uid in uids write the open directory fd, and new files
/// in it. The group stays r-x and other stays nothing.
fn shareAclFd(fd: i32, label: []const u8, uids: []const u32) void {
    var buf: [4 + 8 * (4 + max_acl_writers)]u8 = undefined;
    const acl = userAcl(&buf, uids);
    for ([_][*:0]const u8{ "system.posix_acl_access", "system.posix_acl_default" }) |attr| {
        if (linux.errno(linux.fsetxattr(fd, attr, acl.ptr, acl.len, 0)) != .SUCCESS)
            say("oci: {s}: cannot set its ACL", .{label});
    }
}

/// userAcl is a POSIX ACL: the owner may do anything, each uid in uids
/// may too, the group may read and search, and other may nothing.
fn userAcl(buf: []u8, uids: []const u32) []const u8 {
    std.mem.writeInt(u32, buf[0..4], 2, .little);
    var i: usize = 4;
    i = aclEntry(buf, i, 0x01, 7, 0xffffffff);
    for (uids) |uid| i = aclEntry(buf, i, 0x02, 7, uid);
    i = aclEntry(buf, i, 0x04, 5, 0xffffffff);
    i = aclEntry(buf, i, 0x10, 7, 0xffffffff);
    i = aclEntry(buf, i, 0x20, 0, 0xffffffff);
    return buf[0..i];
}

fn aclEntry(buf: []u8, i: usize, tag: u16, perm: u16, id: u32) usize {
    std.mem.writeInt(u16, buf[i..][0..2], tag, .little);
    std.mem.writeInt(u16, buf[i + 2 ..][0..2], perm, .little);
    std.mem.writeInt(u32, buf[i + 4 ..][0..4], id, .little);
    return i + 8;
}

test "shared mount points and /data walks refuse symlinks and path traversal" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "var/lib/gvm");
    try tmp.dir.createDirPath(io, "outside");
    try tmp.dir.createDirPath(io, "victim");
    const root_path = try tmp.dir.realPathFileAlloc(io, ".", gpa);
    defer gpa.free(root_path);
    const root_z = try gpa.dupeSentinel(u8, root_path, 0);
    defer gpa.free(root_z);
    const ids: phase_config.Ids = .{ .uid = linux.getuid(), .gid = linux.getgid() };
    try mountTarget(root_z, "/var/lib/gvm/scap-data", ids);
    try tmp.dir.access(io, "var/lib/gvm/scap-data", .{});
    try tmp.dir.symLink(io, "../../../outside", "var/lib/gvm/link", .{});
    try std.testing.expectError(
        error.UnsafeMountPoint,
        mountTarget(root_z, "/var/lib/gvm/link/created", ids),
    );
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(io, "outside/created", .{}));
    try std.testing.expectError(
        error.InvalidPath,
        mountTarget(root_z, "/var/lib/gvm/../escaped", ids),
    );

    const root_fd = try openMountRoot(root_z);
    defer _ = linux.close(root_fd);
    const leaf = try ensureWalk(root_fd, "/svc/app/cache", ids, 0o755);
    _ = linux.close(leaf);
    try tmp.dir.symLink(io, "../../victim", "svc/app/escaped", .{});
    try std.testing.expectError(
        error.UnsafePath,
        ensureWalk(root_fd, "/svc/app/escaped/sub", ids, 0o700),
    );
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(io, "victim/sub", .{}));
}

test "a shared directory's ACL names both OCI and host writers, sorted and unique" {
    var buf: [64]u8 = undefined;
    const acl = userAcl(&buf, &.{4242});
    try std.testing.expectEqualSlices(u8, &.{
        2,    0,    0,    0,
        0x01, 0,    7,    0,
        0xff, 0xff, 0xff, 0xff,
        0x02, 0,    7,    0,
        0x92, 0x10, 0,    0,
        0x04, 0,    5,    0,
        0xff, 0xff, 0xff, 0xff,
        0x10, 0,    7,    0,
        0xff, 0xff, 0xff, 0xff,
        0x20, 0,    0,    0,
        0xff, 0xff, 0xff, 0xff,
    }, acl);
    try std.testing.expect(shareHost("/data/share/gvm/vt"));
    try std.testing.expect(!shareHost("/data/share/gvm"));
    try std.testing.expect(!shareHost("/data/share/gvm/../vt"));
    try std.testing.expect(!shareHost("/data/svc/gvmd/x"));

    const passwd =
        "root:x:0:0::/:/sbin/nologin\n" ++
        "_oci-unifi-core:x:70001:70001::/var/empty:/sbin/nologin\n" ++
        "nginx:x:70005:70005::/var/empty:/sbin/nologin\n" ++
        "unifi-systemd:x:70002:70002::/var/empty:/sbin/nologin\n";
    var hw: [8]HostWriter = undefined;
    var nhw: usize = 0;
    nhw += parseHostShareWriters(
        "nginx",
        "exec /usr/lib/werewolf/unifi-nginx\nuser nginx\nwrite /data/share/unifi/reload\n",
        passwd,
        hw[nhw..],
    );
    nhw += parseHostShareWriters(
        "unifi-systemd",
        "exec /usr/lib/werewolf/unifi-systemd\nuser unifi-systemd\nwrite /data/share/unifi/bus\n",
        passwd,
        hw[nhw..],
    );
    // An OCI service file (`root /oci/...`) is ignored by parseHostShareWriters.
    nhw += parseHostShareWriters(
        "unifi-core",
        "exec /app\nuser _oci-unifi-core\nroot /oci/unifi-core\nwrite /data/share/unifi/bus\n",
        passwd,
        hw[nhw..],
    );
    try std.testing.expectEqual(@as(usize, 2), nhw);

    const roots = [_]Root{
        .{ .name = "unifi-core", .dir = "/oci/unifi-core", .ids = .{ .uid = 70001, .gid = 70001 } },
        .{ .name = "helper", .dir = "/oci/helper", .ids = .{ .uid = 70009, .gid = 70009 } },
    };
    const shares = [_]Share{
        .{
            .name = "unifi-core",
            .host = "/data/share/unifi/bus",
            .image = "/werewolf/bus",
            .write = true,
        },
        .{
            .name = "helper",
            .host = "/data/share/unifi/bus",
            .image = "/werewolf/bus",
            .write = true,
        },
    };
    var extra: [max_acl_writers]u32 = undefined;
    const n = extraWriters(
        &shares,
        &roots,
        hw[0..nhw],
        "/data/share/unifi/bus",
        "unifi-core",
        70001,
        &extra,
    );
    try std.testing.expectEqualSlices(u32, &.{ 70002, 70009 }, extra[0..n]);
}
