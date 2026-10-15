//! init's image roots phase: it mounts what each OCI image root needs
//! (proc, devices, its own /tmp, /run, /data) before fence forbids
//! mounting. See docs/design/adhoc.md.
//!
//! The build lists the roots in /usr/share/werewolf/oci:
//!
//!     root web /oci/web _oci-web
//!     write web /var/cache/web
//!     data feed /data/share/gvm/vt /var/lib/openvas/plugins write
//!
//! Each target already exists in the image, and mount opens it without
//! following links. A failed bind is logged and the boot goes on; the
//! service will fail and park.

const std = @import("std");
const linux = std.os.linux;
const init = @import("init.zig");
const Machine = init.Machine;
const phase_config = @import("config.zig");
const exists = init.exists;
const mkdir = init.mkdir;
const mount_bin = init.mount_bin;
const say = init.say;

const list = "/usr/share/werewolf/oci";
const devices = [_][]const u8{ "null", "zero", "full", "random", "urandom" };

/// oci mounts what the listed image roots need, and reports whether there
/// were any.
pub fn oci(m: *Machine) bool {
    const text = m.read(list);
    if (text.len == 0) return false;
    const nodata = exists("/run/werewolf/nodata");
    const passwd = m.read("/etc/passwd");
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
            if (name.len == 0 or dir.len == 0 or ids == null) {
                say("oci: {s}: not a root line the build writes", .{line});
                name = "";
                continue;
            }
            root(m, name, dir, ids.?, nodata);
            if (nroot < max_roots) {
                roots[nroot] = .{ .name = name, .dir = dir, .ids = ids.? };
                nroot += 1;
            }
        } else if (std.mem.eql(u8, key, "write") and name.len > 0 and
            std.mem.eql(u8, words.next() orelse "", name))
        {
            const path = words.next() orelse continue;
            if (nodata) continue;
            const from = m.fmtZ("/data/svc/{s}{s}", .{ name, path });
            m.mkdirAll(from);
            _ = linux.fchmodat2(linux.AT.FDCWD, from, 0o755, linux.AT.SYMLINK_NOFOLLOW);
            own(from, ids.?);
            m.mount(&.{ "--bind", from, m.fmt("{s}{s}", .{ dir, path }) });
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
    if (!nodata) shareMounts(m, shares[0..nshare], roots[0..nroot]);
    // The binds are made: close each service's directories to its user
    // alone, as leash would, so one that parks before it starts leaves
    // none open. leash widens them for a share line when it starts.
    lines = std.mem.tokenizeScalar(u8, text, '\n');
    while (lines.next()) |line| {
        var words = std.mem.tokenizeScalar(u8, line, ' ');
        if (!std.mem.eql(u8, words.next() orelse "", "root")) continue;
        const svc = words.next() orelse continue;
        _ = linux.fchmodat2(
            linux.AT.FDCWD,
            m.fmtZ("/run/svc/{s}", .{svc}),
            0o700,
            linux.AT.SYMLINK_NOFOLLOW,
        );
        if (!nodata) _ = linux.fchmodat2(
            linux.AT.FDCWD,
            m.fmtZ("/data/svc/{s}", .{svc}),
            0o700,
            linux.AT.SYMLINK_NOFOLLOW,
        );
    }
    return true;
}

/// root mounts into dir a private procfs, the CPU list, five devices and
/// the resolver, and binds the service's own /tmp, /run and /data.
fn root(m: *Machine, name: []const u8, dir: []const u8, ids: phase_config.Ids, nodata: bool) void {
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
    // Bind the directory, so atomic DHCP replacements are visible in the
    // image's resolver symlink. Older retained roots have a plain placeholder.
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
    // Make the service's directories as leash would, owned by its user, so
    // it can write there from the start. They are 0711 while init binds
    // what is inside them, since the mount tool, root without
    // CAP_DAC_OVERRIDE, must pass through, and 0700 once oci is done;
    // leash sets the mode its share line asks for when the service starts.
    mkdir("/run/svc", 0o755);
    const run_dir = m.fmtZ("/run/svc/{s}", .{name});
    mkdir(run_dir, 0o711);
    _ = linux.fchmodat2(linux.AT.FDCWD, run_dir, 0o711, linux.AT.SYMLINK_NOFOLLOW);
    own(run_dir, ids);
    m.mount(&.{ "--bind", run_dir, m.fmt("{s}/tmp", .{dir}) });
    // A /run for a pid file or a socket, as every runtime provides.
    const run_run = m.fmtZ("/run/svc/{s}/run", .{name});
    mkdir(run_run, 0o755);
    own(run_run, ids);
    m.mount(&.{ "--bind", run_run, m.fmt("{s}/run", .{dir}) });
    if (nodata) return;
    mkdir("/data/svc", 0o755);
    const data_dir = m.fmtZ("/data/svc/{s}", .{name});
    mkdir(data_dir, 0o711);
    _ = linux.fchmodat2(linux.AT.FDCWD, data_dir, 0o711, linux.AT.SYMLINK_NOFOLLOW);
    own(data_dir, ids);
    m.mount(&.{ "--bind", data_dir, m.fmt("{s}/data", .{dir}) });
}

const max_roots = 16;
const max_shares = 32;

const Root = struct { name: []const u8, dir: []const u8, ids: phase_config.Ids };
const Share = struct { name: []const u8, host: []const u8, image: []const u8, write: bool };

/// shareMounts binds each data directory into the image that named it.
/// /data/share is traversable and not listable. The first writer of a
/// path owns it, mode 02750, so the group may read and the world may
/// not. A later writer is an ACL entry for that user alone, not a
/// group write. Other machines have no data lines, so this does nothing.
fn shareMounts(m: *Machine, shares: []const Share, roots: []const Root) void {
    if (shares.len == 0) return;
    mkdir("/data/share", 0o711);
    _ = linux.fchmodat2(linux.AT.FDCWD, "/data/share", 0o711, linux.AT.SYMLINK_NOFOLLOW);
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
        // mount keeps only CAP_SYS_ADMIN. Admit traversal while it opens
        // these paths, as root() does for the private service directories.
        shareMode(m, s.host, ids, 0o2751);
    }
    for (shares) |s| {
        const at = for (roots) |r| {
            if (std.mem.eql(u8, r.name, s.name)) break r;
        } else {
            say("oci: {s}: {s} is not a root", .{ s.host, s.name });
            continue;
        };
        m.mount(&.{ "--bind", m.z(s.host), m.fmt("{s}{s}", .{ at.dir, s.image }) });
    }
    // No service has started yet. Close traversal before handover, then
    // set writer ACLs: chmod after an ACL would narrow its writer mask.
    for (shares) |s| {
        const owner = ownerOf(shares, s.host) orelse continue;
        if (!std.mem.eql(u8, s.name, owner)) continue;
        const ids = idsOf(roots, owner) orelse continue;
        shareMode(m, s.host, ids, 0o2750);
        var extra: [4]u32 = undefined;
        const n = extraWriters(shares, roots, s.host, owner, &extra);
        if (n > 0) shareAcl(m.z(s.host), extra[0..n]);
    }
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

/// shareMode creates host and gives every directory under /data/share
/// to ids with mode. /data/share itself stays 0711.
fn shareMode(m: *Machine, host: []const u8, ids: phase_config.Ids, mode: u32) void {
    m.mkdirAll(m.z(host));
    const prefix = "/data/share";
    var at: usize = prefix.len;
    while (std.mem.findScalarPos(u8, host, at + 1, '/')) |slash| {
        if (slash > prefix.len) {
            const z = m.z(host[0..slash]);
            _ = linux.fchmodat2(linux.AT.FDCWD, z, mode, linux.AT.SYMLINK_NOFOLLOW);
            own(z, ids);
        }
        at = slash;
    }
    const z = m.z(host);
    _ = linux.fchmodat2(linux.AT.FDCWD, z, mode, linux.AT.SYMLINK_NOFOLLOW);
    own(z, ids);
}

/// extraWriters lists uids, other than the owner, that write host.
fn extraWriters(
    shares: []const Share,
    roots: []const Root,
    host: []const u8,
    owner: []const u8,
    out: *[4]u32,
) usize {
    var n: usize = 0;
    for (shares) |s| {
        if (!s.write or !std.mem.eql(u8, s.host, host) or std.mem.eql(u8, s.name, owner))
            continue;
        const ids = idsOf(roots, s.name) orelse continue;
        if (n == out.len) break;
        out[n] = ids.uid;
        n += 1;
    }
    // USER entries in an ACL are ordered by id.
    std.mem.sort(u32, out[0..n], {}, struct {
        fn less(_: void, a: u32, b: u32) bool {
            return a < b;
        }
    }.less);
    return n;
}

/// shareHost reports whether host is /data/share/NAME/ and a directory
/// beneath it, so a data line cannot bind /data/share itself or /etc.
fn shareHost(host: []const u8) bool {
    const prefix = "/data/share/";
    if (!std.mem.startsWith(u8, host, prefix)) return false;
    const rest = host[prefix.len..];
    const slash = std.mem.findScalar(u8, rest, '/') orelse return false;
    return slash > 0 and slash + 1 < rest.len;
}

/// shareAcl lets each uid in uids write the directory, and new files in
/// it. The group stays r-x and other stays nothing, unlike a `share
/// group` directory, whose ACL grants other r-x.
fn shareAcl(path: [:0]const u8, uids: []const u32) void {
    var buf: [4 + 8 * 6]u8 = undefined;
    const acl = userAcl(&buf, uids);
    const rc = linux.open(
        path,
        .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true },
        0,
    );
    if (linux.errno(rc) != .SUCCESS) {
        say("oci: {s}: cannot set its ACL", .{path});
        return;
    }
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    for ([_][*:0]const u8{ "system.posix_acl_access", "system.posix_acl_default" }) |attr| {
        if (linux.errno(linux.fsetxattr(fd, attr, acl.ptr, acl.len, 0)) != .SUCCESS)
            say("oci: {s}: cannot set its ACL", .{path});
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

test "a shared directory's ACL names the writer and not the world" {
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
    try std.testing.expect(!shareHost("/data/svc/gvmd/x"));
}

fn own(path: [:0]const u8, ids: phase_config.Ids) void {
    if (linux.errno(linux.fchownat(
        linux.AT.FDCWD,
        path,
        ids.uid,
        ids.gid,
        linux.AT.SYMLINK_NOFOLLOW,
    )) != .SUCCESS) say("oci: cannot give {s} to uid {d}", .{ path, ids.uid });
}
