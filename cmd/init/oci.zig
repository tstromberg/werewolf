//! init's image roots phase: it mounts what each OCI image root needs
//! (proc, devices, its own /tmp, /run, /data) before fence forbids
//! mounting. See docs/design/adhoc.md.
//!
//! The build lists the roots in /usr/share/werewolf/oci:
//!
//!     root web /oci/web _oci-web
//!     write web /var/cache/web
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
        } else if (std.mem.eql(u8, key, "write") and name.len > 0 and
            std.mem.eql(u8, words.next() orelse "", name))
        {
            const path = words.next() orelse continue;
            if (nodata) continue;
            const from = m.fmtZ("/data/svc/{s}{s}", .{ name, path });
            m.mkdirAll(from);
            _ = linux.fchmodat(linux.AT.FDCWD, from, 0o755);
            own(from, ids.?);
            m.mount(&.{ "--bind", from, m.fmt("{s}{s}", .{ dir, path }) });
        } else say("oci: {s}: not a line the build writes", .{line});
    }
    // The binds are made: close each service's directories to its user
    // alone, as leash would, so one that parks before it starts leaves
    // none open. leash widens them for a share line when it starts.
    lines = std.mem.tokenizeScalar(u8, text, '\n');
    while (lines.next()) |line| {
        var words = std.mem.tokenizeScalar(u8, line, ' ');
        if (!std.mem.eql(u8, words.next() orelse "", "root")) continue;
        const svc = words.next() orelse continue;
        _ = linux.fchmodat(linux.AT.FDCWD, m.fmtZ("/run/svc/{s}", .{svc}), 0o700);
        if (!nodata) _ = linux.fchmodat(linux.AT.FDCWD, m.fmtZ("/data/svc/{s}", .{svc}), 0o700);
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
    // With no resolver there is no file, and the image's empty one stays.
    const resolv = "/run/werewolf/network/resolv.conf";
    if (exists(resolv)) m.mount(&.{ "--bind", resolv, m.fmt("{s}/etc/resolv.conf", .{dir}) });
    // Make the service's directories as leash would, owned by its user, so
    // it can write there from the start. They are 0711 while init binds
    // what is inside them, since the mount tool, root without
    // CAP_DAC_OVERRIDE, must pass through, and 0700 once oci is done;
    // leash sets the mode its share line asks for when the service starts.
    mkdir("/run/svc", 0o755);
    const run_dir = m.fmtZ("/run/svc/{s}", .{name});
    mkdir(run_dir, 0o711);
    _ = linux.fchmodat(linux.AT.FDCWD, run_dir, 0o711);
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
    _ = linux.fchmodat(linux.AT.FDCWD, data_dir, 0o711);
    own(data_dir, ids);
    m.mount(&.{ "--bind", data_dir, m.fmt("{s}/data", .{dir}) });
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
