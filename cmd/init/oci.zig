//! init's image roots (docs/design/adhoc.md): what a service with a leash
//! `root` needs bound into the image it runs in, made before fence closes
//! mounting to everyone.
//!
//! The build compiled the rooted services into /usr/share/werewolf/oci,
//! from their service files:
//!
//!     root web /oci/web _oci-web
//!     write web /var/cache/web
//!
//! For each root, beneath it: a procfs of its own, hidepid=invisible; the
//! machine's CPU count, read-only; its five devices, null, zero, full,
//! random and urandom; the resolvers, where DHCP writes them; /tmp from
//! /run/svc/NAME, /run from its run/ and /data from /data/svc/NAME, all
//! noexec and the service's own; and each `write` path from
//! /data/svc/NAME/PATH, noexec.
//! Every target is a place the image carries for it (an empty directory
//! or file), which the mount tool opens with no link followed. A bind that
//! fails is said, and the boot goes on: the service finds out, and parks.

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

/// Bind what the image roots need; whether there were any.
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
    return true;
}

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
    // Where /etc/resolv.conf leads (cmd/init/network.zig); a machine with
    // no resolver has no file, and the image's own, empty, stands.
    const resolv = "/run/werewolf/network/resolv.conf";
    if (exists(resolv)) m.mount(&.{ "--bind", resolv, m.fmt("{s}/etc/resolv.conf", .{dir}) });
    // Its own two places, made here as leash would make them, and owned
    // by its user, so the service writes there from its first moment.
    mkdir("/run/svc", 0o755);
    const run_dir = m.fmtZ("/run/svc/{s}", .{name});
    mkdir(run_dir, 0o755);
    own(run_dir, ids);
    m.mount(&.{ "--bind", run_dir, m.fmt("{s}/tmp", .{dir}) });
    // Its /run, for a pid file or a socket, as every runtime gives one.
    const run_run = m.fmtZ("/run/svc/{s}/run", .{name});
    mkdir(run_run, 0o755);
    own(run_run, ids);
    m.mount(&.{ "--bind", run_run, m.fmt("{s}/run", .{dir}) });
    if (nodata) return;
    mkdir("/data/svc", 0o755);
    const data_dir = m.fmtZ("/data/svc/{s}", .{name});
    mkdir(data_dir, 0o755);
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
