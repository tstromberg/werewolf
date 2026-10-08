//! leash-reap: a leashed service's ./finish. When runsv stops the service
//! -- on `sv down`, a crash, a restart, or shutdown -- it runs this, which
//! kills the service's cgroup, and so its whole process tree, any detached
//! child included, by writing cgroup.kill. The cgroup is
//! /run/cgroup/svc/NAME, where NAME is the service directory this runs in
//! (cmd/init makes the hierarchy, cmd/leash joins each service to its leaf).
//!
//! What is still in the cgroup when this runs outlived the service's main
//! process: workers still stopping, or a child left behind on purpose. It
//! says how many, and waits, up to five seconds, for the kernel to see them
//! gone, so runsv starts the service again into an empty cgroup, with its
//! ports free, rather than into the last one's dying processes.
//!
//! runsv runs ./finish as root, in the service's directory, with the run's
//! exit status as arguments, which this ignores. Where there is no cgroup2
//! (cmd/init said so at boot), there is nothing to kill and it does
//! nothing. It is one of werewolf's own tiny programs (docs/programs.md):
//! no arguments it trusts, and nothing read but the service's own cgroup.

const std = @import("std");
const linux = std.os.linux;

/// How long the kernel is given to see the tree gone.
const patience_ms = 5000;

pub fn main() void {
    var cwd_buf: [std.fs.max_path_bytes]u8 = undefined;
    const cwd = linux.getcwd(&cwd_buf, cwd_buf.len);
    if (linux.errno(cwd) != .SUCCESS) return;
    const name = std.fs.path.basename(std.mem.sliceTo(cwd_buf[0..], 0));
    // Refuse a name that is not a plain service name, so the path is only
    // ever a leaf of /run/cgroup/svc.
    if (name.len == 0 or name.len > 64) return;
    for (name) |c| if (!std.ascii.isAlphanumeric(c) and c != '-' and c != '_') return;

    var dir_buf: [96]u8 = undefined;
    const dir = std.mem.print(&dir_buf, "/run/cgroup/svc/{s}", .{name}) catch return;
    var buf: [4096]u8 = undefined;
    const procs = read(dir, "cgroup.procs", &buf) orelse return; // no cgroup: nothing to reap
    const left = std.mem.count(u8, procs, "\n");
    if (left == 0) return;
    if (!write(dir, "cgroup.kill", "1")) return say(name, left, "could not be killed");
    var waited: u64 = 0;
    while (waited < patience_ms) : (waited += 10) {
        const events = read(dir, "cgroup.events", &buf) orelse
            return say(name, left, "killed, but cgroup.events cannot be read to see them gone");
        if (std.mem.find(u8, events, "populated 0\n") != null)
            return say(name, left, "killed");
        _ = linux.nanosleep(&.{ .sec = 0, .nsec = 10 * std.time.ns_per_ms }, null);
    }
    say(name, left, "killed, but not all gone after five seconds");
}

/// dir/file, read once, or null.
fn read(dir: []const u8, file: []const u8, buf: []u8) ?[]const u8 {
    var path_buf: [128]u8 = undefined;
    const path = std.mem.printSentinel(&path_buf, "{s}/{s}", .{ dir, file }, 0) catch return null;
    const fd = linux.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(fd) != .SUCCESS) return null;
    defer _ = linux.close(@intCast(fd));
    const n = linux.read(@intCast(fd), buf.ptr, buf.len);
    if (linux.errno(n) != .SUCCESS) return null;
    return buf[0..n];
}

/// text to dir/file, which must exist: a cgroup control file.
fn write(dir: []const u8, file: []const u8, text: []const u8) bool {
    var path_buf: [128]u8 = undefined;
    const path = std.mem.printSentinel(&path_buf, "{s}/{s}", .{ dir, file }, 0) catch
        return false;
    const fd = linux.open(path, .{ .ACCMODE = .WRONLY, .CLOEXEC = true }, 0);
    if (linux.errno(fd) != .SUCCESS) return false;
    defer _ = linux.close(@intCast(fd));
    const n = linux.write(@intCast(fd), text.ptr, text.len);
    return linux.errno(n) == .SUCCESS and n == text.len;
}

/// One JSON line on the console, as leash writes its own.
fn say(name: []const u8, left: usize, what: []const u8) void {
    var line: [256]u8 = undefined;
    const s = std.mem.print(
        &line,
        "leash-reap: {{\"event\":\"reaped\",\"service\":\"{s}\",\"left\":{d},\"what\":\"{s}\"}}\n",
        .{ name, left, what },
    ) catch return;
    _ = linux.write(1, s.ptr, s.len);
}
