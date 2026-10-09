//! leash-reap is a leashed service's ./finish. It kills whatever is left in
//! the service's cgroup and waits for it to die. See README.md.

const std = @import("std");
const linux = std.os.linux;

/// patience_ms bounds the wait for the cgroup to empty, so runsv is never stuck.
const patience_ms = 5000;

pub fn main() void {
    var cwd_buf: [std.fs.max_path_bytes]u8 = undefined;
    const cwd = linux.getcwd(&cwd_buf, cwd_buf.len);
    if (linux.errno(cwd) != .SUCCESS) return;
    const name = std.fs.path.basename(std.mem.sliceTo(cwd_buf[0..], 0));
    if (!isServiceName(name)) return;

    var dir_buf: [96]u8 = undefined;
    const dir = std.mem.print(&dir_buf, "/run/cgroup/svc/{s}", .{name}) catch return;
    var buf: [4096]u8 = undefined;
    const procs = read(dir, "cgroup.procs", &buf) orelse return; // no cgroup2: nothing to reap
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

/// isServiceName reports whether name is a plain service name, which keeps
/// the cgroup path a leaf of /run/cgroup/svc.
fn isServiceName(name: []const u8) bool {
    if (name.len == 0 or name.len > 64) return false;
    for (name) |c| if (!std.ascii.isAlphanumeric(c) and c != '-' and c != '_') return false;
    return true;
}

/// read returns dir/file from a single read, or null on any error.
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

/// write writes text to the existing cgroup control file dir/file.
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

/// say logs one JSON line to the console, in the same form as leash's.
fn say(name: []const u8, left: usize, what: []const u8) void {
    var line: [256]u8 = undefined;
    const s = std.mem.print(
        &line,
        "leash-reap: {{\"event\":\"reaped\",\"service\":\"{s}\",\"left\":{d},\"what\":\"{s}\"}}\n",
        .{ name, left, what },
    ) catch return;
    _ = linux.write(1, s.ptr, s.len);
}

test isServiceName {
    const t = std.testing;
    const long: [65]u8 = @splat('a');
    try t.expect(isServiceName("web"));
    try t.expect(isServiceName("php-fpm_2"));
    try t.expect(isServiceName(long[0..64]));
    try t.expect(!isServiceName(""));
    try t.expect(!isServiceName(&long));
    try t.expect(!isServiceName(".."));
    try t.expect(!isServiceName("a.b"));
    try t.expect(!isServiceName("a/b"));
    try t.expect(!isServiceName("a b"));
}
