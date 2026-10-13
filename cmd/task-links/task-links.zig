//! A private metadata-only process observer, started before init drops tracing authority.
const std = @import("std");
const linux = std.os.linux;
const sandbox = @import("sandbox");
const broker = @import("broker");

pub fn main() void {
    confine() catch linux.exit_group(1);
    var request: [broker.link_request_size]u8 = undefined;
    while (transfer(false, &request)) {
        const parsed = broker.parseLinkRequest(&request) catch linux.exit_group(1);
        var path_buf: [64]u8 = undefined;
        const path = std.mem.printSentinel(&path_buf, "/proc/{d}/{s}", .{
            parsed.pid, @tagName(parsed.kind),
        }, 0) catch linux.exit_group(1);
        var reply: [broker.link_limit + 2]u8 = undefined;
        const n = linux.readlinkat(linux.AT.FDCWD, path, reply[2..].ptr, broker.link_limit);
        const size: u16 = if (linux.errno(n) == .SUCCESS and n < broker.link_limit)
            @intCast(n)
        else
            0;
        std.mem.writeInt(u16, reply[0..2], size, .little);
        if (!transfer(true, reply[0 .. size + 2])) break;
    }
    linux.exit_group(0);
}

/// No file opening, memory access, tracing, execution, mount, or additional sockets.
/// The retained capability serves readlinkat's kernel permission check only.
fn confine() !void {
    _ = linux.close(1);
    _ = linux.close(2);
    try sandbox.keepOnly(1 << 19); // CAP_SYS_PTRACE
    var filter = restrictions();
    try filter.install();
}

fn restrictions() sandbox.Filter {
    var filter: sandbox.Filter = .{};
    filter.allowArg("read", 0, 0);
    filter.allowArg("write", 0, 0);
    filter.allowArg("readlinkat", 0, @as(u32, @bitCast(@as(i32, linux.AT.FDCWD))));
    filter.allow("exit_group");
    return filter;
}

fn transfer(write: bool, data: []u8) bool {
    var at: usize = 0;
    while (at < data.len) {
        const n = if (write)
            linux.write(0, data[at..].ptr, data.len - at)
        else
            linux.read(0, data[at..].ptr, data.len - at);
        if (linux.errno(n) == .INTR) continue;
        if (linux.errno(n) != .SUCCESS or n == 0) return false;
        at += n;
    }
    return true;
}

test "metadata observer filter permits links but kills memory, file and extra descriptor access" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    const t = std.testing;
    // Execute the actual kernel filter in disposable children. No tracing
    // capability is needed to verify syscall confinement or our own link.
    inline for (.{
        "openat", "ptrace", "process_vm_readv", "process_vm_writev", "mmap",
        "socket", "execve", "read",             "write",             "readlinkat",
    }) |call| {
        const pid = linux.fork();
        try t.expect(linux.errno(pid) == .SUCCESS);
        if (pid == 0) {
            var filter = restrictions();
            filter.install() catch linux.exit_group(3);
            if (comptime std.mem.eql(u8, call, "readlinkat")) {
                var buf: [broker.link_limit]u8 = undefined;
                const n = linux.readlinkat(linux.AT.FDCWD, "/proc/self/exe", &buf, buf.len);
                linux.exit_group(if (linux.errno(n) == .SUCCESS and n > 0) 0 else 4);
            } else {
                // read/write on descriptor 1 must also be refused.
                _ = linux.syscall6(@field(linux.SYS, call), 1, 0, 0, 0, 0, 0);
                linux.exit_group(2);
            }
        }
        var status: i32 = 0;
        while (linux.errno(linux.wait4(@intCast(pid), &status, 0, null)) == .INTR) {}
        const result: u32 = @bitCast(status);
        if (comptime std.mem.eql(u8, call, "readlinkat")) {
            try t.expect(linux.W.IFEXITED(result) and linux.W.EXITSTATUS(result) == 0);
        } else {
            try t.expect(linux.W.IFSIGNALED(result) and linux.W.TERMSIG(result) == linux.SIG.SYS);
        }
    }
}
