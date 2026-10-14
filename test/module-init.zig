//! Isolated kernel module-signature probe; no userspace enforcement explains the refusals.
const std = @import("std");
const linux = std.os.linux;

pub fn main() void {
    run() catch |err| {
        std.debug.print("module-check: FAIL {s}\n", .{@errorName(err)});
        poweroff();
    };
    std.debug.print("module-check: PASS\n", .{});
    poweroff();
}

fn run() !void {
    _ = linux.mkdir("/dev", 0o755);
    // Rootless initramfs tests have no device nodes until PID 1 creates its console.
    _ = linux.mknodat(linux.AT.FDCWD, "/dev/console", linux.S.IFCHR | 0o600, 5 * 256 + 1);
    const console = linux.open("/dev/console", .{ .ACCMODE = .WRONLY }, 0);
    if (linux.errno(console) != .SUCCESS) return error.Console;
    if (console != 2) {
        if (linux.errno(linux.dup3(@intCast(console), 2, 0)) != .SUCCESS) return error.Console;
        _ = linux.close(@intCast(console));
    }
    const loaded = try insert("/trusted.ko");
    if (loaded != .SUCCESS) {
        std.debug.print("module-check: trusted errno {s}\n", .{@tagName(loaded)});
        return error.TrustedModuleRefused;
    }
    const removed = linux.syscall2(.delete_module, @intFromPtr("dummy"), 0);
    if (linux.errno(removed) != .SUCCESS) return error.Unload;
    for ([_][:0]const u8{ "/unsigned.ko", "/foreign.ko", "/tampered.ko" }) |path| {
        const err = try insert(path);
        switch (err) {
            .KEYREJECTED, .NOKEY, .BADMSG => {},
            else => {
                std.debug.print("module-check: {s} errno {s}\n", .{ path, @tagName(err) });
                return error.SignatureBoundaryMissing;
            },
        }
        std.debug.print("module-check: refused {s} ({s})\n", .{ path, @tagName(err) });
    }
}

fn insert(path: [:0]const u8) !linux.E {
    const fd = linux.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(fd) != .SUCCESS) return error.Open;
    defer _ = linux.close(@intCast(fd));
    return linux.errno(linux.syscall3(.finit_module, fd, @intFromPtr("numdummies=0"), 0));
}

fn poweroff() noreturn {
    _ = linux.reboot(.MAGIC1, .MAGIC2, .POWER_OFF, null);
    linux.exit_group(1);
}
