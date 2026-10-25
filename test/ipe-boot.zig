//! ipe-boot LOG QEMU... runs test/check-ipe's isolated kernel probe for at
//! most five minutes, its console kept in LOG, and passes only if QEMU
//! exits 0 having said "ipe-check: PASS" and never "ipe-check: FAIL".

const std = @import("std");
const host = @import("host");
const Io = std.Io;
const mem = std.mem;

pub fn main(init: std.process.Init) void {
    var c = host.Check.init(
        init,
        "ipe-kernel",
    ) catch |err| std.process.fatal("ipe-boot: {t}", .{err});
    c.finish(run(&c));
}

fn run(c: *host.Check) !void {
    if (c.args.len < 3) return c.fail("usage: ipe-boot LOG QEMU...", .{});
    const log = c.args[1];
    var argv: std.ArrayList([]const u8) = .empty;
    for (c.args[2..]) |a| try argv.append(c.gpa, a);
    var m: host.qemu.Machine = undefined;
    try m.start(c.io, c.gpa, argv.items, .{ .log = log, .environ_map = &c.env });
    const Never = struct {
        pub fn done(_: @This(), _: []const u8) !bool {
            return false;
        }
    };
    const ended = m.until(host.qemu.after(c.io, 300), Never{});
    m.stop(.fromSeconds(10));
    ended catch |err| switch (err) {
        error.MachineExited => {},
        error.Timeout => return c.fail("ipe-check: timeout; see {s}", .{log}),
        else => |e| return e,
    };
    const text = try m.console(c.gpa);
    if (!m.term.?.success() or mem.find(u8, text, "ipe-check: PASS") == null or
        mem.find(u8, text, "ipe-check: FAIL") != null)
    {
        Io.File.stderr().writeStreamingAll(c.io, host.check.tail(text, 6000)) catch {};
        return c.fail("ipe-check: kernel probe failed; see {s}", .{log});
    }
    c.say("pass   ipe-kernel: independent execution and mmap checks", .{});
}
