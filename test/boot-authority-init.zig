//! Signed rootless probe of the actual firmware variable trust parser.
const std = @import("std");
const linux = std.os.linux;
const authority = @import("authority");
const apk = @import("apk");

pub fn main(init: std.process.Init) noreturn {
    check(init.io, init.arena.allocator()) catch |err| {
        std.debug.print("boot-authority-check: refuse {s}\n", .{@errorName(err)});
        poweroff();
    };
    std.debug.print("boot-authority-check: PASS\n", .{});
    poweroff();
}

fn check(io: std.Io, gpa: std.mem.Allocator) !void {
    if (linux.errno(linux.mount("sysfs", "/sys", "sysfs", 0, 0)) != .SUCCESS)
        return error.MountFailed;
    if (linux.errno(linux.mount(
        "efivarfs",
        "/sys/firmware/efi/efivars",
        "efivarfs",
        linux.MS.RDONLY | linux.MS.NOSUID | linux.MS.NODEV | linux.MS.NOEXEC,
        0,
    )) != .SUCCESS)
        return error.MountFailed;
    const vendor = try std.Io.Dir.cwd().readFileAlloc(io, "/vendor.sha256", gpa, .limited(33));
    if (vendor.len != 32) return error.BadFixture;
    const selected = try authority.load(io, gpa, vendor[0..32].*);
    const expected = try apk.parseKey(gpa, try std.Io.Dir.cwd().readFileAlloc(
        io,
        "/owner.pub",
        gpa,
        .limited(8192),
    ));
    if (!std.mem.eql(u8, selected.modulus, expected.modulus) or
        !std.mem.eql(
            u8,
            selected.exponent,
            expected.exponent,
        )) return error.IncorrectMachineAuthority;
}

fn poweroff() noreturn {
    // Power-off logs must not overtake the result queued on the serial TTY.
    while (linux.errno(linux.tcdrain(linux.STDERR_FILENO)) == .INTR) {}
    linux.sync();
    _ = linux.reboot(.MAGIC1, .MAGIC2, .POWER_OFF, null);
    while (true) _ = linux.pause();
}
