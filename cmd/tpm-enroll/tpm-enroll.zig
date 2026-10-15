//! PID 1 of the signed rootless TPM bootstrap. Reboots after protected readback.
const std = @import("std");
const linux = std.os.linux;
const cmdline = @import("cmdline");
const ipe = @import("ipe");
const apk = @import("apk");
const enrollment = @import("enrollment");

pub fn main(init: std.process.Init) void {
    run(init) catch |err| {
        say("refused: {s}; no workload handover", .{@errorName(err)});
        // Stay stopped: rebooting a refusal would create an enrollment retry loop.
        while (true) _ = linux.pause();
    };
    say("protected factory enrollment complete; rebooting", .{});
    linux.sync();
    _ = linux.reboot(.MAGIC1, .MAGIC2, .RESTART, null);
    while (true) _ = linux.pause();
}

fn run(init: std.process.Init) !void {
    if (linux.getpid() != 1) return error.NotBootstrapInit;
    const io = init.io;
    const gpa = init.arena.allocator();
    try mount("proc", "/proc", "proc", linux.MS.NOSUID | linux.MS.NODEV | linux.MS.NOEXEC);
    try mount("sys", "/sys", "sysfs", linux.MS.NOSUID | linux.MS.NODEV | linux.MS.NOEXEC);
    try mount("dev", "/dev", "devtmpfs", linux.MS.NOSUID | linux.MS.NOEXEC);
    var refused: cmdline.Failure = .{};
    const boot = cmdline.parse(try read(io, gpa, "/proc/cmdline", 4096), &refused) orelse
        return error.BadBootstrapCommandLine;
    if (!boot.bootstrap) return error.NotBootstrapBoot;
    try mount(
        "efivarfs",
        "/sys/firmware/efi/efivars",
        "efivarfs",
        linux.MS.NOSUID | linux.MS.NODEV | linux.MS.NOEXEC | linux.MS.RDONLY,
    );
    const vars = "/sys/firmware/efi/efivars/";
    try enrollment.firmware(
        try read(io, gpa, vars ++ "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c", 5),
        try read(io, gpa, vars ++ "SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c", 5),
    );
    try mount(
        "securityfs",
        "/sys/kernel/security",
        "securityfs",
        linux.MS.NOSUID | linux.MS.NODEV | linux.MS.NOEXEC,
    );
    const lockdown = "/sys/kernel/security/lockdown";
    if (std.mem.find(u8, try read(io, gpa, lockdown, 128), "[confidentiality]") == null)
        try write(io, lockdown, "confidentiality");
    if (std.mem.find(u8, try read(io, gpa, lockdown, 128), "[confidentiality]") == null)
        return error.UnenforcedLockdown;
    // The kernel has no IPE policy of its own: activate the bootstrap's,
    // signed with the image key, so only this initramfs may execute.
    write(
        io,
        ipe.base ++ "/new_policy",
        try read(io, gpa, "/enrollment/ipe-boot.p7b", ipe.max_policy),
    ) catch
        return error.BootstrapIpeRejected;
    try write(io, ipe.base ++ "/policies/werewolf_boot/active", "1");
    try write(io, ipe.base ++ "/enforce", "1");
    if (!ipe.bootstrapEnforced(
        try read(io, gpa, ipe.base ++ "/policies/werewolf_boot/policy", ipe.max_policy),
        try read(io, gpa, ipe.base ++ "/policies/werewolf_boot/active", 8),
        try read(io, gpa, ipe.base ++ "/enforce", 8),
    )) return error.UnenforcedBootstrapIpe;
    // werewolf's kernel has no module loader at all; a kernel that has one is refused.
    if (linux.errno(linux.access(
        "/proc/modules",
        linux.F_OK,
    )) == .SUCCESS) return error.ModuleLoaderOpen;
    try ipe.lockAdmin();
    const key = try apk.parseKey(gpa, try read(io, gpa, "/enrollment/publisher.pub", 1024));
    const factory = try read(io, gpa, "/enrollment/factory.permit", 688);
    _ = try enrollment.factory(key, factory);
    const device = try openDevice(io, "/dev/tpmrm0");
    defer device.close(io);
    // This isolated VM channel is not exposed as a workload administration service.
    const channel = try openChannel(io, gpa);
    defer channel.close(io);
    say("secure firmware, IPE and immutable factory checked", .{});
    const anchor = try enrollment.exchange(
        io,
        device,
        channel,
        channel,
        key,
        factory,
        if (boot.recovery) .recovery else .fresh,
    );
    try channel.writeStreamingAll(io, enrollment.done_tag);
    try channel.writeStreamingAll(io, &anchor);
}

fn openChannel(io: std.Io, gpa: std.mem.Allocator) !std.Io.File {
    for (0..1000) |_| {
        if (try findChannel(io, gpa)) |name| return openDevice(io, name);
        var delay: linux.timespec = .{ .sec = 0, .nsec = 10 * std.time.ns_per_ms };
        _ = linux.nanosleep(&delay, null);
    }
    return error.MissingBootstrapChannel;
}

fn findChannel(io: std.Io, gpa: std.mem.Allocator) !?[]const u8 {
    var dir = std.Io.Dir.cwd().openDir(
        io,
        "/sys/class/virtio-ports",
        .{ .iterate = true },
    ) catch |err|
        return if (err == error.FileNotFound) null else err;
    defer dir.close(io);
    var entries = dir.iterate();
    var found: ?[]const u8 = null;
    var count: usize = 0;
    while (try entries.next(io)) |entry| {
        count += 1;
        if (count > 16) return error.TooManyBootstrapPorts;
        if (!cmdline.isDeviceName(entry.name) or !std.mem.startsWith(u8, entry.name, "vport"))
            return error.BadBootstrapPort;
        const attr = try gpa.print("/sys/class/virtio-ports/{s}/name", .{entry.name});
        const name = read(io, gpa, attr, 64) catch |err|
            if (err == error.FileNotFound) continue else return err;
        if (std.mem.eql(u8, std.mem.trim(u8, name, "\n"), "werewolf.enroll")) {
            if (found != null) return error.AmbiguousBootstrapChannel;
            found = try gpa.print("/dev/{s}", .{entry.name});
        }
    }
    return found;
}

fn read(io: std.Io, gpa: std.mem.Allocator, name: []const u8, limit: usize) ![]u8 {
    const file = std.Io.Dir.cwd().openFile(io, name, .{}) catch |err| {
        say("cannot read {s}: {s}", .{ name, @errorName(err) });
        return err;
    };
    defer file.close(io);
    const raw = try gpa.alloc(u8, limit + 1);
    var got: usize = 0;
    while (got < raw.len) {
        const n = file.readStreaming(io, &.{raw[got..]}) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        if (n == 0) break;
        got += n;
    }
    if (got > limit) return error.TooBig;
    return raw[0..got];
}

fn openDevice(io: std.Io, name: []const u8) !std.Io.File {
    for (0..1000) |_| {
        return std.Io.Dir.cwd().openFile(
            io,
            name,
            .{ .mode = .read_write },
        ) catch |err| switch (err) {
            error.FileNotFound => {
                var delay: linux.timespec = .{ .sec = 0, .nsec = 10 * std.time.ns_per_ms };
                _ = linux.nanosleep(&delay, null);
                continue;
            },
            else => return err,
        };
    }
    say("missing device {s}", .{name});
    return error.MissingBootstrapDevice;
}

fn say(comptime format: []const u8, args: anytype) void {
    var buffer: [512]u8 = undefined;
    const line = std.mem.print(&buffer, "tpm-enroll: " ++ format ++ "\n", args) catch return;
    _ = linux.write(2, line.ptr, line.len);
}

fn write(io: std.Io, name: []const u8, bytes: []const u8) !void {
    const file = try std.Io.Dir.cwd().openFile(io, name, .{ .mode = .write_only });
    defer file.close(io);
    try file.writeStreamingAll(io, bytes);
}

fn mount(source: [:0]const u8, target: [:0]const u8, kind: [:0]const u8, flags: u32) !void {
    _ = linux.mkdir(target, 0o700);
    if (linux.errno(linux.mount(
        source,
        target,
        kind,
        flags,
        0,
    )) != .SUCCESS) return error.BootstrapMount;
}
