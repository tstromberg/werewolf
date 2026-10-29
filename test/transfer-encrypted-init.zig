//! Trusted fixture builder in the networkless helper VM. Public test data only.
const std = @import("std");
const data = @import("data-transfer");
const linux = std.os.linux;
const Io = std.Io;
const Dir = Io.Dir;

pub fn main(init: std.process.Init) noreturn {
    prepare(init.io, init.arena.allocator()) catch |err| {
        var buf: [128]u8 = undefined;
        const message = std.mem.print(
            &buf,
            "encrypted-fixture: {s}\n",
            .{@errorName(err)},
        ) catch unreachable;
        Io.File.stdout().writeStreamingAll(init.io, message) catch {};
        poweroff();
    };
    Io.File.stdout().writeStreamingAll(init.io, "encrypted-fixture-ready\n") catch {};
    poweroff();
}

fn mount(device: [:0]const u8, at: [:0]const u8, kind: [:0]const u8, flags: usize) !void {
    if (linux.errno(linux.mount(
        device,
        at,
        kind,
        @intCast(flags),
        0,
    )) != .SUCCESS) return error.Mount;
}

fn command(io: Io, argv: []const []const u8) !void {
    var child = try std.process.spawn(
        io,
        .{ .argv = argv, .stdin = .ignore, .stdout = .inherit, .stderr = .inherit },
    );
    defer child.kill(io);
    if (!(try child.wait(io)).success()) return error.Tool;
}

fn prepare(io: Io, a: std.mem.Allocator) !void {
    if (linux.getpid() != 1) return error.Pid;
    for ([_][:0]const u8{
        "/dev",
        "/proc",
        "/sys",
        "/run",
        "/control",
        "/volume",
    }) |path| _ = linux.mkdir(path, 0o755);
    try mount("devtmpfs", "/dev", "devtmpfs", linux.MS.NOSUID);
    const fd = linux.open("/dev/console", .{ .ACCMODE = .RDWR }, 0);
    if (linux.errno(fd) != .SUCCESS) return error.Console;
    for (0..3) |n| _ = linux.dup2(@intCast(fd), @intCast(n));
    if (fd > 2) _ = linux.close(@intCast(fd));
    try mount("proc", "/proc", "proc", linux.MS.NOSUID | linux.MS.NODEV | linux.MS.NOEXEC);
    try mount("sysfs", "/sys", "sysfs", linux.MS.NOSUID | linux.MS.NODEV | linux.MS.NOEXEC);
    try mount(
        "/dev/vdb",
        "/control",
        "ext4",
        linux.MS.RDONLY | linux.MS.NOSUID | linux.MS.NODEV | linux.MS.NOEXEC,
    );
    const config = try std.json.parseFromSliceLeaky(
        struct { image: []const u8, initialize: bool },
        a,
        try Dir.cwd().readFileAlloc(io, "/control/request.json", a, .limited(4096)),
        .{ .ignore_unknown_fields = true },
    );
    try command(
        io,
        &.{
            "/usr/sbin/cryptsetup",
            "luksFormat",
            "--type",
            "luks2",
            "--batch-mode",
            "--pbkdf",
            "pbkdf2",
            "--pbkdf-force-iterations",
            "1000",
            "--key-file",
            "/control/key",
            "/dev/vda",
        },
    );
    try command(
        io,
        &.{
            "/usr/sbin/cryptsetup",
            "open",
            "--batch-mode",
            "--key-file",
            "/control/key",
            "/dev/vda",
            "fixture",
        },
    );
    try command(
        io,
        &.{
            "/usr/sbin/mke2fs",
            "-q",
            "-F",
            "-t",
            "ext4",
            "-m",
            "0",
            "-E",
            "lazy_itable_init=0,lazy_journal_init=0",
            "/dev/mapper/fixture",
        },
    );
    try mount(
        "/dev/mapper/fixture",
        "/volume",
        "ext4",
        linux.MS.NOSUID | linux.MS.NODEV | linux.MS.NOEXEC,
    );
    {
        var root = try Dir.cwd().openDir(io, "/volume", .{});
        defer root.close(io);
        try data.images.record(io, root, config.image);
        if (!config.initialize) {
            try root.createDirPath(io, "svc/postgres");
            try root.writeFile(
                io,
                .{ .sub_path = "svc/postgres/payload", .data = "encrypted public fixture\n" },
            );
        }
    }
    _ = linux.sync();
    if (linux.errno(linux.umount2("/volume", 0)) != .SUCCESS) return error.Unmount;
    try command(io, &.{ "/usr/sbin/cryptsetup", "close", "fixture" });
}

fn poweroff() noreturn {
    _ = linux.sync();
    _ = linux.reboot(.MAGIC1, .MAGIC2, .POWER_OFF, null);
    while (true) _ = linux.pause();
}
