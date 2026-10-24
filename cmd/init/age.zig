//! Start the age authority before the seal forbids new namespaces. The writer
//! keeps a private writable mount view; every later process sees read-only
//! database and socket directories.
const std = @import("std");
const linux = std.os.linux;
const dns = @import("dns");
const init = @import("init.zig");

const program = "/usr/lib/werewolf/unwound-age";

pub fn start() !void {
    if (!init.exists(dns.age_marker_path)) return;
    if (!init.executable(program)) return error.MissingAgeAuthority;
    const ephemeral = init.exists("/run/werewolf/nodata");
    const db_dir: [:0]const u8 = if (ephemeral) dns.age_temporary_dir else dns.age_durable_dir;
    if (!ephemeral) try directory("/data/svc", 0o755, null);
    try directory(db_dir, 0o700, dns.age_id);
    try directory(dns.age_socket_dir, 0o755, 0);

    var pair: [2]i32 = undefined;
    try okay(linux.socketpair(linux.AF.UNIX, linux.SOCK.SEQPACKET | linux.SOCK.CLOEXEC, 0, &pair));
    const pid = linux.fork();
    try okay(pid);
    if (pid == 0) {
        _ = linux.close(pair[0]);
        if (linux.errno(linux.dup2(pair[1], 3)) != .SUCCESS) linux.exit_group(127);
        _ = linux.close_range(
            4,
            std.math.maxInt(linux.fd_t),
            .{ .UNSHARE = false, .CLOEXEC = false },
        );
        const argv: [*:null]const ?[*:0]const u8 = &[_:null]?[*:0]const u8{program};
        const envp: [*:null]const ?[*:0]const u8 = &[_:null]?[*:0]const u8{
            "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/", "TERM=linux",
        };
        _ = linux.execve(program, argv, envp);
        linux.exit_group(127);
    }
    _ = linux.close(pair[1]);
    defer _ = linux.close(pair[0]);
    var ready: [1]linux.pollfd = .{.{ .fd = pair[0], .events = linux.POLL.IN, .revents = 0 }};
    if (linux.poll(&ready, 1, 10_000) != 1 or ready[0].revents & linux.POLL.IN == 0)
        return error.AgeAuthorityTimeout;
    var response: [1]u8 = undefined;
    if (linux.read(pair[0], &response, 1) != 1 or response[0] != 'R')
        return error.AgeAuthorityFailed;
    try readOnlyBind(db_dir);
    try readOnlyBind(dns.age_socket_dir);
    if (linux.write(pair[0], "G", 1) != 1) return error.AgeAuthorityFailed;
}

fn directory(path: [:0]const u8, mode: u32, owner: ?u32) !void {
    const created = linux.mkdir(path, mode);
    if (linux.errno(created) != .SUCCESS and linux.errno(created) != .EXIST)
        return error.AgeDirectory;
    const fd = linux.open(
        path,
        .{ .PATH = true, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true },
        0,
    );
    try okay(fd);
    _ = linux.close(@intCast(fd));
    if (owner) |uid| {
        try okay(linux.fchownat(
            linux.AT.FDCWD,
            path,
            uid,
            uid,
            linux.AT.SYMLINK_NOFOLLOW,
        ));
        try okay(linux.fchmodat2(linux.AT.FDCWD, path, mode, linux.AT.SYMLINK_NOFOLLOW));
    }
}

fn readOnlyBind(path: [:0]const u8) !void {
    const nosymfollow: u32 = 256;
    try okay(linux.mount(path, path, null, linux.MS.BIND, 0));
    try okay(linux.mount(null, path, null, linux.MS.BIND | linux.MS.REMOUNT |
        linux.MS.RDONLY | linux.MS.NOSUID | linux.MS.NODEV | linux.MS.NOEXEC |
        nosymfollow, 0));
}

fn okay(rc: usize) !void {
    if (linux.errno(rc) != .SUCCESS) return error.AgeSetup;
}
