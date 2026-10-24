//! Run through an ordinary SSH login, never through root changing UID.
const std = @import("std");
const linux = std.os.linux;
var failures: usize = 0;

fn check(name: []const u8, okay: bool) void {
    std.debug.print("{s} {s}\n", .{ if (okay) "PASS" else "FAIL", name });
    if (!okay) failures += 1;
}

fn denied(name: []const u8, rc: usize, allowed: []const linux.E) void {
    const err = linux.errno(rc);
    check(name, std.mem.findScalar(linux.E, allowed, err) != null);
    std.debug.print("  errno={s}\n", .{@tagName(err)});
}

pub fn main() void {
    const uid = linux.getuid();
    if (uid == 0) {
        std.debug.print("REFUSE: probe needs a real unprivileged SSH session\n", .{});
        linux.exit_group(2);
    }
    var ids: [3]u32 = undefined;
    const got = linux.syscall3(
        .getresuid,
        @intFromPtr(&ids[0]),
        @intFromPtr(&ids[1]),
        @intFromPtr(&ids[2]),
    );
    check(
        "all-user-ids-unprivileged",
        linux.errno(got) == .SUCCESS and ids[0] == uid and ids[1] == uid and ids[2] == uid,
    );
    const gid = linux.getgid();
    const groups = linux.syscall3(
        .getresgid,
        @intFromPtr(&ids[0]),
        @intFromPtr(&ids[1]),
        @intFromPtr(&ids[2]),
    );
    check(
        "all-group-ids-unprivileged",
        linux.errno(groups) == .SUCCESS and gid != 0 and ids[0] == gid and ids[1] == gid and
            ids[2] == gid,
    );
    var supplementary: [64]u32 = undefined;
    const count = linux.syscall2(.getgroups, supplementary.len, @intFromPtr(&supplementary));
    check("no-root-supplementary-group", linux.errno(count) == .SUCCESS and
        std.mem.findScalar(u32, supplementary[0..count], 0) == null);
    const Header = extern struct { version: u32 = 0x20080522, pid: i32 = 0 };
    const Caps = extern struct { effective: u32, permitted: u32, inheritable: u32 };
    var header: Header = .{};
    var caps: [2]Caps = undefined;
    const caprc = linux.syscall2(.capget, @intFromPtr(&header), @intFromPtr(&caps));
    check(
        "no-capabilities",
        linux.errno(caprc) == .SUCCESS and std.mem.allEqual(u8, std.mem.asBytes(&caps), 0),
    );
    check(
        "no-new-privileges",
        linux.prctl(@backingInt(linux.PR.GET_NO_NEW_PRIVS), 0, 0, 0, 0) == 1,
    );
    check("seccomp-active", linux.prctl(@backingInt(linux.PR.GET_SECCOMP), 0, 0, 0, 0) == 2);
    var leaked: usize = 0;
    for (3..1024) |fd| {
        if (linux.errno(linux.fcntl(@intCast(fd), linux.F.GETFD, 0)) != .BADF) {
            std.debug.print("  inherited-fd={d}\n", .{fd});
            leaked += 1;
        }
    }
    check("no-inherited-authority-descriptors", leaked == 0);
    denied("cannot-regain-root", linux.setresuid(0, 0, 0), &.{.PERM});
    denied("cannot-regain-root-group", linux.setresgid(0, 0, 0), &.{.PERM});
    var root_group: u32 = 0;
    denied("cannot-add-root-group", linux.setgroups(1, @ptrCast(&root_group)), &.{.PERM});
    caps = @splat(.{ .effective = 0, .permitted = 0, .inheritable = 0 });
    caps[0].effective = 1 << 7;
    caps[0].permitted = 1 << 7;
    denied(
        "cannot-acquire-setuid-capability",
        linux.syscall2(.capset, @intFromPtr(&header), @intFromPtr(&caps)),
        &.{.PERM},
    );
    for ([_][:0]const u8{
        "/run/werewolf/shadow",
        "/run/werewolf/keys/root",
        "/data/.werewolf/identities",
        "/dev/tpmrm0",
    }) |path| {
        const fd = linux.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
        denied(path, fd, &.{.ACCES});
        if (linux.errno(fd) == .SUCCESS) _ = linux.close(@intCast(fd));
    }
    const socket = linux.socket(linux.AF.UNIX, linux.SOCK.SEQPACKET | linux.SOCK.CLOEXEC, 0);
    check("unix-socket-positive-control", linux.errno(socket) == .SUCCESS);
    if (linux.errno(socket) == .SUCCESS) {
        const fd: i32 = @intCast(socket);
        defer _ = linux.close(fd);
        var addr: linux.sockaddr.un = .{ .family = linux.AF.UNIX, .path = @splat(0) };
        const path = "/run/werewolf/update-control.sock";
        @memcpy(addr.path[0..path.len], path);
        denied(
            "updater-control-refused",
            linux.connect(fd, @ptrCast(&addr), @sizeOf(@TypeOf(addr))),
            &.{.ACCES},
        );
    }
    denied("user-namespace-refused", linux.syscall1(.unshare, 0x10000000), &.{ .NOSYS, .PERM });
    denied("ptrace-refused", linux.syscall4(.ptrace, 0, 0, 0, 0), &.{ .NOSYS, .PERM });
    denied("bpf-filtered", linux.syscall3(.bpf, 0, 0, 0), &.{.NOSYS});
    denied("io-uring-filtered", linux.syscall2(.io_uring_setup, 0, 0), &.{.NOSYS});
    denied(
        "packet-socket-refused",
        linux.socket(linux.AF.PACKET, linux.SOCK.RAW, 0),
        &.{ .PERM, .ACCES, .AFNOSUPPORT },
    );
    denied(
        "algorithm-socket-filtered",
        linux.socket(38, linux.SOCK.SEQPACKET, 0),
        &.{ .AFNOSUPPORT, .NOSYS },
    );
    var winsize: [4]u16 = undefined;
    if (linux.errno(linux.ioctl(0, 0x5413, @intFromPtr(&winsize))) == .SUCCESS) {
        const nul: u8 = 0;
        denied(
            "terminal-input-injection-refused",
            linux.ioctl(0, 0x5412, @intFromPtr(&nul)),
            &.{ .IO, .PERM, .ACCES, .NOSYS },
        );
    } else std.debug.print("SKIP terminal-input-injection (no PTY)\n", .{});
    const page = linux.mmap(
        null,
        4096,
        .{ .READ = true, .WRITE = true },
        .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
        -1,
        0,
    );
    check("writable-memory-positive-control", linux.errno(page) == .SUCCESS);
    if (linux.errno(page) == .SUCCESS) {
        const bytes: [*]align(4096) u8 = @ptrFromInt(page);
        const rc = linux.mprotect(bytes, 4096, .{ .READ = true, .EXEC = true });
        denied("executable-memory-refused", rc, &.{ .ACCES, .PERM });
        _ = linux.munmap(bytes, 4096);
    }
    if (failures != 0) linux.exit_group(1);
}
