//! Run through an ordinary SSH login, never through root changing UID;
//! `privilege-probe root` through a root SSH login (forms/sshd's leash).
const std = @import("std");
const linux = std.os.linux;
const service = @import("service");
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

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const uid = linux.getuid();
    if (args.len == 2 and std.mem.eql(u8, args[1], "root")) {
        if (uid != 0) {
            std.debug.print("REFUSE: probe root needs a root SSH session\n", .{});
            linux.exit_group(2);
        }
        rootSession();
        if (failures != 0) linux.exit_group(1);
        return;
    }
    if (uid == 0 or args.len != 1) {
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
    // sshd's pledge no longer promises caps, so the filter refuses capset
    // itself; a kernel check refuses it under one that does.
    denied(
        "cannot-acquire-setuid-capability",
        linux.syscall2(.capset, @intFromPtr(&header), @intFromPtr(&caps)),
        &.{ .NOSYS, .PERM },
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
        &.{ .NOSYS, .PERM, .ACCES, .AFNOSUPPORT },
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

/// rootSession checks what a root SSH login holds (docs/design/ssh-hardening.md):
/// sshd's login capabilities and no others, a pledge without netlink, packet,
/// caps, Landlock or seccomp, and writes only where forms/sshd's layer grants.
fn rootSession() void {
    const Header = extern struct { version: u32 = 0x20080522, pid: i32 = 0 };
    const Caps = extern struct { effective: u32, permitted: u32, inheritable: u32 };
    var header: Header = .{};
    var caps: [2]Caps = undefined;
    const caprc = linux.syscall2(.capget, @intFromPtr(&header), @intFromPtr(&caps));
    const effective = @as(u64, caps[1].effective) << 32 | caps[0].effective;
    const permitted = @as(u64, caps[1].permitted) << 32 | caps[0].permitted;
    var bounding: u64 = 0;
    for (0..64) |n| {
        if (linux.prctl(@backingInt(linux.PR.CAPBSET_READ), n, 0, 0, 0) == 1)
            bounding |= @as(u64, 1) << @intCast(n);
    }
    std.debug.print("  bounding={x} permitted={x}\n", .{ bounding, permitted });
    check("root-bounding-set-is-login-set", bounding == service.cap.login_set);
    check(
        "root-capabilities-within-login-set",
        linux.errno(caprc) == .SUCCESS and (effective | permitted) & ~service.cap.login_set == 0,
    );
    check("root-no-dac-override", bounding & 1 << linux.CAP.DAC_OVERRIDE == 0);
    check(
        "root-no-new-privileges",
        linux.prctl(@backingInt(linux.PR.GET_NO_NEW_PRIVS), 0, 0, 0, 0) == 1,
    );
    check("root-seccomp-active", linux.prctl(@backingInt(linux.PR.GET_SECCOMP), 0, 0, 0, 0) == 2);
    // Where the session layer grants no write: accounts and keys, every
    // service's cgroup, the kernel log, the console and the TPM.
    refusedCreate("root-cannot-create-in-run-werewolf", "/run/werewolf/privilege-probe");
    refusedCreate("root-cannot-create-in-run", "/run/privilege-probe");
    for ([_]struct { [:0]const u8, [:0]const u8 }{
        .{ "root-cannot-write-root-keys", "/run/werewolf/keys/root" },
        .{ "root-cannot-leave-sshd-cgroup", "/run/cgroup/cgroup.procs" },
        .{ "root-cannot-write-kmsg", "/dev/kmsg" },
        .{ "root-cannot-write-console", "/dev/console" },
        .{ "root-cannot-use-tpm", "/dev/tpmrm0" },
    }) |w| {
        const fd = linux.open(
            w[1],
            .{ .ACCMODE = .WRONLY, .NOCTTY = true, .NONBLOCK = true, .CLOEXEC = true },
            0,
        );
        if (linux.errno(fd) == .NOENT) {
            std.debug.print("SKIP {s} (no {s})\n", .{ w[0], w[1] });
            continue;
        }
        denied(w[0], fd, &.{.ACCES});
        if (linux.errno(fd) == .SUCCESS) _ = linux.close(@intCast(fd));
    }
    serviceData();
    for ([_][:0]const u8{ "/tmp/privilege-probe-root", "/data/privilege-probe-root" }) |path| {
        const fd = linux.open(
            path,
            .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .CLOEXEC = true },
            0o600,
        );
        check(path, linux.errno(fd) == .SUCCESS);
        if (linux.errno(fd) == .SUCCESS) {
            _ = linux.close(@intCast(fd));
            _ = linux.unlink(path);
        }
    }
    // The pledge: refused calls answer ENOSYS, from the filter.
    denied("root-netlink-refused", linux.socket(linux.AF.NETLINK, linux.SOCK.RAW, 0), &.{.NOSYS});
    denied("root-packet-refused", linux.socket(linux.AF.PACKET, linux.SOCK.RAW, 0), &.{.NOSYS});
    denied(
        "root-capset-refused",
        linux.syscall2(.capset, @intFromPtr(&header), @intFromPtr(&caps)),
        &.{.NOSYS},
    );
    denied("root-landlock-refused", linux.syscall3(.landlock_create_ruleset, 0, 0, 1), &.{.NOSYS});
    denied("root-seccomp-refused", linux.syscall3(.seccomp, 0, 0, 0), &.{.NOSYS});
    denied("root-user-namespace-refused", linux.syscall1(.unshare, 0x10000000), &.{.NOSYS});
    denied("root-mount-refused", linux.syscall5(.mount, 0, 0, 0, 0, 0), &.{.NOSYS});
}

/// refusedCreate checks that path cannot be created, and removes it if it was.
fn refusedCreate(name: []const u8, path: [:0]const u8) void {
    const fd = linux.open(
        path,
        .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .CLOEXEC = true },
        0o600,
    );
    denied(name, fd, &.{.ACCES});
    if (linux.errno(fd) == .SUCCESS) {
        _ = linux.close(@intCast(fd));
        _ = linux.unlink(path);
    }
}

/// serviceData checks that root can change no /data/svc directory a service
/// owns: Landlock refuses it, or the directory is mounted read-only.
fn serviceData() void {
    const dir = linux.open(
        "/data/svc",
        .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true },
        0,
    );
    if (linux.errno(dir) != .SUCCESS) {
        std.debug.print("SKIP root-cannot-change-service-data (no /data/svc)\n", .{});
        return;
    }
    defer _ = linux.close(@intCast(dir));
    var checked: usize = 0;
    var ents: [4096]u8 align(8) = undefined;
    while (true) {
        const n = linux.getdents64(@intCast(dir), &ents, ents.len);
        if (linux.errno(n) != .SUCCESS or n == 0) break;
        var off: usize = 0;
        while (off < n) {
            const ent: *align(1) const linux.dirent64 = @ptrCast(&ents[off]);
            off += ent.reclen;
            const entry: [*:0]const u8 = @ptrCast(&ent.name);
            if (ent.type != linux.DT.DIR or entry[0] == '.') continue;
            var st: linux.Statx = undefined;
            if (linux.errno(linux.statx(
                @intCast(dir),
                entry,
                0,
                .{ .UID = true },
                &st,
            )) != .SUCCESS or
                st.uid == 0) continue;
            var buf: [std.fs.max_path_bytes]u8 = undefined;
            const path = std.mem.printSentinel(
                &buf,
                "/data/svc/{s}/privilege-probe",
                .{std.mem.span(entry)},
                0,
            ) catch
                continue;
            const fd = linux.open(
                path,
                .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .CLOEXEC = true },
                0o600,
            );
            std.debug.print("  {s}\n", .{path});
            denied("root-cannot-change-service-data", fd, &.{ .ACCES, .ROFS });
            if (linux.errno(fd) == .SUCCESS) {
                _ = linux.close(@intCast(fd));
                _ = linux.unlink(path);
            }
            checked += 1;
        }
    }
    if (checked == 0) std.debug.print(
        "SKIP root-cannot-change-service-data (none service-owned)\n",
        .{},
    );
}
