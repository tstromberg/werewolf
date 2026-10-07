//! posture's attacks, for werewolf's tests. With werewolf.check=1 on the
//! kernel command line, which only werewolf's tests set (or --attack, or
//! WEREWOLF_CHECK=1), posture also attacks the machine as an intruder
//! would, and expects each attack refused. Two are meant to leave a line in
//! the kernel's log: the check is that the kernel both refused and said so.
//! The rest act as nobody, in a child, against files posture makes and
//! removes in /tmp and /run; and the leash probe, a copy of posture leashed
//! as nobody, tries what its service file does not grant.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const linux = std.os.linux;
const testing = std.testing;

const posture = @import("posture.zig");
const cap_sys_rawio = @import("kernel.zig").cap_sys_rawio;
const Posture = posture.Posture;
const capBit = posture.capBit;
const exists = posture.exists;
const trim = posture.trim;

const attack_run = "/run/.posture-attack";

const attack_link = "/tmp/.posture-attack-link";

const attack_secret = "/tmp/.posture-attack-secret";

const attack_hard = "/tmp/.posture-attack-hard";

const attack_file = "/tmp/.posture-attack-file";

fn cleanAttacks() void {
    for ([_][:0]const u8{
        attack_run,
        attack_link,
        attack_secret,
        attack_hard,
        attack_file,
    }) |path| _ = linux.unlink(path);
}

/// attack, run in a child as nobody: uid and gid 65534, no other groups, no
/// new privileges. Whether it worked, or null if the child could not become
/// nobody.
fn asNobody(attack: *const fn () bool) ?bool {
    return inChild(attack, true);
}

/// attack, run in a child, as nobody if asked. Whether it worked, or null if
/// there was no child, or it could not become nobody. The child makes only
/// system calls: the parent may have threads.
pub fn inChild(attack: *const fn () bool, as_nobody: bool) ?bool {
    const rc = linux.fork();
    if (linux.errno(rc) != .SUCCESS) return null;
    if (rc == 0) {
        const nobody = 65534;
        const none = [0]linux.gid_t{};
        if (as_nobody and
            (linux.errno(linux.prctl(
                @backingInt(linux.PR.SET_NO_NEW_PRIVS),
                1,
                0,
                0,
                0,
            )) != .SUCCESS or
                linux.errno(linux.setgroups(0, &none)) != .SUCCESS or
                linux.errno(linux.setresgid(nobody, nobody, nobody)) != .SUCCESS or
                linux.errno(linux.setresuid(nobody, nobody, nobody)) != .SUCCESS))
            linux.exit_group(2);
        linux.exit_group(if (attack()) 1 else 0);
    }
    var status: i32 = 0;
    if (linux.errno(linux.wait4(@intCast(rc), &status, 0, null)) != .SUCCESS) return null;
    const s: u32 = @bitCast(status);
    if (!linux.W.IFEXITED(s)) return null;
    return switch (linux.W.EXITSTATUS(s)) {
        0 => false,
        1 => true,
        else => null,
    };
}

fn seesInit() bool {
    return linux.errno(linux.access("/proc/1", linux.F_OK)) == .SUCCESS;
}

fn writesRun() bool {
    return created(attack_run, 0o600);
}

fn plantsLink() bool {
    return linux.errno(linux.symlink(attack_run, attack_link)) == .SUCCESS;
}

fn linksSecret() bool {
    return linux.errno(linux.link(attack_secret, attack_hard)) == .SUCCESS;
}

fn plantsFile() bool {
    return created(attack_file, 0o644);
}

fn created(path: [:0]const u8, mode: linux.mode_t) bool {
    const rc = linux.open(
        path,
        .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .CLOEXEC = true },
        mode,
    );
    if (linux.errno(rc) != .SUCCESS) return false;
    _ = linux.close(@intCast(rc));
    return true;
}

/// Whether root can open path to write, creating it if it is not there.
fn opensForWrite(path: [:0]const u8, append: bool) bool {
    const rc = linux.open(
        path,
        .{ .ACCMODE = .WRONLY, .CREAT = true, .APPEND = append, .CLOEXEC = true },
        0o600,
    );
    if (linux.errno(rc) != .SUCCESS) return false;
    _ = linux.close(@intCast(rc));
    return true;
}

fn hasAll(haystack: []const u8, needles: []const []const u8) bool {
    for (needles) |n| if (std.mem.indexOf(u8, haystack, n) == null) return false;
    return true;
}

pub fn run(p: *Posture) !void {
    const pid = linux.getpid();
    const comm = trim(p.read("/proc/self/comm"));

    // Yama names both sides by their command lines.
    const mem = refusedAndLogged(
        p,
        "/proc/1/mem",
        &.{ "\"[1] was attempted by \"", try p.gpa.print("\"[{d}]", .{pid}) },
    );
    try p.add(.{
        .id = "processes-mem-attack",
        .area = "processes",
        .name = "Another process's memory refused",
        .why = "Not even root can read or change a running program's memory, and the kernel " ++
            "logs every attempt.",
        .how = "opening /proc/1/mem fails, and the kernel logs Yama's refusal",
        .result = if (mem == .logged) .pass else .fail,
        .detail = mem.detail(),
    });
    // Without CAP_SYS_RAWIO, which werewolf's seal takes from every
    // process, the kernel refuses /dev/mem before lockdown is asked, and
    // so before it would log anything.
    const dev = refusedAndLogged(
        p,
        "/dev/mem",
        &.{try p.gpa.print("Lockdown: {s}: /dev/mem,kmem,port is restricted", .{comm})},
    );
    const rawio = capBit(p.read("/proc/self/status"), "CapEff", cap_sys_rawio) orelse true;
    try p.add(.{
        .id = "kernel-mem-attack",
        .area = "kernel",
        .name = "Physical memory refused",
        .why = "Not even root can read or write the machine's memory directly, and the " ++
            "kernel logs every attempt or refuses the capability it takes.",
        .how = "opening /dev/mem fails, and the kernel logs lockdown's refusal, or this " ++
            "process lacks CAP_SYS_RAWIO",
        .result = if (dev == .logged or (dev == .silent and !rawio)) .pass else .fail,
        .detail = if (dev == .silent and !rawio) "refused: no CAP_SYS_RAWIO" else dev.detail(),
    });

    defer cleanAttacks();
    cleanAttacks();
    const sees = asNobody(seesInit);
    try p.add(.{
        .id = "processes-hidden-attack",
        .area = "processes",
        .name = "Processes hidden from another user",
        .why = "A user, or an intruder running as one, cannot see what else runs.",
        .how = "as nobody, /proc/1 does not exist",
        .result = if (sees) |s| (if (s) .fail else .pass) else .skip,
        .detail = if (sees) |s| (if (s)
            "nobody sees /proc/1"
        else
            "") else "could not become nobody",
    });
    const writes = asNobody(writesRun);
    try p.add(.{
        .id = "files-run-attack",
        .area = "files",
        .name = "/run closed to other users",
        .why = "Another user cannot plant files where the services keep their state.",
        .how = "as nobody, creating a file in /run fails",
        .result = if (writes) |w| (if (w) .fail else .pass) else .skip,
        .detail = if (writes) |w| (if (w)
            "nobody wrote to /run"
        else
            "") else "could not become nobody",
    });

    // Each trick needs one side planted by nobody and the other tried
    // by root, or the other way around.
    var got: std.ArrayList(u8) = .empty;
    var missed = false;
    if (asNobody(plantsLink)) |planted| {
        if (planted and
            opensForWrite(
                attack_link,
                false,
            )) try got.appendSlice(p.gpa, "root wrote through nobody's symlink");
        missed = missed or !planted;
    } else missed = true;
    const secret = linux.open(
        attack_secret,
        .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .CLOEXEC = true },
        0o600,
    );
    if (linux.errno(secret) == .SUCCESS) {
        _ = linux.close(@intCast(secret));
        if (asNobody(linksSecret)) |linked| {
            if (linked) try got.print(
                p.gpa,
                "{s}nobody hard-linked root's file",
                .{if (got.items.len > 0) ", " else ""},
            );
        } else missed = true;
    } else missed = true;
    if (asNobody(plantsFile)) |planted| {
        if (planted and
            opensForWrite(
                attack_file,
                true,
            )) try got.print(
            p.gpa,
            "{s}root opened nobody's file with O_CREAT",
            .{if (got.items.len > 0) ", " else ""},
        );
        missed = missed or !planted;
    } else missed = true;
    try p.add(.{
        .id = "files-links-attack",
        .area = "files",
        .name = "Link and file tricks refused",
        .why = "A file planted in a shared directory cannot make root write where it did " ++
            "not mean to, or reach root's files.",
        .how = "in /tmp, root writing through nobody's symlink, nobody hard-linking root's " ++
            "0600 file, and root opening nobody's file with O_CREAT each fail",
        .result = if (got.items.len > 0) .fail else if (missed) .skip else .pass,
        .detail = if (got.items.len > 0)
            got.items
        else if (missed)
            "could not set every trick up"
        else
            "",
    });
    try leashAttack(p);
}

/// A service leash starts as an unprivileged user does what its file
/// grants and nothing more: posture leashes a copy of itself, which
/// tries (probe, below) and says by its exit code what went as it
/// should not.
fn leashAttack(p: *Posture) !void {
    if (!exists(p.io, leash_bin)) return;
    var exe: [Dir.max_path_bytes]u8 = undefined;
    const self = exe[0 .. Dir.cwd().readLink(p.io, "/proc/self/exe", &exe) catch return];
    // Clear any leftover the probe's own directories hold before this
    // run, not only after: on a kept /data, a boot whose power was cut
    // mid-probe could leave /data/svc/posture-probe behind, and leash
    // would then park the probe on it.
    Dir.cwd().deleteTree(p.io, "/run/svc/" ++ probe_name) catch {};
    Dir.cwd().deleteTree(p.io, "/data/svc/" ++ probe_name) catch {};
    Dir.cwd().createDirPath(p.io, probe_dir) catch return;
    defer {
        Dir.cwd().deleteTree(p.io, probe_dir) catch {};
        Dir.cwd().deleteTree(p.io, "/run/svc/" ++ probe_name) catch {};
        Dir.cwd().deleteTree(p.io, "/data/svc/" ++ probe_name) catch {};
    }
    const file = try p.gpa.print(
        "# posture's probe (werewolf.check=1), granted TCP port 1 and nothing else\n" ++
            "exec {s} --probe\nuser nobody\nconnect tcp/1\npledge stdio rpath wpath inet " ++
            "connect proc exec\n",
        .{self},
    );
    Dir.cwd().writeFile(
        p.io,
        .{ .sub_path = probe_dir ++ "/service", .data = file },
    ) catch return;
    var child = std.process.spawn(p.io, .{
        .argv = &.{leash_bin},
        .cwd = .{ .path = probe_dir },
        .stdin = .ignore,
    }) catch return;
    const term = child.wait(p.io) catch return;
    const ran = term == .exited and term.exited == 0x80;
    // The probe writes a bitmask of what went wrong to its own
    // directory, where only it may write; posture, as root, reads it.
    // Not through a link: the directory is nobody's.
    var mask: u32 = 0;
    const result = linux.open(
        "/run/svc/" ++ probe_name ++ "/result",
        .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true },
        0,
    );
    if (linux.errno(result) == .SUCCESS) {
        var m: [4]u8 = undefined;
        if (linux.read(@intCast(result), &m, m.len) == m.len)
            mask = std.mem.readInt(u32, &m, .little);
        _ = linux.close(@intCast(result));
    }
    var got: std.ArrayList(u8) = .empty;
    if (ran) for (probe_tries, 0..) |what, i| {
        if (mask & (@as(u32, 1) << @intCast(i)) != 0)
            try got.print(p.gpa, "{s}{s}", .{ if (got.items.len > 0) ", " else "", what });
    };
    try p.add(.{
        .id = "processes-leash-attack",
        .area = "processes",
        .name = "A leashed service stays on its leash",
        .why = "A service that is taken over can reach only the files, programs and ports " ++
            "its " ++
            "service file names.",
        .how = "this program, leashed as nobody, granted TCP port 1 and pledged " ++
            "stdio rpath wpath inet connect proc exec, cannot read /run/werewolf/hostname, " ++
            "write /tmp, run /usr/bin/sv, connect to port 2, or (its pledge not promising " ++
            "them) make a memfd, an inotify watch or SysV shared memory; and can read " ++
            "/etc/passwd, write its own directory and connect to port 1",
        .result = if (!ran) .fail else if (got.items.len == 0) .pass else .fail,
        .detail = if (!ran) "the probe did not run" else got.items,
    });
}

const Refusal = enum {
    logged,
    silent,
    allowed,

    fn detail(r: Refusal) []const u8 {
        return switch (r) {
            .logged => "",
            .silent => "refused, but the kernel logged nothing",
            .allowed => "opened",
        };
    }
};

/// Whether opening path read-only is refused, with a line in the
/// kernel's log, written after this open, that has every one of needles.
fn refusedAndLogged(p: *Posture, path: [:0]const u8, needles: []const []const u8) Refusal {
    const kmsg_rc = linux.open(
        "/dev/kmsg",
        .{ .ACCMODE = .RDONLY, .NONBLOCK = true, .CLOEXEC = true },
        0,
    );
    const kmsg: ?i32 = if (linux.errno(kmsg_rc) == .SUCCESS) @intCast(kmsg_rc) else null;
    defer if (kmsg) |fd| {
        _ = linux.close(fd);
    };
    if (kmsg) |fd| _ = linux.lseek(fd, 0, linux.SEEK.END);

    const rc = linux.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(rc) == .SUCCESS) {
        _ = linux.close(@intCast(rc));
        return .allowed;
    }
    const fd = kmsg orelse return .silent;
    // One record a read. Yama logs as the open returns; allow a moment.
    var record: [8192]u8 = undefined;
    for (0..20) |_| {
        while (true) {
            const n = linux.read(fd, &record, record.len);
            switch (linux.errno(n)) {
                .SUCCESS => if (hasAll(record[0..n], needles)) return .logged,
                .PIPE => {}, // records lost to newer ones: read on
                else => break,
            }
        }
        p.io.sleep(.fromMilliseconds(100), .awake) catch {};
    }
    return .silent;
}

const leash_bin = "/usr/lib/werewolf/leash";

const probe_name = "posture-probe";

const probe_dir = "/run/werewolf/" ++ probe_name;

/// What the probe tries, in its exit code's bits, each a thing that went
/// as it should not.
const probe_tries = [_][]const u8{
    "read a file it was not granted",
    "could not read /etc/passwd",
    "connected to a port it was not granted",
    "could not connect to the port it was granted",
    "could not write its own directory",
    "wrote to /tmp",
    "ran a program it was not granted",
    "made a memfd, which its pledge did not promise",
    "made an inotify watch, which its pledge did not promise",
    "made SysV shared memory, which its pledge did not promise",
};

/// posture --probe, as leashed by leashAttack: a bit for each of
/// probe_tries that went wrong, written to its own directory, which
/// leashAttack reads; it exits 0x80 to say it ran. It makes only system
/// calls. Bits 0..6 are the leash's Landlock (files, ports, programs);
/// 7..9 the pledge's seccomp (calls it did not promise must be ENOSYS).
pub fn probe() u8 {
    var bits: u32 = 0;
    if (opens("/run/werewolf/hostname")) bits |= 1 << 0;
    if (!opens("/etc/passwd")) bits |= 1 << 1;
    if (connectError(2) != .ACCES) bits |= 1 << 2;
    if (connectError(1) == .ACCES) bits |= 1 << 3;
    if (!creates("/run/svc/" ++ probe_name ++ "/x")) bits |= 1 << 4;
    if (creates("/tmp/." ++ probe_name)) bits |= 1 << 5;
    if (runs("/usr/bin/sv")) bits |= 1 << 6;
    // Its pledge promised none of memfd, watch or ipc, so each of these,
    // which the per-service seccomp filter should refuse (ENOSYS), must not
    // succeed; a success is a hole in the pledge.
    if (made(.memfd_create)) bits |= 1 << 7;
    if (made(.inotify_init1)) bits |= 1 << 8;
    if (made(.shmget)) bits |= 1 << 9;
    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &buf, bits, .little);
    const fd = linux.open(
        "/run/svc/" ++ probe_name ++ "/result",
        .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true, .CLOEXEC = true },
        0o600,
    );
    if (linux.errno(fd) == .SUCCESS) {
        _ = linux.write(@intCast(fd), &buf, buf.len);
        _ = linux.close(@intCast(fd));
    }
    return 0x80;
}

/// Whether a call the probe's pledge did not promise still worked: the
/// per-service seccomp filter should answer ENOSYS, so a success is a hole.
/// Each returns a descriptor or id when allowed, closed or removed at once.
fn made(comptime sys: std.os.linux.SYS) bool {
    const rc = switch (sys) {
        .memfd_create => linux.syscall2(sys, @intFromPtr("probe"), 0),
        .inotify_init1 => linux.syscall1(sys, @as(usize, linux.IN.CLOEXEC)),
        .shmget => linux.syscall3(sys, 0, 4096, 0o600), // IPC_PRIVATE
        else => unreachable,
    };
    if (linux.errno(rc) != .SUCCESS) return false;
    switch (sys) {
        .shmget => _ = linux.syscall3(.shmctl, rc, 0, 0), // IPC_RMID
        else => _ = linux.close(@intCast(rc)),
    }
    return true;
}

fn opens(path: [:0]const u8) bool {
    const fd = linux.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(fd) != .SUCCESS) return false;
    _ = linux.close(@intCast(fd));
    return true;
}

fn creates(path: [:0]const u8) bool {
    const fd = linux.open(
        path,
        .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .CLOEXEC = true },
        0o600,
    );
    if (linux.errno(fd) != .SUCCESS) return false;
    _ = linux.close(@intCast(fd));
    _ = linux.unlink(path);
    return true;
}

/// The error a TCP connect to port on 127.0.0.1 gets: fence lets loopback
/// pass, so a refusal there is the leash's.
fn connectError(port: u16) linux.E {
    const fd = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(fd) != .SUCCESS) return linux.errno(fd);
    defer _ = linux.close(@intCast(fd));
    var addr: linux.sockaddr.in = .{
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    return linux.errno(linux.connect(@intCast(fd), @ptrCast(&addr), @sizeOf(linux.sockaddr.in)));
}

/// Whether path starts: a child tries it, and says by its exit code.
fn runs(path: [:0]const u8) bool {
    const pid = linux.fork();
    if (linux.errno(pid) != .SUCCESS) return false;
    if (pid == 0) {
        const argv = [_:null]?[*:0]const u8{ path, null };
        const envp = [_:null]?[*:0]const u8{null};
        _ = linux.execve(path, &argv, &envp);
        linux.exit_group(42); // refused
    }
    var status: u32 = 0;
    if (linux.errno(linux.wait4(
        @intCast(pid),
        @ptrCast(&status),
        0,
        null,
    )) != .SUCCESS) return false;
    return !(linux.W.IFEXITED(status) and linux.W.EXITSTATUS(status) == 42);
}
