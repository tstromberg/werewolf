//! init's first phases: the filesystems, cgroups, the entropy seed, and
//! the kernel's own protections (lockdown, the modules, the sysctls, no
//! memory both writable and executable).

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const audit = @import("audit");
const init = @import("init.zig");
const Machine = init.Machine;
const exists = init.exists;
const mkdir = init.mkdir;
const mount_bin = init.mount_bin;
const say = init.say;
const trim = init.trim;
const writeErrno = init.writeErrno;
const writeFile = init.writeFile;

/// Every mount is werewolf's own (cmd/mount/mount.zig): nosuid and noexec
/// unless told otherwise, nodev but on device filesystems, nosymfollow
/// but on /proc and /sys, whose links the kernel makes, and /dev, where
/// cryptsetup links /dev/mapper/data and only root writes, and unable to
/// lift a restriction a mount already has. stage0 mounted the first three
/// and moved them here, so they are remounted with the same options
/// either way. Nothing written to memory may run or be setuid, and no
/// link on it is followed: the RAM filesystems are noexec and
/// nosymfollow, so a link planted in /tmp leads nowhere, whoever follows
/// it, and only /tmp, /var/tmp and /dev/shm are writable by everyone.
/// /proc shows each user only their own processes.
pub fn filesystems(m: *Machine) void {
    if (!m.isMounted("/proc")) m.mount(&.{ "-t", "proc", "proc", "/proc" });
    if (!m.isMounted("/sys")) m.mount(&.{ "-t", "sysfs", "sys", "/sys" });
    if (!m.isMounted("/dev")) m.mount(&.{ "-t", "devtmpfs", "dev", "/dev" });
    m.mount(&.{ "-o", "remount,nosuid,nodev,noexec,hidepid=invisible", "/proc" });
    m.mount(&.{ "-o", "remount,nosuid,nodev,noexec", "/sys" });
    m.mount(&.{ "-o", "remount,nosuid,noexec", "/dev" });
    for ([_][:0]const u8{ "/dev/pts", "/dev/shm" }) |d| mkdir(d, 0o755);
    // Pseudo-terminals only where the form allows them (pty): ssh
    // logins. Without devpts mounted, /dev/ptmx opens nothing (ENODEV),
    // so the TTY layer's pseudo-terminal code (CVE-2014-0196) is out of
    // reach of every process, root included, and nothing after boot
    // can mount it.
    if (exists("/etc/werewolf/allow/pty"))
        m.mount(&.{ "-t", "devpts", "-o", "nosuid,noexec", "devpts", "/dev/pts" })
    else
        say("no pseudo-terminals: the form does not allow pty", .{});
    m.mount(&.{ "-t", "tmpfs", "-o", "nosuid,nodev,noexec,mode=1777", "tmpfs", "/dev/shm" });
    m.mount(&.{ "-t", "tmpfs", "-o", "nosuid,nodev,noexec,mode=0755", "tmpfs", "/run" });
    m.mount(&.{ "-t", "tmpfs", "-o", "nosuid,nodev,noexec,mode=1777", "tmpfs", "/tmp" });
    m.mount(&.{
        "-t",
        "tmpfs",
        "-o",
        "nosuid,nodev,noexec,mode=1777,size=25%",
        "tmpfs",
        "/var/tmp",
    });
    mkdir("/run/config", 0o700);
    cgroups(m);
}

/// A cgroup2 hierarchy for the leashed services (cmd/leash), under /run
/// rather than /sys so fence's domain -- which keeps /sys read-only --
/// still lets leash and the finish reaper manage it through the /run it
/// may write. memory and pids are delegated to the svc subtree, so a
/// service gets a memory ceiling and its whole process tree, detached
/// children included, is killed when it stops (its finish writes
/// cgroup.kill). Without cgroup2 or its controllers, services still run,
/// uncapped and without that reaper.
fn cgroups(m: *Machine) void {
    mkdir("/run/cgroup", 0o755);
    if (!m.run(&.{
        mount_bin,
        "-t",
        "cgroup2",
        "-o",
        "nosuid,nodev,noexec",
        "cgroup2",
        "/run/cgroup",
    })) return say("no cgroup2; services run uncapped and unreaped", .{});
    if (!writeFile("/run/cgroup/cgroup.subtree_control", "+memory +pids"))
        return say("cgroup2 without memory/pids; services run uncapped", .{});
    mkdir("/run/cgroup/svc", 0o755);
    _ = writeFile("/run/cgroup/svc/cgroup.subtree_control", "+memory +pids");
    say("cgroups: a memory cap and a reaper per service", .{});
}

/// What init and the services change of the read-only root lives in
/// /run, where the image's /etc links: the accounts, seeded from the
/// image's own copies, the hostname, the resolvers, root's and users' ssh
/// keys, runit's controls and each service's supervise directory.
pub fn seed(m: *Machine) void {
    for ([_][:0]const u8{
        "/run/werewolf",
        "/run/werewolf/keys",
        "/run/runit",
    }) |d| mkdir(d, 0o755);
    for ([_][]const u8{ "passwd", "group", "shadow" }) |f| {
        const src = m.fmt("/usr/share/werewolf/etc/{s}", .{f});
        const text = m.read(src);
        if (text.len == 0) {
            say("cannot read {s}", .{src});
            continue;
        }
        m.write(
            m.fmt("/run/werewolf/{s}", .{f}),
            text,
            if (std.mem.eql(u8, f, "shadow")) 0o600 else 0o644,
        );
    }
    for (m.list("/etc/sv")) |s| mkdir(m.fmtZ("/run/runit/supervise.{s}", .{s}), 0o755);
}

/// Lockdown first. At integrity the kernel loads only modules signed by
/// the key it was built with (Alpine's), so a module that is not is
/// refused, not merely logged; it only ever rises, so init raises it
/// here rather than trusting whatever command line the machine booted
/// with. stage0 has raised it already. Then the modules, and the loader
/// closes for the life of the machine (cmd/modload/modload.zig); stage0 has
/// done both, and the loader says so. Then the settings.
pub fn kernel(m: *Machine) !void {
    if (!m.isMounted("/sys/kernel/security")) m.mount(&.{
        "-t",
        "securityfs",
        "securityfs",
        "/sys/kernel/security",
    });
    m.mount(&.{ "-o", "remount,nosuid,nodev,noexec,nosymfollow", "/sys/kernel/security" });
    const lockdown = "/sys/kernel/security/lockdown";
    if (std.mem.indexOf(u8, m.read(lockdown), "[none]") != null)
        _ = writeFile(lockdown, "integrity");
    say("lockdown: {s}", .{lockdownLevel(m.read(lockdown))});

    if (!m.run(&.{"/usr/lib/werewolf/modload"})) say("not every module loaded; see above", .{});

    var all = true;
    // Each is a protection, so one the kernel refuses ends the boot, and
    // the machine returns on the slot that last worked, as the seal and
    // fence do. werewolf's kernel has every one. In a container these
    // are the host's to set: its /proc/sys is read-only, and a network
    // namespace of its own lacks what only the host's has (EROFS or
    // ENOENT), so there any refusal is said and passed. And a kernel
    // without a BPF JIT has no bpf_jit_harden: nothing to harden.
    const contained = linux.errno(linux.access("/proc/sys/kernel/panic", linux.W_OK)) == .ROFS;
    for (sysctls) |kv| switch (writeErrno(m.fmtZ("/proc/sys/{s}", .{kv[0]}), kv[1])) {
        .SUCCESS => {},
        .NOENT => if (contained or std.mem.eql(u8, kv[0], "net/core/bpf_jit_harden")) {
            all = false;
        } else {
            say("sysctl {s} not set: the kernel has none", .{kv[0]});
            return error.Sysctl;
        },
        else => |e| if (contained) {
            all = false;
        } else {
            say("sysctl {s} not set: {t}", .{ kv[0], e });
            return error.Sysctl;
        },
    };
    if (contained) say("in a container: the kernel's settings are the host's", .{});
    // Every exec the kernel refuses, logged (lib/audit.zig): the record
    // goes to the kernel's log, and the console, with no daemon to run.
    // Locked, and CAP_AUDIT_CONTROL leaves the bounding set with the seal,
    // so nothing can stop it before a reboot. A kernel without audit, or
    // a container, where audit is the host's, is said and passed.
    audit.enable() catch |err| say("refused execs not logged: {s}", .{@errorName(err)});
    // Redirects, per interface: a host takes or sends them on one if all
    // or the interface says so, and all and default do not reach the
    // interfaces stage0's drivers made before now. IPv6 has only the
    // interface's own setting.
    for (m.list("/proc/sys/net/ipv4/conf")) |c| for ([_][]const u8{
        "accept_redirects",
        "secure_redirects",
        "send_redirects",
    }) |k| {
        if (!writeFile(m.fmtZ("/proc/sys/net/ipv4/conf/{s}/{s}", .{ c, k }), "0")) all = false;
    };
    for (m.list("/proc/sys/net/ipv6/conf")) |c| {
        if (!writeFile(
            m.fmtZ("/proc/sys/net/ipv6/conf/{s}/accept_redirects", .{c}),
            "0",
        )) all = false;
    }
    if (!all) say("some sysctls were not applied", .{});
    try writeXorExecute(contained);
    // A panic reboots in the seconds the command line gave (bite's and
    // boot/mkdisk's say 10), or, given none, in 10: the kernel's own
    // default is to hang, and an oops now panics.
    if (std.mem.eql(u8, trim(m.read("/proc/sys/kernel/panic")), "0") and
        !writeFile(
            "/proc/sys/kernel/panic",
            "10",
        )) say("kernel.panic not set; a panic will hang", .{});
}

/// No memory both writable and executable, nor made executable once
/// written (Memory-Deny-Write-Execute): set on PID 1, so every process the
/// machine runs holds to it, and one-way. Code an attacker writes into a
/// program, its heap or a mapping of its own, never runs; only what the
/// kernel maps from a file, the read-only root's programs and libraries,
/// does. A form whose runtime compiles code as it runs (a JVM, V8, .NET,
/// PHP's PCRE, PostgreSQL's LLVM) says so with an allowance, jit. It costs
/// nothing: nothing else here ever writes code. A protection, so a kernel
/// that refuses it ends the boot; in a container, it is said and passed.
fn writeXorExecute(contained: bool) !void {
    if (exists("/etc/werewolf/allow/jit"))
        return say("memory may be written and then run: the form allows jit", .{});
    const PR_SET_MDWE = 65;
    const PR_MDWE_REFUSE_EXEC_GAIN = 1;
    const e = linux.errno(linux.prctl(PR_SET_MDWE, PR_MDWE_REFUSE_EXEC_GAIN, 0, 0, 0));
    if (e == .SUCCESS) return;
    say("memory-deny-write-execute not set: {t}", .{e});
    if (!contained) return error.WriteXorExecute;
}

/// What closes doors root could use against the running kernel or another
/// process, and what an ordinary user could use against root. Lockdown,
/// raised before, refuses kexec and /dev/mem. Yama's ptrace scope 3 stops
/// any process writing into another, root's included, and cannot be
/// lowered; memfds can no longer be executed, though root may lower that
/// one. The rest hide kernel pointers and the log, keep BPF to root, stop
/// forwarding, and close user namespaces (a private mount namespace would let
/// a user mount its own tmpfs without noexec) and the symlink, hardlink,
/// FIFO and file tricks the kernel refuses in sticky directories such as
/// /tmp only when asked. Root could undo these; no one else can. io_uring,
/// a large kernel interface nothing here uses, is off; the magic SysRq keys
/// are off (stage0's deadman writes /proc/sysrq-trigger, which they do not
/// govern); ICMP redirects are neither taken nor sent (and, per interface,
/// in kernel(), above); packets from impossible addresses are logged; pings
/// to a broadcast address and bogus ICMP errors are ignored, and a forged
/// reset cannot cut short a closing connection (RFC 1337). Programs' addresses
/// are randomized as far as the kernel allows (4K pages, 48-bit addresses),
/// the first 64 KiB cannot be mapped, the filters any user may install are
/// compiled with their constants blinded, and an oops panics, so a kernel
/// a failed exploit left wrong reboots rather than runs on; so does the
/// first warning once init has set it (warn_limit), as when the kernel
/// catches its own memory corrupted and carries on: a list's links wrong,
/// a reference count overflowing, KFENCE finding a use after free. Alpine's
/// kernel only warns of those (no CONFIG_BUG_ON_DATA_CORRUPTION). A
/// warning in early boot, before this, counts toward nothing. kernel.panic,
/// below, makes the panic a reboot. None of it costs a program anything.
/// See docs/security.md.
const sysctls = [_][2][]const u8{
    .{ "vm/mmap_rnd_bits", switch (builtin.cpu.arch) {
        .aarch64 => "33",
        .x86_64 => "32",
        else => @compileError("init runs on aarch64 and x86_64"),
    } },
    .{ "vm/mmap_min_addr", "65536" },
    .{ "net/core/bpf_jit_harden", "1" },
    .{ "kernel/panic_on_oops", "1" },
    .{ "kernel/warn_limit", "1" },
    .{ "kernel/kptr_restrict", "2" },
    .{ "kernel/dmesg_restrict", "1" },
    .{ "kernel/unprivileged_bpf_disabled", "1" },
    .{ "net/ipv4/ip_forward", "0" },
    .{ "kernel/yama/ptrace_scope", "3" },
    .{ "vm/memfd_noexec", "2" },
    .{ "user/max_user_namespaces", "0" },
    .{ "fs/protected_symlinks", "1" },
    .{ "fs/protected_hardlinks", "1" },
    .{ "fs/protected_fifos", "2" },
    .{ "fs/protected_regular", "2" },
    .{ "kernel/io_uring_disabled", "2" },
    .{ "kernel/sysrq", "0" },
    // No program for the kernel to start on every device event, or to
    // load a module it wants: it would run outside the seal (see seal()),
    // and the loader is closed anyway. An empty line empties each, and
    // the kernel then starts nothing (request_module answers ENOENT).
    .{ "kernel/hotplug", "\n" },
    .{ "kernel/modprobe", "\n" },
    .{ "net/ipv4/conf/all/log_martians", "1" },
    .{ "net/ipv4/conf/default/log_martians", "1" },
    .{ "net/ipv4/icmp_echo_ignore_broadcasts", "1" },
    .{ "net/ipv4/icmp_ignore_bogus_error_responses", "1" },
    .{ "net/ipv4/tcp_rfc1337", "1" },
    // The kernel's audit records (refused execs) reach the log through
    // printk's rate limit, 10 lines in 5 seconds, which a few refusals
    // together would exceed: posture's own proofs refuse seven execs in a
    // row. A hundred keeps a burst on record and a flood bounded.
    .{ "kernel/printk_ratelimit_burst", "100" },
};

/// The level in /sys/kernel/security/lockdown: "none [integrity] confidentiality".
fn lockdownLevel(text: []const u8) []const u8 {
    const a = std.mem.findScalar(u8, text, '[') orelse return "unavailable";
    const b = std.mem.findScalarPos(u8, text, a, ']') orelse return "unavailable";
    return text[a + 1 .. b];
}

test lockdownLevel {
    try std.testing.expectEqualStrings(
        "integrity",
        lockdownLevel("none [integrity] confidentiality\n"),
    );
}
