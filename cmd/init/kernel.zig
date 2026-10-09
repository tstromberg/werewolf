//! init's first phases: filesystems, cgroups, the /run seed, and the
//! kernel's protections (lockdown, modules, sysctls, MDWE).

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const allow = @import("allow");
const audit = @import("audit");
const init = @import("init.zig");
const Machine = init.Machine;
const mkdir = init.mkdir;
const mount_bin = init.mount_bin;
const say = init.say;
const trim = init.trim;
const writeErrno = init.writeErrno;
const writeFile = init.writeFile;

/// filesystems mounts /proc, /sys, /dev and the RAM filesystems. werewolf's
/// mount (cmd/mount) adds nosuid, noexec, nodev and nosymfollow by default,
/// so a file written to RAM never runs and a link planted in /tmp is not
/// followed. stage0 may have mounted /proc, /sys and /dev already, so they
/// are remounted to get the same options either way.
pub fn filesystems(m: *Machine) void {
    if (!m.isMounted("/proc")) m.mount(&.{ "-t", "proc", "proc", "/proc" });
    if (!m.isMounted("/sys")) m.mount(&.{ "-t", "sysfs", "sys", "/sys" });
    if (!m.isMounted("/dev")) m.mount(&.{ "-t", "devtmpfs", "dev", "/dev" });
    m.mount(&.{ "-o", "remount,nosuid,nodev,noexec,hidepid=invisible", "/proc" });
    m.mount(&.{ "-o", "remount,nosuid,nodev,noexec", "/sys" });
    m.mount(&.{ "-o", "remount,nosuid,noexec", "/dev" });
    for ([_][:0]const u8{ "/dev/pts", "/dev/shm" }) |d| mkdir(d, 0o755);
    // devpts is mounted only if the form allows pty (ssh logins). Without
    // it, /dev/ptmx fails with ENODEV, so the pty code (CVE-2014-0196) is
    // out of reach of every process, and nothing can mount it after boot.
    if (allow.has(.pty))
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

/// cgroups mounts cgroup2 for leash's services at /run/cgroup, not under
/// /sys, because fence's domain keeps /sys read-only. The memory and pids
/// controllers give each service a memory cap, and let its finish kill its
/// whole process tree through cgroup.kill. Without them, services run
/// uncapped and unreaped.
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

/// seed creates the /run directories that the read-only root's /etc links
/// point to, and copies the image's passwd, group and shadow there.
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

/// kernel raises lockdown to integrity, loads modules and closes the loader
/// (cmd/modload), and applies the sysctls and MDWE. stage0 has done the
/// first two already; init repeats them rather than trust the command line.
/// At integrity the kernel refuses modules not signed by Alpine's key.
/// It returns an error if a protection is refused outside a container.
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
    // A refused sysctl ends the boot, and the machine returns on the slot
    // that last worked. In a container the settings are the host's: /proc/sys
    // is read-only (EROFS) and a network namespace lacks some (ENOENT), so
    // refusals are logged and passed. A kernel without a BPF JIT has no
    // bpf_jit_harden, and needs none.
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
    // Log every exec the kernel refuses to the kernel log, with no daemon
    // (lib/audit.zig). The rule is locked and the seal drops
    // CAP_AUDIT_CONTROL, so nothing can stop it before a reboot. Without
    // audit (or in a container), this is logged and passed.
    audit.enable() catch |err| say("refused execs not logged: {s}", .{@errorName(err)});
    // Turn off ICMP redirects on each interface: the kernel honors them if
    // "all" or the interface allows them, and "default" does not reach
    // interfaces that already exist. IPv6 has only the per-interface setting.
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
    // A panic must reboot: the kernel's default is to hang, and an oops now
    // panics. Keep a timeout the command line set (bite and boot/mkdisk set
    // 10), else set 10 seconds.
    if (std.mem.eql(u8, trim(m.read("/proc/sys/kernel/panic")), "0") and
        !writeFile(
            "/proc/sys/kernel/panic",
            "10",
        )) say("kernel.panic not set; a panic will hang", .{});
}

/// writeXorExecute sets Memory-Deny-Write-Execute on PID 1, which every
/// process inherits and none can undo, so code an attacker writes into memory
/// never runs. A form with a JIT (a JVM, V8, .NET, PCRE, LLVM) opts out with
/// the jit allowance. Refusal is an error unless contained.
fn writeXorExecute(contained: bool) !void {
    if (allow.has(.jit))
        return say("memory may be written and then run: the form allows jit", .{});
    const PR_SET_MDWE = 65;
    const PR_MDWE_REFUSE_EXEC_GAIN = 1;
    const e = linux.errno(linux.prctl(PR_SET_MDWE, PR_MDWE_REFUSE_EXEC_GAIN, 0, 0, 0));
    if (e == .SUCCESS) return;
    say("memory-deny-write-execute not set: {t}", .{e});
    if (!contained) return error.WriteXorExecute;
}

/// sysctls close what root could use against the kernel or another process,
/// and what a user could use against root. Root could undo most of them; no
/// one else can. None costs a program anything. See docs/security.md.
const sysctls = [_][2][]const u8{
    // Randomize addresses as far as 4K pages and 48-bit addresses allow.
    .{ "vm/mmap_rnd_bits", switch (builtin.cpu.arch) {
        .aarch64 => "33",
        .x86_64 => "32",
        else => @compileError("init runs on aarch64 and x86_64"),
    } },
    .{ "vm/mmap_min_addr", "65536" },
    // Blind constants in the BPF filters any user may install.
    .{ "net/core/bpf_jit_harden", "1" },
    // An oops, or the first warning, panics, so a kernel that a failed exploit
    // left corrupt reboots instead of running on. Alpine's kernel only warns
    // of a corrupt list, an overflowed refcount or a KFENCE use after free
    // (no CONFIG_BUG_ON_DATA_CORRUPTION). Warnings before init sets this
    // do not count.
    .{ "kernel/panic_on_oops", "1" },
    .{ "kernel/warn_limit", "1" },
    // Hide kernel pointers and the log, keep BPF to root, and never forward.
    .{ "kernel/kptr_restrict", "2" },
    .{ "kernel/dmesg_restrict", "1" },
    .{ "kernel/unprivileged_bpf_disabled", "1" },
    .{ "net/ipv4/ip_forward", "0" },
    // No process may ptrace another, root included; this cannot be lowered.
    .{ "kernel/yama/ptrace_scope", "3" },
    // memfds cannot be executed, though root may lower this.
    .{ "vm/memfd_noexec", "2" },
    // In a user namespace, a user could mount a tmpfs without noexec.
    .{ "user/max_user_namespaces", "0" },
    // Refuse link, FIFO and file tricks in sticky directories such as /tmp.
    .{ "fs/protected_symlinks", "1" },
    .{ "fs/protected_hardlinks", "1" },
    .{ "fs/protected_fifos", "2" },
    .{ "fs/protected_regular", "2" },
    // io_uring is a large kernel interface nothing here uses.
    .{ "kernel/io_uring_disabled", "2" },
    // stage0's deadman writes /proc/sysrq-trigger, which this does not govern.
    .{ "kernel/sysrq", "0" },
    // The kernel must not start a helper for device events or module
    // requests: it would run outside the seal, and the loader is closed.
    // An empty value makes request_module answer ENOENT.
    .{ "kernel/hotplug", "\n" },
    .{ "kernel/modprobe", "\n" },
    // Log impossible source addresses, ignore broadcast pings and bogus ICMP
    // errors, and stop a forged reset cutting a closing connection short.
    .{ "net/ipv4/conf/all/log_martians", "1" },
    .{ "net/ipv4/conf/default/log_martians", "1" },
    .{ "net/ipv4/icmp_echo_ignore_broadcasts", "1" },
    .{ "net/ipv4/icmp_ignore_bogus_error_responses", "1" },
    .{ "net/ipv4/tcp_rfc1337", "1" },
    // Audit records pass printk's rate limit, 10 lines in 5 seconds by
    // default; posture alone refuses seven execs in a row. 100 keeps a burst
    // on record and a flood bounded.
    .{ "kernel/printk_ratelimit_burst", "100" },
};

/// lockdownLevel returns the bracketed level in
/// /sys/kernel/security/lockdown ("none [integrity] confidentiality").
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
