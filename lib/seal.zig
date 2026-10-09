//! seal maps pledge-style promises to the system calls they allow, and
//! builds the seccomp filters for the machine seal and for each service.
//! See lib/README.md and docs/design/pledge.md.

const std = @import("std");
const linux = std.os.linux;

pub const Promise = enum(u5) {
    stdio,
    rpath,
    watch,
    wpath,
    inet,
    unix,
    netlink,
    packet,
    connect,
    listen,
    proc,
    exec,
    setuid,
    setgid,
    setgroups,
    caps,
    chroot,
    mount,
    umount,
    namespace,
    seccomp,
    landlock,
    memfd,
    ipc,
    sendfile,
    splice,
    mlock,
    aio,
    settime,
    hostname,
    syslog,
    reboot,
};

/// Set is a set of promises.
pub const Set = std.EnumSet(Promise);

/// table lists the calls each promise allows, by name. inet, unix, netlink
/// and packet also allow socket (and unix socketpair); the filter checks the
/// family against the promises.
const table = [_]struct { p: Promise, names: []const []const u8 }{
    .{ .p = .stdio, .names = &.{
        "read",                   "write",              "readv",
        "writev",                 "pread64",            "pwrite64",
        "preadv",                 "pwritev",            "preadv2",
        "pwritev2",               "close",              "close_range",
        "dup",                    "dup2",               "dup3",
        "lseek",                  "fstat",              "newfstatat",
        "fstatat64",              "statx",              "fcntl",
        "ioctl",                  "flock",              "fsync",
        "fdatasync",              "fadvise64",          "readahead",
        "copy_file_range",        "mmap",               "munmap",
        "mprotect",               "mremap",             "madvise",
        "brk",                    "msync",              "mincore",
        "membarrier",             "futex",              "futex_waitv",
        "set_robust_list",        "get_robust_list",    "set_tid_address",
        "rseq",                   "rt_sigaction",       "rt_sigprocmask",
        "rt_sigreturn",           "rt_sigtimedwait",    "rt_sigsuspend",
        "rt_sigpending",          "sigaltstack",        "restart_syscall",
        "nanosleep",              "clock_nanosleep",    "clock_gettime",
        "clock_getres",           "gettimeofday",       "time",
        "times",                  "getitimer",          "setitimer",
        "alarm",                  "pause",              "timer_create",
        "timer_settime",          "timer_gettime",      "timer_getoverrun",
        "timer_delete",           "timerfd_create",     "timerfd_settime",
        "timerfd_gettime",        "exit",               "exit_group",
        "getpid",                 "gettid",             "getppid",
        "getuid",                 "geteuid",            "getgid",
        "getegid",                "getresuid",          "getresgid",
        "getgroups",              "getpgid",            "getpgrp",
        "getsid",                 "getrlimit",          "prlimit64",
        "getrusage",              "sysinfo",            "uname",
        "getcpu",                 "sched_yield",        "sched_getaffinity",
        "sched_getparam",         "sched_getscheduler", "sched_get_priority_max",
        "sched_get_priority_min", "getpriority",        "getrandom",
        "pipe",                   "pipe2",              "poll",
        "ppoll",                  "select",             "pselect6",
        "epoll_create",           "epoll_create1",      "epoll_ctl",
        "epoll_wait",             "epoll_pwait",        "epoll_pwait2",
        "eventfd",                "eventfd2",           "signalfd",
        "signalfd4",              "sendto",             "recvfrom",
        "sendmsg",                "recvmsg",            "sendmmsg",
        "recvmmsg",               "getsockopt",         "setsockopt",
        "getsockname",            "getpeername",        "shutdown",
        "prctl",                  "capget",             "arch_prctl",
        "umask",                  "get_mempolicy",
    } },
    .{ .p = .rpath, .names = &.{
        "open",       "openat",     "openat2",    "getdents",
        "getdents64", "readlink",   "readlinkat", "access",
        "faccessat",  "faccessat2", "stat",       "lstat",
        "statfs",     "fstatfs",    "getcwd",     "chdir",
        "fchdir",     "getxattr",   "lgetxattr",  "fgetxattr",
        "listxattr",  "llistxattr", "flistxattr",
    } },
    // Landlock does not mediate fsnotify, so inotify sees events in
    // directories Landlock denies. watch is a separate promise so that a
    // service that only reads files cannot watch the machine's activity.
    .{ .p = .watch, .names = &.{
        "inotify_init",     "inotify_init1", "inotify_add_watch",
        "inotify_rm_watch", "fanotify_init", "fanotify_mark",
    } },
    .{ .p = .wpath, .names = &.{
        "creat",     "mkdir",       "mkdirat",         "rmdir",
        "unlink",    "unlinkat",    "rename",          "renameat",
        "renameat2", "link",        "linkat",          "symlink",
        "symlinkat", "chmod",       "fchmod",          "fchmodat",
        "fchmodat2", "chown",       "fchown",          "fchownat",
        "lchown",    "truncate",    "ftruncate",       "fallocate",
        "utime",     "utimes",      "utimensat",       "futimesat",
        "mknod",     "mknodat",     "setxattr",        "lsetxattr",
        "fsetxattr", "removexattr", "lremovexattr",    "fremovexattr",
        "sync",      "syncfs",      "sync_file_range",
    } },
    .{ .p = .inet, .names = &.{"socket"} },
    .{ .p = .unix, .names = &.{ "socket", "socketpair" } },
    .{ .p = .netlink, .names = &.{"socket"} },
    .{ .p = .packet, .names = &.{"socket"} },
    .{ .p = .connect, .names = &.{"connect"} },
    .{ .p = .listen, .names = &.{ "bind", "listen", "accept", "accept4" } },
    .{ .p = .proc, .names = &.{
        "clone",             "clone3",          "fork",               "vfork",
        "wait4",             "waitid",          "kill",               "tkill",
        "tgkill",            "rt_sigqueueinfo", "rt_tgsigqueueinfo",  "setpgid",
        "setsid",            "pidfd_open",      "pidfd_send_signal",  "setpriority",
        "sched_setaffinity", "sched_setparam",  "sched_setscheduler", "sched_setattr",
        "sched_getattr",
    } },
    .{ .p = .exec, .names = &.{ "execve", "execveat" } },
    .{ .p = .setuid, .names = &.{ "setuid", "setreuid", "setresuid", "setfsuid" } },
    .{ .p = .setgid, .names = &.{ "setgid", "setregid", "setresgid", "setfsgid" } },
    .{ .p = .setgroups, .names = &.{"setgroups"} },
    .{ .p = .caps, .names = &.{"capset"} },
    .{ .p = .chroot, .names = &.{"chroot"} },
    .{ .p = .mount, .names = &.{
        "mount",      "fsopen",     "fsconfig",  "fsmount",
        "fspick",     "move_mount", "open_tree", "mount_setattr",
        "pivot_root",
    } },
    .{ .p = .umount, .names = &.{ "umount2", "umount" } },
    .{ .p = .namespace, .names = &.{ "unshare", "setns" } },
    .{ .p = .seccomp, .names = &.{"seccomp"} },
    .{
        .p = .landlock,
        .names = &.{ "landlock_create_ruleset", "landlock_add_rule", "landlock_restrict_self" },
    },
    .{ .p = .memfd, .names = &.{ "memfd_create", "memfd_secret" } },
    .{ .p = .ipc, .names = &.{
        "shmget", "shmat",  "shmdt",      "shmctl",
        "semget", "semop",  "semtimedop", "semctl",
        "msgget", "msgsnd", "msgrcv",     "msgctl",
    } },
    // These calls move page-cache pages rather than copies. Into a socket,
    // sendfile and splice reach the code of three bugs exploited in 2026
    // (CVE-2026-31431, CVE-2026-53266, CVE-2026-53362); into a pipe, splice
    // and tee reach Dirty Pipe (CVE-2022-0847). The machine keeps sendfile
    // because Zig's standard library copies files with it; nothing needs
    // splice or tee.
    .{ .p = .sendfile, .names = &.{"sendfile"} },
    .{ .p = .splice, .names = &.{ "splice", "tee" } },
    .{ .p = .mlock, .names = &.{ "mlock", "mlock2", "munlock", "mlockall", "munlockall" } },
    // Legacy asynchronous I/O, not io_uring (which no promise allows).
    // nginx sets up an AIO context at startup.
    .{ .p = .aio, .names = &.{
        "io_setup",             "io_destroy",   "io_submit",
        "io_cancel",            "io_getevents", "io_pgetevents",
        "io_pgetevents_time64",
    } },
    .{ .p = .settime, .names = &.{ "settimeofday", "clock_settime", "clock_adjtime", "adjtimex" } },
    .{ .p = .hostname, .names = &.{ "sethostname", "setdomainname" } },
    .{ .p = .syslog, .names = &.{"syslog"} },
    .{ .p = .reboot, .names = &.{"reboot"} },
};

/// by_promise holds the calls of each promise that this architecture has.
const by_promise = blk: {
    var lists: [std.enums.values(Promise).len][]const linux.SYS = @splat(&.{});
    for (table) |e| for (e.names) |name| {
        if (@hasField(linux.SYS, name))
            lists[@backingInt(e.p)] = lists[@backingInt(e.p)] ++
                [_]linux.SYS{@field(linux.SYS, name)};
    };
    break :blk lists;
};

/// calls returns the calls promise p allows on this architecture.
pub fn calls(p: Promise) []const linux.SYS {
    return by_promise[@backingInt(p)];
}

/// promisesOf returns the promises that allow the call numbered nr.
pub fn promisesOf(nr: u32) Set {
    var set: Set = .empty;
    for (std.enums.values(Promise)) |p| {
        for (calls(p)) |sys| if (number(sys) == nr) set.insert(p);
    }
    return set;
}

/// parse returns the promises named in words. On an unknown word it returns
/// error.UnknownPromise and sets bad to the word.
pub fn parse(words: []const u8, bad: *[]const u8) !Set {
    var set: Set = .empty;
    var it = std.mem.tokenizeAny(u8, words, " \t\n");
    while (it.next()) |w| {
        bad.* = w;
        set.insert(std.meta.stringToEnum(Promise, w) orelse return error.UnknownPromise);
    }
    return set;
}

/// base is what werewolf's own programs need between them (init after the
/// seal, fence, runit, the mount broker, leash, posture, the updater and the
/// DHCP client), so every machine allows it. syslog lets dmesg read the log
/// (dmesg_restrict still limits it to root); Zig's standard library copies
/// files with sendfile. Each program confines itself further (docs/programs.md).
pub const base: Set = .initMany(&.{
    .stdio,  .rpath,  .wpath,   .inet,     .unix,   .netlink,   .packet,   .connect,
    .listen, .proc,   .exec,    .setuid,   .setgid, .setgroups, .caps,     .chroot,
    .mount,  .umount, .seccomp, .landlock, .reboot, .syslog,    .sendfile,
});

/// never_names lists the calls no promise allows, whatever a pledge says:
///
///   bpf, perf_event_open           eBPF and kernel tracing, rootkit tools
///   init_module .. delete_module   modules; the loader is already closed
///   kexec_load, kexec_file_load    another kernel; lockdown refuses it too
///   io_uring_*                     makes kernel.io_uring_disabled permanent
///   userfaultfd                    the usual way to win a kernel race
///   open_by_handle_at, name_..     walks past mounts by inode handle
///   add_key, keyctl, request_key   the kernel keyring; cryptsetup is done
///                                  with it before init hands over
///   process_vm_readv, _writev      another process's memory; Yama refuses it
///   modify_ldt, iopl, ioperm       16-bit code and I/O ports
///   acct .. vhangup                unused here; old, rarely audited code
const never_names = [_][]const u8{
    "bpf",               "perf_event_open",   "init_module",     "finit_module",
    "delete_module",     "kexec_load",        "kexec_file_load", "io_uring_setup",
    "io_uring_enter",    "io_uring_register", "userfaultfd",     "open_by_handle_at",
    "name_to_handle_at", "add_key",           "keyctl",          "request_key",
    "process_vm_readv",  "process_vm_writev", "modify_ldt",      "iopl",
    "ioperm",            "acct",              "swapon",          "swapoff",
    "quotactl",          "quotactl_fd",       "lookup_dcookie",  "uselib",
    "vhangup",
};

/// never holds the calls of never_names that this architecture has.
pub const never: []const linux.SYS = blk: {
    var list: []const linux.SYS = &.{};
    for (never_names) |name| {
        if (@hasField(linux.SYS, name)) list = list ++ [_]linux.SYS{@field(linux.SYS, name)};
    }
    break :blk list;
};

// --- filters -------------------------------------------------------------------

/// Filter is a classic BPF instruction (struct sock_filter). The opcodes
/// below are all that the filters here and in lib/sandbox.zig use.
pub const Filter = extern struct { code: u16, jt: u8 = 0, jf: u8 = 0, k: u32 = 0 };
pub const LD_W_ABS = 0x20;
pub const JEQ_K = 0x15;
pub const JGE_K = 0x35;
pub const JSET_K = 0x45;
pub const RET_K = 0x06;

/// RET_ENOSYS fails a call as if the kernel lacked it, which programs
/// already handle for older kernels.
pub const RET_ENOSYS: u32 = linux.SECCOMP.RET.ERRNO | @as(u32, @backingInt(linux.E.NOSYS));

/// native_arch is the AUDIT_ARCH_* value every system call must carry; the
/// filters and audit rules kill any other. werewolf ships no 32-bit code,
/// and the kernel has no switch to disable 32-bit calls. It is defined here
/// because std's AUDIT.ARCH.current does not compile in Zig 0.17.
pub const native_arch: u32 = switch (@import("builtin").cpu.arch) {
    .aarch64 => 0xc00000b7,
    .x86_64 => 0xc000003e,
    else => @compileError("werewolf builds for aarch64 and x86_64"),
};

const max_calls = 512;
/// max_filter counts the prelude (6), execveat (5), the socket and
/// socketpair families (2 * (3 + 2 * 5)), the machine's refusals
/// (7 + 5 + 7 + 7), the table and the final return.
pub const max_filter = 6 + 5 + 2 * (3 + 2 * 5) + 26 + 2 * max_calls + 1;
const AT_EMPTY_PATH = 0x1000;

/// families maps each socket promise to the address families it allows.
const families = [_]struct { p: Promise, af: u32 }{
    .{ .p = .unix, .af = linux.AF.UNIX },
    .{ .p = .inet, .af = linux.AF.INET },
    .{ .p = .inet, .af = linux.AF.INET6 },
    .{ .p = .netlink, .af = linux.AF.NETLINK },
    .{ .p = .packet, .af = linux.AF.PACKET },
};

/// Refusal is a call the machine seal refuses by its arguments, whatever a
/// pledge says. Each closes a path that exploits in CISA's KEV catalog used
/// and nothing here needs (docs/cve-mitigation-survey.md).
///
///   socket,           a family no promise names: AF_ALG (CVE-2025-39964,
///   socketpair        CVE-2026-31431), and RDS, TIPC, VSOCK, AF_KEY, XDP
///                     and every other the kernel may have
///   setsockopt        TCP_ULP, at the TCP level: kernel TLS (CVE-2025-39682)
///                     and every other upper-layer protocol
///   pipe2             O_NOTIFICATION_PIPE: a watch queue (CVE-2022-0995)
///   timer_create,     a CPU-time clock, the caller's or another process's:
///   clock_nanosleep   POSIX CPU timers (CVE-2025-38352)
///
/// Each fails as a kernel without the feature would fail it, so a program
/// that probes for one carries on. Only these calls miss the kernel's
/// seccomp cache, and none is frequent enough to matter.
pub const Refusal = struct {
    /// what names the refused feature, for seal-watch to log.
    what: []const u8,
    /// arg is the argument that asked for it.
    arg: u64,
    /// errno is what a kernel without the feature would return.
    errno: linux.E,
};

/// by_argument lists the refusals by argument, as `seal` prints them.
pub const by_argument = [_][]const u8{
    "socket and socketpair (a family no promise names)",
    "setsockopt (TCP_ULP)",
    "pipe2 (O_NOTIFICATION_PIPE)",
    "timer_create and clock_nanosleep (a CPU-time clock)",
};

const SOL_TCP = 6;
const TCP_ULP = 31;
/// O_NOTIFICATION_PIPE has the value of O_EXCL on both architectures.
const O_NOTIFICATION_PIPE = 0o200;
const CLOCK_PROCESS_CPUTIME_ID = 2;
const CLOCK_THREAD_CPUTIME_ID = 3;

/// refusal returns why the machine seal refuses this call, or null. The
/// filter decides; this repeats its rules so seal-watch can say why.
pub fn refusal(nr: u32, args: [6]u64) ?Refusal {
    const low = struct {
        fn f(x: u64) u32 {
            return @truncate(x);
        }
    }.f;
    // The seal hands seal-watch a socketpair of an unnamed family (TIPC makes
    // pairs too) just as it does a socket.
    if (nr == number(.socket) or nr == number(.socketpair)) {
        for (families) |f| if (f.af == low(args[0])) return null;
        return .{ .what = "socket family", .arg = low(args[0]), .errno = .AFNOSUPPORT };
    }
    if (nr == number(.setsockopt) and low(args[1]) == SOL_TCP and low(args[2]) == TCP_ULP)
        return .{ .what = "TCP_ULP", .arg = low(args[2]), .errno = .NOENT };
    if (nr == number(.pipe2) and low(args[1]) & O_NOTIFICATION_PIPE != 0)
        return .{ .what = "O_NOTIFICATION_PIPE", .arg = low(args[1]), .errno = .NOPKG };
    if ((nr == number(.timer_create) or nr == number(.clock_nanosleep)) and cpuClock(low(args[0])))
        return .{ .what = "CPU-time clock", .arg = low(args[0]), .errno = .INVAL };
    return null;
}

/// number returns sys's number as seccomp_data.nr holds it.
fn number(sys: linux.SYS) u32 {
    return @intCast(@backingInt(sys));
}

/// cpuClock reports whether clock measures CPU time: the caller's process
/// or thread, or, when negative, another one's. Negative also covers device
/// clocks, which have no timers anyway.
fn cpuClock(clock: u32) bool {
    return clock == CLOCK_PROCESS_CPUTIME_ID or clock == CLOCK_THREAD_CPUTIME_ID or
        clock >= 0x80000000;
}

/// buildFilter writes into buf a filter that allows the calls of promises.
/// The machine seal (per_service false) hands other calls to seal-watch; a
/// service's filter fails them with ENOSYS. A foreign architecture, and on
/// x86_64 an x32 call (bit 30), kill the process: an x32 number would match
/// no comparison as intended. Each comparison has its own return, so jumps
/// stay short however many calls there are.
///
/// socket and socketpair are checked by family: a service's own promises,
/// or for the seal any promise's, so even root cannot open an unnamed
/// family. The seal also adds the refusals by argument (see refusal). Other
/// calls are matched by number alone, so the kernel can cache the verdict.
/// A service without exec may only execveat a descriptor (AT_EMPTY_PATH):
/// that is how leash becomes the service, and Landlock lets it run only
/// its own program.
pub fn buildFilter(buf: *[max_filter]Filter, promises: Set, per_service: bool) []const Filter {
    // A service's filter needs no listener, so leash can install it after
    // dropping CAP_SYS_ADMIN. The seal on PID 1 hands the rest to
    // seal-watch to log and count.
    const other = if (per_service) RET_ENOSYS else linux.SECCOMP.RET.USER_NOTIF;
    var n: usize = 0;
    const put = struct {
        fn f(b: *[max_filter]Filter, i: *usize, code: u16, jt: u8, jf: u8, k: u32) void {
            b[i.*] = .{ .code = code, .jt = jt, .jf = jf, .k = k };
            i.* += 1;
        }
    }.f;
    put(buf, &n, LD_W_ABS, 0, 0, 4); // seccomp_data.arch
    put(buf, &n, JEQ_K, 1, 0, native_arch);
    put(buf, &n, RET_K, 0, 0, linux.SECCOMP.RET.KILL_PROCESS);
    put(buf, &n, LD_W_ABS, 0, 0, 0); // seccomp_data.nr
    if (@import("builtin").cpu.arch == .x86_64) {
        put(buf, &n, JGE_K, 0, 1, 0x40000000); // __X32_SYSCALL_BIT
        put(buf, &n, RET_K, 0, 0, linux.SECCOMP.RET.KILL_PROCESS);
    }
    const socket = number(.socket);
    if (per_service and !promises.contains(.exec)) {
        put(buf, &n, JEQ_K, 0, 4, number(.execveat));
        put(buf, &n, LD_W_ABS, 0, 0, 48); // seccomp_data.args[4], low word: flags
        put(buf, &n, JSET_K, 0, 1, AT_EMPTY_PATH);
        put(buf, &n, RET_K, 0, 0, linux.SECCOMP.RET.ALLOW);
        put(buf, &n, RET_K, 0, 0, other);
    }
    {
        var afs: [families.len]u32 = undefined;
        var m: usize = 0;
        for (families) |f| if (promises.contains(f.p)) {
            afs[m] = f.af;
            m += 1;
        };
        // Compare the family, the low word of args[0] (both architectures
        // are little-endian), with each promised one. socketpair is checked
        // too because families besides unix (TIPC) make pairs.
        for ([_]u32{ socket, number(.socketpair) }) |sys| {
            put(buf, &n, JEQ_K, 0, @intCast(2 + 2 * m), sys);
            put(buf, &n, LD_W_ABS, 0, 0, 16); // seccomp_data.args[0], low word
            for (afs[0..m]) |af| {
                put(buf, &n, JEQ_K, 0, 1, af);
                put(buf, &n, RET_K, 0, 0, linux.SECCOMP.RET.ALLOW);
            }
            put(buf, &n, RET_K, 0, 0, other);
        }
    }
    // The machine's refusals by argument (see refusal). Each block reloads
    // the call number for what follows. A service's filter skips them
    // because the machine's filter applies to it too.
    if (!per_service) {
        // setsockopt(_, SOL_TCP, TCP_ULP)
        put(buf, &n, JEQ_K, 0, 6, number(.setsockopt));
        put(buf, &n, LD_W_ABS, 0, 0, 24); // args[1]: level
        put(buf, &n, JEQ_K, 0, 3, SOL_TCP);
        put(buf, &n, LD_W_ABS, 0, 0, 32); // args[2]: option
        put(buf, &n, JEQ_K, 0, 1, TCP_ULP);
        put(buf, &n, RET_K, 0, 0, other);
        put(buf, &n, LD_W_ABS, 0, 0, 0);
        // pipe2(_, O_NOTIFICATION_PIPE)
        put(buf, &n, JEQ_K, 0, 4, number(.pipe2));
        put(buf, &n, LD_W_ABS, 0, 0, 24); // args[1]: flags
        put(buf, &n, JSET_K, 0, 1, O_NOTIFICATION_PIPE);
        put(buf, &n, RET_K, 0, 0, other);
        put(buf, &n, LD_W_ABS, 0, 0, 0);
        // timer_create and clock_nanosleep on a CPU-time clock
        for ([_]linux.SYS{ .timer_create, .clock_nanosleep }) |sys| {
            put(buf, &n, JEQ_K, 0, 6, number(sys));
            put(buf, &n, LD_W_ABS, 0, 0, 16); // args[0]: the clock
            put(buf, &n, JGE_K, 2, 0, 0x80000000);
            put(buf, &n, JEQ_K, 1, 0, CLOCK_PROCESS_CPUTIME_ID);
            put(buf, &n, JEQ_K, 0, 1, CLOCK_THREAD_CPUTIME_ID);
            put(buf, &n, RET_K, 0, 0, other);
            put(buf, &n, LD_W_ABS, 0, 0, 0);
        }
    }
    var seen: [max_calls]u32 = undefined;
    var n_seen: usize = 0;
    var it = promises.iterator();
    while (it.next()) |p| for (calls(p)) |sys| {
        const nr = number(sys);
        if (nr == socket) continue;
        if (std.mem.findScalar(u32, seen[0..n_seen], nr) != null) continue;
        seen[n_seen] = nr;
        n_seen += 1;
        put(buf, &n, JEQ_K, 0, 1, nr);
        put(buf, &n, RET_K, 0, 0, linux.SECCOMP.RET.ALLOW);
    };
    put(buf, &n, RET_K, 0, 0, other);
    return buf[0..n];
}

/// install loads filter on every thread of this process (TSYNC, with ESRCH
/// so a thread left out is an error, not a thread id). With listener (the
/// machine seal on PID 1), it returns the notification descriptor for
/// seal-watch. Without it (a service), it returns -1 and the kernel audits
/// each refused call instead (SECCOMP_FILTER_FLAG_LOG), which seal-watch
/// never sees.
pub fn install(filter: []const Filter, listener: bool) !i32 {
    const SECCOMP_SET_MODE_FILTER = 1;
    const SECCOMP_FILTER_FLAG_TSYNC = 1 << 0;
    const SECCOMP_FILTER_FLAG_LOG = 1 << 1;
    const SECCOMP_FILTER_FLAG_NEW_LISTENER = 1 << 3;
    const SECCOMP_FILTER_FLAG_TSYNC_ESRCH = 1 << 4;
    const prog = extern struct { len: u16, filter: [*]const Filter }{
        .len = @intCast(filter.len),
        .filter = filter.ptr,
    };
    const rc = linux.seccomp(
        SECCOMP_SET_MODE_FILTER,
        SECCOMP_FILTER_FLAG_TSYNC | SECCOMP_FILTER_FLAG_TSYNC_ESRCH |
            @as(u32, if (listener) SECCOMP_FILTER_FLAG_NEW_LISTENER else SECCOMP_FILTER_FLAG_LOG),
        &prog,
    );
    if (linux.errno(rc) != .SUCCESS) return error.Seccomp;
    return if (listener) @intCast(rc) else -1;
}

/// sendListener sends fd over sock (SCM_RIGHTS) with bytes: from init, l to
/// learn or e to enforce; from leash, the service's name. It reports success.
pub fn sendListener(sock: i32, fd: i32, bytes: []const u8) bool {
    var control: [24]u8 align(8) = @splat(0);
    const e = @import("builtin").cpu.arch.endian();
    std.mem.writeInt(usize, control[0..8], 20, e); // CMSG_LEN(sizeof(int))
    std.mem.writeInt(i32, control[8..12], linux.SOL.SOCKET, e);
    std.mem.writeInt(i32, control[12..16], 1, e); // SCM_RIGHTS
    std.mem.writeInt(i32, control[16..20], fd, e);
    const iov = [_]std.posix.iovec_const{.{ .base = bytes.ptr, .len = bytes.len }};
    const msg: linux.msghdr_const = .{
        .name = null,
        .namelen = 0,
        .iov = &iov,
        .iovlen = 1,
        .control = &control,
        .controllen = control.len,
        .flags = 0,
    };
    return linux.errno(linux.sendmsg(sock, &msg, linux.MSG.NOSIGNAL)) == .SUCCESS;
}

/// policy_path is where init records the seal it installed:
/// `mode enforce|learn`, then `promises WORD...`, one line each.
pub const policy_path = "/run/werewolf/seal/policy";
/// refused_path is where seal-watch counts refusals, one line per call:
/// `NAME COUNT LAST_PID FIRST_SECONDS PROMISE`. Calls past the table's last
/// row are counted together as `other`.
pub const refused_path = "/run/werewolf/seal/refused";

const testing = std.testing;

/// action runs filter on a call as the kernel would, for the few opcodes
/// used here, and returns its verdict.
fn action(filter: []const Filter, arch: u32, nr: u32, arg0: u32) u32 {
    return actionArgs(filter, arch, nr, .{ arg0, 0, 0, 0, arg0, 0 });
}

/// actionArgs is action with the low word of each argument given.
fn actionArgs(filter: []const Filter, arch: u32, nr: u32, args: [6]u32) u32 {
    var a: u32 = 0;
    var pc: usize = 0;
    while (true) {
        const i = filter[pc];
        switch (i.code) {
            LD_W_ABS => a = switch (i.k) {
                4 => arch,
                0 => nr,
                16, 24, 32, 40, 48, 56 => args[(i.k - 16) / 8],
                else => unreachable,
            },
            JSET_K => pc += if (a & i.k != 0) i.jt else i.jf,
            JEQ_K => pc += if (a == i.k) i.jt else i.jf,
            JGE_K => pc += if (a >= i.k) i.jt else i.jf,
            RET_K => return i.k,
            else => unreachable,
        }
        pc += 1;
    }
}

test buildFilter {
    var buf: [max_filter]Filter = undefined;
    const socket = number(.socket);
    // A filter with every promise fits.
    _ = buildFilter(&buf, .full, true);
    const machine = buildFilter(&buf, .initMany(&.{ .stdio, .inet }), false);
    try testing.expectEqual(
        linux.SECCOMP.RET.ALLOW,
        action(machine, native_arch, number(.read), 0),
    );
    try testing.expectEqual(
        linux.SECCOMP.RET.ALLOW,
        action(machine, native_arch, socket, linux.AF.INET),
    );
    try testing.expectEqual(
        linux.SECCOMP.RET.ALLOW,
        action(machine, native_arch, socket, linux.AF.INET6),
    );
    // A family no promise names goes to the listener, even for root.
    const AF_ALG = 38;
    try testing.expectEqual(
        linux.SECCOMP.RET.USER_NOTIF,
        action(machine, native_arch, socket, AF_ALG),
    );
    // Each case is a call, its first three arguments, and whether the seal
    // refuses it.
    const Case = struct { linux.SYS, u32, u32, u32, bool };
    const cloexec = 0o2000000;
    const pid1_cpu = 0xfffffff6; // ~1 << 3 | CPUCLOCK_SCHED: pid 1's CPU clock
    for ([_]Case{
        .{ .socket, linux.AF.ALG, 0, 0, true },
        .{ .socket, linux.AF.INET, 0, 0, false },
        .{ .socketpair, linux.AF.TIPC, 0, 0, true },
        .{ .socketpair, linux.AF.INET, 0, 0, false },
        .{ .setsockopt, 3, SOL_TCP, TCP_ULP, true },
        .{ .setsockopt, 3, SOL_TCP, 1, false }, // TCP_NODELAY
        .{ .setsockopt, 3, 1, TCP_ULP, false }, // SOL_SOCKET's option 31
        .{ .pipe2, 0, O_NOTIFICATION_PIPE | cloexec, 0, true },
        .{ .pipe2, 0, cloexec, 0, false },
        .{ .timer_create, CLOCK_THREAD_CPUTIME_ID, 0, 0, true },
        .{ .timer_create, CLOCK_PROCESS_CPUTIME_ID, 0, 0, true },
        .{ .timer_create, pid1_cpu, 0, 0, true },
        .{ .timer_create, 1, 0, 0, false }, // CLOCK_MONOTONIC
        .{ .clock_nanosleep, CLOCK_PROCESS_CPUTIME_ID, 0, 0, true },
        .{ .clock_nanosleep, 0, 0, 0, false }, // CLOCK_REALTIME
    }) |c| {
        const want: u32 = if (c[4]) linux.SECCOMP.RET.USER_NOTIF else linux.SECCOMP.RET.ALLOW;
        const nr = number(c[0]);
        const args: [6]u32 = .{ c[1], c[2], c[3], 0, 0, 0 };
        try testing.expectEqual(want, actionArgs(machine, native_arch, nr, args));
        // seal-watch's reading of the same call agrees with the filter's.
        try testing.expectEqual(c[4], refusal(nr, .{ c[1], c[2], c[3], 0, 0, 0 }) != null);
    }
    // The call after a refusal block is still judged by its number.
    try testing.expectEqual(
        linux.SECCOMP.RET.ALLOW,
        action(machine, native_arch, number(.read), 0),
    );
    // The machine seal hands the rest to the listener (seal-watch).
    try testing.expectEqual(
        linux.SECCOMP.RET.USER_NOTIF,
        action(machine, native_arch, number(.memfd_create), 0),
    );
    for (never) |sys| try testing.expectEqual(
        linux.SECCOMP.RET.USER_NOTIF,
        action(machine, native_arch, number(sys), 0),
    );
    try testing.expectEqual(
        linux.SECCOMP.RET.KILL_PROCESS,
        action(machine, 0x40000028, 0, 0),
    ); // AUDIT_ARCH_ARM
    try testing.expectEqual(
        linux.SECCOMP.RET.KILL_PROCESS,
        action(machine, 0x40000003, 0, 0),
    ); // AUDIT_ARCH_I386
    if (@import("builtin").cpu.arch == .x86_64)
        try testing.expectEqual(
            linux.SECCOMP.RET.KILL_PROCESS,
            action(machine, native_arch, 0x40000000 | number(.read), 0),
        );

    // A service's filter refuses with ENOSYS and needs no listener.
    const service = buildFilter(&buf, .initMany(&.{ .stdio, .inet }), true);
    try testing.expectEqual(
        linux.SECCOMP.RET.ALLOW,
        action(service, native_arch, socket, linux.AF.INET),
    );
    try testing.expectEqual(
        linux.SECCOMP.RET.ALLOW,
        action(service, native_arch, socket, linux.AF.INET6),
    );
    try testing.expectEqual(RET_ENOSYS, action(service, native_arch, socket, linux.AF.UNIX));
    try testing.expectEqual(
        RET_ENOSYS,
        action(service, native_arch, number(.socketpair), linux.AF.UNIX),
    );
    // socketpair reads the family as socket does: unix where promised,
    // and never a family no promise names (TIPC makes pairs too).
    var unix_buf: [max_filter]Filter = undefined;
    const unix = buildFilter(&unix_buf, .initMany(&.{ .stdio, .unix }), true);
    try testing.expectEqual(
        linux.SECCOMP.RET.ALLOW,
        action(unix, native_arch, number(.socketpair), linux.AF.UNIX),
    );
    try testing.expectEqual(
        RET_ENOSYS,
        action(unix, native_arch, number(.socketpair), linux.AF.TIPC),
    );
    var all_buf: [max_filter]Filter = undefined;
    const all = buildFilter(&all_buf, .initMany(&.{ .stdio, .unix, .inet }), false);
    try testing.expectEqual(
        linux.SECCOMP.RET.USER_NOTIF,
        action(all, native_arch, number(.socketpair), linux.AF.TIPC),
    );
    try testing.expectEqual(
        linux.SECCOMP.RET.ALLOW,
        action(service, native_arch, number(.write), 0),
    );
    try testing.expectEqual(RET_ENOSYS, action(service, native_arch, number(.clone), 0));
    // The risky calls from the findings are refused to a plain reader-and-server.
    for ([_]linux.SYS{
        .memfd_create,
        .shmget,
        .msgget,
        .inotify_add_watch,
        .ptrace,
        .unshare,
    }) |sys|
        try testing.expectEqual(RET_ENOSYS, action(service, native_arch, number(sys), 0));

    // Without exec, only execveat of a descriptor runs a program; that is
    // how leash becomes the service.
    try testing.expectEqual(
        linux.SECCOMP.RET.ALLOW,
        action(service, native_arch, number(.execveat), AT_EMPTY_PATH),
    );
    try testing.expectEqual(RET_ENOSYS, action(service, native_arch, number(.execveat), 0));
    try testing.expectEqual(RET_ENOSYS, action(service, native_arch, number(.execve), 0));
    const exec = buildFilter(&buf, .initMany(&.{ .stdio, .exec }), true);
    try testing.expectEqual(linux.SECCOMP.RET.ALLOW, action(exec, native_arch, number(.execve), 0));
    try testing.expectEqual(
        linux.SECCOMP.RET.ALLOW,
        action(exec, native_arch, number(.execveat), 0),
    );

    // A service's filter leaves the refusals by argument to the machine's.
    try testing.expectEqual(
        linux.SECCOMP.RET.ALLOW,
        actionArgs(service, native_arch, number(.setsockopt), .{ 3, SOL_TCP, TCP_ULP, 0, 0, 0 }),
    );
    // No program here needs splice or tee; the machine needs sendfile.
    try testing.expect(!base.contains(.splice));
    try testing.expect(base.contains(.sendfile));
    try testing.expectEqual(RET_ENOSYS, action(service, native_arch, number(.splice), 0));
    try testing.expectEqual(RET_ENOSYS, action(service, native_arch, number(.sendfile), 0));

    const none = buildFilter(&buf, .initMany(&.{.stdio}), true);
    try testing.expectEqual(RET_ENOSYS, action(none, native_arch, socket, linux.AF.INET));
    try testing.expectEqual(linux.SECCOMP.RET.ALLOW, action(none, native_arch, number(.read), 0));

    // The longest filter, with every promise, fits the kernel's 4096.
    const biggest = buildFilter(&buf, .full, true);
    try testing.expect(biggest.len <= 4096);
    // No never call is ever allowed, even by the fullest filter.
    for (never) |sys| try testing.expectEqual(
        RET_ENOSYS,
        action(biggest, native_arch, number(sys), 0),
    );
}

test calls {
    // No promise brings a never call.
    for (std.enums.values(Promise)) |p| {
        for (calls(p)) |sys| try testing.expect(std.mem.findScalar(linux.SYS, never, sys) == null);
    }
    try testing.expect(std.mem.findScalar(linux.SYS, calls(.memfd), .memfd_create) != null);
}

test promisesOf {
    const socket = number(.socket);
    try testing.expect(promisesOf(socket).contains(.inet));
    try testing.expect(promisesOf(socket).contains(.unix));
    try testing.expect(promisesOf(number(.memfd_create)).contains(.memfd));
    // inotify is `watch`, not `rpath`, so reading files does not bring it.
    const inotify = number(.inotify_add_watch);
    try testing.expect(promisesOf(inotify).contains(.watch));
    try testing.expect(!promisesOf(inotify).contains(.rpath));
    // ptrace belongs to no promise, so nothing can ask for it.
    try testing.expectEqual(@as(usize, 0), promisesOf(number(.ptrace)).count());
    // Every never call belongs to no promise.
    for (never) |sys| try testing.expectEqual(@as(usize, 0), promisesOf(number(sys)).count());
}

test "no promise grants a risky call" {
    // Each call an escape would want is allowed only by one narrow promise,
    // never a broad one.
    const Case = struct { sys: linux.SYS, want: Promise };
    const cases = [_]Case{
        .{ .sys = .memfd_create, .want = .memfd },
        .{ .sys = .execve, .want = .exec },
        .{ .sys = .setuid, .want = .setuid },
        .{ .sys = .setgid, .want = .setgid },
        .{ .sys = .setgroups, .want = .setgroups },
        .{ .sys = .capset, .want = .caps },
        .{ .sys = .chroot, .want = .chroot },
        .{ .sys = .mount, .want = .mount },
        .{ .sys = .umount2, .want = .umount },
        .{ .sys = .unshare, .want = .namespace },
        .{ .sys = .setns, .want = .namespace },
        .{ .sys = .shmget, .want = .ipc },
        .{ .sys = .settimeofday, .want = .settime },
        .{ .sys = .sethostname, .want = .hostname },
        .{ .sys = .inotify_add_watch, .want = .watch },
        .{ .sys = .splice, .want = .splice },
        .{ .sys = .tee, .want = .splice },
        .{ .sys = .sendfile, .want = .sendfile },
    };
    for (cases) |c| {
        const set = promisesOf(number(c.sys));
        var it = set.iterator();
        while (it.next()) |p| try testing.expectEqual(c.want, p);
        try testing.expect(set.contains(c.want));
    }
    // A plain reader-and-server pledge brings none of them.
    const plain: Set = .initMany(&.{ .stdio, .rpath, .inet, .listen });
    inline for (cases) |c| for (calls(c.want)) |sys| if (!plain.contains(c.want)) {
        try testing.expect(!hasCall(plain, number(sys)));
    };
}

/// hasCall reports whether promises allow the call numbered nr.
fn hasCall(promises: Set, nr: u32) bool {
    var it = promises.iterator();
    while (it.next()) |p| for (calls(p)) |sys| if (number(sys) == nr) return true;
    return false;
}

test parse {
    var bad: []const u8 = "";
    const set = try parse("stdio rpath\tinet\n", &bad);
    try testing.expect(set.contains(.inet) and !set.contains(.exec));
    try testing.expectError(error.UnknownPromise, parse("stdio ptrace", &bad));
    try testing.expectEqualStrings("ptrace", bad);
}
