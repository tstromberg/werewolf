//! posture: measure a Linux machine's security posture, and print it as a
//! list of what passed and failed, or as JSON.
//!
//!     posture           check, print, and exit 1 if any check fails
//!     posture --json    the same, as JSON, with why and how each was checked
//!     posture --noop    exit 0 at once: what the run-a-program checks run
//!
//! Each check says what it protects against in plain words, how it was
//! checked, and whether it passed. Where it is safe, a check tests rather
//! than reads: it asks the kernel to undo a one-way setting and expects a
//! refusal, and it copies itself into each writable place and into a memfd
//! and expects the copy not to start. It asks the kernel only when the
//! setting already reads as locked, when the refusal is certain, so a check
//! that fails never weakens the machine. Nothing touches another process or
//! /dev/mem, which would write to the kernel log.
//!
//! Run as root for the whole picture; as another user some checks read what
//! they can and some are skipped. It assumes nothing of werewolf: run it on
//! any Linux to compare. werewolf's own checks (its services, its declared
//! ports, /victim) are skipped where those do not exist.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const linux = std.os.linux;

pub fn main(init: std.process.Init) !void {
    const gpa = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(gpa);
    if (args.len == 2 and std.mem.eql(u8, args[1], "--noop")) return;
    const json = args.len == 2 and std.mem.eql(u8, args[1], "--json");
    if (args.len != 1 and !json) {
        std.debug.print("usage: posture [--json]\n", .{});
        std.process.exit(2);
    }

    var p: Posture = .{ .io = io, .gpa = gpa, .root = linux.geteuid() == 0 };
    try p.run();
    const report = try p.report();
    var out: Io.Writer.Allocating = .init(gpa);
    if (json) {
        try std.json.Stringify.value(report, .{ .whitespace = .indent_2 }, &out.writer);
        try out.writer.writeByte('\n');
    } else try printText(&out.writer, report, columns());
    try Io.File.stdout().writeStreamingAll(io, out.written());
    if (report.summary.fail > 0) std.process.exit(1);
}

/// What posture prints.
pub const Report = struct {
    tool: []const u8 = "posture",
    version: u32 = 1,
    time: []const u8,
    /// The distribution, as /etc/os-release names it.
    os: []const u8,
    host: []const u8,
    kernel: []const u8,
    root: bool,
    summary: struct { pass: usize = 0, fail: usize = 0, skip: usize = 0 },
    checks: []const Check,
};

pub const Check = struct {
    id: []const u8,
    /// kernel, processes, programs, files or network.
    area: []const u8,
    name: []const u8,
    /// What it protects against, in plain words.
    why: []const u8,
    /// How it was checked, exactly.
    how: []const u8,
    result: Result,
    /// What was found, when that adds to the result.
    detail: []const u8 = "",
};

pub const Result = enum {
    pass,
    fail,
    skip,

    fn mark(r: Result) []const u8 {
        return switch (r) {
            .pass => "✅",
            .fail => "❌",
            .skip => "⚠️",
        };
    }
};

const Posture = struct {
    io: Io,
    gpa: Allocator,
    root: bool,
    checks: std.ArrayList(Check) = .empty,

    fn add(p: *Posture, c: Check) !void {
        try p.checks.append(p.gpa, c);
    }

    fn report(p: *Posture) !Report {
        const uts = std.posix.uname();
        const os_release = p.read("/etc/os-release");
        var r: Report = .{
            .time = try rfc3339(p.gpa, nowSecs(p.io)),
            .os = prettyName(if (os_release.len > 0) os_release else p.read("/usr/lib/os-release")),
            .host = try p.gpa.dupe(u8, std.mem.sliceTo(&uts.nodename, 0)),
            .kernel = try p.gpa.dupe(u8, std.mem.sliceTo(&uts.release, 0)),
            .root = p.root,
            .summary = .{},
            .checks = p.checks.items,
        };
        for (p.checks.items) |c| switch (c.result) {
            .pass => r.summary.pass += 1,
            .fail => r.summary.fail += 1,
            .skip => r.summary.skip += 1,
        };
        return r;
    }

    fn run(p: *Posture) !void {
        try p.kernel();
        try p.processes();
        try p.programs();
        try p.files();
        try p.network();
    }

    // --- kernel ------------------------------------------------------------

    fn kernel(p: *Posture) !void {
        const level = lockdownLevel(p.read("/sys/kernel/security/lockdown"));
        const locked = isLocked(level);
        const lowered = locked and p.root and !p.refused("/sys/kernel/security/lockdown", "none");
        try p.add(.{
            .id = "kernel-lockdown",
            .area = "kernel",
            .name = "Kernel lockdown",
            .why = "Root cannot change the running kernel: no /dev/mem, no unsigned code, no hibernation images.",
            .how = if (p.root) "lockdown is integrity or higher, and writing none is refused" else "lockdown is integrity or higher",
            .result = if (locked and !lowered) .pass else .fail,
            .detail = level,
        });
        try p.oneWay("kernel-modules-closed", "Kernel module loading closed", "No new kernel code can be loaded after boot, by anyone.", "kernel/modules_disabled", "1", "0");
        const tainted = std.fmt.parseInt(u64, trim(p.read("/proc/sys/kernel/tainted")), 10) catch std.math.maxInt(u64);
        try p.add(.{
            .id = "kernel-modules-signed",
            .area = "kernel",
            .name = "Only signed kernel modules",
            .why = "Every module in the kernel was signed by whoever built the kernel.",
            .how = "the kernel's unsigned-module taint (bit 13) is clear",
            .result = if (tainted & (1 << 13) == 0) .pass else .fail,
        });
        const kexec_off = std.mem.eql(u8, p.sysctl("kernel/kexec_load_disabled"), "1");
        try p.add(.{
            .id = "kernel-kexec",
            .area = "kernel",
            .name = "No booting another kernel",
            .why = "Root cannot replace the running kernel with kexec.",
            .how = "kernel.kexec_load_disabled is 1, or lockdown (integrity) refuses unsigned kexec",
            .result = if (kexec_off or locked) .pass else .fail,
        });
        try p.oneWay("kernel-ptrace", "No process debugging", "No process can read or change another's memory, root's included.", "kernel/yama/ptrace_scope", "3", "0");
        try p.oneWay("kernel-bpf", "BPF only for root", "Ordinary users cannot load BPF programs into the kernel.", "kernel/unprivileged_bpf_disabled", "1", "0");
        try p.sysctls("kernel-hidden", "kernel", "Kernel addresses and log hidden", "An exploit cannot read kernel addresses or the kernel's log.", &.{ .{ "kernel/kptr_restrict", "2" }, .{ "kernel/dmesg_restrict", "1" } });
        const perf = std.fmt.parseInt(i32, trim(p.sysctl("kernel/perf_event_paranoid")), 10) catch -9;
        try p.add(.{
            .id = "kernel-perf",
            .area = "kernel",
            .name = "Performance events restricted",
            .why = "Ordinary users cannot watch the kernel through performance counters.",
            .how = "kernel.perf_event_paranoid is 2 or more",
            .result = if (perf >= 2) .pass else .fail,
            .detail = trim(p.sysctl("kernel/perf_event_paranoid")),
        });
        try p.sysctls("kernel-userns", "kernel", "No user namespaces", "Removes kernel code that privilege-escalation exploits often start from.", &.{.{ "user/max_user_namespaces", "0" }});
        try p.sysctls("kernel-io-uring", "kernel", "No io_uring", "Removes a large interface that has carried many kernel exploits.", &.{.{ "kernel/io_uring_disabled", "2" }});
        try p.sysctls("kernel-sysrq", "kernel", "No SysRq", "The console's magic keys cannot dump memory or reboot.", &.{.{ "kernel/sysrq", "0" }});
        try p.sysctls("kernel-core-dumps", "kernel", "No core dumps of privileged programs", "A program that changed its privileges leaves no memory dump behind.", &.{.{ "fs/suid_dumpable", "0" }});
    }

    // --- processes ---------------------------------------------------------

    fn processes(p: *Posture) !void {
        const mounts = p.read("/proc/self/mounts");
        try p.add(.{
            .id = "processes-hidden",
            .area = "processes",
            .name = "Processes hidden",
            .why = "A user sees only their own processes, not what else runs.",
            .how = "/proc is mounted hidepid=invisible",
            .result = if (hasOption(mounts, "/proc", "hidepid=invisible") or hasOption(mounts, "/proc", "hidepid=2")) .pass else .fail,
        });
        const setid = try p.findSetid();
        try p.add(.{
            .id = "processes-no-setid",
            .area = "processes",
            .name = "No setuid or setgid programs",
            .why = "No program gains privileges by being run.",
            .how = "no file on the root filesystem has either bit",
            .result = if (setid.len == 0) .pass else .fail,
            .detail = setid,
        });
        // A web server's workers, which face the network, are not root.
        if (p.root) {
            const nginx = try p.workerUids("nginx: worker");
            try p.add(.{
                .id = "processes-workers",
                .area = "processes",
                .name = "Web server workers unprivileged",
                .why = "The processes that answer requests cannot act as root.",
                .how = "every nginx worker runs as a uid other than 0",
                .result = if (nginx.found == 0) .skip else if (nginx.root == 0) .pass else .fail,
                .detail = if (nginx.found == 0) "no nginx running" else "",
            });
        }
    }

    // --- programs ----------------------------------------------------------

    fn programs(p: *Posture) !void {
        try p.absent("programs-no-shell", "No shell", "An intruder finds no shell to run commands with.", &.{ "sh", "ash", "bash", "dash", "zsh", "ksh", "mksh", "fish" });
        try p.absent("programs-no-downloaders", "No download or network tools", "An intruder cannot fetch more tools or open a connection out.", &.{ "wget", "curl", "nc", "ncat", "netcat", "socat", "telnet", "tftp", "ftp", "ftpget", "ftpput", "scp", "sftp", "rsync" });
        try p.absent("programs-no-interpreters", "No script interpreters", "There is nothing to run a script with.", &.{ "awk", "gawk", "mawk", "perl", "python", "python3", "ruby", "node", "lua", "luajit", "php", "tclsh", "expect" });
        try p.absent("programs-no-compilers", "No compilers", "Code cannot be built on the machine.", &.{ "cc", "gcc", "clang", "tcc", "as", "ld", "go", "rustc", "zig" });
        try p.absent("programs-no-module-tools", "No kernel module tools", "Nothing on the system can load, unload or list kernel modules.", &.{ "insmod", "modprobe", "rmmod", "lsmod", "kmod", "depmod" });
        try p.absent("programs-no-network-tools", "No network configuration tools", "An intruder cannot readdress the machine or change its routes with the usual tools.", &.{ "ifconfig", "ip", "route", "iptables", "nft", "tc", "ethtool" });
        try p.absent("programs-no-debuggers", "No debuggers", "Nothing to attach to a process or trace its calls.", &.{ "gdb", "lldb", "strace", "ltrace" });

        // werewolf's services: each started straight from its program.
        var d = Dir.cwd().openDir(p.io, "/etc/sv", .{ .iterate = true }) catch return;
        defer d.close(p.io);
        var scripts: std.ArrayList(u8) = .empty;
        var programs_: usize = 0;
        var names: std.ArrayList([]const u8) = .empty;
        var it = d.iterate();
        while (it.next(p.io) catch null) |e| try names.append(p.gpa, try p.gpa.dupe(u8, e.name));
        std.mem.sort([]const u8, names.items, {}, lessString);
        for (names.items) |name| {
            const path = try std.fmt.allocPrint(p.gpa, "/etc/sv/{s}/run", .{name});
            if (!exists(p.io, path)) continue;
            if (p.isElf(path)) {
                programs_ += 1;
            } else try scripts.print(p.gpa, "{s}{s}", .{ if (scripts.items.len > 0) ", " else "", name });
        }
        try p.add(.{
            .id = "programs-services-no-shell",
            .area = "programs",
            .name = "Services start without a shell",
            .why = "Every service starts straight from its program, with no script between.",
            .how = "each /etc/sv/*/run leads to an ELF program, not a script",
            .result = if (scripts.items.len == 0) .pass else .fail,
            .detail = if (scripts.items.len > 0) try std.fmt.allocPrint(p.gpa, "{d} without; scripts: {s}", .{ programs_, scripts.items }) else "",
        });
    }

    /// None of names is on the system's PATH directories.
    fn absent(p: *Posture, id: []const u8, name: []const u8, why: []const u8, names: []const []const u8) !void {
        var found: std.ArrayList(u8) = .empty;
        var how: std.ArrayList(u8) = .empty;
        try how.appendSlice(p.gpa, "none of ");
        for (names, 0..) |n, i| {
            if (i > 0) try how.appendSlice(p.gpa, ", ");
            try how.appendSlice(p.gpa, n);
            for ([_][]const u8{ "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin" }) |dir| {
                const path = try std.fmt.allocPrint(p.gpa, "{s}/{s}", .{ dir, n });
                if (!exists(p.io, path)) continue;
                try found.print(p.gpa, "{s}{s}", .{ if (found.items.len > 0) ", " else "", path });
                break;
            }
        }
        try how.appendSlice(p.gpa, " in /bin, /sbin, /usr/bin, /usr/sbin or /usr/local");
        try p.add(.{ .id = id, .area = "programs", .name = name, .why = why, .how = how.items, .result = if (found.items.len == 0) .pass else .fail, .detail = found.items });
    }

    // --- files -------------------------------------------------------------

    fn files(p: *Posture) !void {
        const mounts = p.read("/proc/self/mounts");
        try p.add(.{
            .id = "files-root-readonly",
            .area = "files",
            .name = "Read-only root",
            .why = "Nothing can change the running system's programs.",
            .how = "/ is mounted ro",
            .result = if (hasOption(mounts, "/", "ro")) .pass else .fail,
        });
        const nosuid = try missingOption(p.gpa, mounts, "nosuid", &.{});
        try p.add(.{
            .id = "files-nosuid-everywhere",
            .area = "files",
            .name = "setuid ignored everywhere",
            .why = "No filesystem, the root included, honours a setuid or setgid bit.",
            .how = "every mount in /proc/self/mounts is nosuid",
            .result = if (nosuid.len == 0) .pass else .fail,
            .detail = nosuid,
        });
        const noexec = try missingOption(p.gpa, mounts, "noexec", &.{"/"});
        try p.add(.{
            .id = "files-noexec-everywhere",
            .area = "files",
            .name = "Only the system's programs run",
            .why = "Every filesystem but the root refuses to run programs from it.",
            .how = "every mount in /proc/self/mounts but / is noexec",
            .result = if (noexec.len == 0) .pass else .fail,
            .detail = noexec,
        });
        // /dev and /dev/pts hold device nodes, terminals among them.
        const nodev = try missingOption(p.gpa, mounts, "nodev", &.{ "/dev", "/dev/pts" });
        try p.add(.{
            .id = "files-nodev-everywhere",
            .area = "files",
            .name = "Device files only in /dev",
            .why = "A device file made anywhere else is not honoured.",
            .how = "every mount in /proc/self/mounts but /dev and /dev/pts is nodev",
            .result = if (nodev.len == 0) .pass else .fail,
            .detail = nodev,
        });

        // The proof: a program put in each place does not start.
        var ran: std.ArrayList(u8) = .empty;
        var tried: std.ArrayList(u8) = .empty;
        for ([_][]const u8{ "/tmp", "/var/tmp", "/run", "/dev/shm", "/dev/mqueue", "/data" }) |dir| {
            if (!exists(p.io, dir)) continue;
            try tried.print(p.gpa, "{s}{s}", .{ if (tried.items.len > 0) ", " else "", dir });
            if (p.runsFrom(dir)) try ran.print(p.gpa, "{s}{s}", .{ if (ran.items.len > 0) ", " else "", dir });
        }
        try p.add(.{
            .id = "files-exec-refused",
            .area = "files",
            .name = "A program written there does not run",
            .why = "Malware dropped into a temporary or data directory cannot be started.",
            .how = try std.fmt.allocPrint(p.gpa, "a copy of this program, put in each of {s}, fails to start (or cannot be put there)", .{tried.items}),
            .result = if (ran.items.len == 0) .pass else .fail,
            .detail = if (ran.items.len > 0) try std.fmt.allocPrint(p.gpa, "ran from {s}", .{ran.items}) else "",
        });

        const sealed = std.mem.eql(u8, p.sysctl("vm/memfd_noexec"), "2");
        const memfd_ran = p.runsFromMemfd();
        try p.add(.{
            .id = "files-memfd-exec",
            .area = "files",
            .name = "No programs from memory",
            .why = "Code cannot run from an anonymous memory file, the usual way to run malware without writing it to disk.",
            .how = "vm.memfd_noexec is 2, and a copy of this program in a memfd fails to start",
            .result = if (sealed and !memfd_ran) .pass else .fail,
            .detail = if (memfd_ran) "a memfd program ran" else if (!sealed) try std.fmt.allocPrint(p.gpa, "vm.memfd_noexec is {s}", .{p.sysctl("vm/memfd_noexec")}) else "",
        });
        try p.sysctls("files-links", "files", "Link and FIFO tricks blocked", "Symlinks, hard links and FIFOs in shared directories cannot be turned against another user.", &.{
            .{ "fs/protected_symlinks", "1" }, .{ "fs/protected_hardlinks", "1" }, .{ "fs/protected_fifos", "2" }, .{ "fs/protected_regular", "2" },
        });
        if (mountType(mounts, "/victim") != null) try p.add(.{
            .id = "files-victim-readonly",
            .area = "files",
            .name = "Old system read-only",
            .why = "The system this machine replaced stays readable, not writable.",
            .how = "/victim is mounted ro",
            .result = if (hasOption(mounts, "/victim", "ro")) .pass else .fail,
        });
    }

    /// Whether a copy of this program, put in dir, starts. A place it
    /// cannot be put is one it cannot start from.
    fn runsFrom(p: *Posture, dir: []const u8) bool {
        const path = std.fmt.allocPrint(p.gpa, "{s}/.posture-exec-check", .{dir}) catch return true;
        defer Dir.cwd().deleteFile(p.io, path) catch {};
        Dir.cwd().copyFile("/proc/self/exe", Dir.cwd(), path, p.io, .{ .permissions = .fromMode(0o755) }) catch return false;
        return p.starts(path);
    }

    /// Whether a copy of this program in a memfd starts. memfd_create's flags
    /// are none but close-on-exec, as malware's would be.
    fn runsFromMemfd(p: *Posture) bool {
        const rc = linux.memfd_create("posture", linux.MFD.CLOEXEC);
        if (linux.errno(rc) != .SUCCESS) return false;
        const fd: i32 = @intCast(rc);
        defer _ = linux.close(fd);
        const self = Dir.cwd().readFileAlloc(p.io, "/proc/self/exe", p.gpa, .limited(64 << 20)) catch return false;
        var off: usize = 0;
        while (off < self.len) {
            const n = linux.write(fd, self[off..].ptr, self.len - off);
            if (linux.errno(n) != .SUCCESS or n == 0) return false;
            off += n;
        }
        // The child reaches the memfd through this process's fd table.
        const path = std.fmt.allocPrint(p.gpa, "/proc/{d}/fd/{d}", .{ linux.getpid(), fd }) catch return false;
        return p.starts(path);
    }

    /// Whether path starts, run with --noop, and exits 0.
    fn starts(p: *Posture, path: []const u8) bool {
        var child = std.process.spawn(p.io, .{ .argv = &.{ path, "--noop" }, .stdin = .ignore, .stdout = .ignore, .stderr = .ignore }) catch return false;
        const term = child.wait(p.io) catch return false;
        return switch (term) {
            .exited => |code| code == 0,
            else => false,
        };
    }

    // --- network -----------------------------------------------------------

    fn network(p: *Posture) !void {
        var ports: std.ArrayList(u16) = .empty;
        for ([_][]const u8{ "/proc/net/tcp", "/proc/net/tcp6" }) |f| try listenPorts(p.gpa, p.read(f), &ports);
        var list: std.ArrayList(u8) = .empty;
        for (ports.items, 0..) |port, i| try list.print(p.gpa, "{s}{d}", .{ if (i > 0) ", " else "", port });
        // The machine's network policy (fence), or the older list of ports.
        const declared: ?[]const u8 = if (Dir.cwd().readFileAlloc(p.io, "/usr/share/werewolf/net", p.gpa, .limited(64 << 10))) |net|
            try policyPorts(p.gpa, net)
        else |_|
            Dir.cwd().readFileAlloc(p.io, "/etc/werewolf/listen", p.gpa, .limited(64 << 10)) catch null;
        var undeclared: std.ArrayList(u8) = .empty;
        if (declared) |text| for (ports.items) |port| {
            if (!isDeclared(text, port)) try undeclared.print(p.gpa, "{s}{d}", .{ if (undeclared.items.len > 0) ", " else "", port });
        };
        try p.add(.{
            .id = "network-ports",
            .area = "network",
            .name = "Only declared ports open",
            .why = "Nothing listens on the network that the machine is not meant to offer.",
            .how = "listening TCP ports (/proc/net/tcp, tcp6) are those the machine's policy declares (/usr/share/werewolf/net)",
            .result = if (declared == null) .skip else if (undeclared.items.len == 0) .pass else .fail,
            .detail = if (undeclared.items.len > 0)
                try std.fmt.allocPrint(p.gpa, "undeclared: {s}", .{undeclared.items})
            else
                try std.fmt.allocPrint(p.gpa, "listening: {s}", .{if (list.items.len > 0) list.items else "none"}),
        });
        try p.fence();
        try p.absentNamed("network-no-login", "network", "No remote login", "There is no ssh or telnet server to log in through.", &.{ "sshd", "dropbear", "telnetd", "in.telnetd" });
        try p.sysctls("network-no-forwarding", "network", "No routing", "The machine forwards no traffic for others.", &.{ .{ "net/ipv4/ip_forward", "0" }, .{ "net/ipv6/conf/all/forwarding", "0" } });
        try p.sysctls("network-redirects", "network", "ICMP redirects ignored", "Nobody on the network can reroute the machine's traffic.", &.{ .{ "net/ipv4/conf/all/accept_redirects", "0" }, .{ "net/ipv6/conf/all/accept_redirects", "0" } });
        try p.sysctls("network-source-route", "network", "Source routing refused", "Packets cannot choose their own way through the machine.", &.{.{ "net/ipv4/conf/all/accept_source_route", "0" }});
        try p.sysctls("network-syncookies", "network", "SYN flood protection", "A flood of half-open connections cannot exhaust it.", &.{.{ "net/ipv4/tcp_syncookies", "1" }});
    }

    // werewolf's network policy (design/fence.md): only declared ports can be
    // bound, only declared traffic sent, nothing unsolicited received, the
    // metadata server only for those named, IPv6 off. Each protection is
    // tested where a test is safe and quiet (a bind, a UDP connect, which
    // sends nothing, a connect the policy refuses at once), and fails where
    // it is missing, on any Linux.
    fn fence(p: *Posture) !void {
        const policy: []const u8 = Dir.cwd().readFileAlloc(p.io, "/usr/share/werewolf/net", p.gpa, .limited(64 << 10)) catch "";

        const port = unusedPort(policy);
        const bound = probeBind(port);
        try p.add(.{
            .id = "network-bind",
            .area = "network",
            .name = "Undeclared ports cannot be opened",
            .why = "Not even root can start a listener on a port the machine is not meant to offer.",
            .how = try std.fmt.allocPrint(p.gpa, "bind() of a TCP socket to port {d}, which the policy does not declare, is refused with EACCES (Landlock, inherited from PID 1)", .{port}),
            .result = if (bound == .ACCES) .pass else .fail,
            .detail = try std.fmt.allocPrint(p.gpa, "bind: {s}", .{errnoText(bound)}),
        });

        const sent = probeSend();
        try p.add(.{
            .id = "network-outbound",
            .area = "network",
            .name = "Only declared traffic leaves",
            .why = "A program can send nothing its form did not declare: no beacon, no exfiltration, no download.",
            .how = "connect() of a UDP socket to 192.0.2.1 port 9 (an address for documentation, never routed), which looks the route up without sending, is refused with EACCES (policy routing)",
            .result = if (sent == .ACCES) .pass else .fail,
            .detail = try std.fmt.allocPrint(p.gpa, "connect: {s}", .{errnoText(sent)}),
        });

        const md = probeMetadata();
        try p.add(.{
            .id = "network-metadata",
            .area = "network",
            .name = "Cloud metadata server closed",
            .why = "Only the programs named can read the instance's metadata, where its config and any secrets in it are.",
            .how = "a TCP connect() to 169.254.169.254 port 80, for a second at most, is refused with EACCES",
            .result = switch (md) {
                .refused => .pass,
                .reached => .fail,
                // Nothing there and no policy to refuse it: not a cloud.
                .absent => if (policy.len == 0) .skip else .fail,
            },
            .detail = @tagName(md),
        });

        var rules: RuleSummary = .{};
        if (ruleDump(p.gpa)) |dump| rules = summarizeRules(dump) else |_| {}
        try p.add(.{
            .id = "network-inbound",
            .area = "network",
            .name = "Unsolicited traffic dropped",
            .why = "Packets the machine did not ask for and does not serve are dropped unanswered, whatever is listening.",
            .how = "the IPv4 policy-routing rules (RTM_GETRULE) drop arriving traffic with a blackhole rule before any rule delivers it to the local table, and refuse locally sent traffic that no rule allows",
            .result = if (rules.inbound_dropped and rules.outbound_refused) .pass else .fail,
            .detail = try std.fmt.allocPrint(p.gpa, "arriving: {s}; sent: {s}", .{
                if (rules.inbound_dropped) "dropped unless declared" else "delivered",
                if (rules.outbound_refused) "refused unless declared" else "routed",
            }),
        });

        const v6 = std.mem.trim(u8, p.read("/proc/sys/net/ipv6/conf/all/disable_ipv6"), " \n");
        try p.add(.{
            .id = "network-ipv6-off",
            .area = "network",
            .name = "IPv6 off",
            .why = "An interface's IPv6 link-local address is reachable from the network with none of the IPv4 rules.",
            .how = "/proc/sys/net/ipv6/conf/all/disable_ipv6 reads 1, or the kernel has no IPv6",
            .result = if (v6.len == 0 or std.mem.eql(u8, v6, "1")) .pass else .fail,
            .detail = if (v6.len == 0) "no IPv6 in this kernel" else try std.fmt.allocPrint(p.gpa, "disable_ipv6 = {s}", .{v6}),
        });
    }

    fn absentNamed(p: *Posture, id: []const u8, area: []const u8, name: []const u8, why: []const u8, names: []const []const u8) !void {
        try p.absent(id, name, why, names);
        p.checks.items[p.checks.items.len - 1].area = area;
    }

    // --- helpers -------------------------------------------------------------

    /// A setting the kernel lets rise but never fall: it must read locked,
    /// and as root, writing the unlocked value must be refused.
    fn oneWay(p: *Posture, id: []const u8, name: []const u8, why: []const u8, key: []const u8, locked: []const u8, unlocked: []const u8) !void {
        const path = try std.fmt.allocPrint(p.gpa, "/proc/sys/{s}", .{key});
        const value = trim(p.read(path));
        const is_locked = std.mem.eql(u8, value, locked);
        const lowered = is_locked and p.root and !p.refused(path, unlocked);
        try p.add(.{
            .id = id,
            .area = "kernel",
            .name = name,
            .why = why,
            .how = if (p.root)
                try std.fmt.allocPrint(p.gpa, "{s} is {s}, and writing {s} is refused", .{ dotted(p.gpa, key), locked, unlocked })
            else
                try std.fmt.allocPrint(p.gpa, "{s} is {s}", .{ dotted(p.gpa, key), locked }),
            .result = if (is_locked and !lowered) .pass else .fail,
            .detail = if (is_locked) "" else try std.fmt.allocPrint(p.gpa, "{s} is {s}", .{ dotted(p.gpa, key), if (value.len > 0) value else "absent" }),
        });
    }

    /// Settings that must hold these values.
    fn sysctls(p: *Posture, id: []const u8, area: []const u8, name: []const u8, why: []const u8, want: []const [2][]const u8) !void {
        var how: std.ArrayList(u8) = .empty;
        var bad: std.ArrayList(u8) = .empty;
        for (want, 0..) |kv, i| {
            if (i > 0) try how.appendSlice(p.gpa, ", ");
            try how.print(p.gpa, "{s} = {s}", .{ dotted(p.gpa, kv[0]), kv[1] });
            const value = trim(p.sysctl(kv[0]));
            if (!std.mem.eql(u8, value, kv[1])) try bad.print(p.gpa, "{s}{s} is {s}", .{ if (bad.items.len > 0) ", " else "", dotted(p.gpa, kv[0]), if (value.len > 0) value else "absent" });
        }
        try p.add(.{ .id = id, .area = area, .name = name, .why = why, .how = how.items, .result = if (bad.items.len == 0) .pass else .fail, .detail = bad.items });
    }

    /// A setting's value, without its newline.
    fn sysctl(p: *Posture, key: []const u8) []const u8 {
        return trim(p.read(std.fmt.allocPrint(p.gpa, "/proc/sys/{s}", .{key}) catch return ""));
    }

    /// path, read to its end, or "". Not Dir.readFileAlloc, which reads
    /// only as much as stat reports: procfs reports 0.
    fn read(p: *Posture, path: []const u8) []const u8 {
        var f = Dir.cwd().openFile(p.io, path, .{}) catch return "";
        defer f.close(p.io);
        var buf: [4096]u8 = undefined;
        var r = f.readerStreaming(p.io, &buf);
        return r.interface.allocRemaining(p.gpa, .limited(16 << 20)) catch "";
    }

    /// Whether writing value to path fails.
    fn refused(p: *Posture, path: []const u8, value: []const u8) bool {
        Dir.cwd().writeFile(p.io, .{ .sub_path = path, .data = value }) catch return true;
        return false;
    }

    fn isElf(p: *Posture, path: []const u8) bool {
        var f = Dir.cwd().openFile(p.io, path, .{}) catch return false;
        defer f.close(p.io);
        var magic: [4]u8 = undefined;
        const n = f.readPositionalAll(p.io, &magic, 0) catch return false;
        return n == 4 and std.mem.eql(u8, &magic, "\x7fELF");
    }

    /// How many processes have a command line starting with prefix, and how
    /// many of those run as root.
    fn workerUids(p: *Posture, prefix: []const u8) !struct { found: usize, root: usize } {
        var found: usize = 0;
        var root: usize = 0;
        var d = Dir.cwd().openDir(p.io, "/proc", .{ .iterate = true }) catch return .{ .found = 0, .root = 0 };
        defer d.close(p.io);
        var it = d.iterate();
        while (it.next(p.io) catch null) |e| {
            _ = std.fmt.parseInt(u32, e.name, 10) catch continue;
            const cmd = p.read(try std.fmt.allocPrint(p.gpa, "/proc/{s}/cmdline", .{e.name}));
            if (!std.mem.startsWith(u8, cmd, prefix)) continue;
            found += 1;
            const status = p.read(try std.fmt.allocPrint(p.gpa, "/proc/{s}/status", .{e.name}));
            if (uidOf(status) == 0) root += 1;
        }
        return .{ .found = found, .root = root };
    }

    /// Files on the root filesystem with setuid or setgid, as a list. It
    /// does not cross into other filesystems (/proc, /data and the like).
    fn findSetid(p: *Posture) ![]const u8 {
        var found: std.ArrayList(u8) = .empty;
        const root = statx(p.gpa, "/") orelse return "cannot stat /";
        try p.walkSetid("/", root, &found, 0);
        return found.items;
    }

    fn walkSetid(p: *Posture, dir: []const u8, root: linux.Statx, found: *std.ArrayList(u8), depth: usize) !void {
        if (depth > 40) return;
        var d = Dir.cwd().openDir(p.io, dir, .{ .iterate = true }) catch return;
        defer d.close(p.io);
        var it = d.iterate();
        while (it.next(p.io) catch null) |e| {
            const path = try std.fmt.allocPrint(p.gpa, "{s}{s}{s}", .{ dir, if (dir.len > 1) "/" else "", e.name });
            const st = statx(p.gpa, path) orelse continue;
            if (st.dev_major != root.dev_major or st.dev_minor != root.dev_minor) continue;
            const kind = st.mode & linux.S.IFMT;
            if (kind == linux.S.IFDIR) {
                try p.walkSetid(path, root, found, depth + 1);
            } else if (kind == linux.S.IFREG and st.mode & (linux.S.ISUID | linux.S.ISGID) != 0) {
                try found.print(p.gpa, "{s}{s}", .{ if (found.items.len > 0) ", " else "", path });
            }
        }
    }
};

// --- text ----------------------------------------------------------------------

/// The report as people read it: a mark for each check, by area, and what
/// was found where a check did not pass. Details are cut to fit cols, the
/// terminal's width, when there is one.
fn printText(w: *Io.Writer, r: Report, cols: ?usize) !void {
    try w.print("{s}, Linux {s}, on {s} ({s})\n", .{ r.os, r.kernel, r.host, if (r.root) "root" else "not root: some checks are limited" });
    var width: usize = 0;
    for (r.checks) |c| width = @max(width, c.name.len);
    // Two spaces, a mark two columns wide, a space, the name padded to
    // width, two spaces, then the detail.
    const room = if (cols) |n| n -| (width + 7) else std.math.maxInt(usize);
    var area: []const u8 = "";
    for (r.checks) |c| {
        if (!std.mem.eql(u8, c.area, area)) {
            area = c.area;
            try w.print("\n{c}{s}\n", .{ std.ascii.toUpper(area[0]), area[1..] });
        }
        try w.print("  {s} {s}", .{ c.result.mark(), c.name });
        if (c.result != .pass and c.detail.len > 0) {
            const f = fit(c.detail, room);
            try w.splatByteAll(' ', width - c.name.len + 2);
            try w.writeAll(c.detail[0..f.len]);
            if (f.more > 0) try w.print(", +{d} more", .{f.more});
        }
        try w.writeByte('\n');
    }
    try w.print("\n{s} {d} passed   {s} {d} failed   {s} {d} skipped\n", .{
        Result.pass.mark(), r.summary.pass, Result.fail.mark(), r.summary.fail, Result.skip.mark(), r.summary.skip,
    });
}

/// How much of detail, items between ", ", fits in max bytes: whole items,
/// with room left to say how many more there are. The first item is kept
/// even when it alone is too long.
fn fit(detail: []const u8, max: usize) struct { len: usize, more: usize } {
    if (detail.len <= max) return .{ .len = detail.len, .more = 0 };
    const items = std.mem.count(u8, detail, ", ") + 1;
    var len: usize = 0;
    var shown: usize = 0;
    var it = std.mem.splitSequence(u8, detail, ", ");
    while (it.next()) |item| : (shown += 1) {
        const end = if (shown == 0) item.len else len + 2 + item.len;
        if (shown > 0 and end + std.fmt.count(", +{d} more", .{items - shown - 1}) > max) break;
        len = end;
    }
    return .{ .len = len, .more = items - shown };
}

/// stdout's width in columns, or null when it is not a terminal.
fn columns() ?usize {
    var ws: std.posix.winsize = undefined;
    const rc = linux.ioctl(Io.File.stdout().handle, linux.T.IOCGWINSZ, @intFromPtr(&ws));
    if (linux.errno(rc) != .SUCCESS or ws.col == 0) return null;
    return ws.col;
}

// --- pure functions, tested below ----------------------------------------------

/// PRETTY_NAME in an os-release file, unquoted, or "Linux", its default.
fn prettyName(text: []const u8) []const u8 {
    var it = std.mem.tokenizeScalar(u8, text, '\n');
    while (it.next()) |line| {
        if (!std.mem.startsWith(u8, line, "PRETTY_NAME=")) continue;
        const name = std.mem.trim(u8, line["PRETTY_NAME=".len..], "\"' \r");
        if (name.len > 0) return name;
    }
    return "Linux";
}

/// The level in /sys/kernel/security/lockdown: "none [integrity] confidentiality".
fn lockdownLevel(text: []const u8) []const u8 {
    const a = std.mem.indexOfScalar(u8, text, '[') orelse return "unavailable";
    const b = std.mem.indexOfScalarPos(u8, text, a, ']') orelse return "unavailable";
    return text[a + 1 .. b];
}

fn isLocked(level: []const u8) bool {
    return std.mem.eql(u8, level, "integrity") or std.mem.eql(u8, level, "confidentiality");
}

/// Whether the mount at point (the last there, which is the one that shows)
/// has option among its options.
fn hasOption(mounts: []const u8, point: []const u8, option: []const u8) bool {
    var found = false;
    var it = std.mem.tokenizeScalar(u8, mounts, '\n');
    while (it.next()) |line| {
        const m = parseMount(line) orelse continue;
        if (!std.mem.eql(u8, m.dir, point)) continue;
        found = false;
        var o = std.mem.tokenizeScalar(u8, m.opts, ',');
        while (o.next()) |x| found = found or std.mem.eql(u8, x, option);
    }
    return found;
}

fn mountType(mounts: []const u8, point: []const u8) ?[]const u8 {
    var found: ?[]const u8 = null;
    var it = std.mem.tokenizeScalar(u8, mounts, '\n');
    while (it.next()) |line| {
        const m = parseMount(line) orelse continue;
        if (std.mem.eql(u8, m.dir, point)) found = m.kind;
    }
    return found;
}

const Mount = struct { dir: []const u8, kind: []const u8, opts: []const u8 };

fn parseMount(line: []const u8) ?Mount {
    var f = std.mem.tokenizeScalar(u8, line, ' ');
    _ = f.next() orelse return null;
    const dir = f.next() orelse return null;
    const kind = f.next() orelse return null;
    const opts = f.next() orelse return null;
    return .{ .dir = dir, .kind = kind, .opts = opts };
}

/// The mount points, but those in except, whose options lack option, each
/// once.
fn missingOption(gpa: Allocator, mounts: []const u8, option: []const u8, except: []const []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var it = std.mem.tokenizeScalar(u8, mounts, '\n');
    next: while (it.next()) |line| {
        const m = parseMount(line) orelse continue;
        for (except) |e| if (std.mem.eql(u8, m.dir, e)) continue :next;
        if (hasOption(line, m.dir, option)) continue;
        var seen = std.mem.tokenizeAny(u8, out.items, ", ");
        while (seen.next()) |d| if (std.mem.eql(u8, d, m.dir)) continue :next;
        try out.print(gpa, "{s}{s}", .{ if (out.items.len > 0) ", " else "", m.dir });
    }
    return out.items;
}

/// The local ports of listening sockets in /proc/net/tcp or tcp6, each
/// once, in order.
fn listenPorts(gpa: Allocator, text: []const u8, out: *std.ArrayList(u16)) !void {
    var lines = std.mem.tokenizeScalar(u8, text, '\n');
    _ = lines.next(); // the header
    while (lines.next()) |line| {
        var f = std.mem.tokenizeScalar(u8, line, ' ');
        _ = f.next() orelse continue; // sl
        const local = f.next() orelse continue;
        _ = f.next() orelse continue; // remote
        const state = f.next() orelse continue;
        if (!std.mem.eql(u8, state, "0A")) continue; // TCP_LISTEN
        const colon = std.mem.lastIndexOfScalar(u8, local, ':') orelse continue;
        const port = std.fmt.parseInt(u16, local[colon + 1 ..], 16) catch continue;
        if (std.mem.indexOfScalar(u16, out.items, port) == null) try out.append(gpa, port);
    }
    std.mem.sort(u16, out.items, {}, std.sort.asc(u16));
}

/// The ports in a network policy's `listen tcp PORT` lines, one a line.
fn policyPorts(gpa: Allocator, policy: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var it = std.mem.tokenizeScalar(u8, policy, '\n');
    while (it.next()) |line| {
        if (std.mem.startsWith(u8, line, "listen tcp ")) try out.print(gpa, "{s}\n", .{std.mem.trim(u8, line["listen tcp ".len..], " ")});
    }
    return out.items;
}

/// Whether /etc/werewolf/listen declares port: one a line, or 22 for sshd,
/// which the image declares by carrying it.
fn isDeclared(text: []const u8, port: u16) bool {
    var it = std.mem.tokenizeAny(u8, text, " \n");
    while (it.next()) |d| if ((std.fmt.parseInt(u16, d, 10) catch 0) == port) return true;
    return false;
}

/// The real uid on a /proc/PID/status Uid: line.
fn uidOf(status: []const u8) ?u32 {
    var it = std.mem.tokenizeScalar(u8, status, '\n');
    while (it.next()) |line| {
        if (!std.mem.startsWith(u8, line, "Uid:")) continue;
        var f = std.mem.tokenizeAny(u8, line[4..], " \t");
        return std.fmt.parseInt(u32, f.next() orelse return null, 10) catch null;
    }
    return null;
}

/// kernel/yama/ptrace_scope as sysctl names it: kernel.yama.ptrace_scope.
fn dotted(gpa: Allocator, key: []const u8) []const u8 {
    const out = gpa.dupe(u8, key) catch return key;
    std.mem.replaceScalar(u8, out, '/', '.');
    return out;
}

fn trim(s: []const u8) []const u8 {
    return std.mem.trim(u8, s, " \r\n");
}

fn exists(io: Io, path: []const u8) bool {
    Dir.cwd().access(io, path, .{}) catch return false;
    return true;
}

fn statx(gpa: Allocator, path: []const u8) ?linux.Statx {
    const z = std.fmt.allocPrintSentinel(gpa, "{s}", .{path}, 0) catch return null;
    var st: linux.Statx = undefined;
    const rc = linux.statx(linux.AT.FDCWD, z, linux.AT.SYMLINK_NOFOLLOW, .{ .TYPE = true, .MODE = true }, &st);
    if (linux.errno(rc) != .SUCCESS) return null;
    return st;
}

fn lessString(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

fn nowSecs(io: Io) u64 {
    return @intCast(@max(0, @divFloor(Io.Timestamp.now(io, .real).nanoseconds, std.time.ns_per_s)));
}

fn rfc3339(gpa: Allocator, secs: u64) ![]const u8 {
    const es: std.time.epoch.EpochSeconds = .{ .secs = secs };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    return std.fmt.allocPrint(gpa, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        yd.year, md.month.numeric(), md.day_index + 1, ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
    });
}

// --- tests -------------------------------------------------------------------

const testing = std.testing;

// --- fence probes ------------------------------------------------------------

/// A TCP port the policy does not declare, to try binding.
fn unusedPort(policy: []const u8) u16 {
    var port: u16 = 47321;
    while (isDeclared(policy, port)) port += 1;
    return port;
}

fn inet(addr: [4]u8, port: u16) linux.sockaddr.in {
    return .{ .port = std.mem.nativeToBig(u16, port), .addr = @bitCast(addr) };
}

/// bind() of a fresh TCP socket to `port` on every address: its errno. The
/// socket never listens, and is closed.
fn probeBind(port: u16) linux.E {
    const rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return linux.errno(rc);
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    const a = inet(.{ 0, 0, 0, 0 }, port);
    return linux.errno(linux.bind(fd, @ptrCast(&a), @sizeOf(linux.sockaddr.in)));
}

/// connect() of a UDP socket to 192.0.2.1:9: a route lookup, and no packet.
fn probeSend() linux.E {
    const rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return linux.errno(rc);
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    const a = inet(.{ 192, 0, 2, 1 }, 9);
    return linux.errno(linux.connect(fd, @ptrCast(&a), @sizeOf(linux.sockaddr.in)));
}

const Metadata = enum { refused, reached, absent };

/// A TCP connect() to 169.254.169.254:80, given a second: refused by
/// policy, reached (connected, or something answered), or absent.
fn probeMetadata() Metadata {
    const rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK, 0);
    if (linux.errno(rc) != .SUCCESS) return .absent;
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    const a = inet(.{ 169, 254, 169, 254 }, 80);
    switch (linux.errno(linux.connect(fd, @ptrCast(&a), @sizeOf(linux.sockaddr.in)))) {
        .ACCES, .PERM => return .refused,
        .SUCCESS => return .reached,
        .INPROGRESS => {},
        else => return .absent,
    }
    var fds = [1]linux.pollfd{.{ .fd = fd, .events = linux.POLL.OUT, .revents = 0 }};
    if (linux.poll(&fds, 1, 1000) != 1) return .absent;
    var err: i32 = 0;
    var len: linux.socklen_t = @sizeOf(i32);
    _ = linux.getsockopt(fd, linux.SOL.SOCKET, linux.SO.ERROR, @ptrCast(&err), &len);
    return if (err == 0 or err == @backingInt(linux.E.CONNREFUSED)) .reached else .absent;
}

fn errnoText(e: linux.E) []const u8 {
    return if (e == .SUCCESS) "allowed" else std.enums.tagName(linux.E, e) orelse "unknown";
}

/// The IPv4 policy-routing rules, as the kernel lists them: RTM_GETRULE
/// messages, one after another. Listing them needs no privilege.
fn ruleDump(gpa: Allocator) ![]const u8 {
    const rc = linux.socket(linux.AF.NETLINK, linux.SOCK.RAW | linux.SOCK.CLOEXEC, linux.NETLINK.ROUTE);
    if (linux.errno(rc) != .SUCCESS) return error.NoNetlink;
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    var req: [28]u8 = @splat(0);
    std.mem.writeInt(u32, req[0..4], req.len, .little);
    std.mem.writeInt(u16, req[4..6], 34, .little); // RTM_GETRULE
    std.mem.writeInt(u16, req[6..8], 0x301, .little); // NLM_F_REQUEST | NLM_F_DUMP
    std.mem.writeInt(u32, req[8..12], 1, .little);
    req[16] = linux.AF.INET;
    if (linux.errno(linux.sendto(fd, &req, req.len, 0, null, 0)) != .SUCCESS) return error.NoNetlink;
    var out: std.ArrayList(u8) = .empty;
    var buf: [32 << 10]u8 align(4) = undefined;
    while (out.items.len < 1 << 20) {
        var fds = [1]linux.pollfd{.{ .fd = fd, .events = linux.POLL.IN, .revents = 0 }};
        if (linux.poll(&fds, 1, 1000) != 1) return error.NoReply;
        const n = linux.recvfrom(fd, &buf, buf.len, 0, null, null);
        if (linux.errno(n) != .SUCCESS) return error.NoReply;
        try out.appendSlice(gpa, buf[0..n]);
        if (dumpDone(buf[0..n])) return out.items;
    }
    return error.TooLong;
}

/// Whether a batch of netlink messages ends the dump.
fn dumpDone(batch: []const u8) bool {
    var off: usize = 0;
    while (off + 16 <= batch.len) {
        const len = std.mem.readInt(u32, batch[off..][0..4], .little);
        const kind = std.mem.readInt(u16, batch[off + 4 ..][0..2], .little);
        if (kind == 3 or kind == 2) return true; // NLMSG_DONE, NLMSG_ERROR
        if (len < 16) return true;
        off += std.mem.alignForward(usize, len, 4);
    }
    return false;
}

const RuleSummary = struct {
    /// A rule refuses whatever is sent here (from lo) that no earlier rule
    /// allowed: no selector but the interface, action prohibit.
    outbound_refused: bool = false,
    /// A rule drops whatever arrives that no earlier rule allowed, and no
    /// rule without selectors delivers to the local table before it.
    inbound_dropped: bool = false,
};

/// What a dump of policy-routing rules says about traffic in and out.
fn summarizeRules(dump: []const u8) RuleSummary {
    var drop_at: ?u32 = null;
    var local_at: ?u32 = null;
    var out_refused = false;
    var off: usize = 0;
    while (off + 28 <= dump.len) {
        const len = std.mem.readInt(u32, dump[off..][0..4], .little);
        if (len < 16 or off + len > dump.len) break;
        const msg = dump[off .. off + len];
        off += std.mem.alignForward(usize, len, 4);
        if (std.mem.readInt(u16, msg[4..6], .little) != 32 or msg.len < 28) continue; // RTM_NEWRULE
        var table: u32 = msg[16 + 4];
        const action = msg[16 + 7];
        var priority: u32 = 0;
        var from_lo = false;
        var iif = false;
        var selective = false;
        var a: usize = 28;
        while (a + 4 <= msg.len) {
            const alen = std.mem.readInt(u16, msg[a..][0..2], .little);
            if (alen < 4 or a + alen > msg.len) break;
            const kind = std.mem.readInt(u16, msg[a + 2 ..][0..2], .little) & 0x3fff;
            const v = msg[a + 4 .. a + alen];
            switch (kind) {
                6 => if (v.len == 4) {
                    priority = std.mem.readInt(u32, v[0..4], .little);
                },
                15 => if (v.len == 4) {
                    table = std.mem.readInt(u32, v[0..4], .little);
                },
                3 => {
                    iif = true;
                    from_lo = std.mem.eql(u8, std.mem.sliceTo(v, 0), "lo");
                },
                1, 2, 10, 17, 20, 22, 23, 24 => selective = true, // dst, src, fwmark, oif, uid, proto, ports
                else => {},
            }
            a += std.mem.alignForward(usize, alen, 4);
        }
        if (selective) continue;
        if (action == 8 and from_lo) out_refused = true; // FR_ACT_PROHIBIT
        if (iif) continue;
        if (action == 6) drop_at = @min(drop_at orelse priority, priority); // FR_ACT_BLACKHOLE
        if (action == 1 and table == 255) local_at = @min(local_at orelse priority, priority); // to local
    }
    const dropped = if (drop_at) |d| (local_at == null or d < local_at.?) else false;
    return .{ .outbound_refused = out_refused, .inbound_dropped = dropped };
}

test lockdownLevel {
    try testing.expectEqualStrings("integrity", lockdownLevel("none [integrity] confidentiality\n"));
    try testing.expectEqualStrings("unavailable", lockdownLevel(""));
    try testing.expect(isLocked("confidentiality"));
    try testing.expect(!isLocked("none"));
}

const test_mounts =
    \\/dev/root / ext4 rw,relatime 0 0
    \\proc /proc proc rw,nosuid,nodev,noexec,relatime,hidepid=invisible 0 0
    \\dev /dev devtmpfs rw,nosuid,noexec,relatime 0 0
    \\tmpfs /tmp tmpfs rw,nosuid,nodev,noexec 0 0
    \\tmpfs /run tmpfs rw,nosuid,nodev 0 0
    \\/dev/vda1 /victim ext4 ro,nosuid,nodev,noexec 0 0
    \\/dev/vda1 /data ext4 rw,nosuid,nodev,noexec,noatime 0 0
    \\mqueue /dev/mqueue mqueue rw,nosuid,nodev,noexec 0 0
;

test hasOption {
    try testing.expect(hasOption(test_mounts, "/proc", "hidepid=invisible"));
    try testing.expect(hasOption(test_mounts, "/victim", "ro"));
    try testing.expect(!hasOption(test_mounts, "/", "ro"));
    try testing.expect(!hasOption(test_mounts, "/run", "noexec"));
    try testing.expectEqualStrings("ext4", mountType(test_mounts, "/data").?);
    try testing.expectEqual(null, mountType(test_mounts, "/nowhere"));
}

test missingOption {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectEqualStrings("/", try missingOption(a, test_mounts, "nosuid", &.{}));
    try testing.expectEqualStrings("/run", try missingOption(a, test_mounts, "noexec", &.{"/"}));
    try testing.expectEqualStrings("", try missingOption(a, test_mounts, "nodev", &.{ "/", "/dev" }));
}

test listenPorts {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var ports: std.ArrayList(u16) = .empty;
    const tcp =
        \\  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
        \\   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1
        \\   1: 0F05A8C0:0050 0105A8C0:C350 01 00000000:00000000 00:00000000 00000000   200        0 2 1
        \\   2: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 3 1
        \\   3: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4 1
    ;
    try listenPorts(arena.allocator(), tcp, &ports);
    try testing.expectEqualSlices(u16, &.{ 22, 80 }, ports.items);
    try testing.expect(isDeclared("80\n", 80));
    const policy = try policyPorts(arena.allocator(), "listen tcp 22\nlisten tcp 80\nmetadata 68\n");
    try testing.expectEqualStrings("22\n80\n", policy);
    try testing.expect(isDeclared(policy, 80) and !isDeclared(policy, 68));
    try testing.expect(!isDeclared("80\n", 22));
}

test uidOf {
    try testing.expectEqual(200, uidOf("Name:\tnginx\nUid:\t200\t200\t200\t200\nGid:\t200\n").?);
    try testing.expectEqual(null, uidOf("Name:\tx\n"));
}

test dotted {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    try testing.expectEqualStrings("kernel.yama.ptrace_scope", dotted(arena.allocator(), "kernel/yama/ptrace_scope"));
}

/// A netlink rule message for the tests: priority, action, table, and the
/// iif name and selectors given.
fn testRule(buf: []u8, priority: u32, action: u8, table: u8, iif: ?[]const u8, proto: ?u8) []const u8 {
    @memset(buf, 0);
    var n: usize = 28;
    buf[16] = linux.AF.INET;
    buf[16 + 4] = table;
    buf[16 + 7] = action;
    const put = struct {
        fn f(b: []u8, at: *usize, kind: u16, v: []const u8) void {
            std.mem.writeInt(u16, b[at.*..][0..2], @intCast(4 + v.len), .little);
            std.mem.writeInt(u16, b[at.* + 2 ..][0..2], kind, .little);
            @memcpy(b[at.* + 4 ..][0..v.len], v);
            at.* += std.mem.alignForward(usize, 4 + v.len, 4);
        }
    }.f;
    put(buf, &n, 6, std.mem.asBytes(&priority));
    if (iif) |name| put(buf, &n, 3, name);
    if (proto) |pr| put(buf, &n, 22, &.{pr});
    std.mem.writeInt(u32, buf[0..4], @intCast(n), .little);
    std.mem.writeInt(u16, buf[4..6], 32, .little);
    return buf[0..n];
}

test summarizeRules {
    var dump: std.ArrayList(u8) = .empty;
    defer dump.deinit(std.testing.allocator);
    var b: [64]u8 = undefined;
    // The kernel's own rules: local at 0, main, default. Nothing dropped.
    try dump.appendSlice(std.testing.allocator, testRule(&b, 0, 1, 255, null, null));
    try dump.appendSlice(std.testing.allocator, testRule(&b, 32766, 1, 254, null, null));
    try std.testing.expectEqual(RuleSummary{}, summarizeRules(dump.items));

    // fence's: local first only for lo, allowances with selectors, the
    // refusal from lo, the drop, then the local rule moved after it.
    dump.clearRetainingCapacity();
    try dump.appendSlice(std.testing.allocator, testRule(&b, 10, 1, 255, "lo\x00", null));
    try dump.appendSlice(std.testing.allocator, testRule(&b, 200, 1, 254, "lo\x00", 6));
    try dump.appendSlice(std.testing.allocator, testRule(&b, 299, 8, 0, "lo\x00", null));
    try dump.appendSlice(std.testing.allocator, testRule(&b, 300, 1, 255, null, 6));
    try dump.appendSlice(std.testing.allocator, testRule(&b, 399, 6, 0, null, null));
    try dump.appendSlice(std.testing.allocator, testRule(&b, 400, 1, 255, null, null));
    try std.testing.expectEqual(RuleSummary{ .outbound_refused = true, .inbound_dropped = true }, summarizeRules(dump.items));

    // A drop that comes after delivery to the local table drops nothing.
    var late: std.ArrayList(u8) = .empty;
    defer late.deinit(std.testing.allocator);
    try late.appendSlice(std.testing.allocator, testRule(&b, 0, 1, 255, null, null));
    try late.appendSlice(std.testing.allocator, testRule(&b, 399, 6, 0, null, null));
    try std.testing.expect(!summarizeRules(late.items).inbound_dropped);

    // Truncated input is not trusted past its end.
    try std.testing.expectEqual(RuleSummary{}, summarizeRules(dump.items[0..20]));
}

test unusedPort {
    try std.testing.expectEqual(47321, unusedPort(""));
    try std.testing.expectEqual(47322, unusedPort("listen tcp 47321\n"));
}

test printText {
    const checks = [_]Check{
        .{ .id = "a", .area = "kernel", .name = "Kernel lockdown", .why = "", .how = "", .result = .pass, .detail = "integrity" },
        .{ .id = "b", .area = "kernel", .name = "No SysRq", .why = "", .how = "", .result = .fail, .detail = "kernel.sysrq is 176" },
        .{ .id = "c", .area = "processes", .name = "No setuid or setgid programs", .why = "", .how = "", .result = .fail, .detail = "/usr/bin/su, /usr/bin/sudo, /usr/bin/passwd, /usr/bin/mount" },
        .{ .id = "d", .area = "network", .name = "Only declared ports open", .why = "", .how = "", .result = .skip, .detail = "listening: 22" },
    };
    const r: Report = .{ .time = "", .os = "Wolfi", .host = "h", .kernel = "6.12.1", .root = true, .summary = .{ .pass = 1, .fail = 2, .skip = 1 }, .checks = &checks };
    var out: Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try printText(&out.writer, r, 60);
    try testing.expectEqualStrings(
        \\Wolfi, Linux 6.12.1, on h (root)
        \\
        \\Kernel
        \\  ✅ Kernel lockdown
        \\  ❌ No SysRq                      kernel.sysrq is 176
        \\
        \\Processes
        \\  ❌ No setuid or setgid programs  /usr/bin/su, +3 more
        \\
        \\Network
        \\  ⚠️ Only declared ports open      listening: 22
        \\
        \\✅ 1 passed   ❌ 2 failed   ⚠️ 1 skipped
        \\
    , out.written());

    // Not a terminal: nothing is cut.
    out.clearRetainingCapacity();
    try printText(&out.writer, r, null);
    try testing.expect(std.mem.indexOf(u8, out.written(), "/usr/bin/passwd, /usr/bin/mount\n") != null);
}

test fit {
    const list = "/usr/bin/su, /usr/bin/sudo, /usr/bin/passwd";
    try testing.expectEqual(list.len, fit(list, list.len).len);
    try testing.expectEqual(0, fit(list, list.len).more);
    // "/usr/bin/su, /usr/bin/sudo, +1 more" is 35 bytes.
    try testing.expectEqualStrings("/usr/bin/su, /usr/bin/sudo", list[0..fit(list, 35).len]);
    try testing.expectEqual(1, fit(list, 35).more);
    try testing.expectEqualStrings("/usr/bin/su", list[0..fit(list, 34).len]);
    try testing.expectEqual(2, fit(list, 34).more);
    // The first item stays, however little room.
    try testing.expectEqual(11, fit(list, 0).len);
    try testing.expectEqual(2, fit(list, 0).more);
    try testing.expectEqual(13, fit("ran from /tmp", 3).len);
    try testing.expectEqual(0, fit("ran from /tmp", 3).more);
}

test prettyName {
    try testing.expectEqualStrings("Ubuntu 24.04.1 LTS", prettyName("NAME=\"Ubuntu\"\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nID=ubuntu\n"));
    try testing.expectEqualStrings("Wolfi", prettyName("ID=wolfi\nPRETTY_NAME=Wolfi\n"));
    try testing.expectEqualStrings("Linux", prettyName("PRETTY_NAME=\"\"\n"));
    try testing.expectEqualStrings("Linux", prettyName(""));
}
