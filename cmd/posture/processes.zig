//! processes holds posture's process and program checks: hidden processes,
//! leashed services, and the absence of tools an intruder would want.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const linux = std.os.linux;
const testing = std.testing;

const service = @import("service");
const posture = @import("posture.zig");
const files = @import("files.zig");
const Posture = posture.Posture;
const exists = posture.exists;
const hasOption = posture.hasOption;
const lessString = posture.lessString;
const listAdd = posture.listAdd;
const statusField = posture.statusField;
const trim = posture.trim;
const uidOf = posture.uidOf;

pub fn check(p: *Posture) !void {
    if (p.werewolf) try updates(p);
    const mounts = p.read("/proc/self/mounts");
    try p.add(.{
        .id = "processes-hidden",
        .area = "processes",
        .name = "Processes hidden",
        .why = "A user sees only their own processes, not what else runs.",
        .how = "/proc is mounted hidepid=invisible",
        .expected = "options contain hidepid=invisible or hidepid=2",
        .observed = posture.mountOptions(mounts, "/proc") orelse "mount not found",
        .result = if (hasOption(mounts, "/proc", "hidepid=invisible") or
            hasOption(mounts, "/proc", "hidepid=2"))
            .pass
        else
            .fail,
    });
    const setid = try files.findSetid(p);
    try p.add(.{
        .id = "processes-no-setid",
        .area = "processes",
        .name = "No setuid or setgid programs",
        .why = "No program gains privileges by being run.",
        .how = "no file on the root filesystem has either bit",
        .result = if (setid.len == 0) .pass else .fail,
        .detail = setid,
    });
    // Web server workers face the network, so they must not be root.
    if (p.root) {
        const nginx = try workerUids(p, "nginx: worker");
        try p.add(.{
            .id = "processes-workers",
            .area = "processes",
            .name = "Web server workers unprivileged",
            .why = "The processes that answer requests cannot act as root.",
            .how = "every nginx worker runs as a uid other than 0",
            .result = if (nginx.found == 0) .skip else if (nginx.root == 0) .pass else .fail,
            .detail = if (nginx.found == 0) "no nginx running" else "",
        });
        const console = try consoleShell(p) orelse
            if (askedShell(p.read("/proc/cmdline"))) |w|
                try p.gpa.print("{s} asks for one", .{w})
            else
                null;
        try p.add(.{
            .id = "processes-no-root-console",
            .area = "processes",
            .name = "No root shell without a password",
            .why = "Whoever reaches the console, a host's serial log or a cloud's console " ++
                "viewer, would be root.",
            .how = "no root shell runs on a console or serial line but by a password login, " ++
                "and the kernel command line asks for none",
            .result = if (console == null) .pass else .fail,
            .detail = console orelse "",
        });
        if (p.werewolf) {
            try servicesLeashed(p);
            try serviceDirs(p);
            try imageRoots(p);
        }
    }
}

fn updates(p: *Posture) !void {
    const werewolf_image = exists(p.io, "/usr/share/werewolf/form");
    const held_marker = exists(p.io, "/data/svc/autoupdate/held");
    try p.add(.{
        .id = "update-held",
        .area = "processes",
        .name = "Updates resolve",
        .why = "An unsolvable package pin must not silently hold the last image forever.",
        .how = "the last update resolution left no held marker",
        .observed = try p.gpa.print(
            "werewolf image={s}; held marker={s}",
            .{
                if (werewolf_image) "present" else "absent",
                if (held_marker) "present" else "absent",
            },
        ),
        .result = if (!p.root or !werewolf_image)
            .skip
        else if (held_marker)
            .fail
        else
            .pass,
        .detail = if (p.root) p.read("/data/svc/autoupdate/held") else "",
    });
    const update_run = exists(p.io, "/etc/sv/autoupdate/run");
    const update_service = exists(p.io, "/etc/sv/autoupdate/service");
    const update_down = exists(p.io, "/etc/sv/autoupdate/down");
    try p.add(.{
        .id = "updates-enabled",
        .area = "processes",
        .name = "Automatic updates enabled",
        .why = "Security fixes reach the machine without an operator rebuilding it.",
        .how = "werewolf's autoupdate service is present and not marked down",
        .observed = try p.gpa.print("werewolf image={s}; run={s}; service={s}; down={s}", .{
            if (werewolf_image) "present" else "absent", if (update_run) "present" else "absent",
            if (update_service) "present" else "absent", if (update_down) "present" else "absent",
        }),
        .result = if (!werewolf_image)
            .skip
        else if ((update_run or update_service) and !update_down)
            .pass
        else
            .fail,
    });
}

/// serviceDirs checks that each service's directories, /run/svc/NAME and
/// /data/svc/NAME, remain private or have the mode its share line asks for.
fn serviceDirs(p: *Posture) !void {
    var names: std.ArrayList([]const u8) = .empty;
    if (Dir.cwd().openDir(p.io, "/etc/sv", .{ .iterate = true })) |d| {
        var dir = d;
        defer dir.close(p.io);
        var it = dir.iterate();
        while (try it.next(p.io)) |e| try names.append(p.gpa, try p.gpa.dupe(u8, e.name));
    } else |_| {}
    std.mem.sort([]const u8, names.items, {}, lessString);
    var bad: std.ArrayList(u8) = .empty;
    var checked: usize = 0;
    for (names.items) |name| {
        const text = p.read(try p.gpa.print("/etc/sv/{s}/service", .{name}));
        if (text.len == 0) continue;
        const want = shareMode(text);
        for ([_][]const u8{ "/run/svc", "/data/svc" }) |parent| {
            const path = try p.gpa.print("{s}/{s}", .{ parent, name });
            const st = posture.statx(p.gpa, path) orelse continue; // not started yet
            checked += 1;
            const mode = st.mode & 0o7777;
            if (!serviceModeSafe(want, mode))
                try listAdd(p.gpa, &bad, "{s} is {o}", .{ path, mode });
        }
    }
    try p.add(.{
        .id = "processes-service-dirs",
        .area = "processes",
        .name = "Services' directories are their own",
        .why = "A service cannot look inside another's directories, or reach its sockets, " ++
            "unless that service shares them.",
        .how = "for each /etc/sv/NAME/service, /run/svc/NAME and /data/svc/NAME are 0700, " ++
            "or 0711 (share shared), 0755 (share browseable) or 02771 (share group) " ++
            "as its file says",
        .result = if (checked == 0) .skip else if (bad.items.len == 0) .pass else .fail,
        .detail = if (checked == 0)
            "no service directory"
        else if (bad.items.len > 0)
            bad.items
        else
            try p.gpa.print("{d} directories", .{checked}),
    });
}

// Init keeps directories private until leash applies a service's sharing mode.
// A service parked for missing configuration has not reached that step.
fn serviceModeSafe(want: ?u32, mode: u32) bool {
    const declared = want orelse return false;
    return mode == 0o700 or mode == declared;
}

test "service directories may stay private but cannot broaden sharing" {
    try testing.expect(serviceModeSafe(0o2771, 0o700));
    try testing.expect(serviceModeSafe(0o2771, 0o2771));
    try testing.expect(!serviceModeSafe(0o700, 0o777));
    try testing.expect(!serviceModeSafe(0o711, 0o755));
    try testing.expect(!serviceModeSafe(0o2771, 0o2775));
    try testing.expect(!serviceModeSafe(null, 0o700));
}

/// shareMode returns the mode a service file's first share line asks for:
/// 0700 when there is none, null when its word is not one leash accepts.
fn shareMode(text: []const u8) ?u32 {
    var lines = std.mem.tokenizeScalar(u8, text, '\n');
    while (lines.next()) |line| {
        var words = std.mem.tokenizeAny(u8, line, " \t\r");
        if (!std.mem.eql(u8, words.next() orelse continue, "share")) continue;
        const word = words.next() orelse return null;
        if (std.mem.eql(u8, word, "strict")) return 0o700;
        if (std.mem.eql(u8, word, "shared")) return 0o711;
        if (std.mem.eql(u8, word, "browseable")) return 0o755;
        if (std.mem.eql(u8, word, "group")) return 0o2771;
        return null;
    }
    return 0o700;
}

/// imageRoots checks that each service with a `root` (a baked-in OCI image,
/// docs/design/implemented/adhoc.md) runs inside it, and that its writable binds are
/// noexec and nodev.
fn imageRoots(p: *Posture) !void {
    const mounts = p.read("/proc/self/mounts");
    var names: std.ArrayList([]const u8) = .empty;
    if (Dir.cwd().openDir(p.io, "/etc/sv", .{ .iterate = true })) |d| {
        var dir = d;
        defer dir.close(p.io);
        var it = dir.iterate();
        while (try it.next(p.io)) |e| try names.append(p.gpa, try p.gpa.dupe(u8, e.name));
    } else |_| {}
    std.mem.sort([]const u8, names.items, {}, lessString);
    var bad: std.ArrayList(u8) = .empty;
    var rooted: usize = 0;
    var running: usize = 0;
    for (names.items) |name| {
        const text = p.read(try p.gpa.print("/etc/sv/{s}/service", .{name}));
        var root: []const u8 = "";
        var lines = std.mem.tokenizeScalar(u8, text, '\n');
        while (lines.next()) |line| {
            var words = std.mem.tokenizeAny(u8, line, " \t");
            if (std.mem.eql(
                u8,
                words.next() orelse continue,
                "root",
            )) root = words.next() orelse "";
        }
        if (root.len == 0) continue;
        rooted += 1;
        for ([_][]const u8{ "tmp", "run", "data" }) |sub| {
            const at = try p.gpa.print("{s}/{s}", .{ root, sub });
            if (!hasOption(mounts, at, "noexec") or !hasOption(mounts, at, "nodev"))
                try listAdd(p.gpa, &bad, "{s}: {s} not a noexec, nodev bind", .{ name, at });
        }
        const pid = trim(p.read(try p.gpa.print("/etc/sv/{s}/supervise/pid", .{name})));
        if (pid.len == 0) continue; // down or parked
        var buf: [4096]u8 = undefined;
        const n = Dir.cwd().readLink(
            p.io,
            try p.gpa.print("/proc/{s}/root", .{pid}),
            &buf,
        ) catch continue;
        running += 1;
        if (!std.mem.eql(u8, buf[0..n], root))
            try listAdd(p.gpa, &bad, "{s}: runs in {s}, not {s}", .{ name, buf[0..n], root });
    }
    try p.add(.{
        .id = "processes-image-roots",
        .area = "processes",
        .name = "Images run inside their roots",
        .why = "A baked-in image's program sees its image alone, and may write only beneath " ++
            "binds that run nothing.",
        .how = "for each /etc/sv/NAME/service with a root line, /proc/PID/root is that root, " ++
            "and its tmp, run and data are mounts with noexec and nodev",
        .result = if (rooted == 0) .skip else if (bad.items.len == 0) .pass else .fail,
        .detail = if (rooted == 0)
            "no service with a root"
        else if (bad.items.len > 0)
            bad.items
        else
            try p.gpa.print("{d} rooted, {d} running", .{ rooted, running }),
    });
}

/// servicesLeashed checks that each service with an /etc/sv/NAME/service
/// file still runs as leash left it.
fn servicesLeashed(p: *Posture) !void {
    var names: std.ArrayList([]const u8) = .empty;
    if (Dir.cwd().openDir(p.io, "/etc/sv", .{ .iterate = true })) |d| {
        var dir = d;
        defer dir.close(p.io);
        var it = dir.iterate();
        while (try it.next(p.io)) |e| {
            if (exists(p.io, try p.gpa.print("/etc/sv/{s}/service", .{e.name})))
                try names.append(p.gpa, try p.gpa.dupe(u8, e.name));
        }
    } else |_| {}
    std.mem.sort([]const u8, names.items, {}, lessString);
    var bad: std.ArrayList(u8) = .empty;
    var running: usize = 0;
    for (names.items) |name| {
        const pid = trim(p.read(try p.gpa.print("/etc/sv/{s}/supervise/pid", .{name})));
        if (pid.len == 0) continue; // down, or parked
        const status = p.read(try p.gpa.print("/proc/{s}/status", .{pid}));
        if (status.len == 0) continue;
        running += 1;
        // A file that does not parse keeps nothing but the low-port bit,
        // so a capability it cannot name still fails.
        const text = p.read(try p.gpa.print("/etc/sv/{s}/service", .{name}));
        var bad_file: service.Bad = .{};
        const named: u32 = if (service.parse(p.gpa, text, &bad_file)) |parsed|
            parsed.caps
        else |_|
            0;
        const login = named & service.cap.login != 0 and
            (std.mem.eql(u8, name, "sshd") or (p.dev and std.mem.eql(u8, name, "sshd-dev")));
        const allowed: u64 = if (login)
            if (p.dev and std.mem.eql(u8, name, "sshd-dev"))
                service.cap.developer_login_set
            else
                service.cap.login_set
        else
            (1 << linux.CAP.NET_BIND_SERVICE) | @as(u64, named & ~service.cap.login);
        if (whyNotLeashed(
            status,
            allowed,
            login,
        )) |why| try listAdd(p.gpa, &bad, "{s} {s}", .{ name, why });
    }
    try p.add(.{
        .id = "processes-services-leashed",
        .area = "processes",
        .name = "Services others wrote run leashed",
        .why = "Programs werewolf did not write, nginx and PostgreSQL among them, run as " ++
            "users of their own, with no capability but binding a low port or the packet " ++
            "capabilities their service file names, can gain none, and make no file " ++
            "another user may write.",
        .how = "for each service with an /etc/sv/NAME/service file, its /proc/PID/status: " ++
            "no uid 0, no capability in any set but CAP_NET_BIND_SERVICE, or CAP_NET_RAW and " ++
            "CAP_NET_ADMIN when that file names them, NoNewPrivs 1, and a Umask with group " ++
            "and other write cleared (022 or tighter)",
        .result = if (running == 0) .skip else if (bad.items.len == 0) .pass else .fail,
        .detail = if (running == 0) "no leashed service running" else bad.items,
    });
}

pub fn programs(p: *Posture) !void {
    try p.absent(
        "programs-no-shell",
        "programs",
        "No shell",
        "An intruder finds no shell to run commands with.",
        &.{ "sh", "ash", "bash", "dash", "zsh", "ksh", "mksh", "fish" },
    );
    try p.absent(
        "programs-no-downloaders",
        "programs",
        "No download or network tools",
        "An intruder cannot fetch more tools or open a connection out.",
        &.{
            "wget",
            "curl",
            "nc",
            "ncat",
            "netcat",
            "socat",
            "telnet",
            "tftp",
            "ftp",
            "ftpget",
            "ftpput",
            "scp",
            "sftp",
            "rsync",
        },
    );
    // awk is a text filter, not a general interpreter, and does not count.
    try p.absent(
        "programs-no-interpreters",
        "programs",
        "No script interpreters",
        "There is nothing to run a script with.",
        &.{
            "perl",
            "python",
            "python3",
            "ruby",
            "node",
            "lua",
            "luajit",
            "php",
            "php-fpm",
            "java",
            "dotnet",
            "tclsh",
            "expect",
        },
    );
    try p.absent(
        "programs-no-compilers",
        "programs",
        "No compilers",
        "Code cannot be built on the machine.",
        &.{ "cc", "gcc", "clang", "tcc", "as", "ld", "go", "rustc", "zig" },
    );
    try p.absent(
        "programs-no-module-tools",
        "programs",
        "No kernel module tools",
        "Nothing on the system can load, unload or list kernel modules.",
        &.{ "insmod", "modprobe", "rmmod", "lsmod", "kmod", "depmod" },
    );
    try p.absent(
        "programs-no-network-tools",
        "programs",
        "No network configuration tools",
        "An intruder cannot readdress the machine or change its routes with the usual tools.",
        &.{ "ifconfig", "ip", "route", "iptables", "nft", "tc", "ethtool" },
    );
    try p.absent(
        "programs-no-debuggers",
        "programs",
        "No debuggers",
        "Nothing to attach to a process or trace its calls.",
        &.{ "gdb", "lldb", "strace", "ltrace" },
    );

    if (!p.werewolf) return;
    // Each image service must start straight from an ELF program.
    var d = Dir.cwd().openDir(p.io, "/etc/sv", .{ .iterate = true }) catch return;
    defer d.close(p.io);
    var scripts: std.ArrayList(u8) = .empty;
    var programs_: usize = 0;
    var names: std.ArrayList([]const u8) = .empty;
    var it = d.iterate();
    while (it.next(p.io) catch null) |e| try names.append(p.gpa, try p.gpa.dupe(u8, e.name));
    std.mem.sort([]const u8, names.items, {}, lessString);
    for (names.items) |name| {
        const path = try p.gpa.print("/etc/sv/{s}/run", .{name});
        if (!exists(p.io, path)) continue;
        if (p.isElf(path)) {
            programs_ += 1;
        } else try listAdd(p.gpa, &scripts, "{s}", .{name});
    }
    try p.add(.{
        .id = "programs-services-no-shell",
        .area = "programs",
        .name = "Services start without a shell",
        .why = "Every service starts straight from its program, with no script between.",
        .how = "each /etc/sv/*/run leads to an ELF program, not a script",
        .result = if (scripts.items.len == 0) .pass else .fail,
        .detail = if (scripts.items.len > 0)
            try p.gpa.print("{d} without; scripts: {s}", .{ programs_, scripts.items })
        else
            "",
    });
}

/// workerUids counts processes whose command line starts with prefix, and
/// how many of those run as root.
fn workerUids(p: *Posture, prefix: []const u8) !struct { found: usize, root: usize } {
    var found: usize = 0;
    var root: usize = 0;
    var d = Dir.cwd().openDir(
        p.io,
        "/proc",
        .{ .iterate = true },
    ) catch return .{ .found = 0, .root = 0 };
    defer d.close(p.io);
    var it = d.iterate();
    while (it.next(p.io) catch null) |e| {
        _ = std.fmt.parseInt(u32, e.name, 10) catch continue;
        const cmd = p.read(try p.gpa.print("/proc/{s}/cmdline", .{e.name}));
        if (!std.mem.startsWith(u8, cmd, prefix)) continue;
        found += 1;
        const status = p.read(try p.gpa.print("/proc/{s}/status", .{e.name}));
        if (uidOf(status) == 0) root += 1;
    }
    return .{ .found = found, .root = root };
}

/// shells are the commands a root console runs: werewolf's debug shell
/// (getty -n -l /bin/ash), systemd's (bash on tty9), an inittab's sh.
const shells = [_][]const u8{ "sh", "ash", "bash", "dash", "zsh", "ksh", "mksh", "yash", "fish" };

fn isShell(name: []const u8) bool {
    for (shells) |s| if (std.mem.eql(u8, name, s)) return true;
    return false;
}

/// consoleShell returns "SHELL on TTY" for a root shell whose terminal is a
/// console or serial line, not a pseudo-terminal as ssh's are, unless a
/// password login started it; or null. It reads only /proc and /sys, so it
/// holds on any Linux.
fn consoleShell(p: *Posture) !?[]const u8 {
    var d = Dir.cwd().openDir(p.io, "/proc", .{ .iterate = true }) catch return null;
    defer d.close(p.io);
    var it = d.iterate();
    while (it.next(p.io) catch null) |e| {
        _ = std.fmt.parseInt(u32, e.name, 10) catch continue;
        const s = procStat(p.read(try p.gpa.print("/proc/{s}/stat", .{e.name}))) orelse continue;
        const major = (s.tty >> 8) & 0xfff;
        // 136 to 143 are pseudo-terminals' (Documentation/admin-guide/devices.txt).
        if (!isShell(s.comm) or s.tty == 0 or (major >= 136 and major <= 143)) continue;
        if (uidOf(p.read(try p.gpa.print("/proc/{s}/status", .{e.name}))) != 0) continue;
        if (passwordLogin(p.read(try p.gpa.print("/proc/{d}/cmdline", .{s.ppid})))) continue;
        const minor = (s.tty & 0xff) | ((s.tty >> 12) & 0xfff00);
        const uevent = p.read(try p.gpa.print("/sys/dev/char/{d}:{d}/uevent", .{ major, minor }));
        var lines = std.mem.splitScalar(u8, uevent, '\n');
        const tty = while (lines.next()) |l| {
            if (std.mem.cutPrefix(u8, l, "DEVNAME=")) |n| break n;
        } else try p.gpa.print("tty {d}:{d}", .{ major, minor });
        return try p.gpa.print("{s} on {s}", .{ s.comm, tty });
    }
    return null;
}

const Stat = struct { comm: []const u8, ppid: u32, tty: u32 };

/// procStat reads a /proc/PID/stat line: the command, which lies between the
/// first ( and the last ), the parent, and the controlling terminal.
fn procStat(text: []const u8) ?Stat {
    const open = std.mem.findScalar(u8, text, '(') orelse return null;
    const close = std.mem.findScalarLast(u8, text, ')') orelse return null;
    if (close < open) return null;
    var f = std.mem.tokenizeScalar(u8, text[close + 1 ..], ' ');
    _ = f.next() orelse return null; // state
    const ppid = std.fmt.parseInt(u32, f.next() orelse return null, 10) catch return null;
    _ = f.next() orelse return null; // process group
    _ = f.next() orelse return null; // session
    const tty = std.fmt.parseInt(i32, f.next() orelse return null, 10) catch return null;
    return .{ .comm = text[open + 1 .. close], .ppid = ppid, .tty = @bitCast(tty) };
}

/// passwordLogin reports whether cmdline, a /proc/PID/cmdline, is a login
/// that asked a password: login, but not login -f, which autologin runs.
fn passwordLogin(cmdline: []const u8) bool {
    var args = std.mem.splitScalar(u8, std.mem.trimEnd(u8, cmdline, "\x00"), 0);
    if (!std.mem.eql(u8, std.fs.path.basename(args.first()), "login")) return false;
    while (args.next()) |a| {
        if (a.len > 1 and a[0] == '-' and a[1] != '-' and std.mem.findScalar(u8, a, 'f') != null)
            return false;
    }
    return true;
}

/// askedShell returns the word of the kernel command line that gives root a
/// console shell without a password, or null.
fn askedShell(cmdline: []const u8) ?[]const u8 {
    var words = std.mem.tokenizeAny(u8, cmdline, " \t\n");
    while (words.next()) |w| {
        const name = w[0 .. std.mem.findScalar(u8, w, '=') orelse w.len];
        const value = if (name.len < w.len) w[name.len + 1 ..] else "";
        const off = std.mem.eql(u8, value, "0") or std.mem.eql(u8, value, "no") or
            std.mem.eql(u8, value, "false");
        const asks = ((std.mem.eql(u8, name, "systemd.debug_shell") or
            std.mem.eql(u8, name, "rd.shell")) and !off) or
            std.mem.eql(u8, name, "rd.break") or
            (std.mem.eql(u8, name, "init") and isShell(std.fs.path.basename(value)));
        if (asks) return w;
    }
    return null;
}

test procStat {
    const s = procStat("412 (a) b) S 1 412 412 1088 412 4194560 0").?;
    try testing.expectEqualStrings("a) b", s.comm);
    try testing.expectEqual(1, s.ppid);
    try testing.expectEqual(1088, s.tty); // 4:64, ttyS0
    try testing.expectEqual(null, procStat("412 sh S 1"));
    try testing.expectEqual(null, procStat("412 (sh) S"));
}

test passwordLogin {
    try testing.expect(passwordLogin("/bin/login\x00--\x00root\x00"));
    try testing.expect(passwordLogin("login\x00-p\x00-h\x00host\x00"));
    try testing.expect(!passwordLogin("/bin/login\x00-f\x00root\x00"));
    try testing.expect(!passwordLogin("login\x00-pf\x00root\x00"));
    try testing.expect(!passwordLogin("/usr/bin/getty\x00-n\x00-l\x00/bin/ash\x00"));
    try testing.expect(!passwordLogin(""));
}

test askedShell {
    // werewolf.debug=1 asks for none: no image has a console shell to give.
    try testing.expectEqual(null, askedShell("console=ttyAMA0 werewolf.debug=1 quiet"));
    try testing.expectEqualStrings(
        "systemd.debug_shell",
        askedShell("systemd.debug_shell").?,
    );
    try testing.expectEqualStrings("init=/bin/sh", askedShell("ro init=/bin/sh").?);
    for ([_][]const u8{
        "systemd.debug_shell=0 rd.shell=no",
        "init=/sbin/init single",
        "quiet splash",
    }) |line| try testing.expectEqual(null, askedShell(line));
}

/// whyNotLeashed says why a /proc/PID/status does not look leashed, or null.
/// allowed is CAP_NET_BIND_SERVICE and the capabilities that service file names.
fn whyNotLeashed(status: []const u8, allowed: u64, login: bool) ?[]const u8 {
    const uids = statusField(status, "Uid") orelse return "shows no uid";
    var ids = std.mem.tokenizeAny(u8, uids, " \t");
    if (!login) while (ids.next()) |id| if (std.mem.eql(u8, id, "0")) return "runs as root";
    for ([_][]const u8{ "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb" }) |key| {
        const v = std.fmt.parseInt(u64, statusField(status, key) orelse "", 16) catch
            return "shows no capabilities";
        const mask = if (login and (std.mem.eql(u8, key, "CapInh") or
            std.mem.eql(u8, key, "CapAmb"))) 0 else allowed;
        if (v & ~mask != 0) return "has capabilities";
    }
    if (!std.mem.eql(u8, statusField(status, "NoNewPrivs") orelse "", "1"))
        return "may gain privileges";
    // Kernels before 4.7 show no umask, so there is nothing to judge.
    if (statusField(status, "Umask")) |mask| {
        const m = std.fmt.parseInt(u32, mask, 8) catch return "shows no umask";
        if (m & 0o022 != 0o022) return "makes files others may write";
    }
    return null;
}

test shareMode {
    try testing.expectEqual(0o700, shareMode("exec /a\nuser x\n").?);
    try testing.expectEqual(0o711, shareMode("exec /a\nshare   shared\n").?);
    try testing.expectEqual(0o2771, shareMode("exec /a\nshare group\n").?);
    try testing.expectEqual(0o755, shareMode("share\tbrowseable # all\n").?);
    try testing.expectEqual(0o700, shareMode("# share shared\nshare strict\n").?);
    try testing.expectEqual(null, shareMode("share open\n"));
}

test whyNotLeashed {
    const bind: u64 = 1 << linux.CAP.NET_BIND_SERVICE;
    const ok = "Name:\tnginx\nUid:\t200\t200\t200\t200\nCapInh:\t0000000000000000\nCapPrm:\t0000" ++
        "000000000400\n" ++
        "CapEff:\t0000000000000400\nCapBnd:\t0000000000000400\nCapAmb:\t0000000000000400\nNoNewP" ++
        "rivs:\t1\n";
    try testing.expectEqual(null, whyNotLeashed(ok, bind, false));
    try testing.expectEqualStrings(
        "runs as root",
        whyNotLeashed("Uid:\t200\t0\t200\t200\n", bind, false).?,
    );
    const caps = "Uid:\t70\t70\t70\t70\nCapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapBnd:\t000001fffff" ++
        "fffff\nCapAmb:\t0\nNoNewPrivs:\t1\n";
    try testing.expectEqualStrings("has capabilities", whyNotLeashed(caps, bind, false).?);
    const packet: u64 = service.cap.net_raw | service.cap.net_admin;
    const scan = "Uid:\t70\t70\t70\t70\nCapInh:\t3000\nCapPrm:\t3000\nCapEff:\t3000\nCapBnd:\t30" ++
        "00\n" ++
        "CapAmb:\t3000\nNoNewPrivs:\t1\n";
    try testing.expectEqual(null, whyNotLeashed(scan, bind | packet, false));
    try testing.expectEqualStrings("has capabilities", whyNotLeashed(scan, bind, false).?);
    const nnp = "Uid:\t70\t70\t70\t70\nCapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapBnd:\t0\nCapAmb:\t" ++
        "0\nNoNewPrivs:\t0\n";
    try testing.expectEqualStrings("may gain privileges", whyNotLeashed(nnp, bind, false).?);
    try testing.expectEqual(null, whyNotLeashed(ok ++ "Umask:\t0022\n", bind, false));
    try testing.expectEqual(null, whyNotLeashed(ok ++ "Umask:\t0077\n", bind, false));
    try testing.expectEqualStrings(
        "makes files others may write",
        whyNotLeashed(ok ++ "Umask:\t0002\n", bind, false).?,
    );
    try testing.expectEqualStrings(
        "shows no umask",
        whyNotLeashed(ok ++ "Umask:\tx\n", bind, false).?,
    );
    const sshd = "Uid:\t0\t0\t0\t0\nCapInh:\t0\nCapPrm:\t4004404ed\nCapEff:\t4004404ed\n" ++
        "CapBnd:\t4004404ed\nCapAmb:\t0\nNoNewPrivs:\t1\n";
    try testing.expectEqual(null, whyNotLeashed(sshd, service.cap.login_set, true));
    // The set before DAC_OVERRIDE, FSETID, SYS_RESOURCE, SYS_TTY_CONFIG and
    // AUDIT_WRITE went.
    const wider = "Uid:\t0\t0\t0\t0\nCapInh:\t0\nCapPrm:\t4254404ff\nCapEff:\t4254404ff\n" ++
        "CapBnd:\t4254404ff\nCapAmb:\t0\nNoNewPrivs:\t1\n";
    try testing.expectEqualStrings(
        "has capabilities",
        whyNotLeashed(wider, service.cap.login_set, true).?,
    );
    const developer = "Uid:\t0\t0\t0\t0\nCapInh:\t0\nCapPrm:\t100\nCapEff:\t100\n" ++
        "CapBnd:\t100\nCapAmb:\t0\nNoNewPrivs:\t1\n";
    try testing.expectEqual(null, whyNotLeashed(developer, service.cap.developer_login_set, true));
    try testing.expectEqualStrings(
        "has capabilities",
        whyNotLeashed(developer, service.cap.login_set, true).?,
    );
    try testing.expectEqualStrings(
        "runs as root",
        whyNotLeashed(sshd, service.cap.login_set, false).?,
    );
}
