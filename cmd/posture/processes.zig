//! processes holds posture's process and program checks: hidden processes,
//! leashed services, and the absence of tools an intruder would want.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const linux = std.os.linux;
const testing = std.testing;

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
    try p.add(.{
        .id = "update-held",
        .area = "processes",
        .name = "Updates resolve",
        .why = "An unsolvable package pin must not silently hold the last image forever.",
        .how = "the last update resolution left no held marker",
        .result = if (!p.root or !exists(p.io, "/usr/share/werewolf/form"))
            .skip
        else if (exists(p.io, "/data/svc/autoupdate/held"))
            .fail
        else
            .pass,
        .detail = if (p.root) p.read("/data/svc/autoupdate/held") else "",
    });
    try p.add(.{
        .id = "updates-enabled",
        .area = "processes",
        .name = "Automatic updates enabled",
        .why = "Security fixes reach the machine without an operator rebuilding it.",
        .how = "werewolf's autoupdate service is present and not marked down",
        .result = if (!exists(p.io, "/usr/share/werewolf/form"))
            .skip
        else if ((exists(p.io, "/etc/sv/autoupdate/run") or exists(p.io, "/etc/sv/autoupdate/service")) and !exists(p.io, "/etc/sv/autoupdate/down"))
            .pass
        else
            .fail,
    });
    const mounts = p.read("/proc/self/mounts");
    try p.add(.{
        .id = "processes-hidden",
        .area = "processes",
        .name = "Processes hidden",
        .why = "A user sees only their own processes, not what else runs.",
        .how = "/proc is mounted hidepid=invisible",
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
        try servicesLeashed(p);
        try serviceDirs(p);
        try imageRoots(p);
    }
}

/// serviceDirs checks that each service's directories, /run/svc/NAME and
/// /data/svc/NAME, have the mode its share line asks for: 0700 by default.
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
            if (want == null or mode != want.?)
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
/// docs/design/adhoc.md) runs inside it, and that its writable binds are
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
        if (whyNotLeashed(status)) |why| try listAdd(p.gpa, &bad, "{s} {s}", .{ name, why });
    }
    try p.add(.{
        .id = "processes-services-leashed",
        .area = "processes",
        .name = "Services others wrote run leashed",
        .why = "Programs werewolf did not write, nginx and PostgreSQL among them, run as " ++
            "users of their own, with no capability but binding a low port, can gain " ++
            "none, and make no file another user may write.",
        .how = "for each service with an /etc/sv/NAME/service file, its /proc/PID/status: " ++
            "no uid 0, no capability in any set but CAP_NET_BIND_SERVICE, NoNewPrivs 1, " ++
            "and a Umask with group and other write cleared (022 or tighter)",
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
    try p.absent(
        "programs-no-interpreters",
        "programs",
        "No script interpreters",
        "There is nothing to run a script with.",
        &.{
            "awk",
            "gawk",
            "mawk",
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

    // Each werewolf service must start straight from an ELF program.
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

/// whyNotLeashed says why a /proc/PID/status does not look leashed, or null.
fn whyNotLeashed(status: []const u8) ?[]const u8 {
    const uids = statusField(status, "Uid") orelse return "shows no uid";
    var ids = std.mem.tokenizeAny(u8, uids, " \t");
    while (ids.next()) |id| if (std.mem.eql(u8, id, "0")) return "runs as root";
    const bind: u64 = 1 << linux.CAP.NET_BIND_SERVICE;
    for ([_][]const u8{ "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb" }) |key| {
        const v = std.fmt.parseInt(u64, statusField(status, key) orelse "", 16) catch
            return "shows no capabilities";
        if (v & ~bind != 0) return "has capabilities";
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
    const ok = "Name:\tnginx\nUid:\t200\t200\t200\t200\nCapInh:\t0000000000000000\nCapPrm:\t0000" ++
        "000000000400\n" ++
        "CapEff:\t0000000000000400\nCapBnd:\t0000000000000400\nCapAmb:\t0000000000000400\nNoNewP" ++
        "rivs:\t1\n";
    try testing.expectEqual(null, whyNotLeashed(ok));
    try testing.expectEqualStrings("runs as root", whyNotLeashed("Uid:\t200\t0\t200\t200\n").?);
    const caps = "Uid:\t70\t70\t70\t70\nCapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapBnd:\t000001fffff" ++
        "fffff\nCapAmb:\t0\nNoNewPrivs:\t1\n";
    try testing.expectEqualStrings("has capabilities", whyNotLeashed(caps).?);
    const nnp = "Uid:\t70\t70\t70\t70\nCapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapBnd:\t0\nCapAmb:\t" ++
        "0\nNoNewPrivs:\t0\n";
    try testing.expectEqualStrings("may gain privileges", whyNotLeashed(nnp).?);
    try testing.expectEqual(null, whyNotLeashed(ok ++ "Umask:\t0022\n"));
    try testing.expectEqual(null, whyNotLeashed(ok ++ "Umask:\t0077\n"));
    try testing.expectEqualStrings(
        "makes files others may write",
        whyNotLeashed(ok ++ "Umask:\t0002\n").?,
    );
    try testing.expectEqualStrings("shows no umask", whyNotLeashed(ok ++ "Umask:\tx\n").?);
}
