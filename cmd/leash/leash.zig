//! leash starts a service someone else wrote as its own user, confined by
//! Landlock, a seccomp pledge and a cgroup. /etc/sv/NAME/run links to it, and
//! it reads /etc/sv/NAME/service. Run by /etc/sv/NAME/narrow/PROGRAM, it
//! starts that program on a narrower leash. See leash.8.

const std = @import("std");
const allowances = @import("allow");
const seal = @import("seal");
const settings = @import("settings");
const sandbox = @import("sandbox");
const service = @import("service");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const linux = std.os.linux;

const path_env = "/usr/sbin:/usr/bin:/sbin:/bin";
const max_file = 64 << 10;
const max_secret = 4 << 10;
/// max_tasks is every service's pids.max, which counts processes and threads.
const max_tasks = 4096;
const service_config = "/usr/lib/werewolf/service-config";
const leash_bin = "/usr/lib/werewolf/leash";
const sh_shim = "/usr/lib/werewolf/sh-shim";

/// why_buf holds the message Leash.fail logs.
var why_buf: [512]u8 = undefined;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();

    // AT_EXECFN is the path this program was run by, through any link.
    const at = linux.getauxval(std.elf.AT.EXECFN);
    const run_by = if (at == 0) "" else std.mem.span(@as([*:0]const u8, @ptrFromInt(at)));
    if (narrowLink(run_by)) |link| try narrow(io, gpa, link, init.minimal);
    // Anything else must be runsv, or posture's probe, as root.
    if (linux.getuid() != 0) {
        record(io, .stderr(), .{
            .event = "refused",
            .why = "leash runs as root, or by a narrowed program's link",
        });
        std.process.exit(1);
    }

    // Close whatever runsv left open, and mark leash's own files CLOEXEC.
    _ = linux.close_range(3, std.math.maxInt(linux.fd_t), .{ .UNSHARE = false, .CLOEXEC = false });
    // runsv gives fd 0 the console, write-only. A service that kept it could
    // forge log lines there (WEBSHELL_VULNS #1), so make fd 0 /dev/null.
    // Services log on fd 1 and 2, which runsv routes.
    // Not CLOEXEC: if fd 0 was closed, open returns 0, and it must survive exec.
    const null_fd = linux.open("/dev/null", .{ .ACCMODE = .RDONLY }, 0);
    if (linux.errno(null_fd) != .SUCCESS) {
        record(io, .stdout(), .{
            .event = "warning",
            .why = "cannot open /dev/null; fd 0 stays as runsv left it",
            .errno = @tagName(linux.errno(null_fd)),
        });
    } else if (null_fd != 0) {
        _ = linux.dup2(@intCast(null_fd), 0);
        _ = linux.close(@intCast(null_fd));
    }
    // Open runsv's control pipe while root, so fail can park the service
    // even after root is given up.
    const ctl_rc = linux.open(
        "supervise/control",
        .{ .ACCMODE = .WRONLY, .NONBLOCK = true, .CLOEXEC = true },
        0,
    );
    var l: Leash = .{
        .io = io,
        .ctl = if (linux.errno(ctl_rc) == .SUCCESS) @intCast(ctl_rc) else null,
        .name = "?",
    };

    var cwd_buf: [Dir.max_path_bytes]u8 = undefined;
    const cwd_len = std.process.currentPath(io, &cwd_buf) catch 0;
    const name = std.fs.path.basename(cwd_buf[0..cwd_len]);
    if (!service.isName(name)) l.fail(
        .park,
        "run from /etc/sv/NAME, not {s}",
        .{cwd_buf[0..cwd_len]},
    );
    l.name = name;

    // System helpers still have the console. Start applications once the
    // local receiver and its file worker have both finished confinement.
    if (exists("/usr/lib/werewolf/syslogd")) {
        var ready: [2]u8 = undefined;
        const value = Dir.cwd().readFile(io, "/run/syslog/ready", &ready) catch "";
        if (!std.mem.eql(u8, value, "1")) l.fail(.retry, "waiting for syslogd", .{});
    }

    const text = Dir.cwd().readFileAlloc(io, "service", gpa, .limited(max_file)) catch |err|
        l.fail(.park, "./service: {s}", .{@errorName(err)});
    var bad: service.Bad = .{};
    const s = service.parse(gpa, text, &bad) catch
        l.fail(.park, "./service, line {d}: {s}", .{ bad.line, bad.why });

    const passwd = Dir.cwd().readFileAlloc(
        io,
        "/usr/share/werewolf/etc/passwd",
        gpa,
        .limited(1 << 20),
    ) catch Dir.cwd().readFileAlloc(io, "/etc/passwd", gpa, .limited(1 << 20)) catch "";
    const user = lookupUser(passwd, s.user) orelse
        l.fail(.park, "no user {s} in /etc/passwd", .{s.user});
    // The groups it joins, each another service's (lib/compose.zig checks
    // that at build), and never one below the services' ids: a system's.
    const group_file = Dir.cwd().readFileAlloc(
        io,
        "/usr/share/werewolf/etc/group",
        gpa,
        .limited(1 << 20),
    ) catch Dir.cwd().readFileAlloc(io, "/etc/group", gpa, .limited(1 << 20)) catch "";
    const groups = try gpa.alloc(linux.gid_t, s.groups.len);
    for (s.groups, groups) |group_name, *gid| {
        gid.* = lookupGroup(group_file, group_name) orelse
            l.fail(.park, "no group {s} in /etc/group", .{group_name});
        if (gid.* < 1 << 16) l.fail(.park, "group {s} is a system's", .{group_name});
    }
    const login = s.caps & service.cap.login != 0;
    if (login) {
        const listener = std.mem.eql(u8, name, "sshd") or
            (std.mem.eql(u8, name, "sshd-dev") and exists("/usr/share/werewolf/dev"));
        const export_only = std.mem.eql(u8, name, "sshd") and
            exists("/usr/share/werewolf/export-only");
        if (user.uid != 0 or user.gid != 0 or !listener or
            (!allowances.has(.pty) and !export_only))
            l.fail(.park, "caps login needs an SSH listener and the pty allowance", .{});
        // Disable Speculative Store Bypass for ssh-keygen, sshd and every
        // session (docs/security.md).
        _ = linux.prctl(
            @backingInt(linux.PR.SET_SPECULATION_CTRL),
            linux.PR.SPEC_STORE_BYPASS,
            linux.PR.SPEC_FORCE_DISABLE,
            0,
            0,
        );
    } else {
        if (user.uid == 0 or user.gid == 0) l.fail(.park, "{s} is root's", .{s.user});
        if (user.uid <= service.system_id_max or user.gid <= service.system_id_max)
            l.fail(.park, "{s} is a system's", .{s.user});
    }
    // The build could not tell this service's directories from another's.
    // Each narrowed program's link ships in the image, as ./run does.
    for (s.narrow) |n| {
        for (n.read) |p| if (!service.reaches(s, name, p, false))
            l.fail(.park, "narrow {s}: {s} is not the service's to read", .{ n.program, p });
        for (n.write) |p| if (!service.reaches(s, name, p, true))
            l.fail(.park, "narrow {s}: {s} is not the service's to write", .{ n.program, p });
        const link = try gpa.printSentinel(
            "/etc/sv/{s}/narrow/{s}",
            .{ name, std.fs.path.basename(n.program) },
            0,
        );
        var buf: [Dir.max_path_bytes]u8 = undefined;
        const len = linux.readlink(link, &buf, buf.len);
        if (linux.errno(len) != .SUCCESS or !std.mem.eql(u8, buf[0..len], leash_bin))
            l.fail(.park, "narrow {s}: {s} is not a link to {s}", .{ n.program, link, leash_bin });
    }

    // --- as root ------------------------------------------------------------

    const nodata = exists("/run/werewolf/nodata");
    for (s.requires) |p| {
        if (!exists(try gpa.dupeSentinel(u8, p, 0)))
            l.fail(.park, "requires {s}, which is not there", .{p});
    }
    var env: std.process.Environ.Map = .init(gpa);
    try env.put("PATH", path_env);
    for (s.env) |e| try env.put(e[0], e[1]);
    for (s.secrets) |sec| {
        const value = readSecret(io, gpa, sec.path) catch |err| {
            if (sec.optional and err == error.FileNotFound) continue;
            l.fail(.park, "secret {s}: {s}: {s}", .{ sec.name, sec.path, @errorName(err) });
        };
        try env.put(sec.name, value);
    }
    // Read the config files the image names while root, but write the
    // copies only after dropping root and entering Landlock, so a service
    // cannot use a link or a restart race to make root write for it.
    // A missing settings file reads as {}, so the image's defaults hold.
    const configs = try gpa.alloc(?[]const u8, s.configs.len);
    for (s.configs, configs) |cfg, *value| {
        value.* = Dir.cwd().readFileAlloc(io, cfg.path, gpa, .limited(max_file)) catch |err| v: {
            if (err == error.FileNotFound) {
                const is_settings = std.mem.eql(u8, cfg.name, settings.input_file);
                if (s.render != null and is_settings) break :v "{}";
                if (cfg.optional) break :v null;
            }
            l.fail(.park, "config {s}: {s}", .{ cfg.name, @errorName(err) });
        };
    }

    const run_dir = try gpa.printSentinel("/run/svc/{s}", .{name}, 0);
    const data_dir = try gpa.printSentinel("/data/svc/{s}", .{name}, 0);
    _ = linux.mkdir("/run/svc", 0o755);
    own(l, run_dir, user, s.share);
    if (s.root != null)
        own(l, try gpa.printSentinel("/run/svc/{s}/run", .{name}, 0), user, s.share);
    if (!nodata) {
        _ = linux.mkdir("/data/svc", 0o755);
        own(l, data_dir, user, s.share);
    }
    var rlim: linux.rlimit = undefined;
    if (linux.errno(linux.getrlimit(.NOFILE, &rlim)) != .SUCCESS)
        l.fail(.park, "nofile: getrlimit refused", .{});
    const target_nofile: linux.rlim_t = if (s.nofile) |n| n else rlim.cur;
    // Reserve one slot above target_nofile while root so pledgeAndExec can
    // place prog on target_nofile and immediately drop RLIMIT_NOFILE back to
    // target_nofile, leaving exec_fd >= rlim_max after exec.
    const prep_nofile: linux.rlim_t = if (!s.pledge.contains(.exec) and
        target_nofile < (1 << 20))
        target_nofile + 1
    else
        target_nofile;
    if (linux.errno(linux.setrlimit(
        .NOFILE,
        &.{ .cur = prep_nofile, .max = prep_nofile },
    )) != .SUCCESS)
        l.fail(.park, "nofile {d}: refused", .{target_nofile});
    // Join the service's cgroup (cmd/init delegates memory and pids under
    // /run/cgroup/svc). memory.max caps resident memory, not address space,
    // which the JVM and V8 over-reserve; leash-reap kills the whole tree at
    // stop. Join as root, before the drop, so the service cannot leave the
    // cgroup or raise its limits. Without cgroup2 it runs uncapped.
    if (exists("/run/cgroup/svc")) {
        const dir = try gpa.printSentinel("/run/cgroup/svc/{s}", .{name}, 0);
        _ = linux.mkdir(dir, 0o755);
        _ = writeIn(gpa, dir, "cgroup.kill", "1");
        if (s.memory) |mib| {
            var buf: [24]u8 = undefined;
            const max = std.mem.print(&buf, "{d}\n", .{@as(u64, mib) << 20}) catch unreachable;
            if (!writeIn(gpa, dir, "memory.max", max))
                l.fail(.park, "memory {d}: cannot set memory.max", .{mib});
        }
        if (!writeIn(gpa, dir, "pids.max", std.fmt.comptimePrint("{d}\n", .{max_tasks})))
            l.fail(.park, "cannot set pids.max", .{});
        // A share of contended CPUs is fairness, not containment, so a
        // kernel without the cpu controller runs the service anyway.
        if (s.cpu) |weight| {
            var buf: [8]u8 = undefined;
            const w = std.mem.print(&buf, "{d}\n", .{weight}) catch unreachable;
            if (!writeIn(gpa, dir, "cpu.weight", w))
                record(
                    io,
                    .stdout(),
                    .{ .event = "uncapped", .service = name, .why = "no cpu controller" },
                );
        }
        var pid_buf: [24]u8 = undefined;
        const pid = std.mem.print(&pid_buf, "{d}\n", .{linux.getpid()}) catch unreachable;
        if (!writeIn(gpa, dir, "cgroup.procs", pid)) l.fail(.park, "cannot join its cgroup", .{});
    } else if (s.memory != null) {
        record(io, .stdout(), .{ .event = "uncapped", .service = name, .why = "no cgroup2" });
    }

    // The allowance files live on the machine. An image's root does not
    // contain them, and the chroot below would hide them.
    const allow_packet = allowances.has(.packet);
    const allow_netadmin = allowances.has(.netadmin);

    // Chroot into the service's image as root, before building any rule, so
    // every later path, links included, resolves inside the image. Only what
    // init bound in (cmd/init/oci.zig) is reachable; the image's /tmp and
    // /data are /run/svc/NAME and /data/svc/NAME, made above.
    if (s.root) |r| {
        const rz = try gpa.dupeSentinel(u8, r, 0);
        if (linux.errno(linux.chroot(rz)) != .SUCCESS or linux.errno(linux.chdir("/")) != .SUCCESS)
            l.fail(.park, "root {s}: cannot enter it", .{r});
    }
    const own_run: [:0]const u8 = if (s.root != null) "/tmp" else run_dir;
    const own_data: [:0]const u8 = if (s.root != null) "/data" else data_dir;
    // Images log by reopening /dev/stdout and /dev/stderr. Reopening runsv's
    // pipes by path checks their owner (root, 0600), so give them to the
    // service's user.
    if (s.root != null) for ([_]i32{ 1, 2 }) |fd| {
        _ = linux.fchown(fd, user.uid, user.gid);
    };

    // Production sshd's layer also handles writes, which login_writes grant;
    // developer SSH's handles only binds.
    const rules = sandbox.Ruleset.init(if (login)
        .{ .only_bind = true, .writes = !std.mem.eql(u8, name, "sshd-dev") }
    else
        .{ .sockets = true }) catch |err| l.fail(
        .park,
        "Landlock: {s}; this kernel cannot leash a service",
        .{sandbox.whyNot(gpa, err)},
    );
    if ((s.listen.len > 0 or s.connect.len > 0 or s.connect_any or s.dns) and rules.abi < 4)
        l.fail(.park, "Landlock ABI {d} has no TCP rules", .{rules.abi});
    if (login) {
        if (rules.abi >= 4) rules.port(sandbox.bind_tcp, 0) catch |err|
            l.fail(.park, "listen tcp/0: {s}", .{sandbox.whyNot(gpa, err)});
        for (s.listen) |port| rules.port(sandbox.bind_tcp, port) catch |err|
            l.fail(.park, "listen tcp/{d}: {s}", .{ port, sandbox.whyNot(gpa, err) });
    } else {
        const floor_rules: []const Floor = if (s.root != null) &rooted_floor else &floor;
        for (floor_rules) |f| allow(rules, f.path, f.access, .optional) catch {};
        // Resolve this socket across daemon restarts without granting file
        // writes to its directory. UNIX syscalls still need a pledge.
        if (rules.fs & sandbox.resolve_unix != 0)
            allow(rules, "/run/syslog", sandbox.resolve_unix, .optional) catch |err|
                l.fail(.park, "syslog socket: {s}", .{sandbox.whyNot(gpa, err)});
        for ([_][:0]const u8{ "/proc/self/fd/1", "/proc/self/fd/2" }) |fd|
            allow(rules, fd, sandbox.write_file, .optional) catch {};
        allow(rules, own_run, write_tree, .own) catch |err|
            l.fail(.park, "{s}: {s}", .{ own_run, sandbox.whyNot(gpa, err) });
        if (!nodata) allow(rules, own_data, write_tree, .own) catch |err|
            l.fail(.park, "{s}: {s}", .{ own_data, sandbox.whyNot(gpa, err) });
        // An image keeps pid files and sockets in /run, which init binds from
        // /run/svc/NAME/run (cmd/init/oci.zig).
        if (s.root != null) allow(rules, "/run", write_tree, .own) catch |err|
            l.fail(.park, "/run: {s}", .{sandbox.whyNot(gpa, err)});
        for (s.read) |p| allowPath(l, rules, gpa, p, read_tree, nodata);
        for (s.write) |p| allowPath(l, rules, gpa, p, write_tree, nodata);
        // A shared directory is a different inode from the image path it is
        // bound over, so the rule names the image path. Write on a parent
        // does not cover it. A reader stays read-only here even if the
        // directory's mode is wider.
        for (s.data) |d| allowPath(
            l,
            rules,
            gpa,
            d.image,
            if (d.write) write_tree else read_tree,
            nodata,
        );
        allowExecSet(l, rules, gpa, s, true);
        if (s.render) |r| if (r.from) |from|
            allowPath(l, rules, gpa, from, sandbox.read_file, nodata);
        // A narrowed program's leash is leash, reading this file.
        if (s.narrow.len > 0) {
            const file = try gpa.printSentinel("/etc/sv/{s}/service", .{name}, 0);
            allowPath(l, rules, gpa, file, sandbox.read_file, nodata);
        }
        for (s.listen) |port| rules.port(sandbox.bind_tcp, port) catch |err|
            l.fail(.park, "listen tcp/{d}: {s}", .{ port, sandbox.whyNot(gpa, err) });
        for (s.connect) |port| rules.port(sandbox.connect_tcp, port) catch |err|
            l.fail(.park, "connect tcp/{d}: {s}", .{ port, sandbox.whyNot(gpa, err) });
        if (s.dns) rules.port(sandbox.connect_tcp, 53) catch |err|
            l.fail(.park, "connect dns: {s}", .{sandbox.whyNot(gpa, err)});
        // Every TCP port, for the one service that declared it. Other
        // services keep the ports on their connect lines and no others.
        if (s.connect_any) {
            var p: u32 = 1;
            while (p <= 65535) : (p += 1) rules.port(sandbox.connect_tcp, @intCast(p)) catch |err|
                l.fail(.park, "connect tcp/{d}: {s}", .{ p, sandbox.whyNot(gpa, err) });
        }
        // A socket's directory, not the socket, which its server makes anew
        // each time it starts; nothing there but reaching sockets.
        if (rules.fs & sandbox.resolve_unix != 0) for (s.sockets) |p|
            allowPath(l, rules, gpa, std.fs.path.dirname(p).?, sandbox.resolve_unix, nodata);
    }

    const cwd: [:0]const u8 = if (s.dir) |d|
        try gpa.dupeSentinel(u8, d, 0)
    else if (nodata)
        own_run
    else
        own_data;
    const cd = linux.chdir(cwd);
    if (linux.errno(cd) != .SUCCESS) record(io, .stdout(), .{
        .event = "warning",
        .service = name,
        .why = "cannot enter its directory; it starts where runsv did",
        .dir = cwd,
        .errno = @tagName(linux.errno(cd)),
    });
    // A port below 1024, TCP or UDP, takes CAP_NET_BIND_SERVICE.
    var low_port = false;
    for ([_][]const u16{ s.listen, s.listen_udp }) |ports| {
        for (ports) |p| low_port = low_port or (p != 0 and p < 1024);
    }
    // A packet capability is kept only when this machine allowed it.
    // A file that names one the machine did not allow parks, so editing
    // the file cannot widen the bounding set.
    var keep: u64 = if (login) loginCapabilities(name) else s.caps;
    if (low_port) keep |= 1 << linux.CAP.NET_BIND_SERVICE;
    if (s.caps & service.cap.net_raw != 0 and !allow_packet)
        l.fail(.park, "caps net_raw: this machine does not allow packet", .{});
    if (s.caps & service.cap.net_admin != 0 and !allow_netadmin)
        l.fail(.park, "caps net_admin: this machine does not allow netadmin", .{});
    dropTo(user, groups, keep, login) catch |err|
        l.fail(.park, "giving root up: {s}", .{@errorName(err)});
    if (!login and !usesJit(s)) sandbox.refuseExecGain() catch |err|
        l.fail(.park, "Memory-Deny-Write-Execute: {s}", .{sandbox.whyNot(gpa, err)});

    // --- leashed --------------------------------------------------------------

    if (!login) rules.restrict() catch |err|
        l.fail(.park, "Landlock: {s}", .{sandbox.whyNot(gpa, err)});
    for (s.configs, configs) |cfg, value| {
        copyConfig(own_run, try gpa.dupeSentinel(u8, cfg.name, 0), value) catch |err|
            l.fail(.park, "config {s}: {s}", .{ cfg.name, @errorName(err) });
    }
    record(
        io,
        .stdout(),
        .{
            .event = "start",
            .service = name,
            .user = s.user,
            .exec = s.exec[0],
            .root = s.root,
            .listen = s.listen,
            .listen_udp = s.listen_udp,
            .connect = s.connect,
            .landlock = rules.abi,
            .pledge = try words(gpa, s.pledge),
        },
    );

    // In an image's root, service-config is init's bind of the machine's
    // (cmd/init/oci.zig), and the service's run directory is its /tmp.
    if (s.render) |r| renderSettings(l, gpa, own_run, name, s, r, &env);
    for (s.before) |argv| {
        var child = std.process.spawn(
            io,
            .{ .argv = argv, .environ_map = &env, .stdin = .ignore },
        ) catch |err| l.fail(.park, "before {s}: {s}", .{ argv[0], @errorName(err) });
        const term = child.wait(io) catch |err|
            l.fail(.park, "before {s}: {s}", .{ argv[0], @errorName(err) });
        if (term != .exited or term.exited != 0) l.fail(.park, "before {s} failed", .{argv[0]});
    }
    // A login's layer goes on after its setup, which may publish its host
    // key's pin to /run/werewolf (forms/ssh-su), where no session writes.
    if (login) {
        if (rules.fs & sandbox.write_file != 0) for (login_writes) |w|
            allow(rules, w.path, w.access, .optional) catch |err| switch (err) {
                error.FileNotFound => {},
                else => l.fail(.park, "{s}: {s}", .{ w.path, sandbox.whyNot(gpa, err) }),
            };
        rules.restrict() catch |err| l.fail(.park, "Landlock: {s}", .{sandbox.whyNot(gpa, err)});
    }
    if (!login and (s.render != null or s.before.len > 0 or
        (!s.pledge.contains(.exec) and (s.run.len > 0 or s.narrow.len > 0))))
    {
        const exec_only = sandbox.Ruleset.init(.{ .only_exec = true }) catch |err|
            l.fail(.park, "Landlock: {s}", .{sandbox.whyNot(gpa, err)});
        allowExecSet(l, exec_only, gpa, s, false);
        exec_only.restrict() catch |err|
            l.fail(.park, "Landlock: {s}", .{sandbox.whyNot(gpa, err)});
    }
    // Open the program before the pledge. A pledge without exec still allows
    // execveat of this descriptor, and Landlock allows only this program.
    const prog_rc = linux.open(
        try gpa.dupeSentinel(u8, s.exec[0], 0),
        .{ .ACCMODE = .RDONLY, .PATH = true, .CLOEXEC = true },
        0,
    );
    if (linux.errno(prog_rc) != .SUCCESS)
        l.fail(.retry, "exec {s}: {s}", .{ s.exec[0], @tagName(linux.errno(prog_rc)) });
    const argv = try gpa.allocSentinel(?[*:0]const u8, s.exec.len, null);
    for (s.exec, argv) |a, *p| p.* = try gpa.dupeSentinel(u8, a, 0);
    const envp = try gpa.allocSentinel(?[*:0]const u8, env.count(), null);
    var env_it = env.iterator();
    var i: usize = 0;
    while (env_it.next()) |e| : (i += 1)
        envp[i] = try gpa.printSentinel("{s}={s}", .{ e.key_ptr.*, e.value_ptr.* }, 0);
    pledgeAndExec(l, prog_rc, s.exec[0], s.pledge, argv.ptr, envp.ptr);
}

/// Developer SSH is the local, disposable arbitrary-execution boundary. It
/// keeps SETPCAP so a root session can start another leash, which immediately
/// drops the bounding set again for an iterated test driver. Production SSH
/// never keeps it.
fn loginCapabilities(name: []const u8) u64 {
    return if (std.mem.eql(u8, name, "sshd-dev"))
        service.cap.developer_login_set
    else
        service.cap.login_set;
}

test "only developer SSH can launch a nested leash" {
    try std.testing.expect(loginCapabilities("sshd-dev") & (@as(u64, 1) << linux.CAP.SETPCAP) != 0);
    try std.testing.expect(loginCapabilities("sshd") & (@as(u64, 1) << linux.CAP.SETPCAP) == 0);
}

/// pledgeAndExec installs a pledge of promises and becomes the program
/// opened as prog, which a pledge without exec allows once via ExecGate.
/// The pledge returns ENOSYS outside its promises and has no listener, so
/// no_new_privs suffices to install it.
fn pledgeAndExec(
    l: Leash,
    prog: usize,
    path: []const u8,
    promises: seal.Set,
    argv: [*:null]const ?[*:0]const u8,
    envp: [*:null]const ?[*:0]const u8,
) noreturn {
    var filter_buf: [seal.max_filter]seal.Filter = undefined;
    if (promises.contains(.exec)) {
        const filter = seal.buildServiceFilter(&filter_buf, promises, null);
        _ = seal.install(filter, false) catch |e| l.fail(.park, "pledge: {s}", .{@errorName(e)});
        const rc = linux.syscall5(
            .execveat,
            prog,
            @intFromPtr(""),
            @intFromPtr(argv),
            @intFromPtr(envp),
            0x1000, // AT_EMPTY_PATH
        );
        l.fail(.park, "exec {s}: {s}", .{ path, @tagName(linux.errno(rc)) });
    }
    const gate = prepareExecGate(prog) catch |e| l.fail(.park, "exec gate: {s}", .{@errorName(e)});
    const filter = seal.buildServiceFilter(&filter_buf, promises, gate);
    _ = seal.install(filter, false) catch |e| l.fail(.park, "pledge: {s}", .{@errorName(e)});
    const rc = execveatTrampoline(
        gate.fd,
        @intCast(gate.empty_path),
        @intFromPtr(argv),
        @intFromPtr(envp),
        0x1000, // AT_EMPTY_PATH
    );
    l.fail(.park, "exec {s}: {s}", .{ path, @tagName(linux.errno(rc)) });
}

/// prepareExecGate maps a read-only zero page at a random byte offset, moves
/// prog onto the highest available descriptor below RLIMIT_NOFILE, and lowers
/// RLIMIT_NOFILE (soft and hard) to that descriptor number so no syscall in
/// the new image can ever allocate it again.
fn prepareExecGate(prog: usize) !seal.ExecGate {
    var rlim: linux.rlimit = undefined;
    if (linux.errno(linux.getrlimit(.NOFILE, &rlim)) != .SUCCESS or rlim.cur < 4)
        return error.LimitExecFd;
    const cap: linux.rlim_t = @min(rlim.cur - 1, (1 << 20) - 1);
    const ceil_fd: i32 = @intCast(cap);
    const page = linux.mmap(
        null,
        4096,
        .{ .READ = true },
        .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
        -1,
        0,
    );
    if (linux.errno(page) != .SUCCESS) return error.Mmap;
    var rnd: [2]u8 = undefined;
    const got = linux.getrandom(&rnd, rnd.len, 0);
    if (linux.errno(got) != .SUCCESS or got != rnd.len) return error.Random;
    const empty_path: u64 = page + (std.mem.readInt(u16, &rnd, .little) & 0xfff);
    if (prog != @as(usize, @intCast(ceil_fd))) {
        if (linux.errno(linux.dup3(
            @intCast(prog),
            ceil_fd,
            @as(u32, @bitCast(linux.O{ .CLOEXEC = true })),
        )) != .SUCCESS) return error.DupExecFd;
        _ = linux.close(@intCast(prog));
    }
    const lim: linux.rlim_t = @intCast(ceil_fd);
    if (linux.errno(linux.setrlimit(.NOFILE, &.{ .cur = lim, .max = lim })) != .SUCCESS)
        return error.LimitExecFd;
    return .{ .fd = @intCast(ceil_fd), .ip = execveatAfterIp(), .empty_path = empty_path };
}

fn execveatAfterIp() u64 {
    if (@import("builtin").os.tag != .linux) return 0;
    return switch (@import("builtin").cpu.arch) {
        .x86_64 => asm (
            \\lea werewolf_leash_execveat_after(%rip), %[ret]
            : [ret] "=r" (-> usize),
        ),
        .aarch64 => asm (
            \\adrp %[ret], werewolf_leash_execveat_after
            \\add %[ret], %[ret], :lo12:werewolf_leash_execveat_after
            : [ret] "=r" (-> usize),
        ),
        else => @compileError("unsupported arch"),
    };
}

noinline fn execveatTrampoline(
    fd: usize,
    empty_path: usize,
    argv: usize,
    envp: usize,
    flags: usize,
) usize {
    if (@import("builtin").os.tag != .linux) return 0;
    return switch (@import("builtin").cpu.arch) {
        .x86_64 => asm volatile (
            \\syscall
            \\.globl werewolf_leash_execveat_after
            \\.hidden werewolf_leash_execveat_after
            \\werewolf_leash_execveat_after:
            : [ret] "={rax}" (-> usize),
            : [nr] "{rax}" (@as(usize, @backingInt(linux.SYS.execveat))),
              [a0] "{rdi}" (fd),
              [a1] "{rsi}" (empty_path),
              [a2] "{rdx}" (argv),
              [a3] "{r10}" (envp),
              [a4] "{r8}" (flags),
            : .{ .rcx = true, .r11 = true, .memory = true }),
        .aarch64 => asm volatile (
            \\svc #0
            \\.globl werewolf_leash_execveat_after
            \\.hidden werewolf_leash_execveat_after
            \\werewolf_leash_execveat_after:
            : [ret] "={x0}" (-> usize),
            : [nr] "{x8}" (@as(usize, @backingInt(linux.SYS.execveat))),
              [a0] "{x0}" (fd),
              [a1] "{x1}" (empty_path),
              [a2] "{x2}" (argv),
              [a3] "{x3}" (envp),
              [a4] "{x4}" (flags),
            : .{ .memory = true }),
        else => @compileError("unsupported arch"),
    };
}

// --- a narrowed program ------------------------------------------------------------

/// Link is a narrowed program's link to leash, /etc/sv/SERVICE/narrow/NAME.
const Link = struct { service: []const u8, name: []const u8 };

/// narrowLink splits path, the path leash was run by, if it is a narrowed
/// program's link.
fn narrowLink(path: []const u8) ?Link {
    if (!std.mem.startsWith(u8, path, "/etc/sv/")) return null;
    const rest = path["/etc/sv/".len..];
    const slash = std.mem.findScalar(u8, rest, '/') orelse return null;
    if (!std.mem.startsWith(u8, rest[slash..], "/narrow/")) return null;
    const name = rest[slash + "/narrow/".len ..];
    if (!service.isName(rest[0..slash]) or name.len == 0 or
        std.mem.findScalar(u8, name, '/') != null or
        std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) return null;
    return .{ .service = rest[0..slash], .name = name };
}

/// narrow is leash run by a narrowed program's link, as the service, inside
/// its leash. It reads the program's narrow lines from the service's file,
/// root's on the verified root; stacks on the service's Landlock domain and
/// pledge its own, which no_new_privs lets it install; and becomes the
/// program.
fn narrow(io: Io, gpa: Allocator, link: Link, m: std.process.Init.Minimal) !noreturn {
    const l: Leash = .{ .io = io, .ctl = null, .name = link.service, .narrowed = true };
    const file = try gpa.printSentinel("/etc/sv/{s}/service", .{link.service}, 0);
    const text = readRootFile(gpa, file) catch |err|
        l.fail(.park, "{s}: {s}", .{ file, @errorName(err) });
    var bad: service.Bad = .{};
    const s = service.parse(gpa, text, &bad) catch
        l.fail(.park, "{s}, line {d}: {s}", .{ file, bad.line, bad.why });
    const passwd = Dir.cwd().readFileAlloc(
        io,
        "/usr/share/werewolf/etc/passwd",
        gpa,
        .limited(1 << 20),
    ) catch Dir.cwd().readFileAlloc(io, "/etc/passwd", gpa, .limited(1 << 20)) catch "";
    const user = lookupUser(passwd, s.user) orelse
        l.fail(.park, "no user {s} in /etc/passwd", .{s.user});
    if (user.uid <= service.system_id_max or user.gid <= service.system_id_max or
        linux.getuid() != user.uid or
        linux.getgid() != user.gid)
        l.fail(.park, "{s}: run as {s}, never as another user", .{ link.name, s.user });
    const n = for (s.narrow) |n| {
        if (std.mem.eql(u8, std.fs.path.basename(n.program), link.name)) break n;
    } else l.fail(.park, "{s} narrows no program named {s}", .{ file, link.name });

    check(linux.prctl(@backingInt(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0)) catch
        l.fail(.park, "no_new_privs: refused", .{});
    sandbox.refuseExecGain() catch |err|
        l.fail(.park, "Memory-Deny-Write-Execute: {s}", .{sandbox.whyNot(gpa, err)});
    const rules = sandbox.Ruleset.init(.{ .sockets = true }) catch |err|
        l.fail(.park, "Landlock: {s}", .{sandbox.whyNot(gpa, err)});
    for (narrow_floor) |f| allow(rules, f.path, f.access, .optional) catch {};
    for ([_][:0]const u8{ "/proc/self/fd/1", "/proc/self/fd/2" }) |fd|
        allow(rules, fd, sandbox.write_file, .optional) catch {};
    for (n.read) |p| allowPath(l, rules, gpa, p, read_tree, false);
    for (n.write) |p| allowPath(l, rules, gpa, p, write_tree, false);
    allowProgram(l, rules, gpa, n.program, false);
    rules.restrict() catch |err| l.fail(.park, "Landlock: {s}", .{sandbox.whyNot(gpa, err)});
    record(io, .stderr(), .{
        .event = "narrow",
        .service = link.service,
        .program = n.program,
        .landlock = rules.abi,
        .pledge = try words(gpa, n.pledge),
    });

    const prog_rc = linux.open(
        try gpa.dupeSentinel(u8, n.program, 0),
        .{ .ACCMODE = .RDONLY, .PATH = true, .CLOEXEC = true },
        0,
    );
    if (linux.errno(prog_rc) != .SUCCESS)
        l.fail(.park, "exec {s}: {s}", .{ n.program, @tagName(linux.errno(prog_rc)) });
    const argv = try gpa.allocSentinel(?[*:0]const u8, m.args.vector.len, null);
    for (m.args.vector, argv) |a, *p| p.* = a;
    const envp = try gpa.allocSentinel(?[*:0]const u8, m.environ.block.slice.len, null);
    for (m.environ.block.slice, envp) |e, *p| p.* = e;
    pledgeAndExec(l, prog_rc, n.program, n.pledge, argv.ptr, envp.ptr);
}

/// readRootFile reads the file at path, at most max_file bytes, if root
/// owns it and no one else may write it. It does not follow a final link.
fn readRootFile(gpa: Allocator, path: [:0]const u8) ![]const u8 {
    const rc = linux.open(path, .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true }, 0);
    if (linux.errno(rc) != .SUCCESS) return error.CannotOpen;
    const fd: linux.fd_t = @intCast(rc);
    defer _ = linux.close(fd);
    var st: linux.Statx = undefined;
    if (linux.errno(linux.statx(
        fd,
        "",
        linux.AT.EMPTY_PATH,
        .{ .TYPE = true, .MODE = true, .UID = true, .SIZE = true },
        &st,
    )) != .SUCCESS) return error.CannotStat;
    if (st.uid != 0 or st.mode & 0o022 != 0 or st.mode & linux.S.IFMT != linux.S.IFREG)
        return error.NotRootsAlone;
    if (st.size > max_file) return error.TooBig;
    const buf = try gpa.alloc(u8, @intCast(st.size));
    var off: usize = 0;
    while (off < buf.len) {
        const got = linux.pread(fd, buf[off..].ptr, buf.len - off, @intCast(off));
        if (linux.errno(got) == .INTR) continue;
        if (linux.errno(got) != .SUCCESS or got == 0) return error.ReadFailed;
        off += got;
    }
    return buf;
}

// --- as root ---------------------------------------------------------------------

/// own makes dir if needed, then gives it, not its contents, to user with
/// share's mode, and for `share group` its default ACL. A recursive chown
/// as root could hand the user a file it should not have. It changes dir
/// through a descriptor opened with NOFOLLOW, so a link swapped in for dir
/// cannot redirect the chown, chmod or ACL. It parks the service if dir is
/// not a directory or cannot be changed.
fn own(l: Leash, dir: [:0]const u8, user: User, share: service.Share) void {
    const mode = share.mode();
    const made = linux.mkdir(dir, @intCast(mode));
    switch (linux.errno(made)) {
        .SUCCESS, .EXIST => {},
        else => |err| l.fail(.park, "mkdir {s}: {t}", .{ dir, err }),
    }
    const rc = linux.open(
        dir,
        .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true },
        0,
    );
    if (linux.errno(rc) != .SUCCESS)
        l.fail(.park, "open directory {s}: {t}", .{ dir, linux.errno(rc) });
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    var st: linux.Statx = undefined;
    if (linux.errno(linux.statx(
        fd,
        "",
        linux.AT.EMPTY_PATH,
        .{ .MODE = true, .UID = true, .GID = true },
        &st,
    )) != .SUCCESS)
        l.fail(.park, "{s}: cannot stat it", .{dir});
    if ((st.uid != user.uid or st.gid != user.gid) and
        linux.errno(linux.fchown(fd, user.uid, user.gid)) != .SUCCESS)
        l.fail(.park, "cannot give {s} to its user", .{dir});
    if (st.mode & 0o7777 != mode and linux.errno(linux.fchmod(fd, mode)) != .SUCCESS)
        l.fail(.park, "cannot set {s} to {o}", .{ dir, mode });
    if (share == .group) {
        const set = linux.fsetxattr(fd, "system.posix_acl_default", &group_acl, group_acl.len, 0);
        if (linux.errno(set) != .SUCCESS)
            l.fail(.park, "cannot share {s} with its group: {t}", .{ dir, linux.errno(set) });
    }
}

/// group_acl is the default ACL of a `share group` directory, as the kernel
/// takes it (system.posix_acl_default, version 2): what is made in it gets
/// its user's and group's rights in full and others' read and search, the
/// umask aside. So the group writes what any of its services made, and
/// others read it as they would under umask 022.
const group_acl = acl: {
    const Entry = struct { tag: u16, perm: u16 };
    const entries = [_]Entry{
        .{ .tag = 0x01, .perm = 7 }, // ACL_USER_OBJ rwx
        .{ .tag = 0x04, .perm = 7 }, // ACL_GROUP_OBJ rwx
        .{ .tag = 0x20, .perm = 5 }, // ACL_OTHER r-x
    };
    var b: [4 + entries.len * 8]u8 = undefined;
    std.mem.writeInt(u32, b[0..4], 2, .little);
    for (entries, 0..) |e, i| {
        std.mem.writeInt(u16, b[4 + i * 8 ..][0..2], e.tag, .little);
        std.mem.writeInt(u16, b[6 + i * 8 ..][0..2], e.perm, .little);
        std.mem.writeInt(u32, b[8 + i * 8 ..][0..4], 0xffff_ffff, .little);
    }
    break :acl b;
};

/// readSecret returns the one-line secret at path, at most 4 KiB, without
/// its trailing newline.
fn readSecret(io: Io, gpa: Allocator, path: []const u8) ![]const u8 {
    const text = try Dir.cwd().readFileAlloc(io, path, gpa, .limited(max_secret));
    const value = std.mem.trimEnd(u8, text, "\n");
    if (value.len == 0) return error.Empty;
    for (value) |c| if (c == 0 or c == '\n') return error.NotOneLine;
    return value;
}

/// renderSettings runs service-config, as the service inside Landlock, with
/// the declared settings on its stdin, so neither root nor leash parses the
/// settings JSON. An env file it renders joins env, declared keys only.
fn renderSettings(
    l: Leash,
    gpa: Allocator,
    run_dir: [:0]const u8,
    name: []const u8,
    s: service.Service,
    r: settings.Render,
    env: *std.process.Environ.Map,
) void {
    const io = l.io;
    var decl: std.ArrayList(u8) = .empty;
    for (s.settings) |d| decl.print(gpa, "setting {s} {t}{s}{s} as {s}\n", .{
        d.name,
        d.type,
        if (d.list) "..." else "",
        if (d.required) " required" else "",
        d.key.?,
    }) catch l.fail(.park, "out of memory", .{});
    decl.print(gpa, "render {t} {s}{s}{s}\n", .{
        r.format,
        r.file,
        if (r.from != null) " from " else "",
        r.from orelse "",
    }) catch l.fail(.park, "out of memory", .{});

    var child_env: std.process.Environ.Map = .init(gpa);
    child_env.put("PATH", path_env) catch l.fail(.park, "out of memory", .{});
    var child = std.process.spawn(io, .{
        .argv = &.{ service_config, run_dir, name },
        .environ_map = &child_env,
        .stdin = .pipe,
    }) catch |err| l.fail(.park, "service-config: {s}", .{@errorName(err)});
    child.stdin.?.writeStreamingAll(io, decl.items) catch {};
    child.stdin.?.close(io);
    child.stdin = null;
    const term = child.wait(io) catch |err|
        l.fail(.park, "service-config: {s}", .{@errorName(err)});
    if (term != .exited or term.exited != 0)
        l.fail(.park, "settings refused; service-config said why", .{});
    if (r.format != .env) return;

    const path = gpa.print("{s}/{s}", .{ run_dir, r.file }) catch
        l.fail(.park, "out of memory", .{});
    const text = Dir.cwd().readFileAlloc(
        io,
        path,
        gpa,
        .limited(settings.max_input * 2),
    ) catch |err| l.fail(.park, "settings {s}: {s}", .{ r.file, @errorName(err) });
    const vars = settings.parseEnv(gpa, s.settings, text) catch
        l.fail(.park, "settings {s}: not what was declared", .{r.file});
    for (vars) |v| env.put(v[0], v[1]) catch l.fail(.park, "out of memory", .{});
}

/// copyConfig replaces dir/name with a new 0600 file holding value, or
/// removes it if value is null. It unlinks rather than truncates, since the
/// old name may be a hard link, and refuses symlinks. Call it as the service.
fn copyConfig(dir: [:0]const u8, name: [:0]const u8, value: ?[]const u8) !void {
    const d = linux.open(
        dir,
        .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true },
        0,
    );
    if (linux.errno(d) != .SUCCESS) return error.OpenDirectory;
    const dfd: linux.fd_t = @intCast(d);
    defer _ = linux.close(dfd);
    const un = linux.unlinkat(dfd, name, 0);
    if (linux.errno(un) != .SUCCESS and linux.errno(un) != .NOENT) return error.Unlink;
    const data = value orelse return;
    const f = linux.openat(
        dfd,
        name,
        .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .NOFOLLOW = true, .CLOEXEC = true },
        0o600,
    );
    if (linux.errno(f) != .SUCCESS) return error.CreateFile;
    const fd: linux.fd_t = @intCast(f);
    defer _ = linux.close(fd);
    var off: usize = 0;
    while (off < data.len) {
        const n = linux.write(fd, data[off..].ptr, data.len - off);
        if (linux.errno(n) == .INTR) continue;
        if (linux.errno(n) != .SUCCESS or n == 0) return error.WriteFile;
        off += n;
    }
}

fn allowPath(
    l: Leash,
    rules: sandbox.Ruleset,
    gpa: Allocator,
    path: []const u8,
    access: u64,
    nodata: bool,
) void {
    const z = gpa.dupeSentinel(u8, path, 0) catch l.fail(.park, "out of memory", .{});
    allow(rules, z, access, .plain) catch |err| switch (err) {
        // Another service may yet make it, so let runsv retry. Without
        // /data, a path under it will never appear, so park.
        error.FileNotFound => l.fail(
            if (nodata and std.mem.startsWith(u8, path, "/data/")) .park else .retry,
            "{s} is not there yet",
            .{path},
        ),
        else => l.fail(.park, "{s}: {s}", .{ path, sandbox.whyNot(gpa, err) }),
    };
}

/// allowExecSet grants execute on the programs s may run: s.exec[0] always;
/// s.run, sh_shim and leash (for narrow links) when s pledges exec; and
/// s.before and service-config while setup runs.
fn allowExecSet(
    l: Leash,
    rules: sandbox.Ruleset,
    gpa: Allocator,
    s: service.Service,
    with_setup: bool,
) void {
    allowProgram(l, rules, gpa, s.exec[0], false);
    if (s.pledge.contains(.exec) or with_setup) {
        for (s.run) |p| if (p[p.len - 1] == '/') {
            // Every program beneath an image's directory, as Grafana runs one
            // for each data source: the image is read-only, in the verified root.
            const z = gpa.dupeSentinel(u8, p[0 .. p.len - 1], 0) catch
                l.fail(.park, "out of memory", .{});
            allow(rules, z, run_file, .follow) catch |err|
                l.fail(.park, "{s}: {s}", .{ p, sandbox.whyNot(gpa, err) });
        } else allowProgram(l, rules, gpa, p, true);
        // The image's sh shim, which a service in an image of its own lacks.
        if (allowances.has(.sh) and s.root == null and
            (s.pledge.contains(.exec) or s.before.len > 0))
            allowProgram(l, rules, gpa, sh_shim, false);
        if (s.narrow.len > 0) allowProgram(l, rules, gpa, leash_bin, false);
    }
    if (with_setup) {
        for (s.before) |b| allowProgram(l, rules, gpa, b[0], false);
        if (s.render != null) allowProgram(l, rules, gpa, service_config, false);
    }
}

/// usesJit reports whether s runs a JIT compiler (PostgreSQL's LLVM,
/// Ruby's FFI callbacks, the JVM, .NET, BEAM, Wasmtime, or Node
/// without --jitless), or an
/// OCI image on a machine that allowed jit. Every other service sets
/// Memory-Deny-Write-Execute on itself even when the machine allowed jit.
fn usesJit(s: service.Service) bool {
    if (s.root != null) return true;
    if (isJitProgram(s.exec[0])) {
        for (s.exec[1..]) |arg| {
            if (std.mem.eql(u8, arg, "--jitless") or std.mem.eql(u8, arg, "jit=off")) return false;
        }
        return true;
    }
    for (s.run) |p| if (isJitProgram(p)) return true;
    return false;
}

fn isJitProgram(path: []const u8) bool {
    const base = std.fs.path.basename(path);
    for ([_][]const u8{
        "postgres", "java",     "dotnet",  "beam.smp", "erl", "node", "nodejs",
        "ruby",     "jellyfin", "postdoc",
    }) |jit| {
        if (std.mem.eql(u8, base, jit)) return true;
    }
    return false;
}

/// allowProgram lets the service run path and its ELF interpreter, which the
/// kernel also opens for execution. An explicit run entry may instead be a
/// script: its interpreter must have its own execution grant. Main and setup
/// commands remain ELF programs. It parks the service on any error.
fn allowProgram(
    l: Leash,
    rules: sandbox.Ruleset,
    gpa: Allocator,
    path: []const u8,
    allow_script: bool,
) void {
    const z = gpa.dupeSentinel(u8, path, 0) catch l.fail(.park, "out of memory", .{});
    allow(rules, z, run_file, .follow) catch |err|
        l.fail(.park, "{s}: {s}", .{ path, sandbox.whyNot(gpa, err) });
    var head: [4096]u8 = undefined;
    const fd = linux.open(z, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(fd) != .SUCCESS) l.fail(.park, "{s}: cannot read it", .{path});
    defer _ = linux.close(@intCast(fd));
    const n = linux.pread(@intCast(fd), &head, head.len, 0);
    if (linux.errno(n) != .SUCCESS) l.fail(.park, "{s}: cannot read it", .{path});
    // Grant this named file only. The kernel separately checks the shebang's
    // interpreter; do not infer or grant a shell (or env) from its contents.
    if (allow_script and std.mem.startsWith(u8, head[0..n], "#!")) return;
    const interp = interpreter(head[0..n]) catch
        l.fail(.park, "{s}: not an ELF program leash can read", .{path});
    if (interp) |i| {
        const iz = gpa.dupeSentinel(u8, i, 0) catch l.fail(.park, "out of memory", .{});
        allow(rules, iz, run_file, .follow) catch |err|
            l.fail(.park, "{s}'s loader {s}: {s}", .{ path, i, sandbox.whyNot(gpa, err) });
    }
}

/// interpreter returns the PT_INTERP path of a 64-bit little-endian ELF
/// program from its first bytes, or null for a static one.
fn interpreter(head: []const u8) !?[]const u8 {
    if (head.len < 64 or !std.mem.eql(u8, head[0..4], "\x7fELF") or head[4] != 2 or
        head[5] != 1) return error.NotElf;
    const phoff = std.mem.readInt(u64, head[0x20..0x28], .little);
    const phentsize = std.mem.readInt(u16, head[0x36..0x38], .little);
    const phnum = std.mem.readInt(u16, head[0x38..0x3a], .little);
    if (phentsize < 56) return error.NotElf;
    for (0..phnum) |i| {
        const at = std.math.add(
            u64,
            phoff,
            std.math.mul(u64, i, phentsize) catch return error.NotElf,
        ) catch return error.NotElf;
        if (at + 56 > head.len) return error.NotElf;
        const ph = head[@intCast(at)..][0..56];
        if (std.mem.readInt(u32, ph[0..4], .little) != 3) continue; // PT_INTERP
        const off = std.mem.readInt(u64, ph[8..16], .little);
        const size = std.mem.readInt(u64, ph[32..40], .little);
        if (size < 2 or size > 256 or off + size > head.len) return error.NotElf;
        const path = head[@intCast(off)..][0..@intCast(size)];
        const end = std.mem.findScalar(u8, path, 0) orelse return error.NotElf;
        if (!service.isCleanPath(path[0..end])) return error.NotElf;
        return path[0..end];
    }
    return null;
}

comptime {
    if (service.cap.net_admin != 1 << linux.CAP.NET_ADMIN) @compileError("net_admin");
    if (service.cap.net_raw != 1 << linux.CAP.NET_RAW) @compileError("net_raw");
}

/// dropTo switches to user for good. It keeps no supplementary groups and
/// no capability but the bits in keep (a low port's, the packet
/// capabilities the service file named, or sshd's login_set), which
/// survive exec. It fails with StillRoot if root can be regained.
fn dropTo(user: User, groups: []const linux.gid_t, keep: u64, login: bool) !void {
    // EINVAL means the kernel does not know the capability, so it cannot
    // grant it either. Any other failure is an error.
    var n: usize = 0;
    while (n < 64) : (n += 1) {
        if (keep & (@as(u64, 1) << @intCast(n)) != 0) continue;
        const rc = linux.prctl(@backingInt(linux.PR.CAPBSET_DROP), n, 0, 0, 0);
        if (linux.errno(rc) != .INVAL) try check(rc);
    }
    if (!login and keep != 0)
        try check(linux.prctl(@backingInt(linux.PR.SET_KEEPCAPS), 1, 0, 0, 0));
    try check(linux.setgroups(groups.len, groups.ptr));
    try check(linux.setresgid(user.gid, user.gid, user.gid));
    try check(linux.setresuid(user.uid, user.uid, user.uid));
    var hdr: CapHeader = .{};
    const low: u32 = @truncate(keep);
    const high: u32 = @truncate(keep >> 32);
    const inh: u32 = if (login) 0 else low;
    const caps = [2]CapSets{
        .{ .effective = low, .permitted = low, .inheritable = inh },
        .{ .effective = high, .permitted = high, .inheritable = 0 },
    };
    try check(linux.syscall2(.capset, @intFromPtr(&hdr), @intFromPtr(&caps)));
    // Ambient, so each one survives exec into a program without file
    // capabilities. Other services pass keep 0, or only the low port.
    // bit stays a usize: a u5 cannot count to 32, and the last increment
    // would overflow.
    if (!login) for (0..32) |bit| if (low & (@as(u32, 1) << @intCast(bit)) != 0)
        try check(linux.prctl(
            @backingInt(linux.PR.CAP_AMBIENT),
            linux.PR.CAP_AMBIENT_RAISE,
            bit,
            0,
            0,
        ));
    try check(linux.prctl(@backingInt(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0));
    if (!login and linux.errno(linux.setresuid(0, 0, 0)) == .SUCCESS) return error.StillRoot;
}

fn check(rc: usize) !void {
    if (linux.errno(rc) != .SUCCESS) return error.SystemCall;
}

/// CapHeader is the kernel's struct __user_cap_header_struct (lib/sandbox.zig).
const CapHeader = extern struct {
    version: u32 = 0x20080522, // _LINUX_CAPABILITY_VERSION_3
    pid: i32 = 0,
};
const CapSets = extern struct {
    effective: u32 = 0,
    permitted: u32 = 0,
    inheritable: u32 = 0,
};

// --- Landlock -------------------------------------------------------------------

// Landlock rights: read_tree reads files and lists directories, write_tree
// adds every change but making devices, and reaching the sockets there, a
// past run's too; run_file executes a program.
const read_tree: u64 = sandbox.read_file | sandbox.read_dir;
const write_tree: u64 = read_tree | sandbox.write_file | sandbox.remove_dir |
    sandbox.remove_file | sandbox.make_dir | sandbox.make_reg | sandbox.make_sock |
    sandbox.make_fifo | sandbox.make_sym | sandbox.refer | sandbox.truncate |
    sandbox.resolve_unix;
const run_file: u64 = sandbox.execute | sandbox.read_file;

// openat2(2) arguments, to open a path with no symlink anywhere in it.
const OpenHow = extern struct { flags: u64, mode: u64, resolve: u64 };
const O_PATH = 0o10000000;
const O_CLOEXEC = 0o2000000;
const RESOLVE_NO_MAGICLINKS = 0x02;
const RESOLVE_NO_SYMLINKS = 0x04;

const Floor = struct { path: [:0]const u8, access: u64 };
/// floor is service.floor, which a service reads; /dev/null it writes too.
const floor = blk: {
    var f: [service.floor.len]Floor = undefined;
    for (service.floor, &f) |path, *r| {
        const writes = std.mem.eql(u8, path, "/dev/null");
        r.* = .{
            .path = path,
            .access = if (writes) read_tree | sandbox.write_file else read_tree,
        };
    }
    break :blk f;
};

/// login_writes are where production sshd, and every session it starts, may
/// write, make and remove files (docs/design/implemented/ssh-hardening.md): never
/// /run/werewolf, with the accounts and keys, nor /run/cgroup, with every
/// service's limits. /run/runit holds runsv's controls and the reboot flag;
/// /run/ssh-agent, ssh-su's forwarded agents; /dev/pts and /dev/ptmx, ptys.
/// Not /dev/tpmrm0: a session could raise the release floor past every
/// release, or spend the TPM's lockout; posture reads stage0's record.
const login_writes = [_]Floor{
    .{ .path = "/data", .access = sandbox.writes },
    .{ .path = "/tmp", .access = sandbox.writes },
    .{ .path = "/var/tmp", .access = sandbox.writes },
    .{ .path = "/dev/shm", .access = sandbox.writes },
    .{ .path = "/dev/pts", .access = sandbox.writes },
    .{ .path = "/run/runit", .access = sandbox.writes },
    .{ .path = "/run/ssh-agent", .access = sandbox.writes },
    .{ .path = "/dev/ptmx", .access = sandbox.write_file },
    .{ .path = "/dev/tty", .access = sandbox.write_file },
    .{ .path = "/dev/null", .access = sandbox.write_file },
};

/// narrow_floor is a narrowed program's floor: its service's, but neither
/// the accounts nor what only the network needs.
const narrow_floor = [_]Floor{
    .{ .path = "/usr", .access = read_tree },
    .{ .path = "/proc", .access = read_tree },
    .{ .path = "/sys/devices/system/cpu", .access = read_tree },
    .{ .path = "/etc/ld.so.cache", .access = sandbox.read_file },
    .{ .path = "/etc/localtime", .access = sandbox.read_file },
    .{ .path = "/dev/null", .access = sandbox.read_file | sandbox.write_file },
    .{ .path = "/dev/zero", .access = sandbox.read_file },
    .{ .path = "/dev/random", .access = sandbox.read_file },
    .{ .path = "/dev/urandom", .access = sandbox.read_file },
};

/// rooted_floor is the floor of a service with a root: the whole image,
/// read-only, and the devices init bound in (cmd/init/oci.zig). The
/// machine's own /etc and /usr are not reachable.
const rooted_floor = [_]Floor{
    .{ .path = "/", .access = read_tree },
    .{ .path = "/dev/null", .access = sandbox.read_file | sandbox.write_file },
    .{ .path = "/dev/zero", .access = sandbox.read_file },
    .{ .path = "/dev/full", .access = sandbox.read_file | sandbox.write_file },
    .{ .path = "/dev/random", .access = sandbox.read_file },
    .{ .path = "/dev/urandom", .access = sandbox.read_file },
};

/// How says how allow resolves a path. follow: programs, through image links
/// such as /lib. plain: read and write paths, with no symlink anywhere, since
/// another service could plant one under /data to widen this one's grant.
/// own: the service's directories, refusing a final symlink.
/// optional: the floor, whose paths may be absent.
const How = enum { follow, plain, optional, own };

/// allow adds access to path in rules: the whole tree for a directory, only
/// file rights for a file.
fn allow(rules: sandbox.Ruleset, path: [:0]const u8, access: u64, how: How) !void {
    const fd = if (how == .plain) blk: {
        var open_how: OpenHow = .{
            .flags = O_PATH | O_CLOEXEC,
            .mode = 0,
            .resolve = RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
        };
        break :blk linux.syscall4(
            .openat2,
            @bitCast(@as(isize, linux.AT.FDCWD)),
            @intFromPtr(path.ptr),
            @intFromPtr(&open_how),
            @sizeOf(OpenHow),
        );
    } else linux.open(path, .{ .PATH = true, .CLOEXEC = true, .NOFOLLOW = how == .own }, 0);
    switch (linux.errno(fd)) {
        .SUCCESS => {},
        .NOENT => return error.FileNotFound,
        .LOOP => return error.ThroughALink,
        else => return error.CannotOpen,
    }
    defer _ = linux.close(@intCast(fd));
    var st: linux.Statx = undefined;
    if (linux.errno(linux.statx(
        @intCast(fd),
        "",
        linux.AT.EMPTY_PATH,
        .{ .TYPE = true },
        &st,
    )) != .SUCCESS) return error.CannotOpen;
    const is_dir = st.mode & linux.S.IFMT == linux.S.IFDIR;
    try rules.add(@intCast(fd), if (is_dir) access else access & sandbox.file_rights);
}

// --- small things ------------------------------------------------------------------

const User = struct { uid: linux.uid_t, gid: linux.gid_t };

/// lookupUser returns name's uid and gid from passwd text, or null.
fn lookupUser(passwd: []const u8, name: []const u8) ?User {
    var lines = std.mem.tokenizeScalar(u8, passwd, '\n');
    while (lines.next()) |line| {
        var f = std.mem.splitScalar(u8, line, ':');
        if (!std.mem.eql(u8, f.next() orelse continue, name)) continue;
        _ = f.next() orelse return null;
        const uid = std.fmt.parseInt(linux.uid_t, f.next() orelse return null, 10) catch
            return null;
        const gid = std.fmt.parseInt(linux.gid_t, f.next() orelse return null, 10) catch
            return null;
        return .{ .uid = uid, .gid = gid };
    }
    return null;
}

/// lookupGroup returns name's gid from group text, or null.
fn lookupGroup(group: []const u8, name: []const u8) ?linux.gid_t {
    var lines = std.mem.tokenizeScalar(u8, group, '\n');
    while (lines.next()) |line| {
        var f = std.mem.splitScalar(u8, line, ':');
        if (!std.mem.eql(u8, f.next() orelse continue, name)) continue;
        _ = f.next() orelse return null;
        return std.fmt.parseInt(linux.gid_t, f.next() orelse return null, 10) catch null;
    }
    return null;
}

/// writeIn writes text to the existing cgroup control file dir/file,
/// without creating or truncating it.
fn writeIn(gpa: Allocator, dir: [:0]const u8, file: []const u8, text: []const u8) bool {
    const path = gpa.printSentinel("{s}/{s}", .{ dir, file }, 0) catch return false;
    const fd = linux.open(path, .{ .ACCMODE = .WRONLY, .CLOEXEC = true }, 0);
    if (linux.errno(fd) != .SUCCESS) return false;
    defer _ = linux.close(@intCast(fd));
    const n = linux.write(@intCast(fd), text.ptr, text.len);
    return linux.errno(n) == .SUCCESS and n == text.len;
}

fn exists(path: [:0]const u8) bool {
    return linux.errno(linux.access(path, linux.F_OK)) == .SUCCESS;
}

/// Leash is the service being started, and how to stop it.
const Leash = struct {
    io: Io,
    /// ctl is runsv's control pipe, used to park the service; null if not open.
    ctl: ?linux.fd_t,
    name: []const u8,
    /// narrowed is set while leash starts a narrowed program: it then logs
    /// on stderr, since the program's stdout may be what its service reads,
    /// and has no runsv to tell.
    narrowed: bool = false,

    const Outcome = enum { park, retry };

    /// fail logs why and exits. With .park it also tells runsv to keep the
    /// service down; with .retry runsv starts it again.
    fn fail(l: Leash, how: Outcome, comptime fmt: []const u8, args: anytype) noreturn {
        const why = std.mem.print(&why_buf, fmt, args) catch fmt;
        if (l.narrowed) {
            record(l.io, .stderr(), .{ .event = "refused", .service = l.name, .why = why });
            std.process.exit(1);
        }
        const event = if (how == .park) "down" else "retry";
        record(l.io, .stdout(), .{ .event = event, .service = l.name, .why = why });
        if (how == .park) if (l.ctl) |fd| {
            _ = linux.write(fd, "d", 1);
        };
        std.process.exit(1);
    }
};

/// record logs fields as one JSON line on out: stdout, which runsv routes
/// to the console, or a narrowed program's stderr.
fn record(io: Io, out: Io.File, fields: anytype) void {
    var buf: [2048]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    w.writeAll("leash: ") catch return;
    std.json.Stringify.value(fields, .{}, &w) catch return;
    w.writeByte('\n') catch return;
    out.writeStreamingAll(io, w.buffered()) catch {};
}

/// words returns promises as words, for a log line.
fn words(gpa: Allocator, promises: seal.Set) ![]const []const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    var it = promises.iterator();
    while (it.next()) |p| try list.append(gpa, @tagName(p));
    return list.items;
}

// --- tests ---------------------------------------------------------------------------

const testing = std.testing;

test interpreter {
    var elf: [512]u8 = @splat(0);
    @memcpy(elf[0..6], "\x7fELF\x02\x01");
    std.mem.writeInt(u64, elf[0x20..0x28], 64, .little); // e_phoff
    std.mem.writeInt(u16, elf[0x36..0x38], 56, .little); // e_phentsize
    std.mem.writeInt(u16, elf[0x38..0x3a], 2, .little); // e_phnum
    std.mem.writeInt(u32, elf[64..68], 6, .little); // PT_PHDR
    std.mem.writeInt(u32, elf[120..124], 3, .little); // PT_INTERP
    std.mem.writeInt(u64, elf[128..136], 300, .little);
    std.mem.writeInt(u64, elf[152..160], 27, .little);
    @memcpy(elf[300..327], "/lib/ld-linux-aarch64.so.1\x00");
    try testing.expectEqualStrings("/lib/ld-linux-aarch64.so.1", (try interpreter(&elf)).?);
    std.mem.writeInt(u32, elf[120..124], 1, .little); // PT_LOAD: a static program
    try testing.expectEqual(null, try interpreter(&elf));
    std.mem.writeInt(u16, elf[0x38..0x3a], 60, .little); // headers past the bytes read
    try testing.expectError(error.NotElf, interpreter(&elf));
    try testing.expectError(error.NotElf, interpreter("#!/bin/sh\n"));
}

test group_acl {
    // The header, then user::rwx, group::rwx and other::r-x, in the tag
    // order the kernel requires, each with no id.
    try testing.expectEqualSlices(u8, &.{
        2,    0,    0,    0,
        0x01, 0,    7,    0,
        0xff, 0xff, 0xff, 0xff,
        0x04, 0,    7,    0,
        0xff, 0xff, 0xff, 0xff,
        0x20, 0,    5,    0,
        0xff, 0xff, 0xff, 0xff,
    }, &group_acl);
}

test lookupGroup {
    const group = "root:x:0:root\nvalkey:x:1234567:\nvalkey2:x:5:\nbad:x:z:\n";
    try testing.expectEqual(1234567, lookupGroup(group, "valkey").?);
    try testing.expectEqual(null, lookupGroup(group, "valk"));
    try testing.expectEqual(null, lookupGroup(group, "bad"));
    try testing.expectEqual(null, lookupGroup("", "valkey"));
}

test lookupUser {
    try testing.expectEqual(
        User{ .uid = 200, .gid = 200 },
        lookupUser("root:x:0:0::/:/x\nnginx:x:200:200::/var/empty:/sbin/nologin\n", "nginx").?,
    );
    try testing.expectEqual(null, lookupUser("nginx2:x:1:1::/:/x\n", "nginx"));
}

test "config copies replace links, not their targets" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = testing.io;
    var buf: [Dir.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPath(io, &buf);
    const path = try testing.allocator.dupeSentinel(u8, buf[0..n], 0);
    defer testing.allocator.free(path);
    try tmp.dir.writeFile(io, .{ .sub_path = "victim", .data = "unchanged" });
    try tmp.dir.symLink(io, "victim", "key", .{});
    try copyConfig(path, "key", "first\n");
    try testing.expectEqualStrings("unchanged", try tmp.dir.readFile(io, "victim", &buf));
    try testing.expectEqualStrings("first\n", try tmp.dir.readFile(io, "key", &buf));
    const st = try tmp.dir.statFile(io, "key", .{});
    try testing.expectEqual(@as(u32, 0o600), st.permissions.toMode() & 0o777);
    try copyConfig(path, "key", "second\n");
    try testing.expectEqualStrings("second\n", try tmp.dir.readFile(io, "key", &buf));
    // A missing optional config leaves no stale copy behind.
    try copyConfig(path, "key", null);
    try testing.expectError(error.FileNotFound, tmp.dir.access(io, "key", .{}));
    try testing.expectEqualStrings("unchanged", try tmp.dir.readFile(io, "victim", &buf));
    // Replacing a hard link must not truncate the inode it shares.
    const victim = try testing.allocator.printSentinel("{s}/victim", .{path}, 0);
    defer testing.allocator.free(victim);
    const hard = try testing.allocator.printSentinel("{s}/hard", .{path}, 0);
    defer testing.allocator.free(hard);
    try testing.expectEqual(
        linux.E.SUCCESS,
        linux.errno(linux.linkat(linux.AT.FDCWD, victim, linux.AT.FDCWD, hard, 0)),
    );
    try copyConfig(path, "hard", "replacement");
    try testing.expectEqualStrings("unchanged", try tmp.dir.readFile(io, "victim", &buf));
    try testing.expectEqualStrings("replacement", try tmp.dir.readFile(io, "hard", &buf));
    try tmp.dir.createDir(io, "directory", .default_dir);
    try testing.expectError(error.Unlink, copyConfig(path, "directory", "no"));
}

test narrowLink {
    const l = narrowLink("/etc/sv/mastodon-sidekiq/narrow/ffmpeg").?;
    try testing.expectEqualStrings("mastodon-sidekiq", l.service);
    try testing.expectEqualStrings("ffmpeg", l.name);
    for ([_][]const u8{
        "/usr/lib/werewolf/leash", // leash itself, not a link
        "/etc/sv/app/run",
        "/etc/sv/app/narrow/",
        "/etc/sv/app/narrow/..",
        "/etc/sv/app/narrow/a/b",
        "/etc/sv/App/narrow/cat",
        "/etc/sv//narrow/cat",
        "/etc/sv/app/narrowed/cat",
        "/run/svc/app/narrow/cat",
        "etc/sv/app/narrow/cat",
        "",
    }) |path| try testing.expectEqual(null, narrowLink(path));
}

test "a narrowed program's floor is within its service's" {
    for (narrow_floor) |f| {
        for (floor) |g| {
            if (std.mem.eql(u8, f.path, g.path) and f.access & ~g.access == 0) break;
        } else return error.TestUnexpectedResult;
    }
    // Neither the accounts nor what only the network needs.
    for ([_][]const u8{ "/etc/passwd", "/etc/hosts", "/etc/resolv.conf", "/etc/ssl" }) |p|
        for (narrow_floor) |f| try testing.expect(!std.mem.eql(u8, f.path, p));
    // A service's floor reads every path, and writes /dev/null alone.
    for (floor) |f| {
        try testing.expect(f.access & sandbox.read_file != 0);
        const writes = f.access & sandbox.write_file != 0;
        try testing.expectEqual(std.mem.eql(u8, f.path, "/dev/null"), writes);
    }
}

test usesJit {
    var s: service.Service = .{ .exec = &.{"/usr/bin/caddy"}, .user = "caddy" };
    try testing.expect(!usesJit(s));
    s.exec = &.{ "/usr/bin/postgres", "-D", "/data/svc/postgres/data" };
    try testing.expect(usesJit(s));
    s.exec = &.{ "/usr/bin/postgres", "-D", "/data/svc/postgres/data", "-c", "jit=off" };
    try testing.expect(!usesJit(s));
    s.exec = &.{ "/usr/bin/node", "/app/server.js" };
    try testing.expect(usesJit(s));
    s.exec = &.{ "/usr/bin/node", "--jitless", "/usr/lib/mastodon/streaming/index.js" };
    try testing.expect(!usesJit(s));
    s.exec = &.{ "/usr/bin/supercronic", "/etc/cron/crontab" };
    s.run = &.{"/usr/bin/php"};
    try testing.expect(!usesJit(s));
    s.run = &.{};
    // Hardened PHP has neither PCRE2 nor OPcache JIT, including on a machine
    // where another service allowed JIT and init could not set MDWE globally.
    for ([_][]const u8{ "/usr/bin/php", "/usr/bin/php-fpm" }) |program| {
        s.exec = &.{program};
        try testing.expect(!usesJit(s));
    }
    for ([_][]const u8{
        "/usr/bin/ruby",
        "/usr/lib/jellyfin/jellyfin",
        "/usr/bin/postdoc",
    }) |program| {
        s.exec = &.{program};
        try testing.expect(usesJit(s));
    }
}

test "non-exec gate seals RLIMIT_NOFILE and kills untrusted execveat" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    const pid = linux.fork();
    if (linux.errno(pid) != .SUCCESS) return error.ForkFailed;
    if (pid == 0) {
        _ = linux.prctl(@backingInt(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0);
        _ = linux.setrlimit(.NOFILE, &.{ .cur = 64, .max = 64 });
        const fd = linux.open(
            "/dev/null",
            .{ .ACCMODE = .RDONLY, .PATH = true, .CLOEXEC = true },
            0,
        );
        if (linux.errno(fd) != .SUCCESS) linux.exit_group(2);
        const gate = prepareExecGate(fd) catch linux.exit_group(3);
        if (gate.fd != 63) linux.exit_group(4);
        var buf: [seal.max_filter]seal.Filter = undefined;
        const filter = seal.buildServiceFilter(&buf, .initMany(&.{ .stdio, .rpath }), gate);
        _ = seal.install(filter, false) catch linux.exit_group(5);
        // flags == 0 returns ENOSYS cleanly.
        const probe = linux.syscall5(.execveat, gate.fd, @intCast(gate.empty_path), 0, 0, 0);
        if (linux.errno(probe) != .NOSYS) linux.exit_group(6);
        // Closing gate.fd leaves it >= rlim_max, so reopening cannot reach it.
        _ = linux.close(@intCast(gate.fd));
        var rlim: linux.rlimit = undefined;
        if (linux.errno(linux.getrlimit(.NOFILE, &rlim)) != .SUCCESS or rlim.max != 63)
            linux.exit_group(7);
        // Calling execveat from outside the trampoline kills the process with SIGSYS.
        const argv = [_:null]?[*:0]const u8{null};
        _ = linux.syscall5(
            .execveat,
            gate.fd,
            @intCast(gate.empty_path),
            @intFromPtr(&argv),
            @intFromPtr(&argv),
            0x1000,
        );
        linux.exit_group(8);
    }
    var status: u32 = 0;
    _ = linux.waitpid(@intCast(pid), &status, 0);
    try testing.expectEqual(@as(u32, @backingInt(linux.SIG.SYS)), status & 0x7f);
}
