//! leash: start a service someone else wrote, as its own user, on a leash.
//!
//! On a machine without a shell, runsv can only run ./run, with no
//! arguments, as root. For our own programs that is enough: they give root
//! up themselves. A program someone else wrote (nginx, postgres, grype) needs
//! its user, arguments and environment given to it, and cannot confine
//! itself. /etc/sv/NAME/run is a link to leash, which reads
//! /etc/sv/NAME/service and starts the service as that file says:
//!
//!     # nginx, as its own user, serving the status page.
//!     exec    /usr/bin/nginx
//!     before  /usr/bin/nginx -t -q
//!     user    nginx
//!     listen  tcp/80
//!     read    /etc/nginx /data/svc/status/www
//!
//! One directive a line: a key, then words. Double quotes around a whole
//! word let it hold spaces (env "GREETING=hello world"); there are no
//! escapes, variables or expansions. A # that starts a word starts a
//! comment. lib/service.zig reads it, for leash, howl, seal and the build
//! alike.
//!
//!     exec PROGRAM ARG...     what runs; required, once
//!     before PROGRAM ARG...   run first, in order, leashed; each must exit 0
//!     user NAME               whom it runs as; required, once; never root
//!     listen tcp/PORT...      ports it may bind; one below 1024 brings
//!                             CAP_NET_BIND_SERVICE, and no other capability
//!     connect tcp/PORT...     ports it may reach; without it, none
//!     read PATH...            read beyond the floor (below)
//!     write PATH...           read and write beyond its own directories
//!     run PROGRAM...          other programs it may start. Landlock grants
//!                             exec per file, so a multi-call binary (busybox,
//!                             Wolfi's coreutils, whose applets are symlinks
//!                             to one file) is all-or-nothing: naming one
//!                             applet allows them all. What bounds them then
//!                             is the floor, the capabilities and the network,
//!                             not the names.
//!     requires PATH...        stay down unless each exists
//!     pledge PROMISE...       the system calls it may make, in promises
//!                             (lib/seal.zig); required, once
//!     env NAME=VALUE          its environment, otherwise only PATH
//!     secret NAME PATH        a variable read from a file; never logged
//!     config NAME PATH [optional]
//!                             copy a /run/config file to this service's
//!                             /run/svc/SERVICE/NAME, mode 0600; never logged.
//!                             NAME is a setting's, [a-z][a-z0-9-]*: howl
//!                             pack's --NAME.
//!                             Missing, it keeps the service down, unless
//!                             optional: then there is no copy
//!     setting NAME TYPE[...] [required] [as KEY]
//!                             a value it takes from the machine: from
//!                             the file a `config settings PATH` names,
//!                             which may be missing
//!     render FORMAT FILE [from PATH]
//!                             where its settings go: env, json or conf, in
//!                             /run/svc/SERVICE/FILE (lib/settings.zig)
//!     nofile N                its limit on open files
//!     memory N                its resident memory ceiling, in MiB: the
//!                             service's cgroup memory.max, so one service
//!                             cannot exhaust the machine's memory. A
//!                             ceiling on memory held, not address space
//!                             reserved, so the JVM and V8 fit under it.
//!     root /oci/NAME          an image baked into the root (docs/design/adhoc.md):
//!                             the service runs inside it, and every path
//!                             above is the image's. leash enters it as
//!                             root, before it builds a rule or gives root
//!                             up, so the image's links resolve inside it.
//!                             Its floor is the image, readable; /tmp, /run
//!                             and /data, which init bound from
//!                             /run/svc/NAME, its run/ and /data/svc/NAME;
//!                             and the devices init bound in. No render:
//!                             service-config is not there
//!     dir PATH                where it starts, inside its root; /data otherwise
//!
//! Every service is also held to 4096 tasks, processes and threads together
//! (its cgroup's pids.max), so one that forks or spawns without end stops
//! there, not when the machine has no process left for anyone else.
//!
//! Every service also gets /run/svc/NAME and, while /data is usable,
//! /data/svc/NAME, owned by its user and its working directory; and the
//! floor: read /usr, /proc, /sys/devices/system/cpu (how many CPUs there
//! are), /etc/ssl and the few files in /etc that every
//! program reads (passwd, group, hosts, resolv.conf, nsswitch.conf,
//! ld.so.cache, localtime), and the console and /dev/null, /dev/zero and
//! /dev/urandom.
//!
//! leash reads nothing from outside the image but the secrets it is told
//! of. It checks the whole file before it does anything. As root, it then
//! checks requirements, reads secrets, makes the service's directories and
//! sets its limits; builds a Landlock ruleset of the paths, programs and
//! ports above; and gives root up for good: groups, gid and uid, every
//! capability but the one a low port needs, no_new_privs, and a check that
//! root cannot be had back. Then the ruleset applies, with Landlock's
//! scoping (no signals or abstract UNIX sockets outside the service), and
//! leash renders the service's settings with service-config, as the
//! service, and runs each `before`; then a seccomp filter of the service's
//! promises, stacked on the seal, whose refusals seal-watch answers and
//! says, and leash becomes the service. Nothing of leash runs after that,
//! so the service pays nothing for it.
//!
//! A promise is a class of work (docs/design/pledge.md, System calls:
//! promises): `stdio rpath inet listen` for a server that reads files and
//! takes connections. leash becomes the service by executing an open
//! descriptor of its program, which a pledge without exec still allows,
//! and Landlock lets it execute nothing but that program and, for one
//! dynamically linked, its ELF loader; `pledge exec` lets it run the
//! programs its `run` lines name too. The loader, run itself, would load
//! any program the service can read where the mount allows running one:
//! the image's /usr, never /data, /run or /tmp, which are noexec. What it
//! loads stays this service, under its user, Landlock and pledge
//! (docs/design/pledge.md, Not covered).
//!
//! What cannot change by waiting, a bad line, a missing requirement or a
//! `before` that fails, parks the service: one line on the console says
//! why, and runsv is told to keep it down. A path another service has not
//! made yet is not that: leash exits, and runsv tries again in a second.
//! The `before` programs run before the pledge, under the seal and the
//! rest of the leash.

const std = @import("std");
const seal = @import("seal");
const settings = @import("settings");
const sandbox = @import("sandbox");
const service = @import("service");
const cmdline = @import("cmdline");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const linux = std.os.linux;

const path_env = "/usr/sbin:/usr/bin:/sbin:/bin";
const max_file = 64 << 10;
const max_secret = 4 << 10;
/// Every service's tasks, processes and threads together: pids.max.
const max_tasks = 4096;
const service_config = "/usr/lib/werewolf/service-config";

/// What failed, for the line that says so.
var why_buf: [512]u8 = undefined;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();

    // Whatever runsv left open goes at exec; leash's own files close too.
    _ = linux.close_range(3, std.math.maxInt(linux.fd_t), .{ .UNSHARE = false, .CLOEXEC = true });
    // runsv hands fd 0 the console, write-only: a service that kept it could
    // forge log lines there (WEBSHELL_VULNS #1). It reads nothing from a
    // person, so fd 0 becomes /dev/null; it logs on fd 1 and 2, which runsv
    // routes.
    // Not CLOEXEC: with fd 0 closed, the open lands on 0, and stays.
    const null_fd = linux.open("/dev/null", .{ .ACCMODE = .RDONLY }, 0);
    if (linux.errno(null_fd) != .SUCCESS) {
        record(io, .{
            .event = "warning",
            .why = "cannot open /dev/null; fd 0 stays as runsv left it",
            .errno = @tagName(linux.errno(null_fd)),
        });
    } else if (null_fd != 0) {
        _ = linux.dup2(@intCast(null_fd), 0);
        _ = linux.close(@intCast(null_fd));
    }
    // runsv's control pipe, opened while root, so a service can be parked
    // from any step, before or after root is given up.
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

    const text = Dir.cwd().readFileAlloc(io, "service", gpa, .limited(max_file)) catch |err|
        l.fail(.park, "./service: {s}", .{@errorName(err)});
    var bad: service.Bad = .{};
    const s = service.parse(gpa, text, &bad) catch
        l.fail(.park, "./service, line {d}: {s}", .{ bad.line, bad.why });

    const passwd = Dir.cwd().readFileAlloc(io, "/etc/passwd", gpa, .limited(1 << 20)) catch "";
    const user = lookupUser(passwd, s.user) orelse
        l.fail(.park, "no user {s} in /etc/passwd", .{s.user});
    if (user.uid == 0 or user.gid == 0) l.fail(.park, "{s} is root's", .{s.user});

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
        const value = readSecret(io, gpa, sec[1]) catch |err|
            l.fail(.park, "secret {s}: {s}: {s}", .{ sec[0], sec[1], @errorName(err) });
        try env.put(sec[0], value);
    }
    // Read only the files the image names, while root. Write their copies
    // only AFTER dropping root and entering Landlock: a service cannot use
    // a link or a restart race to make a privileged writer act for it.
    // A service with settings may be given none: its settings file, missing,
    // is an empty object, and the image's defaults hold.
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
    own(l, run_dir, user);
    if (!nodata) {
        _ = linux.mkdir("/data/svc", 0o755);
        own(l, data_dir, user);
    }
    if (s.nofile) |n| {
        if (linux.errno(linux.setrlimit(.NOFILE, &.{ .cur = n, .max = n })) != .SUCCESS)
            l.fail(.park, "nofile {d}: refused", .{n});
    }
    // The service's cgroup (cmd/init made /run/cgroup/svc with memory and
    // pids delegated): its whole process tree lives here, so `memory` caps
    // its resident memory -- not its address space, which the JVM and V8
    // over-reserve -- and its finish reaper kills the tree, detached
    // children included, when it stops. Joined as root, before the drop, so
    // the service cannot leave it or raise its own cap. Where cgroup2 is not
    // available (init said so), the service runs uncapped and unreaped, as
    // before.
    if (exists("/run/cgroup/svc")) {
        const dir = try gpa.printSentinel("/run/cgroup/svc/{s}", .{name}, 0);
        _ = linux.mkdir(dir, 0o755);
        if (s.memory) |mib| {
            var buf: [24]u8 = undefined;
            const max = std.mem.print(&buf, "{d}\n", .{@as(u64, mib) << 20}) catch unreachable;
            if (!writeIn(gpa, dir, "memory.max", max))
                l.fail(.park, "memory {d}: cannot set memory.max", .{mib});
        }
        if (!writeIn(gpa, dir, "pids.max", std.fmt.comptimePrint("{d}\n", .{max_tasks})))
            l.fail(.park, "cannot set pids.max", .{});
        var pid_buf: [24]u8 = undefined;
        const pid = std.mem.print(&pid_buf, "{d}\n", .{linux.getpid()}) catch unreachable;
        if (!writeIn(gpa, dir, "cgroup.procs", pid)) l.fail(.park, "cannot join its cgroup", .{});
    } else if (s.memory != null) {
        record(io, .{ .event = "uncapped", .service = name, .why = "no cgroup2" });
    }

    // A service with a root runs inside the image beneath it. leash enters
    // it here, as root and before any rule: every path from here on, the
    // floor, its programs, its own places, is the image's and resolves
    // inside it, links and all, and nothing of the machine is reachable
    // but what init bound in (cmd/init/oci.zig). Its /tmp and /data are
    // /run/svc/NAME and /data/svc/NAME, bound there, made and owned above.
    if (s.root) |r| {
        const rz = try gpa.dupeSentinel(u8, r, 0);
        if (linux.errno(linux.chroot(rz)) != .SUCCESS or linux.errno(linux.chdir("/")) != .SUCCESS)
            l.fail(.park, "root {s}: cannot enter it", .{r});
    }
    const own_run: [:0]const u8 = if (s.root != null) "/tmp" else run_dir;
    const own_data: [:0]const u8 = if (s.root != null) "/data" else data_dir;
    // An image logs by reopening /dev/stdout and /dev/stderr, which lead
    // through /proc/self/fd to runsv's pipes, and a pipe reopened by path
    // is checked like a file: root's, mode 0600. Given to the service's
    // user, they open; what they carry goes where it always did.
    if (s.root != null) for ([_]i32{ 1, 2 }) |fd| {
        _ = linux.fchown(fd, user.uid, user.gid);
    };

    const rules = sandbox.Ruleset.init() catch |err| l.fail(
        .park,
        "Landlock: {s}; this kernel cannot leash a service",
        .{sandbox.whyNot(gpa, err)},
    );
    if ((s.listen.len > 0 or s.connect.len > 0) and rules.abi < 4)
        l.fail(.park, "Landlock ABI {d} has no TCP rules", .{rules.abi});
    const floor_rules: []const Floor = if (s.root != null) &rooted_floor else &floor;
    for (floor_rules) |f| allow(rules, f.path, f.access, .optional) catch {};
    for ([_][:0]const u8{ "/proc/self/fd/1", "/proc/self/fd/2" }) |fd|
        allow(rules, fd, sandbox.write_file, .optional) catch {};
    allow(rules, own_run, write_tree, .own) catch |err|
        l.fail(.park, "{s}: {s}", .{ own_run, sandbox.whyNot(gpa, err) });
    if (!nodata) allow(rules, own_data, write_tree, .own) catch |err|
        l.fail(.park, "{s}: {s}", .{ own_data, sandbox.whyNot(gpa, err) });
    // And an image's /run, where it keeps its pid file and sockets, bound
    // from its own /run/svc/NAME/run (cmd/init/oci.zig).
    if (s.root != null) allow(rules, "/run", write_tree, .own) catch |err|
        l.fail(.park, "/run: {s}", .{sandbox.whyNot(gpa, err)});
    for (s.read) |p| allowPath(l, rules, gpa, p, read_tree, nodata);
    for (s.write) |p| allowPath(l, rules, gpa, p, write_tree, nodata);
    for (s.run) |p| allowProgram(l, rules, gpa, p);
    allowProgram(l, rules, gpa, s.exec[0]);
    for (s.before) |b| allowProgram(l, rules, gpa, b[0]);
    if (s.render) |r| {
        allowProgram(l, rules, gpa, service_config);
        if (r.from) |from| allowPath(l, rules, gpa, from, sandbox.read_file, nodata);
    }
    for (s.listen) |port| rules.port(sandbox.bind_tcp, port) catch |err|
        l.fail(.park, "listen tcp/{d}: {s}", .{ port, sandbox.whyNot(gpa, err) });
    for (s.connect) |port| rules.port(sandbox.connect_tcp, port) catch |err|
        l.fail(.park, "connect tcp/{d}: {s}", .{ port, sandbox.whyNot(gpa, err) });

    const cwd: [:0]const u8 = if (s.dir) |d|
        try gpa.dupeSentinel(u8, d, 0)
    else if (nodata)
        own_run
    else
        own_data;
    const cd = linux.chdir(cwd);
    if (linux.errno(cd) != .SUCCESS) record(io, .{
        .event = "warning",
        .service = name,
        .why = "cannot enter its directory; it starts where runsv did",
        .dir = cwd,
        .errno = @tagName(linux.errno(cd)),
    });
    const low_port = for (s.listen) |p| {
        if (p < 1024) break true;
    } else false;
    dropTo(user, low_port) catch |err| l.fail(.park, "giving root up: {s}", .{@errorName(err)});

    // --- leashed --------------------------------------------------------------

    rules.restrict() catch |err| l.fail(.park, "Landlock: {s}", .{sandbox.whyNot(gpa, err)});
    for (s.configs, configs) |cfg, value| {
        copyConfig(own_run, try gpa.dupeSentinel(u8, cfg.name, 0), value) catch |err|
            l.fail(.park, "config {s}: {s}", .{ cfg.name, @errorName(err) });
    }
    // The pledge, as the words a service file says it in.
    var pledge: std.ArrayList([]const u8) = .empty;
    var promises = s.pledge.iterator();
    while (promises.next()) |p| try pledge.append(gpa, @tagName(p));
    const learn = learning();
    record(
        io,
        .{
            .event = "start",
            .service = name,
            .user = s.user,
            .exec = s.exec[0],
            .root = s.root,
            .listen = s.listen,
            .connect = s.connect,
            .landlock = rules.abi,
            .pledge = pledge.items,
            // false while the machine learns: no filter of its own.
            .pledged = !learn,
        },
    );

    if (s.render) |r| renderSettings(l, gpa, run_dir, s, r, &env);
    for (s.before) |argv| {
        var child = std.process.spawn(
            io,
            .{ .argv = argv, .environ_map = &env, .stdin = .ignore },
        ) catch |err| l.fail(.park, "before {s}: {s}", .{ argv[0], @errorName(err) });
        const term = child.wait(io) catch |err|
            l.fail(.park, "before {s}: {s}", .{ argv[0], @errorName(err) });
        if (term != .exited or term.exited != 0) l.fail(.park, "before {s} failed", .{argv[0]});
    }
    // The program, open before the pledge: becoming it is executing this
    // descriptor. A pledge without exec still allows that one execveat, and
    // Landlock lets it run only this program.
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

    // The service's own filter, refusing with ENOSYS what its pledge does
    // not promise: no listener, so no_new_privs (set in dropTo) is enough.
    // A machine learning (werewolf.seal=learn, a DEV=1 build) installs none,
    // so every call reaches the machine seal, which records it.
    if (!learn) {
        var filter_buf: [seal.max_filter]seal.Filter = undefined;
        const filter = seal.buildFilter(&filter_buf, s.pledge, true);
        _ = seal.install(filter, false) catch |e| l.fail(.park, "pledge: {s}", .{@errorName(e)});
    }
    const rc = linux.syscall5(
        .execveat,
        prog_rc,
        @intFromPtr(""),
        @intFromPtr(argv.ptr),
        @intFromPtr(envp.ptr),
        0x1000, // AT_EMPTY_PATH
    );
    l.fail(.park, "exec {s}: {s}", .{ s.exec[0], @tagName(linux.errno(rc)) });
}

/// Whether the machine is learning its pledges (werewolf.seal=learn, a
/// DEV=1 build), when a service installs no filter of its own, so every
/// call reaches the machine seal to be recorded. Read as init read it, by
/// lib/cmdline.zig, from the kernel's line, which root cannot rewrite, as
/// it could init's record in /run; a line it refuses is no learning.
fn learning() bool {
    var buf: [4096]u8 = undefined;
    const fd = linux.open("/proc/cmdline", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(fd) != .SUCCESS) return false;
    defer _ = linux.close(@intCast(fd));
    const n = linux.read(@intCast(fd), &buf, buf.len);
    if (linux.errno(n) != .SUCCESS) return false;
    var refused: cmdline.Failure = .{};
    const c = cmdline.parse(buf[0..n], &refused) orelse return false;
    return c.seal == .learn and exists("/usr/share/werewolf/dev");
}

// --- as root ---------------------------------------------------------------------

/// dir, made if need be, a directory of the user's own, 0755. A directory
/// someone else owns becomes the user's, but only itself: what is inside
/// stays as it is, since a recursive chown as root is how a user is handed
/// a file it should not have.
fn own(l: Leash, dir: [:0]const u8, user: User) void {
    _ = linux.mkdir(dir, 0o755);
    var st: linux.Statx = undefined;
    if (linux.errno(linux.statx(
        linux.AT.FDCWD,
        dir,
        linux.AT.SYMLINK_NOFOLLOW,
        .{ .TYPE = true, .UID = true, .GID = true },
        &st,
    )) != .SUCCESS or
        st.mode & linux.S.IFMT != linux.S.IFDIR)
        l.fail(.park, "{s} is not a directory", .{dir});
    if (st.uid != user.uid or st.gid != user.gid) {
        if (linux.errno(linux.fchownat(
            linux.AT.FDCWD,
            dir,
            user.uid,
            user.gid,
            linux.AT.SYMLINK_NOFOLLOW,
        )) != .SUCCESS)
            l.fail(.park, "cannot give {s} to its user", .{dir});
    }
}

/// A secret: one line, at most 4 KiB, without its newline.
fn readSecret(io: Io, gpa: Allocator, path: []const u8) ![]const u8 {
    const text = try Dir.cwd().readFileAlloc(io, path, gpa, .limited(max_secret));
    const value = std.mem.trimEnd(u8, text, "\n");
    if (value.len == 0) return error.Empty;
    for (value) |c| if (c == 0 or c == '\n') return error.NotOneLine;
    return value;
}

/// Called as the service, inside Landlock, once its `config settings` copy
/// is made: have service-config render them, given the service file's
/// declarations on its standard input, so that the tar's JSON is
/// parsed by neither root nor leash. An env file it rendered joins the
/// service's environment, and nothing but the keys declared may.
fn renderSettings(
    l: Leash,
    gpa: Allocator,
    run_dir: [:0]const u8,
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
        .argv = &.{ service_config, run_dir },
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

/// value into dir/name, 0600, replacing whatever was there; null, an
/// optional config the machine does not have, leaves nothing there.
/// Called as the service, inside Landlock. Never truncate an existing
/// inode (which could be a hard link); replace the name with a new 0600
/// file. Pin the directory, refuse symlinks and fail closed on a race.
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
        // Another service makes it; runsv starts this one again in a
        // second. Not while /data is unavailable: it would not appear.
        error.FileNotFound => l.fail(
            if (nodata and std.mem.startsWith(u8, path, "/data/")) .park else .retry,
            "{s} is not there yet",
            .{path},
        ),
        else => l.fail(.park, "{s}: {s}", .{ path, sandbox.whyNot(gpa, err) }),
    };
}

/// A program it may start, and the ELF interpreter that loads it, which
/// the kernel opens for execution too.
fn allowProgram(l: Leash, rules: sandbox.Ruleset, gpa: Allocator, path: []const u8) void {
    const z = gpa.dupeSentinel(u8, path, 0) catch l.fail(.park, "out of memory", .{});
    allow(rules, z, run_file, .follow) catch |err|
        l.fail(.park, "{s}: {s}", .{ path, sandbox.whyNot(gpa, err) });
    var head: [4096]u8 = undefined;
    const fd = linux.open(z, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(fd) != .SUCCESS) l.fail(.park, "{s}: cannot read it", .{path});
    defer _ = linux.close(@intCast(fd));
    const n = linux.pread(@intCast(fd), &head, head.len, 0);
    if (linux.errno(n) != .SUCCESS) l.fail(.park, "{s}: cannot read it", .{path});
    const interp = interpreter(head[0..n]) catch
        l.fail(.park, "{s}: not an ELF program leash can read", .{path});
    if (interp) |i| {
        const iz = gpa.dupeSentinel(u8, i, 0) catch l.fail(.park, "out of memory", .{});
        allow(rules, iz, run_file, .follow) catch |err|
            l.fail(.park, "{s}'s loader {s}: {s}", .{ path, i, sandbox.whyNot(gpa, err) });
    }
}

/// The ELF interpreter a 64-bit little-endian program names (PT_INTERP),
/// or null for a static one, from the program's first bytes.
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

/// Become user for good: no groups but its own, no capability but
/// CAP_NET_BIND_SERVICE where a low port needs it, now or in anything it
/// runs, and no way back to root.
fn dropTo(user: User, bind_low: bool) !void {
    // A capability the kernel does not know (EINVAL) is one it cannot
    // grant; any other failure leaves the set whole, and is an error.
    var cap: usize = 0;
    while (cap < 64) : (cap += 1) {
        if (bind_low and cap == linux.CAP.NET_BIND_SERVICE) continue;
        const rc = linux.prctl(@backingInt(linux.PR.CAPBSET_DROP), cap, 0, 0, 0);
        if (linux.errno(rc) != .INVAL) try check(rc);
    }
    if (bind_low) try check(linux.prctl(@backingInt(linux.PR.SET_KEEPCAPS), 1, 0, 0, 0));
    try check(linux.setgroups(0, &[_]linux.gid_t{}));
    try check(linux.setresgid(user.gid, user.gid, user.gid));
    try check(linux.setresuid(user.uid, user.uid, user.uid));
    const keep: u32 = if (bind_low) 1 << linux.CAP.NET_BIND_SERVICE else 0;
    var hdr: CapHeader = .{};
    const caps = [2]CapSets{ .{ .effective = keep, .permitted = keep, .inheritable = keep }, .{} };
    try check(linux.syscall2(.capset, @intFromPtr(&hdr), @intFromPtr(&caps)));
    // Ambient, so it survives exec into a program with no file capabilities.
    if (bind_low) try check(linux.prctl(
        @backingInt(linux.PR.CAP_AMBIENT),
        linux.PR.CAP_AMBIENT_RAISE,
        linux.CAP.NET_BIND_SERVICE,
        0,
        0,
    ));
    try check(linux.prctl(@backingInt(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0));
    if (linux.errno(linux.setresuid(0, 0, 0)) == .SUCCESS) return error.StillRoot;
}

fn check(rc: usize) !void {
    if (linux.errno(rc) != .SUCCESS) return error.SystemCall;
}

/// The kernel's struct __user_cap_header_struct (lib/sandbox.zig).
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

// Rights, of lib/sandbox.zig's: a tree read, files and listings; a tree
// written, everything but devices; and a program run.
const read_tree: u64 = sandbox.read_file | sandbox.read_dir;
const write_tree: u64 = read_tree | sandbox.write_file | sandbox.remove_dir |
    sandbox.remove_file | sandbox.make_dir | sandbox.make_reg | sandbox.make_sock |
    sandbox.make_fifo | sandbox.make_sym | sandbox.refer | sandbox.truncate;
const run_file: u64 = sandbox.execute | sandbox.read_file;

// openat2(2), for a path resolved with no link in it.
const OpenHow = extern struct { flags: u64, mode: u64, resolve: u64 };
const O_PATH = 0o10000000;
const O_CLOEXEC = 0o2000000;
const RESOLVE_NO_MAGICLINKS = 0x02;
const RESOLVE_NO_SYMLINKS = 0x04;

const Floor = struct { path: [:0]const u8, access: u64 };
const floor = [_]Floor{
    .{ .path = "/usr", .access = read_tree },
    .{ .path = "/proc", .access = read_tree },
    .{ .path = "/sys/devices/system/cpu", .access = read_tree },
    .{ .path = "/etc/passwd", .access = sandbox.read_file },
    .{ .path = "/etc/group", .access = sandbox.read_file },
    .{ .path = "/etc/hosts", .access = sandbox.read_file },
    .{ .path = "/etc/resolv.conf", .access = sandbox.read_file },
    .{ .path = "/etc/nsswitch.conf", .access = sandbox.read_file },
    .{ .path = "/etc/ld.so.cache", .access = sandbox.read_file },
    .{ .path = "/etc/localtime", .access = sandbox.read_file },
    .{ .path = "/etc/ssl", .access = read_tree },
    .{ .path = "/dev/null", .access = sandbox.read_file | sandbox.write_file },
    .{ .path = "/dev/zero", .access = sandbox.read_file },
    .{ .path = "/dev/urandom", .access = sandbox.read_file },
};

/// The floor of a service with a root, inside it: the image, readable
/// whole, /proc and the two writable places beneath it included, and the
/// devices init bound in (cmd/init/oci.zig). Nothing of the machine's own
/// /etc or /usr is there to be read.
const rooted_floor = [_]Floor{
    .{ .path = "/", .access = read_tree },
    .{ .path = "/dev/null", .access = sandbox.read_file | sandbox.write_file },
    .{ .path = "/dev/zero", .access = sandbox.read_file },
    .{ .path = "/dev/full", .access = sandbox.read_file | sandbox.write_file },
    .{ .path = "/dev/random", .access = sandbox.read_file },
    .{ .path = "/dev/urandom", .access = sandbox.read_file },
};

/// How a path is resolved. follow: the image's programs, through its
/// links (/lib to usr/lib). plain: a service file's read and write
/// paths, with no link anywhere in them: one may lie in another
/// service's directory, under /data, which follows links, and that
/// service could make the name a link to what it wants this one
/// granted. own: the service's directories, a link at the end refused.
/// optional: the floor, which may be absent.
const How = enum { follow, plain, optional, own };

/// access beneath path, in rules: on a directory, all of it; on a file,
/// the file's rights alone.
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

/// name's uid and gid in an /etc/passwd.
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

/// Write text to dir/file, which must already exist (a cgroup control
/// file): opened write-only, no create, no truncate.
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

/// The service being started, and how to stop it.
const Leash = struct {
    io: Io,
    /// runsv's control pipe, to park the service; null if it did not open.
    ctl: ?linux.fd_t,
    name: []const u8,

    const Outcome = enum { park, retry };

    /// Say why on the console, then stop: parked, or for runsv to try again.
    fn fail(l: Leash, how: Outcome, comptime fmt: []const u8, args: anytype) noreturn {
        const why = std.mem.print(&why_buf, fmt, args) catch fmt;
        const event = if (how == .park) "down" else "retry";
        record(l.io, .{ .event = event, .service = l.name, .why = why });
        if (how == .park) if (l.ctl) |fd| {
            _ = linux.write(fd, "d", 1);
        };
        std.process.exit(1);
    }
};

/// One JSON line on the console.
fn record(io: Io, fields: anytype) void {
    var buf: [2048]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    w.writeAll("leash: ") catch return;
    std.json.Stringify.value(fields, .{}, &w) catch return;
    w.writeByte('\n') catch return;
    Io.File.stdout().writeStreamingAll(io, w.buffered()) catch {};
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
    std.mem.writeInt(u16, elf[0x38..0x3a], 60, .little); // headers past what was read
    try testing.expectError(error.NotElf, interpreter(&elf));
    try testing.expectError(error.NotElf, interpreter("#!/bin/sh\n"));
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
    // An optional config the machine lacks leaves no stale copy behind.
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
