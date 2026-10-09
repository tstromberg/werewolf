//! service parses a service file, /etc/sv/NAME/service, for every program
//! that reads one, so they all accept the same files. See lib/README.md.

const std = @import("std");
const seal = @import("seal");
const settings = @import("settings");
const Allocator = std.mem.Allocator;

pub const Service = struct {
    exec: []const []const u8 = &.{},
    before: []const []const []const u8 = &.{},
    user: []const u8 = "",
    listen: []const u16 = &.{},
    connect: []const u16 = &.{},
    /// sockets are the pathname UNIX sockets a `connect` line names.
    sockets: []const []const u8 = &.{},
    read: []const []const u8 = &.{},
    write: []const []const u8 = &.{},
    run: []const []const u8 = &.{},
    requires: []const []const u8 = &.{},
    env: []const [2][]const u8 = &.{},
    secrets: []const [2][]const u8 = &.{},
    configs: []const Config = &.{},
    settings: []const settings.Setting = &.{},
    render: ?settings.Render = null,
    nofile: ?u32 = null,
    memory: ?u32 = null,
    /// cpu is the service's cpu.weight, its share of contended CPUs; null
    /// keeps the kernel's 100 (docs/design/cpu-and-first-run.md).
    cpu: ?u16 = null,
    share: Share = .strict,
    pledge: seal.Set = .empty,
    /// root is the OCI image the service runs in, beneath /oci; dir is
    /// where it starts there.
    root: ?[]const u8 = null,
    dir: ?[]const u8 = null,
    /// narrow lists the programs it runs on a narrower leash.
    narrow: []const Narrow = &.{},
};

/// Narrow is a program its service runs on a narrower leash, by the link
/// /etc/sv/NAME/narrow/PROGRAM (docs/design/narrow.md): promises within the
/// service's, no network, and the paths beyond its floor that it may read
/// and write, within the service's. memory caps what it may allocate, in MiB.
pub const Narrow = struct {
    program: []const u8,
    pledge: seal.Set = .empty,
    read: []const []const u8 = &.{},
    write: []const []const u8 = &.{},
    memory: ?u32 = null,
};

/// floor is what leash lets every service without a root read beyond its
/// file's lines; of it, the service may write only /dev/null.
pub const floor = [_][:0]const u8{
    "/usr",             "/proc",              "/sys/devices/system/cpu",
    "/etc/passwd",      "/etc/group",         "/etc/hosts",
    "/etc/resolv.conf", "/etc/nsswitch.conf", "/etc/ld.so.cache",
    "/etc/localtime",   "/etc/ssl",           "/dev/null",
    "/dev/zero",        "/dev/urandom",
};

/// narrowing is what a service with narrowed programs must promise: their
/// leash reads its file, stacks Landlock and seccomp, and runs them.
const narrowing: seal.Set = .initMany(&.{ .rpath, .exec, .landlock, .seccomp });

/// network is what no narrowed program may promise.
const network: seal.Set = .initMany(&.{ .inet, .unix, .netlink, .packet, .connect, .listen });

/// Config is a `config` line: the copy's name in the service's directory,
/// its source beneath /run/config, and whether the service runs without it.
pub const Config = struct { name: []const u8, path: []const u8, optional: bool = false };

/// Share says who may enter the service's directories, /run/svc/NAME and
/// /data/svc/NAME. strict (0700) admits only the service's user. shared
/// (0711) lets others open a path they already know, such as a socket or a
/// file another service reads. browseable (0755) also lets them list it.
pub const Share = enum {
    strict,
    shared,
    browseable,

    pub fn mode(s: Share) u32 {
        return switch (s) {
            .strict => 0o700,
            .shared => 0o711,
            .browseable => 0o755,
        };
    }
};

/// Bad is the line that is wrong, and why.
pub const Bad = struct { line: usize = 0, why: []const u8 = "" };

/// parse reads and checks a whole service file. On a bad line it sets bad
/// and returns error.Invalid.
pub fn parse(gpa: Allocator, text: []const u8, bad: *Bad) !Service {
    var exec: ?[]const []const u8 = null;
    var user: ?[]const u8 = null;
    var nofile: ?u32 = null;
    var memory: ?u32 = null;
    var cpu: ?u16 = null;
    var share: ?Share = null;
    var pledge: ?seal.Set = null;
    var root: ?[]const u8 = null;
    var dir: ?[]const u8 = null;
    var before: std.ArrayList([]const []const u8) = .empty;
    var listen: std.ArrayList(u16) = .empty;
    var connect: std.ArrayList(u16) = .empty;
    var sockets: std.ArrayList([]const u8) = .empty;
    var read: std.ArrayList([]const u8) = .empty;
    var write: std.ArrayList([]const u8) = .empty;
    var run: std.ArrayList([]const u8) = .empty;
    var requires: std.ArrayList([]const u8) = .empty;
    var env: std.ArrayList([2][]const u8) = .empty;
    var secrets: std.ArrayList([2][]const u8) = .empty;
    var configs: std.ArrayList(Config) = .empty;
    var declared: std.ArrayList(settings.Setting) = .empty;
    var render: ?settings.Render = null;
    var narrowed: std.ArrayList(Narrowing) = .empty;

    var lines = std.mem.splitScalar(u8, text, '\n');
    var n: usize = 0;
    while (lines.next()) |line| {
        n += 1;
        bad.line = n;
        const words = try split(gpa, line, bad);
        if (words.len == 0) continue;
        const key = words[0];
        const args = words[1..];
        if (std.mem.eql(u8, key, "exec")) {
            if (exec != null) return invalid(bad, "exec twice");
            exec = try program(args, bad);
        } else if (std.mem.eql(u8, key, "before")) {
            try before.append(gpa, try program(args, bad));
        } else if (std.mem.eql(u8, key, "user")) {
            if (user != null) return invalid(bad, "user twice");
            if (args.len != 1 or !isName(args[0])) return invalid(bad, "user takes one plain name");
            if (std.mem.eql(u8, args[0], "root"))
                return invalid(bad, "user root: a service runs as a user of its own");
            user = args[0];
        } else if (std.mem.eql(u8, key, "listen")) {
            if (args.len == 0) return invalid(bad, "no ports");
            for (args) |a| try listen.append(gpa, try tcpPort(a, bad));
        } else if (std.mem.eql(u8, key, "connect")) {
            if (args.len == 0) return invalid(bad, "no ports or sockets");
            for (args) |a| if (a.len > 0 and a[0] == '/') {
                if (!isCleanPath(a) or std.mem.findScalar(u8, a[1..], '/') == null)
                    return invalid(bad, "a socket's path must be absolute, clean, in a directory");
                try sockets.append(gpa, a);
            } else try connect.append(gpa, try tcpPort(a, bad));
        } else if (std.mem.eql(u8, key, "read") or std.mem.eql(u8, key, "write") or
            std.mem.eql(u8, key, "run") or std.mem.eql(u8, key, "requires"))
        {
            if (args.len == 0) return invalid(bad, "no paths");
            const list = if (std.mem.eql(u8, key, "read"))
                &read
            else if (std.mem.eql(u8, key, "write"))
                &write
            else if (std.mem.eql(u8, key, "run"))
                &run
            else
                &requires;
            for (args) |a| {
                if (!isCleanPath(a))
                    return invalid(bad, "a path must be absolute, without . or .. or //");
                try list.append(gpa, a);
            }
        } else if (std.mem.eql(u8, key, "env")) {
            if (args.len != 1) return invalid(bad, "env takes one NAME=VALUE");
            const eq = std.mem.findScalar(u8, args[0], '=') orelse
                return invalid(bad, "env takes NAME=VALUE");
            if (!isVariable(args[0][0..eq])) return invalid(bad, "not a variable name");
            try env.append(gpa, .{ args[0][0..eq], args[0][eq + 1 ..] });
        } else if (std.mem.eql(u8, key, "secret")) {
            if (args.len != 2 or !isVariable(args[0]))
                return invalid(bad, "secret takes NAME and PATH");
            if (!isCleanPath(args[1]) or !std.mem.startsWith(u8, args[1], "/run/config/"))
                return invalid(bad, "secret source must be beneath /run/config");
            try secrets.append(gpa, .{ args[0], args[1] });
        } else if (std.mem.eql(u8, key, "config")) {
            const optional = args.len == 3 and std.mem.eql(u8, args[2], "optional");
            if ((args.len != 2 and !optional) or !settings.isName(args[0]))
                return invalid(bad, "config takes a NAME, [a-z][a-z0-9-]*, and PATH [optional]");
            if (!isCleanPath(args[1]) or !std.mem.startsWith(u8, args[1], "/run/config/"))
                return invalid(bad, "config source must be beneath /run/config");
            if (configs.items.len == 32) return invalid(bad, "at most 32 config files");
            for (configs.items) |cfg| if (std.mem.eql(u8, cfg.name, args[0]))
                return invalid(bad, "config name repeated");
            if (optional and std.mem.eql(u8, args[0], settings.input_file))
                return invalid(bad, "settings are optional already");
            try configs.append(gpa, .{ .name = args[0], .path = args[1], .optional = optional });
        } else if (std.mem.eql(u8, key, "setting")) {
            try declared.append(
                gpa,
                settings.parseSetting(args, &bad.why) catch return error.Invalid,
            );
        } else if (std.mem.eql(u8, key, "render")) {
            if (render != null) return invalid(bad, "render twice");
            render = settings.parseRender(args, &bad.why) catch return error.Invalid;
        } else if (std.mem.eql(u8, key, "pledge")) {
            if (pledge != null) return invalid(bad, "pledge twice");
            pledge = try promised(args, bad);
        } else if (std.mem.eql(u8, key, "narrow")) {
            try narrowLine(gpa, &narrowed, args, n, bad);
        } else if (std.mem.eql(u8, key, "nofile")) {
            if (nofile != null) return invalid(bad, "nofile twice");
            if (args.len != 1) return invalid(bad, "nofile takes one number");
            nofile = std.fmt.parseInt(u32, args[0], 10) catch
                return invalid(bad, "nofile takes a number");
            if (nofile.? == 0 or nofile.? > 1 << 20) return invalid(bad, "nofile is 1 to 1048576");
        } else if (std.mem.eql(u8, key, "memory")) {
            if (memory != null) return invalid(bad, "memory twice");
            memory = try mib(args, bad);
        } else if (std.mem.eql(u8, key, "cpu")) {
            if (cpu != null) return invalid(bad, "cpu twice");
            if (args.len != 1) return invalid(bad, "cpu takes one weight, 1 to 10000");
            cpu = std.fmt.parseInt(u16, args[0], 10) catch
                return invalid(bad, "cpu takes a weight, 1 to 10000");
            if (cpu.? == 0 or cpu.? > 10000) return invalid(bad, "cpu takes a weight, 1 to 10000");
        } else if (std.mem.eql(u8, key, "share")) {
            if (share != null) return invalid(bad, "share twice");
            if (args.len != 1) return invalid(bad, "share takes strict, shared or browseable");
            share = std.meta.stringToEnum(Share, args[0]) orelse
                return invalid(bad, "share takes strict, shared or browseable");
        } else if (std.mem.eql(u8, key, "root")) {
            if (root != null) return invalid(bad, "root twice");
            if (args.len != 1 or !isCleanPath(args[0]) or
                !std.mem.startsWith(u8, args[0], "/oci/") or
                std.mem.findScalar(u8, args[0]["/oci/".len..], '/') != null)
                return invalid(bad, "root takes one directory beneath /oci");
            root = args[0];
        } else if (std.mem.eql(u8, key, "dir")) {
            if (dir != null) return invalid(bad, "dir twice");
            if (args.len != 1 or !isCleanPath(args[0]))
                return invalid(bad, "dir takes one absolute path, inside the root");
            dir = args[0];
        } else return invalid(bad, "unknown key");
    }
    bad.line = 0;
    if (dir != null and root == null) return invalid(bad, "dir without root");
    if (root != null and render != null)
        return invalid(bad, "render under a root: service-config is not in the image");
    const promises = pledge orelse return invalid(bad, "no pledge: say what it does");
    if (render) |r| {
        settings.declare(gpa, declared.items, r, &bad.why) catch |err| switch (err) {
            error.Invalid => return error.Invalid,
            else => return err,
        };
        const sourced = for (configs.items) |cfg| {
            if (std.mem.eql(u8, cfg.name, settings.input_file)) break true;
        } else false;
        if (!sourced) return invalid(bad, "settings come from a `config settings PATH` line");
        for (configs.items) |cfg| if (std.mem.eql(u8, cfg.name, r.file))
            return invalid(bad, "a config has render's file name");
        if (r.format == .env) for (declared.items) |d| {
            for (env.items) |e| if (std.mem.eql(u8, e[0], d.key.?))
                return invalid(bad, "a setting's key is an env line's too");
            for (secrets.items) |e| if (std.mem.eql(u8, e[0], d.key.?))
                return invalid(bad, "a setting's key is a secret's too");
        };
    } else if (declared.items.len > 0) return invalid(bad, "setting without render");
    var s: Service = .{
        .exec = exec orelse return invalid(bad, "no exec"),
        .user = user orelse return invalid(bad, "no user"),
        .pledge = promises,
        .before = before.items,
        .listen = listen.items,
        .connect = connect.items,
        .sockets = sockets.items,
        .read = read.items,
        .write = write.items,
        .run = run.items,
        .requires = requires.items,
        .env = env.items,
        .secrets = secrets.items,
        .configs = configs.items,
        .settings = declared.items,
        .render = render,
        .nofile = nofile,
        .memory = memory,
        .cpu = cpu,
        .share = share orelse .strict,
        .root = root,
        .dir = dir,
    };
    s.narrow = try narrowWithin(gpa, s, narrowed.items, bad);
    return s;
}

/// Narrowing gathers one program's `narrow` lines; line is its first.
const Narrowing = struct {
    program: []const u8,
    line: usize,
    pledge: ?seal.Set = null,
    read: std.ArrayList([]const u8) = .empty,
    write: std.ArrayList([]const u8) = .empty,
    memory: ?u32 = null,
};

/// narrowLine adds a `narrow PROGRAM KEY WORD...` line, numbered line, to
/// the program's lines in list.
fn narrowLine(
    gpa: Allocator,
    list: *std.ArrayList(Narrowing),
    args: []const []const u8,
    line: usize,
    bad: *Bad,
) !void {
    if (args.len < 2)
        return invalid(bad, "narrow takes PROGRAM, then pledge, read, write or memory");
    const prog = (try program(args[0..1], bad))[0];
    const words = args[2..];
    const nw = for (list.items) |*x| {
        if (std.mem.eql(u8, x.program, prog)) break x;
    } else blk: {
        try list.append(gpa, .{ .program = prog, .line = line });
        break :blk &list.items[list.items.len - 1];
    };
    if (std.mem.eql(u8, args[1], "pledge")) {
        if (nw.pledge != null) return invalid(bad, "narrow pledge twice for one program");
        const set = try promised(words, bad);
        if (set.intersectWith(network).count() > 0) return invalid(
            bad,
            "a narrowed program has no network: no inet, unix, netlink, packet, connect or listen",
        );
        nw.pledge = set;
    } else if (std.mem.eql(u8, args[1], "read") or std.mem.eql(u8, args[1], "write")) {
        if (words.len == 0) return invalid(bad, "no paths");
        for (words) |a| {
            if (!isCleanPath(a))
                return invalid(bad, "a path must be absolute, without . or .. or //");
            const paths = if (std.mem.eql(u8, args[1], "read")) &nw.read else &nw.write;
            try paths.append(gpa, a);
        }
    } else if (std.mem.eql(u8, args[1], "memory")) {
        if (nw.memory != null) return invalid(bad, "narrow memory twice for one program");
        nw.memory = try mib(words, bad);
    } else return invalid(bad, "narrow PROGRAM takes pledge, read, write or memory");
}

/// narrowWithin checks each narrowed program against its service s and
/// returns them. On a fault it sets bad to the program's first line.
fn narrowWithin(gpa: Allocator, s: Service, list: []Narrowing, bad: *Bad) ![]const Narrow {
    const out = try gpa.alloc(Narrow, list.len);
    for (list, out) |*nw, *o| {
        bad.line = nw.line;
        if (s.root != null) return invalid(bad, "narrow under a root: leash is not in the image");
        for (s.run) |r| {
            if (std.mem.eql(u8, r, nw.program)) break;
        } else return invalid(bad, "a narrowed program must be named by a run line");
        const name = std.fs.path.basename(nw.program);
        for (list) |*other| if (other != nw and
            std.mem.eql(u8, std.fs.path.basename(other.program), name))
            return invalid(bad, "two narrowed programs share a name, which their links need");
        const set = nw.pledge orelse return invalid(bad, "a narrowed program needs a pledge");
        var lacking = set.differenceWith(s.pledge).iterator();
        if (lacking.next()) |p| return invalidFmt(
            gpa,
            bad,
            "narrow pledge {t}: the service does not promise it",
            .{p},
        );
        var needed = narrowing.differenceWith(s.pledge).iterator();
        if (needed.next()) |p| return invalidFmt(
            gpa,
            bad,
            "narrowing needs the service to promise {t}",
            .{p},
        );
        for (nw.read.items) |p| if (!reaches(s, null, p, false)) return invalidFmt(
            gpa,
            bad,
            "narrow read {s}: the service may not read it",
            .{p},
        );
        for (nw.write.items) |p| if (!reaches(s, null, p, true)) return invalidFmt(
            gpa,
            bad,
            "narrow write {s}: the service may not write it",
            .{p},
        );
        o.* = .{
            .program = nw.program,
            .pledge = set,
            .read = nw.read.items,
            .write = nw.write.items,
            .memory = nw.memory,
        };
    }
    bad.line = 0;
    return out;
}

/// reaches reports whether service s, named name, may read path, or write
/// it if write: within its read or write lines, its own directories or, to
/// read, the floor. Without a name, as at build, any service's directory
/// passes; leash checks again with it.
pub fn reaches(s: Service, name: ?[]const u8, path: []const u8, write: bool) bool {
    for (s.write) |p| if (within(path, p)) return true;
    if (write) {
        if (std.mem.eql(u8, path, "/dev/null")) return true;
    } else {
        for (s.read) |p| if (within(path, p)) return true;
        for (floor) |p| if (within(path, p)) return true;
    }
    for ([_][]const u8{ "/run/svc/", "/data/svc/" }) |dirs| {
        if (!std.mem.startsWith(u8, path, dirs)) continue;
        const rest = path[dirs.len..];
        const owner = rest[0 .. std.mem.findScalar(u8, rest, '/') orelse rest.len];
        if (owner.len > 0 and (name == null or std.mem.eql(u8, owner, name.?))) return true;
    }
    return false;
}

/// within reports whether path is dir or beneath it.
fn within(path: []const u8, dir: []const u8) bool {
    if (!std.mem.startsWith(u8, path, dir)) return false;
    return path.len == dir.len or std.mem.eql(u8, dir, "/") or path[dir.len] == '/';
}

fn invalid(bad: *Bad, why: []const u8) error{Invalid} {
    bad.why = why;
    return error.Invalid;
}

/// invalidFmt is invalid with a message that names what is wrong.
fn invalidFmt(
    gpa: Allocator,
    bad: *Bad,
    comptime fmt: []const u8,
    args: anytype,
) error{ Invalid, OutOfMemory } {
    return invalid(bad, gpa.print(fmt, args) catch return error.OutOfMemory);
}

/// promised returns the promises args name, at least one.
fn promised(args: []const []const u8, bad: *Bad) !seal.Set {
    if (args.len == 0) return invalid(bad, "pledge takes promises");
    var set: seal.Set = .empty;
    for (args) |a| set.insert(
        std.meta.stringToEnum(seal.Promise, a) orelse return invalid(bad, "no such promise"),
    );
    return set;
}

/// mib returns the one number of MiB args holds, 1 to 1048576.
fn mib(args: []const []const u8, bad: *Bad) !u32 {
    if (args.len != 1) return invalid(bad, "memory takes one number of MiB");
    const m = std.fmt.parseInt(u32, args[0], 10) catch
        return invalid(bad, "memory takes a number of MiB");
    if (m == 0 or m > 1 << 20) return invalid(bad, "memory is 1 to 1048576 MiB");
    return m;
}

/// split returns a line's words. Spaces or tabs separate words, double
/// quotes group them, and a # that starts a word ends the line.
fn split(gpa: Allocator, line: []const u8, bad: *Bad) ![]const []const u8 {
    var words: std.ArrayList([]const u8) = .empty;
    var i: usize = 0;
    while (i < line.len) {
        const c = line[i];
        if (c == ' ' or c == '\t' or c == '\r') {
            i += 1;
        } else if (c == '#') {
            break;
        } else if (c == '"') {
            const end = std.mem.findScalarPos(u8, line, i + 1, '"') orelse
                return invalid(bad, "a quote is not closed");
            if (end + 1 < line.len and line[end + 1] != ' ' and
                line[end + 1] != '\t') return invalid(bad, "a quote ends inside a word");
            try words.append(gpa, line[i + 1 .. end]);
            i = end + 1;
        } else {
            var end = i;
            while (end < line.len and line[end] != ' ' and line[end] != '\t' and
                line[end] != '\r') : (end += 1)
            {
                if (line[end] == '"') return invalid(bad, "a quote inside a word");
            }
            try words.append(gpa, line[i..end]);
            i = end;
        }
    }
    for (words.items) |w| for (w) |c| if (c < 0x20 or c == 0x7f)
        return invalid(bad, "a control character");
    return words.items;
}

fn program(args: []const []const u8, bad: *Bad) ![]const []const u8 {
    if (args.len == 0) return invalid(bad, "no program");
    if (!isCleanPath(args[0]))
        return invalid(bad, "a program is an absolute path, without . or .. or //");
    return args;
}

fn tcpPort(word: []const u8, bad: *Bad) !u16 {
    if (!std.mem.startsWith(u8, word, "tcp/"))
        return invalid(bad, "a port is tcp/PORT: Landlock cannot restrict UDP");
    const p = std.fmt.parseInt(u16, word[4..], 10) catch
        return invalid(bad, "a port is 1 to 65535");
    if (p == 0) return invalid(bad, "a port is 1 to 65535");
    return p;
}

/// isCleanPath reports whether p is absolute with no empty, . or .. part,
/// and no trailing slash unless it is "/".
pub fn isCleanPath(p: []const u8) bool {
    if (p.len == 0 or p[0] != '/') return false;
    if (p.len == 1) return true;
    var parts = std.mem.splitScalar(u8, p[1..], '/');
    while (parts.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, ".") or
            std.mem.eql(u8, part, "..")) return false;
    }
    return true;
}

/// isName reports whether s is a user or service name: [a-z_][a-z0-9_-]*,
/// at most 32 bytes.
pub fn isName(s: []const u8) bool {
    if (s.len == 0 or s.len > 32) return false;
    if (!std.ascii.isLower(s[0]) and s[0] != '_') return false;
    for (s[1..]) |c| if (!std.ascii.isLower(c) and !std.ascii.isDigit(c) and c != '_' and
        c != '-') return false;
    return true;
}

/// isVariable reports whether s is an environment variable name:
/// [A-Za-z_][A-Za-z0-9_]*.
fn isVariable(s: []const u8) bool {
    if (s.len == 0 or std.ascii.isDigit(s[0])) return false;
    for (s) |c| if (!std.ascii.isAlphanumeric(c) and c != '_') return false;
    return true;
}

const testing = std.testing;

test parse {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var bad: Bad = .{};
    const s = try parse(arena.allocator(),
        \\# nginx
        \\exec    /usr/bin/nginx -c "/etc/nginx/nginx.conf"
        \\before  /usr/bin/nginx -t -q   # check first
        \\user    nginx
        \\listen  tcp/80 tcp/443
        \\connect tcp/443 /run/svc/php-fpm/php.sock
        \\read    /etc/nginx /data/svc/status/www
        \\write   /var/lib/nginx
        \\run     /usr/bin/grype
        \\requires /run/config/nginx/cert.pem
        \\env     "GREETING=hello world"
        \\secret  TOKEN /run/config/x/token
        \\config  authorized-keys /run/config/ssh/authorized_keys
        \\nofile  65536
        \\memory  512
        \\cpu     25
        \\share   shared
        \\pledge  stdio rpath inet listen connect exec
    , &bad);
    try testing.expectEqualStrings("/etc/nginx/nginx.conf", s.exec[2]);
    try testing.expectEqual(3, s.before[0].len);
    try testing.expectEqualSlices(u16, &.{ 80, 443 }, s.listen);
    try testing.expectEqualSlices(u16, &.{443}, s.connect);
    try testing.expectEqualStrings("/run/svc/php-fpm/php.sock", s.sockets[0]);
    try testing.expectEqual(2, s.read.len);
    try testing.expectEqualStrings("/var/lib/nginx", s.write[0]);
    try testing.expectEqualStrings("/usr/bin/grype", s.run[0]);
    try testing.expectEqualStrings("/run/config/nginx/cert.pem", s.requires[0]);
    try testing.expectEqualStrings("hello world", s.env[0][1]);
    try testing.expectEqualStrings("TOKEN", s.secrets[0][0]);
    try testing.expectEqualStrings("authorized-keys", s.configs[0].name);
    try testing.expectEqualStrings("/run/config/ssh/authorized_keys", s.configs[0].path);
    try testing.expect(!s.configs[0].optional);
    try testing.expectEqual(65536, s.nofile.?);
    try testing.expectEqual(512, s.memory.?);
    try testing.expectEqual(25, s.cpu.?);
    try testing.expectEqual(.shared, s.share);
    try testing.expectEqual(0o711, s.share.mode());
    try testing.expect(s.pledge.contains(.listen) and !s.pledge.contains(.proc));
    const plain = try parse(arena.allocator(), "exec /a\nuser x\npledge stdio\n", &bad);
    try testing.expectEqual(.strict, plain.share);
    try testing.expectEqual(null, plain.cpu);
}

test "parse refuses" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const cases = [_]struct { text: []const u8, line: usize }{
        .{ .text = "exec /a\nuser x\nfrobnicate 1", .line = 3 },
        .{ .text = "exec /a\nexec /b\nuser x", .line = 2 },
        .{ .text = "exec a\nuser x", .line = 1 },
        .{ .text = "exec /a/../b\nuser x", .line = 1 },
        .{ .text = "exec /a\nuser root", .line = 2 },
        .{ .text = "exec /a\nuser x\nlisten udp/53", .line = 3 },
        .{ .text = "exec /a\nuser x\nlisten tcp/0", .line = 3 },
        .{ .text = "exec /a\nuser x\nlisten /run/x.sock", .line = 3 },
        .{ .text = "exec /a\nuser x\nconnect /run/../x.sock", .line = 3 },
        .{ .text = "exec /a\nuser x\nconnect /x.sock", .line = 3 },
        .{ .text = "exec /a\nuser x\nread /etc//x", .line = 3 },
        .{ .text = "exec /a\nuser x\nenv 1X=y", .line = 3 },
        .{ .text = "exec /a\nuser x\nconfig ../key /run/config/key", .line = 3 },
        .{ .text = "exec /a\nuser x\nconfig key /etc/shadow", .line = 3 },
        .{ .text = "exec /a\nuser x\nconfig key /run/config/../shadow", .line = 3 },
        .{ .text = "exec /a\nuser x\nconfig key /run/config", .line = 3 },
        .{
            .text = "exec /a\nuser x\nconfig key /run/config/a\nconfig key /run/config/b",
            .line = 4,
        },
        .{ .text = "exec /a \"b\nuser x", .line = 1 },
        .{ .text = "exec /a b\"c\"\nuser x", .line = 1 },
        .{ .text = "exec /a\nuser x\nnofile 0", .line = 3 },
        .{ .text = "exec /a\nuser x\nmemory 0", .line = 3 },
        .{ .text = "exec /a\nuser x\nmemory huge", .line = 3 },
        .{ .text = "exec /a\nuser x\ncpu 0", .line = 3 },
        .{ .text = "exec /a\nuser x\ncpu 10001", .line = 3 },
        .{ .text = "exec /a\nuser x\ncpu half", .line = 3 },
        .{ .text = "exec /a\nuser x\ncpu 10\ncpu 20", .line = 4 },
        .{ .text = "exec /a\nuser x\nshare open", .line = 3 },
        .{ .text = "exec /a\nuser x\nshare", .line = 3 },
        .{ .text = "exec /a\nuser x\nshare shared\nshare strict", .line = 4 },
        .{ .text = "user x", .line = 0 },
        .{ .text = "exec /a", .line = 0 },
        .{ .text = "exec /a\x07\nuser x", .line = 1 },
        .{ .text = "exec /a\nuser x", .line = 0 }, // no pledge
        .{ .text = "exec /a\nuser x\npledge stdio ptrace", .line = 3 },
        .{ .text = "exec /a\nuser x\npledge", .line = 3 },
        .{ .text = "exec /a\nuser x\npledge stdio\npledge rpath", .line = 4 },
        .{ .text = "exec /a\nuser x\npledge stdio\nroot /data/x", .line = 4 },
        .{ .text = "exec /a\nuser x\npledge stdio\nroot /oci/a/b", .line = 4 },
        .{ .text = "exec /a\nuser x\npledge stdio\nroot /oci/a\nroot /oci/b", .line = 5 },
        .{ .text = "exec /a\nuser x\npledge stdio\ndir /data", .line = 0 }, // dir without root
        .{
            .text = "exec /a\nuser x\npledge stdio\nroot /oci/a\nconfig settings /run/config/s\n" ++
                "setting port port\nrender env e",
            .line = 0,
        }, // render under a root
    };
    for (cases) |c| {
        var bad: Bad = .{};
        try testing.expectError(error.Invalid, parse(arena.allocator(), c.text, &bad));
        try testing.expectEqual(c.line, bad.line);
    }
}

test "a service with a root" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var bad: Bad = .{};
    const s = try parse(
        arena.allocator(),
        "exec /app/server --port 8080\nuser _oci-web\npledge stdio inet listen\n" ++
            "root /oci/web\ndir /app\nwrite /var/cache/web\nlisten tcp/8080\n",
        &bad,
    );
    try testing.expectEqualStrings("/oci/web", s.root.?);
    try testing.expectEqualStrings("/app", s.dir.?);
    try testing.expectEqualStrings("/var/cache/web", s.write[0]);
    const plain = try parse(arena.allocator(), "exec /a\nuser x\npledge stdio\n", &bad);
    try testing.expectEqual(null, plain.root);
    try testing.expectEqual(null, plain.dir);
}

test "settings are declared, never invented" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const head = "exec /a\nuser x\npledge stdio\nconfig settings /run/config/x/settings.json\n";
    var bad: Bad = .{};
    const s = try parse(gpa, head ++
        \\setting routes cidr... as advertiseRoutes
        \\render  json config.json from /etc/tailscale/config.json
    , &bad);
    try testing.expectEqualStrings("advertiseRoutes", s.settings[0].key.?);
    try testing.expectEqualStrings("/etc/tailscale/config.json", s.render.?.from.?);
    const e = try parse(
        gpa,
        head ++ "setting database-url url required\nrender env app.env\n",
        &bad,
    );
    try testing.expectEqualStrings("DATABASE_URL", e.settings[0].key.?);

    const cases = [_]struct { text: []const u8, line: usize }{
        .{ .text = head ++ "setting a ip\n", .line = 0 }, // no render
        .{ .text = head ++ "render conf x\n", .line = 0 }, // nothing to render
        .{ .text = head ++ "setting a ip\nrender conf x\nrender conf y\n", .line = 7 },
        .{ .text = head ++ "setting a string\nrender conf x\n", .line = 0 },
        .{ .text = head ++ "setting a nonsense\nrender conf x\n", .line = 5 },
        .{ .text = head ++ "env HOME=/x\nsetting home hostname\nrender env e\n", .line = 0 },
        .{ .text = head ++ "secret A /run/config/a\nsetting a ip\nrender env e\n", .line = 0 },
        .{ .text = head ++ "config x /run/config/x\nsetting a ip\nrender conf x\n", .line = 0 },
        // Without `config settings` the values have no source.
        .{ .text = "exec /a\nuser x\npledge stdio\nsetting a ip\nrender conf x\n", .line = 0 },
    };
    for (cases) |c| {
        try testing.expectError(error.Invalid, parse(gpa, c.text, &bad));
        try testing.expectEqual(c.line, bad.line);
    }
}

test isCleanPath {
    try testing.expect(isCleanPath("/"));
    try testing.expect(isCleanPath("/data/svc/status"));
    try testing.expect(!isCleanPath("data"));
    try testing.expect(!isCleanPath("/data/"));
    try testing.expect(!isCleanPath("/data/./x"));
    try testing.expect(!isCleanPath("/data/../etc"));
    try testing.expect(!isCleanPath(""));
}

test "an optional config may be missing; settings are optional already" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var bad: Bad = .{};
    const s = try parse(
        gpa,
        "exec /a\nuser x\npledge stdio\nconfig relay /run/config/x/relay optional\n",
        &bad,
    );
    try testing.expect(s.configs[0].optional);
    for ([_][]const u8{
        "exec /a\nuser x\npledge stdio\nconfig relay /run/config/x/relay maybe\n",
        "exec /a\nuser x\npledge stdio\nconfig settings /run/config/x/settings.json optional\n",
    }) |text| try testing.expectError(error.Invalid, parse(gpa, text, &bad));
}

test "config file count is bounded" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var text: std.ArrayList(u8) = .empty;
    try text.appendSlice(gpa, "exec /a\nuser x\npledge stdio\n");
    for (0..32) |i| try text.appendSlice(
        gpa,
        try gpa.print("config key{d} /run/config/key{d}\n", .{ i, i }),
    );
    var bad: Bad = .{};
    try testing.expectEqual(@as(usize, 32), (try parse(gpa, text.items, &bad)).configs.len);
    try text.appendSlice(gpa, "config extra /run/config/extra\n");
    try testing.expectError(error.Invalid, parse(gpa, text.items, &bad));
}

test "narrowed programs" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    // Lines 1 to 6; a case's narrow lines start at 7.
    const head = "exec /usr/bin/app\nuser app\nrun /usr/bin/ffmpeg /usr/bin/ffprobe\n" ++
        "read /srv/media\nwrite /var/cache/app\n" ++
        "pledge stdio rpath wpath proc exec inet listen landlock seccomp\n";
    // With ffmpeg's pledge, line 7.
    const ff = head ++ "narrow /usr/bin/ffmpeg pledge stdio\n";
    var bad: Bad = .{};
    const s = try parse(gpa, head ++
        \\narrow /usr/bin/ffmpeg pledge stdio rpath wpath proc
        \\narrow /usr/bin/ffmpeg read /srv/media/in /etc/localtime /run/svc/app/in
        \\narrow /usr/bin/ffmpeg write /var/cache/app/out /run/svc/app/tmp /dev/null
        \\narrow /usr/bin/ffmpeg memory 512
        \\narrow /usr/bin/ffprobe pledge stdio rpath
    , &bad);
    try testing.expectEqual(2, s.narrow.len);
    const ffmpeg = s.narrow[0];
    try testing.expectEqualStrings("/usr/bin/ffmpeg", ffmpeg.program);
    try testing.expect(ffmpeg.pledge.contains(.proc) and !ffmpeg.pledge.contains(.exec));
    try testing.expectEqual(3, ffmpeg.read.len);
    try testing.expectEqualStrings("/run/svc/app/tmp", ffmpeg.write[1]);
    try testing.expectEqual(512, ffmpeg.memory.?);
    try testing.expectEqual(null, s.narrow[1].memory);
    try testing.expectEqual(0, s.narrow[1].read.len);

    const cases = [_]struct { text: []const u8, line: usize, why: []const u8 = "" }{
        // The program: absolute, clean, named by a run line, a name of its own.
        .{ .text = head ++ "narrow ffmpeg pledge stdio\n", .line = 7 },
        .{ .text = head ++ "narrow /usr/bin/../bin/ffmpeg pledge stdio\n", .line = 7 },
        .{ .text = head ++ "narrow /usr/bin/cat pledge stdio\n", .line = 7, .why = "run line" },
        .{
            .text = head ++ "run /opt/bin/ffmpeg\nnarrow /usr/bin/ffmpeg pledge stdio\n" ++
                "narrow /opt/bin/ffmpeg pledge stdio\n",
            .line = 8,
            .why = "share a name",
        },
        // Sub-keys: known, with their words, and once where once is all.
        .{ .text = head ++ "narrow /usr/bin/ffmpeg\n", .line = 7 },
        .{ .text = head ++ "narrow /usr/bin/ffmpeg frob x\n", .line = 7 },
        .{ .text = head ++ "narrow /usr/bin/ffmpeg pledge\n", .line = 7 },
        .{ .text = head ++ "narrow /usr/bin/ffmpeg read\n", .line = 7 },
        .{ .text = head ++ "narrow /usr/bin/ffmpeg read /srv//media\n", .line = 7 },
        .{ .text = head ++ "narrow /usr/bin/ffmpeg memory 0\n", .line = 7 },
        .{ .text = ff ++ "narrow /usr/bin/ffmpeg pledge rpath\n", .line = 8 },
        .{
            .text = ff ++ "narrow /usr/bin/ffmpeg memory 1\nnarrow /usr/bin/ffmpeg memory 2\n",
            .line = 9,
        },
        // Promises: some, within the service's, and no network.
        .{ .text = head ++ "narrow /usr/bin/ffmpeg read /srv/media\n", .line = 7, .why = "pledge" },
        .{ .text = head ++ "narrow /usr/bin/ffmpeg pledge mlock\n", .line = 7, .why = "mlock" },
        .{ .text = head ++ "narrow /usr/bin/ffmpeg pledge stdio inet\n", .line = 7 },
        .{ .text = head ++ "narrow /usr/bin/ffmpeg pledge stdio unix\n", .line = 7 },
        .{
            .text = "exec /a\nuser x\nrun /b\npledge stdio rpath exec seccomp\n" ++
                "narrow /b pledge stdio\n",
            .line = 5,
            .why = "landlock",
        },
        // Paths: within what the service may read or write.
        .{
            .text = ff ++ "narrow /usr/bin/ffmpeg read /etc/shadow\n",
            .line = 7,
            .why = "/etc/shadow",
        },
        .{
            .text = ff ++ "narrow /usr/bin/ffmpeg write /srv/media\n",
            .line = 7,
            .why = "/srv/media",
        },
        .{ .text = ff ++ "narrow /usr/bin/ffmpeg write /etc/passwd\n", .line = 7 },
        .{ .text = ff ++ "narrow /usr/bin/ffmpeg read /srv/mediax\n", .line = 7 },
        // Not under a root: leash is not in the image.
        .{
            .text = "exec /a\nuser x\nrun /b\npledge stdio rpath exec landlock seccomp\n" ++
                "root /oci/a\nnarrow /b pledge stdio\n",
            .line = 6,
        },
    };
    for (cases) |c| {
        try testing.expectError(error.Invalid, parse(gpa, c.text, &bad));
        try testing.expectEqual(c.line, bad.line);
        try testing.expect(std.mem.find(u8, bad.why, c.why) != null);
    }
}

test reaches {
    const s: Service = .{ .read = &.{"/srv/www"}, .write = &.{"/var/lib/app"} };
    try testing.expect(reaches(s, "app", "/srv/www/index.html", false));
    try testing.expect(!reaches(s, "app", "/srv/www/index.html", true));
    try testing.expect(reaches(s, "app", "/var/lib/app/db", true));
    try testing.expect(reaches(s, "app", "/var/lib/app", false));
    try testing.expect(!reaches(s, "app", "/var/lib/application", false));
    try testing.expect(reaches(s, "app", "/etc/passwd", false)); // the floor
    try testing.expect(!reaches(s, "app", "/etc/passwd", true));
    try testing.expect(reaches(s, "app", "/dev/null", true));
    try testing.expect(!reaches(s, "app", "/etc/shadow", false));
    // Its own directories, and at build any service's, which leash
    // checks again by name.
    try testing.expect(reaches(s, "app", "/run/svc/app/tmp", true));
    try testing.expect(reaches(s, "app", "/data/svc/app", true));
    try testing.expect(!reaches(s, "app", "/run/svc/db/socket", false));
    try testing.expect(!reaches(s, "app", "/run/svc/application", false));
    try testing.expect(reaches(s, null, "/run/svc/db/socket", false));
    try testing.expect(!reaches(s, null, "/run/svc", false));
}
