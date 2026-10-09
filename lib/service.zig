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
    share: Share = .strict,
    pledge: seal.Set = .empty,
    /// root is the OCI image the service runs in, beneath /oci; dir is
    /// where it starts there.
    root: ?[]const u8 = null,
    dir: ?[]const u8 = null,
};

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
    var share: ?Share = null;
    var pledge: ?seal.Set = null;
    var root: ?[]const u8 = null;
    var dir: ?[]const u8 = null;
    var before: std.ArrayList([]const []const u8) = .empty;
    var listen: std.ArrayList(u16) = .empty;
    var connect: std.ArrayList(u16) = .empty;
    var read: std.ArrayList([]const u8) = .empty;
    var write: std.ArrayList([]const u8) = .empty;
    var run: std.ArrayList([]const u8) = .empty;
    var requires: std.ArrayList([]const u8) = .empty;
    var env: std.ArrayList([2][]const u8) = .empty;
    var secrets: std.ArrayList([2][]const u8) = .empty;
    var configs: std.ArrayList(Config) = .empty;
    var declared: std.ArrayList(settings.Setting) = .empty;
    var render: ?settings.Render = null;

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
        } else if (std.mem.eql(u8, key, "listen") or std.mem.eql(u8, key, "connect")) {
            if (args.len == 0) return invalid(bad, "no ports");
            const list = if (std.mem.eql(u8, key, "listen")) &listen else &connect;
            for (args) |a| try list.append(gpa, try tcpPort(a, bad));
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
            if (args.len == 0) return invalid(bad, "pledge takes promises");
            var set: seal.Set = .empty;
            for (args) |a| set.insert(
                std.meta.stringToEnum(seal.Promise, a) orelse
                    return invalid(bad, "no such promise"),
            );
            pledge = set;
        } else if (std.mem.eql(u8, key, "nofile")) {
            if (nofile != null) return invalid(bad, "nofile twice");
            if (args.len != 1) return invalid(bad, "nofile takes one number");
            nofile = std.fmt.parseInt(u32, args[0], 10) catch
                return invalid(bad, "nofile takes a number");
            if (nofile.? == 0 or nofile.? > 1 << 20) return invalid(bad, "nofile is 1 to 1048576");
        } else if (std.mem.eql(u8, key, "memory")) {
            if (memory != null) return invalid(bad, "memory twice");
            if (args.len != 1) return invalid(bad, "memory takes one number of MiB");
            memory = std.fmt.parseInt(u32, args[0], 10) catch
                return invalid(bad, "memory takes a number of MiB");
            if (memory.? == 0 or memory.? > 1 << 20)
                return invalid(bad, "memory is 1 to 1048576 MiB");
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
    return .{
        .exec = exec orelse return invalid(bad, "no exec"),
        .user = user orelse return invalid(bad, "no user"),
        .pledge = promises,
        .before = before.items,
        .listen = listen.items,
        .connect = connect.items,
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
        .share = share orelse .strict,
        .root = root,
        .dir = dir,
    };
}

fn invalid(bad: *Bad, why: []const u8) error{Invalid} {
    bad.why = why;
    return error.Invalid;
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
        \\connect tcp/443
        \\read    /etc/nginx /data/svc/status/www
        \\write   /var/lib/nginx
        \\run     /usr/bin/grype
        \\requires /run/config/nginx/cert.pem
        \\env     "GREETING=hello world"
        \\secret  TOKEN /run/config/x/token
        \\config  authorized-keys /run/config/ssh/authorized_keys
        \\nofile  65536
        \\memory  512
        \\share   shared
        \\pledge  stdio rpath inet listen connect exec
    , &bad);
    try testing.expectEqualStrings("/etc/nginx/nginx.conf", s.exec[2]);
    try testing.expectEqual(3, s.before[0].len);
    try testing.expectEqualSlices(u16, &.{ 80, 443 }, s.listen);
    try testing.expectEqualSlices(u16, &.{443}, s.connect);
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
    try testing.expectEqual(.shared, s.share);
    try testing.expectEqual(0o711, s.share.mode());
    try testing.expect(s.pledge.contains(.listen) and !s.pledge.contains(.proc));
    const plain = try parse(arena.allocator(), "exec /a\nuser x\npledge stdio\n", &bad);
    try testing.expectEqual(.strict, plain.share);
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
