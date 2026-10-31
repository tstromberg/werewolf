//! Supervise one confined nginx master; stage screened HTTP fragments and accept Core's reload.
const std = @import("std");
const linux = std.os.linux;
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

const socket_path = "/data/share/unifi/reload/nginx.sock";
const request = "reload\n";
const nginx = "/usr/bin/nginx";
const config = "/etc/nginx/nginx.conf";
const source_http = "/data/share/unifi/config/http";
const baked_http = "/oci/unifi-core/usr/share/unifi-core/http";
const runtime_dir = "/run/svc/nginx";
const staged_name = "http";
const next_name = "http.next";
const prev_name = "http.prev";
const legacy_http_prefix = "/werewolf/config/http/";
const share_http_prefix = "/data/share/unifi/config/http/";
const staged_http_prefix = "/run/svc/nginx/http/";
const vendor_http_prefix = "/usr/share/unifi-core/http/";
const max_configs = 64;
const max_config_bytes = 256 << 10;

var stopping: std.atomic.Value(bool) = .init(false);

pub fn main(init: std.process.Init) void {
    serve(init) catch |err| {
        var buf: [128]u8 = undefined;
        const line = std.mem.print(&buf, "unifi-nginx: {s}\n", .{@errorName(err)}) catch return;
        Io.File.stderr().writeStreamingAll(init.io, line) catch {};
        std.process.exit(1);
    };
}

fn serve(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();
    const passwd = try Dir.cwd().readFileAlloc(io, "/etc/passwd", gpa, .limited(64 << 10));
    const uid = try coreUid(passwd);
    try stageInitial(io);
    const action: linux.Sigaction = .{
        .handler = .{ .handler = terminate },
        .mask = linux.sigemptyset(),
        .flags = 0,
    };
    _ = linux.sigaction(.TERM, &action, null);
    _ = linux.sigaction(.INT, &action, null);
    const master = try spawn(
        &.{ nginx, "-c", config, "-e", "stderr", "-g", "daemon off;" },
        init.minimal.environ,
    );
    // This child is never reaped while requests are processed, so its PID
    // cannot be reused for another process. No PID comes from a caller/file.
    defer {
        _ = linux.kill(master, linux.SIG.TERM);
        var status: i32 = 0;
        _ = linux.waitpid(master, &status, 0);
    }
    var fd: i32 = -1;
    defer if (fd >= 0) {
        _ = linux.close(fd);
    };
    while (!stopping.load(.acquire)) {
        var status: i32 = 0;
        const gone = linux.waitpid(master, &status, linux.W.NOHANG);
        if (gone != 0 and linux.errno(gone) != .INTR) {
            // Do not run the deferred signal after reaping this PID.
            std.process.exit(1);
        }
        if (fd < 0) fd = listener() catch {
            var empty: [0]linux.pollfd = .{};
            _ = linux.poll(&empty, 0, 100);
            continue;
        };
        var fds = [_]linux.pollfd{.{ .fd = fd, .events = linux.POLL.IN, .revents = 0 }};
        if (linux.errno(linux.poll(&fds, 1, 250)) == .INTR) continue;
        if (fds[0].revents & linux.POLL.IN == 0) continue;
        const raw = linux.accept4(fd, null, null, linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK);
        if (linux.errno(raw) != .SUCCESS) continue;
        const client: i32 = @intCast(raw);
        defer _ = linux.close(client);
        if (!corePeer(client, uid)) continue;
        var incoming = [_]linux.pollfd{.{ .fd = client, .events = linux.POLL.IN, .revents = 0 }};
        if (linux.poll(&incoming, 1, 1000) != 1 or
            incoming[0].revents & linux.POLL.IN == 0) continue;
        var packet: [32]u8 = undefined;
        const n = linux.recvfrom(client, &packet, packet.len, linux.MSG.TRUNC, null, null);
        if (n != request.len or !std.mem.eql(u8, packet[0..request.len], request)) {
            _ = linux.sendto(client, "denied\n", 7, linux.MSG.NOSIGNAL, null, 0);
            continue;
        }
        const reloaded = reloadMaster(io, master);
        const reply = if (reloaded) "ok\n" else "failed\n";
        _ = linux.sendto(client, reply.ptr, reply.len, linux.MSG.NOSIGNAL, null, 0);
    }
}

fn stageInitial(io: Io) !void {
    var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena.deinit();
    var run = try Dir.cwd().openDir(io, runtime_dir, .{});
    defer run.close(io);
    run.deleteTree(io, next_name) catch {};
    run.deleteTree(io, prev_name) catch {};
    stageFromPaths(io, arena.allocator(), run) catch {
        // Core may still be preparing its config tree at initial boot; start
        // with an empty private include directory until Core requests a reload.
        run.deleteTree(io, next_name) catch {};
        try run.createDir(io, next_name, .fromMode(0o700));
    };
    run.deleteTree(io, staged_name) catch {};
    try Dir.rename(run, next_name, run, staged_name, io);
}

fn reloadMaster(io: Io, master: i32) bool {
    var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena.deinit();
    var run = Dir.cwd().openDir(io, runtime_dir, .{}) catch return false;
    defer run.close(io);
    run.deleteTree(io, next_name) catch {};
    run.deleteTree(io, prev_name) catch {};
    stageFromPaths(io, arena.allocator(), run) catch {
        run.deleteTree(io, next_name) catch {};
        return false;
    };
    Dir.rename(run, staged_name, run, prev_name, io) catch {
        run.deleteTree(io, next_name) catch {};
        return false;
    };
    Dir.rename(run, next_name, run, staged_name, io) catch {
        Dir.rename(run, prev_name, run, staged_name, io) catch {};
        run.deleteTree(io, next_name) catch {};
        return false;
    };
    const valid = testNginx(io);
    if (!valid or linux.errno(linux.kill(master, linux.SIG.HUP)) != .SUCCESS) {
        Dir.rename(run, staged_name, run, next_name, io) catch {};
        Dir.rename(run, prev_name, run, staged_name, io) catch {};
        run.deleteTree(io, next_name) catch {};
        return false;
    }
    run.deleteTree(io, prev_name) catch {};
    return true;
}

fn testNginx(io: Io) bool {
    var check = std.process.spawn(io, .{
        .argv = &.{ nginx, "-c", config, "-e", "stderr", "-t", "-q" },
        .stdin = .ignore,
    }) catch return false;
    const result = check.wait(io) catch return false;
    return result == .exited and result.exited == 0;
}

fn stageFromPaths(io: Io, gpa: Allocator, run: Dir) !void {
    var src = Dir.cwd().openDir(io, source_http, .{
        .iterate = true,
        .follow_symlinks = false,
    }) catch |err| switch (err) {
        error.FileNotFound => {
            try run.createDir(io, next_name, .fromMode(0o700));
            return;
        },
        else => return err,
    };
    defer src.close(io);
    var baked = Dir.cwd().openDir(io, baked_http, .{ .follow_symlinks = false }) catch null;
    defer if (baked) |*b| b.close(io);
    try stageNext(io, gpa, src, baked, run);
}

fn stageNext(io: Io, gpa: Allocator, src: Dir, baked: ?Dir, run: Dir) !void {
    try run.createDir(io, next_name, .fromMode(0o700));
    var dst = try run.openDir(io, next_name, .{ .follow_symlinks = false });
    defer dst.close(io);
    var count: usize = 0;
    var it = src.iterate();
    while (try it.next(io)) |entry| {
        if (entry.name.len == 0 or entry.name[0] == '.') continue;
        if (!std.mem.endsWith(u8, entry.name, ".conf")) continue;
        if (!safeConfName(entry.name)) return error.UnsafeConfigName;
        count += 1;
        if (count > max_configs) return error.TooManyConfigs;
        const raw = try readSourceConf(io, gpa, src, baked, entry.name, entry.kind);
        const screened = try screenFragment(gpa, raw);
        var out = try dst.createFile(io, entry.name, .{
            .exclusive = true,
            .permissions = .fromMode(0o600),
        });
        defer out.close(io);
        try out.writeStreamingAll(io, screened);
        try out.sync(io);
    }
}

fn readSourceConf(
    io: Io,
    gpa: Allocator,
    src: Dir,
    baked: ?Dir,
    name: []const u8,
    kind: Io.File.Kind,
) ![]u8 {
    switch (kind) {
        .file => return readRegularNoFollow(io, gpa, src, name),
        .sym_link => {
            var link_buf: [256]u8 = undefined;
            const n = try src.readLink(io, name, &link_buf);
            const target = link_buf[0..n];
            if (!std.mem.startsWith(u8, target, vendor_http_prefix)) return error.UnsafeSymlink;
            const leaf = target[vendor_http_prefix.len..];
            if (!safeConfName(leaf)) return error.UnsafeSymlink;
            const dir = baked orelse return error.UnsafeSymlink;
            return readRegularNoFollow(io, gpa, dir, leaf);
        },
        else => return error.UnsafeConfigEntry,
    }
}

fn readRegularNoFollow(io: Io, gpa: Allocator, dir: Dir, name: []const u8) ![]u8 {
    var file = try dir.openFile(io, name, .{ .follow_symlinks = false });
    defer file.close(io);
    const stat = try file.stat(io);
    if (stat.kind != .file) return error.UnsafeConfigEntry;
    var buf: [4096]u8 = undefined;
    var reader = file.readerStreaming(io, &buf);
    return reader.interface.allocRemaining(gpa, .limited(max_config_bytes));
}

const Token = struct {
    value: []const u8,
    raw_start: usize,
    raw_end: usize,
    quoted: bool,
};

/// Screen an untrusted nginx configuration fragment from Core and rewrite
/// legacy `/werewolf/config/http/` includes to the private staged directory.
fn screenFragment(gpa: Allocator, input: []const u8) ![]u8 {
    for (input) |c| {
        if (c == 0) return error.ControlCharacter;
    }
    var out: std.ArrayList(u8) = .empty;
    var tokens: std.ArrayList(Token) = .empty;
    var unquoted_bufs: std.ArrayList([]u8) = .empty;
    defer {
        for (unquoted_bufs.items) |b| gpa.free(b);
        unquoted_bufs.deinit(gpa);
        tokens.deinit(gpa);
    }
    var pos: usize = 0;
    var emit_from: usize = 0;
    var depth: usize = 0;
    while (pos < input.len) {
        const c = input[pos];
        if (c == ' ' or c == '\t' or c == '\r' or c == '\n') {
            pos += 1;
            continue;
        }
        if (c == '#') {
            while (pos < input.len and input[pos] != '\n') : (pos += 1) {}
            continue;
        }
        if (c == ';' or c == '{' or c == '}') {
            if (tokens.items.len > 0) {
                if (c == '}') return error.MalformedDirective;
                if (try checkDirective(tokens.items)) |rewritten| {
                    const arg = tokens.items[1];
                    try out.appendSlice(gpa, input[emit_from..arg.raw_start]);
                    try out.appendSlice(gpa, rewritten);
                    emit_from = arg.raw_end;
                }
                tokens.clearRetainingCapacity();
            } else if (c == ';' or c == '{') {
                return error.MalformedDirective;
            }
            if (c == '{') {
                depth += 1;
            } else if (c == '}') {
                if (depth == 0) return error.UnbalancedBraces;
                depth -= 1;
            }
            pos += 1;
            continue;
        }
        if (c == '\'' or c == '"') {
            const quote = c;
            const start = pos;
            pos += 1;
            var decoded: std.ArrayList(u8) = .empty;
            errdefer decoded.deinit(gpa);
            while (pos < input.len and input[pos] != quote) : (pos += 1) {
                if (input[pos] == '\\') {
                    pos += 1;
                    if (pos >= input.len) return error.UnterminatedQuote;
                }
                if (input[pos] < 0x20 and input[pos] != '\t') return error.ControlCharacter;
                try decoded.append(gpa, input[pos]);
            }
            if (pos >= input.len) return error.UnterminatedQuote;
            pos += 1;
            if (pos < input.len and !isDelimiter(input[pos])) return error.MalformedToken;
            const slice = try decoded.toOwnedSlice(gpa);
            try unquoted_bufs.append(gpa, slice);
            try tokens.append(gpa, .{
                .value = slice,
                .raw_start = start,
                .raw_end = pos,
                .quoted = true,
            });
            continue;
        }
        const start = pos;
        while (pos < input.len and !isDelimiter(input[pos])) : (pos += 1) {
            if (input[pos] == '\'' or input[pos] == '"' or input[pos] == '\\')
                return error.MalformedToken;
            if (input[pos] < 0x20 or input[pos] == 0x7f) return error.ControlCharacter;
        }
        try tokens.append(gpa, .{
            .value = input[start..pos],
            .raw_start = start,
            .raw_end = pos,
            .quoted = false,
        });
    }
    if (tokens.items.len != 0 or depth != 0) return error.UnbalancedBraces;
    try out.appendSlice(gpa, input[emit_from..]);
    return out.toOwnedSlice(gpa);
}

fn isDelimiter(c: u8) bool {
    return c == ' ' or c == '\t' or c == '\r' or c == '\n' or
        c == ';' or c == '{' or c == '}' or c == '#';
}

/// Returns a replacement argument slice when `include` needs prefix rewriting.
fn checkDirective(tokens: []const Token) !?[]const u8 {
    const cmd = tokens[0].value;
    for ([_][]const u8{
        "load_module",
        "env",
        "user",
        "pid",
        "lock_file",
        "working_directory",
        "daemon",
        "master_process",
        "ssl_engine",
        "timer_resolution",
        "debug_points",
        "google_perftools_profiles",
    }) |denied| {
        if (std.mem.eql(u8, cmd, denied)) return error.ForbiddenDirective;
    }
    for ([_][]const u8{ "lua_", "perl_", "js_" }) |prefix| {
        if (std.mem.startsWith(u8, cmd, prefix)) return error.ForbiddenDirective;
    }
    if (std.mem.endsWith(u8, cmd, "_temp_path") or std.mem.endsWith(u8, cmd, "_cache_path")) {
        return error.ForbiddenDirective;
    }
    if (std.mem.eql(u8, cmd, "access_log")) {
        if (tokens.len != 2 or !std.mem.eql(u8, tokens[1].value, "off"))
            return error.ForbiddenLogPath;
        return null;
    }
    if (std.mem.eql(u8, cmd, "error_log")) {
        if (tokens.len < 2 or (!std.mem.eql(u8, tokens[1].value, "stderr") and
            !std.mem.eql(u8, tokens[1].value, "/dev/stderr")))
        {
            return error.ForbiddenLogPath;
        }
        return null;
    }
    if (std.mem.eql(u8, cmd, "include")) {
        if (tokens.len != 2 or tokens[1].quoted) return error.ForbiddenInclude;
        const target = tokens[1].value;
        if (hasDotDot(target)) return error.ForbiddenInclude;
        if (std.mem.startsWith(u8, target, legacy_http_prefix)) {
            const tail = target[legacy_http_prefix.len..];
            if (!safeIncludeTail(tail)) return error.ForbiddenInclude;
            return tryRewrite(tail);
        }
        if (std.mem.startsWith(u8, target, share_http_prefix)) {
            const tail = target[share_http_prefix.len..];
            if (!safeIncludeTail(tail)) return error.ForbiddenInclude;
            return tryRewrite(tail);
        }
        if (std.mem.startsWith(u8, target, staged_http_prefix)) {
            if (!safeIncludeTail(target[staged_http_prefix.len..])) return error.ForbiddenInclude;
            return null;
        }
        if (std.mem.startsWith(u8, target, vendor_http_prefix)) {
            if (!safeIncludeTail(target[vendor_http_prefix.len..])) return error.ForbiddenInclude;
            return null;
        }
        return error.ForbiddenInclude;
    }
    if (std.mem.eql(u8, cmd, "root") or std.mem.eql(u8, cmd, "alias")) {
        if (tokens.len != 2) return error.ForbiddenRoot;
        const path = tokens[1].value;
        if (hasDotDot(path)) return error.ForbiddenRoot;
        for ([_][]const u8{
            "/usr/share/unifi-core/",
            "/usr/share/unifi-assets/",
            "/usr/lib/unifi-directory/",
            "/data/unifi-core/devices/",
        }) |allowed| {
            if (std.mem.startsWith(u8, path, allowed)) return null;
        }
        return error.ForbiddenRoot;
    }
    for ([_][]const u8{
        "ssl_certificate",
        "ssl_certificate_key",
        "ssl_trusted_certificate",
        "ssl_client_certificate",
        "ssl_dhparam",
    }) |tls_cmd| {
        if (std.mem.eql(u8, cmd, tls_cmd)) {
            if (tokens.len != 2) return error.ForbiddenTlsPath;
            const path = tokens[1].value;
            if (hasDotDot(path)) return error.ForbiddenTlsPath;
            if (std.mem.startsWith(u8, path, "/werewolf/config/") or
                std.mem.startsWith(u8, path, "/data/share/unifi/config/") or
                std.mem.startsWith(u8, path, "/usr/share/unifi-core/"))
            {
                return null;
            }
            return error.ForbiddenTlsPath;
        }
    }
    return null;
}

const RewriteBuf = struct {
    var buf: [256]u8 = undefined;
};

fn tryRewrite(tail: []const u8) ![]const u8 {
    return std.mem.print(&RewriteBuf.buf, "{s}{s}", .{ staged_http_prefix, tail }) catch
        error.ForbiddenInclude;
}

fn safeConfName(name: []const u8) bool {
    if (name.len <= ".conf".len or name.len > 128 or name[0] == '.') return false;
    if (!std.mem.endsWith(u8, name, ".conf")) return false;
    for (name) |c| switch (c) {
        'a'...'z', 'A'...'Z', '0'...'9', '.', '_', '-' => {},
        else => return false,
    };
    return !hasDotDot(name);
}

fn safeIncludeTail(tail: []const u8) bool {
    if (tail.len <= ".conf".len or tail.len > 128 or tail[0] == '.') return false;
    if (!std.mem.endsWith(u8, tail, ".conf")) return false;
    for (tail) |c| switch (c) {
        'a'...'z', 'A'...'Z', '0'...'9', '.', '_', '-', '*', '[', ']' => {},
        else => return false,
    };
    return !hasDotDot(tail);
}

fn hasDotDot(path: []const u8) bool {
    var parts = std.mem.splitScalar(u8, path, '/');
    while (parts.next()) |seg| {
        if (std.mem.eql(u8, seg, "..")) return true;
    }
    return false;
}

fn listener() !i32 {
    const raw = linux.socket(
        linux.AF.UNIX,
        linux.SOCK.SEQPACKET | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK,
        0,
    );
    if (linux.errno(raw) != .SUCCESS) return error.Socket;
    const fd: i32 = @intCast(raw);
    errdefer _ = linux.close(fd);
    _ = linux.unlink(socket_path);
    var address: linux.sockaddr.un = .{ .family = linux.AF.UNIX, .path = @splat(0) };
    @memcpy(address.path[0..socket_path.len], socket_path);
    if (linux.errno(linux.bind(fd, @ptrCast(&address), @sizeOf(linux.sockaddr.un))) != .SUCCESS or
        linux.errno(linux.fchmodat(linux.AT.FDCWD, socket_path, 0o660)) != .SUCCESS or
        linux.errno(linux.listen(fd, 4)) != .SUCCESS) return error.Listen;
    return fd;
}

const Credentials = extern struct { pid: i32, uid: u32, gid: u32 };

fn corePeer(fd: i32, uid: u32) bool {
    var credentials: Credentials = undefined;
    var size: linux.socklen_t = @sizeOf(Credentials);
    return linux.errno(linux.getsockopt(
        fd,
        linux.SOL.SOCKET,
        linux.SO.PEERCRED,
        @ptrCast(&credentials),
        &size,
    )) == .SUCCESS and
        size == @sizeOf(Credentials) and credentials.uid == uid;
}

fn coreUid(passwd: []const u8) !u32 {
    var lines = std.mem.splitScalar(u8, passwd, '\n');
    while (lines.next()) |line| {
        var fields = std.mem.splitScalar(u8, line, ':');
        if (!std.mem.eql(u8, fields.next() orelse "", "_oci-unifi-core")) continue;
        _ = fields.next();
        return std.fmt.parseInt(u32, fields.next() orelse return error.NoCoreUser, 10);
    }
    return error.NoCoreUser;
}

fn spawn(argv: []const []const u8, environ: std.process.Environ) !i32 {
    var ptrs: [10:null]?[*:0]const u8 = @splat(null);
    var storage: [9][128:0]u8 = undefined;
    if (argv.len >= ptrs.len) return error.Arguments;
    for (argv, 0..) |arg, i| {
        if (arg.len >= storage[i].len) return error.Arguments;
        @memcpy(storage[i][0..arg.len], arg);
        storage[i][arg.len] = 0;
        ptrs[i] = &storage[i];
    }
    const raw = linux.fork();
    if (linux.errno(raw) != .SUCCESS) return error.Fork;
    if (raw == 0) {
        const entries = environ.block.view().slice;
        var env: [256:null]?[*:0]const u8 = @splat(null);
        if (entries.len >= env.len) linux.exit_group(127);
        for (entries, 0..) |entry, i| env[i] = entry;
        _ = linux.execve(ptrs[0].?, &ptrs, &env);
        linux.exit_group(127);
    }
    return @intCast(raw);
}

fn terminate(_: linux.SIG) callconv(.c) void {
    stopping.store(true, .release);
}

test "reload peer is the declared Core user, never root or a claimed identity" {
    try std.testing.expectEqual(
        @as(u32, 1234),
        try coreUid("root:x:0:0::/:\n_oci-unifi-core:x:1234:1234::/:\n"),
    );
    try std.testing.expectError(error.NoCoreUser, coreUid("root:x:0:0::/:\n"));
    try std.testing.expectError(error.InvalidCharacter, coreUid("_oci-unifi-core:x:bad:1::/:\n"));
}

test "screenFragment rewrites Core HTTP includes and rejects dangerous directives" {
    const gpa = std.testing.allocator;
    const good =
        \\server {
        \\    listen 443 ssl;
        \\    include /werewolf/config/http/local-certs.conf;
        \\    include /usr/share/unifi-core/http/shared-server-defaults.conf;
        \\    ssl_certificate /werewolf/config/tls/unifi-core.crt;
        \\    ssl_certificate_key /werewolf/config/tls/unifi-core.key;
        \\    access_log off;
        \\    error_log stderr warn;
        \\    location /assets/ {
        \\        alias /usr/share/unifi-assets/;
        \\    }
        \\}
    ;
    const out = try screenFragment(gpa, good);
    defer gpa.free(out);
    try std.testing.expect(
        std.mem.find(u8, out, "include /run/svc/nginx/http/local-certs.conf;") != null,
    );
    try std.testing.expect(std.mem.find(u8, out, "/werewolf/config/http/") == null);

    for ([_][]const u8{
        "load_module /tmp/evil.so;",
        "include /etc/passwd;",
        "include /werewolf/config/http/../tls/unifi-core.key;",
        "include \"/run/svc/nginx/http/local-certs.conf\";",
        "access_log /data/share/unifi/reload/access.log;",
        "error_log /data/share/unifi/reload/error.log;",
        "client_body_temp_path /data/share/unifi/reload;",
        "proxy_cache_path /data/share/unifi/reload keys_zone=x:1m;",
        "location / { root /etc/nginx; }",
        "location / { alias /data/svc/unifi-core/; }",
        "ssl_certificate_key /etc/ssl/private/x.key;",
    }) |bad| {
        try std.testing.expect(std.meta.isError(screenFragment(gpa, bad)));
    }
}

test "stageNext copies regular configs and vetted template links while refusing foreign symlinks" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(io, "src");
    try tmp.dir.createDirPath(io, "baked");
    try tmp.dir.createDirPath(io, "run");
    try tmp.dir.writeFile(io, .{
        .sub_path = "src/upstream-uos.conf",
        .data = "upstream uos_api_backend { server 127.0.0.1:11081; }\n",
    });
    try tmp.dir.writeFile(io, .{
        .sub_path = "baked/site-setup.conf",
        .data = "server { include /werewolf/config/http/local-certs.conf; }\n",
    });
    try tmp.dir.symLink(
        io,
        "/usr/share/unifi-core/http/site-setup.conf",
        "src/site-setup.conf",
        .{},
    );
    // Non-.conf socket symlinks inside Core's http dir are ignored, never staged.
    try tmp.dir.symLink(io, "/werewolf/reload/uos-internal.sock", "src/uos-internal.sock", .{});

    var src = try tmp.dir.openDir(io, "src", .{ .iterate = true, .follow_symlinks = false });
    defer src.close(io);
    var baked = try tmp.dir.openDir(io, "baked", .{ .follow_symlinks = false });
    defer baked.close(io);
    var run = try tmp.dir.openDir(io, "run", .{ .follow_symlinks = false });
    defer run.close(io);

    try stageNext(io, gpa, src, baked, run);
    const staged_site = try run.readFileAlloc(io, "http.next/site-setup.conf", gpa, .limited(4096));
    defer gpa.free(staged_site);
    try std.testing.expectEqualStrings(
        "server { include /run/svc/nginx/http/local-certs.conf; }\n",
        staged_site,
    );
    try std.testing.expectError(
        error.FileNotFound,
        run.access(io, "http.next/uos-internal.sock", .{}),
    );

    // A .conf symlink pointing outside /usr/share/unifi-core/http/ fails closed.
    try run.deleteTree(io, next_name);
    try tmp.dir.symLink(io, "/etc/passwd", "src/evil.conf", .{});
    try std.testing.expectError(error.UnsafeSymlink, stageNext(io, gpa, src, baked, run));
}
