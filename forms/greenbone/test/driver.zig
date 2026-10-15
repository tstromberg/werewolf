//! Local GMP checks. No shell, feed download, scan, or production policy change.
//! Protocol: https://docs.greenbone.net/API/GMP/gmp-22.7.html
const std = @import("std");
const driver = @import("test-driver");
const Io = std.Io;
const linux = std.os.linux;
const Allocator = std.mem.Allocator;
const manager = "/run/svc/gvmd/run/gvmd.sock";
const bridge = "/run/svc/gsad/run/manager.sock";
const scanner = "/data/share/gvm/ospd/ospd.sock";

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();
    const args = try init.minimal.args.toSlice(gpa);
    if (args.len != 4) return error.Usage;
    const suite = args[1];
    const ctx = try driver.Run.load(io, gpa, args[3]);
    const scanner_denied = std.mem.eql(u8, args[2], "scanner-denied");
    if (std.mem.eql(u8, args[2], "denied") or scanner_denied) {
        const rc = connectSocket(if (scanner_denied) scanner else manager);
        if (rc) |fd| {
            _ = linux.close(fd);
            try ctx.result(io, suite, "socket-refused", false);
        } else |err| try ctx.result(io, suite, "socket-refused", err == error.AccessDenied);
        return;
    }
    if (std.mem.eql(u8, args[2], "scanner")) {
        var client = Client{ .fd = try connectSocket(scanner), .gpa = gpa };
        defer client.close();
        const response = try client.command("<get_version/>", "get_version_response");
        try ctx.result(io, suite, "osp-version", try status(
            response,
            "get_version_response",
        ) == 200 and
            std.mem.indexOf(u8, response, "<name>OSP</name>") != null and
            hasVersion(response));
        const mounts = try driver.readKernel(io, gpa, "/proc/self/mountinfo");
        const checks = [_]struct { path: []const u8, readonly: bool }{
            .{ .path = "/oci/gvmd/run/ospd", .readonly = true },
            .{ .path = "/oci/gvmd/var/lib/gvm/scap-data", .readonly = true },
            .{ .path = "/oci/gvmd/var/lib/gvm/cert-data", .readonly = true },
            .{ .path = "/oci/gvmd/var/lib/gvm/data-objects", .readonly = true },
            .{ .path = "/oci/openvas/var/lib/notus", .readonly = true },
            .{ .path = "/oci/feed/var/lib/openvas/plugins", .readonly = false },
            .{ .path = "/oci/openvas/var/lib/openvas/plugins", .readonly = false },
            .{ .path = "/oci/openvas/run/ospd", .readonly = false },
        };
        var correct = true;
        for (checks) |check| {
            const readonly = mountedReadOnly(mounts, check.path) catch |err| {
                try Io.File.stderr().writeStreamingAll(io, try gpa.print("mount {s}: {s}\n", .{
                    check.path, @errorName(err),
                }));
                correct = false;
                continue;
            };
            if (readonly != check.readonly) {
                try Io.File.stderr().writeStreamingAll(io, try gpa.print("mount {s}: expected " ++
                    "{s}\n", .{
                    check.path, if (check.readonly) "read-only" else "writable",
                }));
                correct = false;
            }
        }
        try ctx.result(io, suite, "shared-mount-modes", correct);
        return;
    }
    if (std.mem.eql(u8, args[2], "database")) {
        const checks = [_]struct { name: []const u8, sql: []const u8 }{
            .{ .name = "ordinary-database-role" ++
                "s", .sql = "SELECT count(*)=2 AND bool_and(NOT rolsuper AND NOT rolcreaterole " ++
                "AND NOT rolreplication AND NOT rolbypassrls) FROM pg_roles " ++
                "WHERE rolname IN ('gvmd','dba')" },
            .{ .name = "database-owner-rol" ++
                "e", .sql = "SELECT COALESCE((SELECT 'role=dba'=ANY(setconfig) FROM " ++
                "pg_db_role_setting " ++
                "WHERE setrole=(SELECT oid FROM pg_roles WHERE rolname='gvmd') AND " ++
                "setdatabase=0),false) " ++
                "AND pg_has_role('gvmd','dba','SET') AND NOT pg_has_role('gvmd','postgres','SET'" ++
                ") " ++
                "AND (SELECT pg_get_userbyid(datdba)='dba' FROM pg_database WHERE " ++
                "datname='postgres')" },
            .{
                .name = "database-extensions",
                .sql = "SELECT count(*)=3 FROM pg_extension WHERE extname IN " ++
                    "('pg-gvm','uuid-ossp','pgcrypto')",
            },
        };
        for (checks) |check| {
            const result = try std.process.run(gpa, io, .{
                .argv = &.{
                    "/usr/bin/psql",
                    "-X",
                    "-q",
                    "-w",
                    "-A",
                    "-t",
                    "-v",
                    "ON_ERROR_STOP=1",
                    "-P",
                    "pager=off",
                    "-h",
                    "/run/svc/postgres",
                    "-U",
                    "postgres",
                    "-d",
                    "postgres",
                    "-c",
                    check.sql,
                },
                .stdout_limit = .limited(4096),
                .stderr_limit = .limited(4096),
                .timeout = driver.deadline(io, 15),
            });
            const ok = result.term == .exited and result.term.exited == 0 and
                std.mem.eql(u8, std.mem.trim(u8, result.stdout, " \r\n\t"), "t");
            if (!ok) try Io.File.stderr().writeStreamingAll(io, result.stderr);
            try ctx.result(io, suite, check.name, ok);
        }
        return;
    }
    if (std.mem.eql(u8, args[2], "valkey")) {
        const get = try valkey(io, gpa, &.{ "CONFIG", "GET", "databases" });
        var lines = std.mem.tokenizeAny(u8, get.stdout, "\r\n");
        const key = lines.next() orelse "";
        const value = std.fmt.parseInt(u32, lines.next() orelse "", 10) catch 0;
        try ctx.result(io, suite, "config-get-databases", get.term == .exited and
            get.term.exited == 0 and
            std.mem.eql(u8, key, "databases") and value >= 4 and lines.next() == null);
        // A valid command shape, with an unknown setting: even a broken ACL
        // cannot mutate configuration. Only an ACL refusal satisfies the case.
        const set = try valkey(io, gpa, &.{ "CONFIG", "SET", "werewolf-no-such-setting", "1" });
        const refused = std.mem.startsWith(
            u8,
            std.mem.trimStart(u8, set.stdout, "\r\n"),
            "NOPERM ",
        ) or
            std.mem.startsWith(u8, std.mem.trimStart(u8, set.stderr, "\r\n"), "NOPERM ");
        try ctx.result(
            io,
            suite,
            "config-set-refused",
            set.term == .exited and set.term.exited != 0 and refused,
        );
        return;
    }
    const via_bridge = std.mem.eql(u8, args[2], "bridge");
    if (!via_bridge and !std.mem.eql(u8, args[2], "manager")) return error.Usage;
    const path = if (via_bridge) bridge else manager;
    const secret = try gpa.print("/run/svc/{s}/password", .{suite});
    const password = try Io.Dir.cwd().readFileAlloc(io, secret, gpa, .limited(256));
    const escaped = try escape(gpa, std.mem.trimEnd(u8, password, "\r\n"));
    var client = Client{ .fd = try connectSocket(path), .gpa = gpa };
    defer client.close();
    const auth = try gpa.print(
        "<authenticate><credentials><username>admin</username><password>{s}</password></credenti" ++
            "als></authenticate>",
        .{escaped},
    );
    const authenticated = try client.command(auth, "authenticate_response");
    try ctx.result(
        io,
        suite,
        "configured-login",
        try status(authenticated, "authenticate_response") == 200,
    );
    const name = try gpa.print("native-{s}", .{ctx.run});
    if (!via_bridge and std.mem.eql(u8, ctx.phase, "seed")) {
        const create = try gpa.print(
            "<create_target><name>{s}</name><hosts>192.0.2.1</hosts><port_range>T:80</port_range" ++
                "></create_target>",
            .{name},
        );
        const created = try client.command(create, "create_target_response");
        try ctx.result(
            io,
            suite,
            "create-target",
            try status(created, "create_target_response") == 201,
        );
    }
    // The verify boot reads before any setup write. The bridge also reads the
    // manager driver's row, proving the gsad-to-gvmd socket relay carries GMP.
    const query = try gpa.print("<get_targets filter=\"name={s} rows=-1\"/>", .{name});
    const found = try client.command(query, "get_targets_response");
    try ctx.result(io, suite, "persisted-target", try status(
        found,
        "get_targets_response",
    ) == 200 and
        std.mem.count(u8, found, "<target id=") == 1 and
        std.mem.indexOf(u8, found, try gpa.print("<name>{s}</name>", .{name})) != null and
        std.mem.indexOf(u8, found, "<hosts>192.0.2.1</hosts>") != null);
    if (!via_bridge) {
        const scanners = try client.command(
            "<get_scanners details=\"1\"/>",
            "get_scanners_response",
        );
        const id = socketScanner(scanners) catch null;
        try ctx.result(
            io,
            suite,
            "scanner-configured",
            try status(scanners, "get_scanners_response") == 200 and id != null,
        );
        const verify = try gpa.print("<verify_scanner scanner_id=\"{s}\"/>", .{id.?});
        const verified = try client.command(verify, "verify_scanner_response");
        // OSP's scanner version is empty until scanner initialization finishes.
        // GMP success proves gvmd connected; the direct OSP case checks its
        // protocol version independently of a live feed download.
        try ctx.result(
            io,
            suite,
            "scanner-verified",
            try status(verified, "verify_scanner_response") == 200,
        );
    }
    for ([_][]const u8{ "admin", "werewolf-incorrect-password" }, 0..) |wrong, i| {
        var denied = Client{ .fd = try connectSocket(path), .gpa = gpa };
        defer denied.close();
        const command = try gpa.print(
            "<authenticate><credentials><username>admin</username><password>{s}</password></cred" ++
                "entials></authenticate>",
            .{wrong},
        );
        const response = try denied.command(command, "authenticate_response");
        // GMP uses 400 for authentication failure. A transport error, timeout,
        // unsupported command or a successful login cannot satisfy this case.
        try ctx.result(io, suite, if (i == 0)
            "default-password-refused"
        else
            "wrong-password-refused", try status(response, "authenticate_response") == 400);
    }
    if (!via_bridge) {
        for ([_]u16{ 5432, 6379, 9391, 9392 }) |port| {
            try ctx.result(
                io,
                suite,
                try gpa.print("private-port-{d}", .{port}),
                try driver.tcpPrivate(io, gpa, port, true),
            );
        }
    }
}

fn hasVersion(response: []const u8) bool {
    const start = (std.mem.indexOf(
        u8,
        response,
        "<version>",
    ) orelse return false) + "<version>".len;
    const end = std.mem.indexOf(u8, response[start..], "</version>") orelse return false;
    return std.mem.trim(u8, response[start..][0..end], " \t\r\n").len > 0;
}

test "OSP requires a nonempty protocol version" {
    try std.testing.expect(hasVersion("<version>22.7</version>"));
    try std.testing.expect(!hasVersion("<version></version>"));
    try std.testing.expect(!hasVersion("<version/>"));
}

fn mountedReadOnly(table: []const u8, path: []const u8) !bool {
    var lines = std.mem.tokenizeScalar(u8, table, '\n');
    while (lines.next()) |line| {
        var fields = std.mem.tokenizeScalar(u8, line, ' ');
        for (0..4) |_| _ = fields.next() orelse return error.MountRecord;
        const target = fields.next() orelse return error.MountRecord;
        const flags = fields.next() orelse return error.MountRecord;
        if (!std.mem.eql(u8, target, path)) continue;
        var options = std.mem.tokenizeScalar(u8, flags, ',');
        while (options.next()) |option| if (std.mem.eql(u8, option, "ro")) return true;
        return false;
    }
    return error.MountMissing;
}

fn valkey(io: Io, gpa: Allocator, command: []const []const u8) !std.process.RunResult {
    const argv = try std.mem.concat(gpa, []const u8, &.{
        &.{ "/usr/bin/valkey-cli", "--raw", "-e", "-h", "127.0.0.1", "-p", "6379" }, command,
    });
    return std.process.run(gpa, io, .{
        .argv = argv,
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(4096),
        .timeout = driver.deadline(io, 15),
    });
}

fn socketScanner(response: []const u8) ![]const u8 {
    var entries = std.mem.splitSequence(u8, response, "<scanner id=\"");
    _ = entries.next();
    while (entries.next()) |entry| {
        const end = std.mem.indexOf(u8, entry, "</scanner>") orelse return error.ScannerResponse;
        const item = entry[0..end];
        if (std.mem.indexOf(u8, item, "<host>/run/ospd/ospd.sock</host>") == null or
            std.mem.indexOf(u8, item, "<port>0</port>") == null) continue;
        if (item.len < 37 or item[36] != '"') return error.ScannerId;
        for (item[0..36], 0..) |ch, i| {
            if (i == 8 or i == 13 or i == 18 or i == 23) {
                if (ch != '-') return error.ScannerId;
            } else if (!std.ascii.isHex(ch)) return error.ScannerId;
        }
        return item[0..36];
    }
    return error.NoSocketScanner;
}

const Client = struct {
    fd: i32,
    gpa: Allocator,

    fn close(c: Client) void {
        _ = linux.close(c.fd);
    }

    fn command(c: Client, request: []const u8, tag: []const u8) ![]const u8 {
        var offset: usize = 0;
        while (offset < request.len) {
            const n = linux.write(c.fd, request[offset..].ptr, request.len - offset);
            if (linux.errno(n) == .INTR) continue;
            if (linux.errno(n) != .SUCCESS or n == 0) return error.Write;
            offset += n;
        }
        const buffer = try c.gpa.alloc(u8, 256 << 10);
        var used: usize = 0;
        while (used < buffer.len) {
            var poll = [_]linux.pollfd{.{ .fd = c.fd, .events = linux.POLL.IN, .revents = 0 }};
            const polled = linux.poll(&poll, 1, 15000);
            if (linux.errno(polled) == .INTR) continue;
            if (linux.errno(polled) != .SUCCESS or polled == 0) return error.ResponseTimeout;
            const n = linux.read(c.fd, buffer[used..].ptr, buffer.len - used);
            if (linux.errno(n) == .INTR) continue;
            if (linux.errno(n) != .SUCCESS or n == 0) return error.Read;
            used += n;
            if (try complete(buffer[0..used], tag)) return buffer[0..used];
        }
        return error.ResponseTooLarge;
    }
};

fn connectSocket(path: []const u8) !i32 {
    const rc = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return error.Socket;
    const fd: i32 = @intCast(rc);
    errdefer _ = linux.close(fd);
    const Address = extern struct { family: u16, path: [108]u8 };
    var address: Address = .{ .family = linux.AF.UNIX, .path = @splat(0) };
    if (path.len >= address.path.len) return error.PathTooLong;
    @memcpy(address.path[0..path.len], path);
    switch (linux.errno(linux.connect(fd, @ptrCast(&address), @intCast(2 + path.len + 1)))) {
        .SUCCESS => return fd,
        .ACCES, .PERM => return error.AccessDenied,
        else => return error.Connect,
    }
}

// A bounded, deliberately narrow GMP response envelope. Reject foreign roots,
// duplicate attributes and trailing records; never search arbitrary XML text
// for a status that might belong to an inner element.
fn header(raw: []const u8, tag: []const u8) !?[]const u8 {
    const text = std.mem.trim(u8, raw, " \r\n\t");
    if (text.len < tag.len + 2) return null;
    if (text[0] != '<' or !std.mem.eql(u8, text[1 .. tag.len + 1], tag) or
        text[tag.len + 1] != ' ') return error.ResponseRoot;
    const end = std.mem.findScalar(u8, text, '>') orelse return null;
    return text[tag.len + 1 .. end];
}

fn complete(raw: []const u8, tag: []const u8) !bool {
    const attrs = (try header(raw, tag)) orelse return false;
    const text = std.mem.trim(u8, raw, " \r\n\t");
    const end = std.mem.findScalar(u8, text, '>').?;
    if (std.mem.endsWith(u8, attrs, "/")) {
        if (end + 1 != text.len) return error.TrailingResponse;
        return true;
    }
    var buf: [128]u8 = undefined;
    const closing = try std.mem.print(&buf, "</{s}>", .{tag});
    const at = std.mem.indexOf(u8, text, closing) orelse return false;
    if (at + closing.len != text.len) return error.TrailingResponse;
    return true;
}

fn status(raw: []const u8, tag: []const u8) !u16 {
    var attrs = (try header(raw, tag)) orelse return error.IncompleteResponse;
    var result: ?u16 = null;
    while (true) {
        attrs = std.mem.trimStart(u8, attrs, " \t\r\n");
        if (attrs.len == 0 or std.mem.eql(u8, attrs, "/")) break;
        const eq = std.mem.findScalar(u8, attrs, '=') orelse return error.Attribute;
        const name = std.mem.trimEnd(u8, attrs[0..eq], " \t\r\n");
        attrs = std.mem.trimStart(u8, attrs[eq + 1 ..], " \t\r\n");
        if (attrs.len == 0 or (attrs[0] != '"' and attrs[0] != '\'')) return error.Attribute;
        const end = std.mem.findScalarPos(u8, attrs, 1, attrs[0]) orelse return error.Attribute;
        if (std.mem.eql(u8, name, "status")) {
            if (result != null) return error.DuplicateStatus;
            result = try std.fmt.parseInt(u16, attrs[1..end], 10);
        }
        attrs = attrs[end + 1 ..];
    }
    return result orelse error.MissingStatus;
}

fn escape(gpa: Allocator, text: []const u8) ![]const u8 {
    var out: std.Io.Writer.Allocating = .init(gpa);
    for (text) |ch| try out.writer.writeAll(switch (ch) {
        '&' => "&amp;",
        '<' => "&lt;",
        '>' => "&gt;",
        '"' => "&quot;",
        '\'' => "&apos;",
        else => &.{ch},
    });
    return out.toOwnedSlice();
}

test "password XML escapes syntax without changing the credential" {
    const value = try escape(std.testing.allocator, "a&b<c>\"d'");
    defer std.testing.allocator.free(value);
    try std.testing.expectEqualStrings("a&amp;b&lt;c&gt;&quot;d&apos;", value);
}

test "scanner selection requires the configured Unix endpoint and a UUID" {
    const id = "01234567-89ab-cdef-0123-456789abcdef";
    const response = "<get_scanners_response><scanner id=\"" ++ id ++
        "\"><host>/run/ospd/ospd.sock</host><port>0</port></scanner></get_scanners_response>";
    try std.testing.expectEqualStrings(id, try socketScanner(response));
    try std.testing.expectError(error.NoSocketScanner, socketScanner(
        "<scanner id=\"" ++ id ++ "\"><host>127.0.0.1</host><port>9391</port></scanner>",
    ));
    try std.testing.expectError(error.ScannerId, socketScanner(
        "<scanner id=\"untrusted-id\"><host>/run/ospd/ospd.sock</host><port>0</port></scanner>",
    ));
}

test "shared mount checks use VFS flags and require the exact mount point" {
    const table = "1 0 1:1 / /oci/gvmd/run/ospd ro,nosuid - ext4 /data rw,errors=remount-ro\n" ++
        "2 0 1:1 / /oci/openvas/run/ospd rw,nosuid - ext4 /data rw,errors=remount-ro\n";
    try std.testing.expect(try mountedReadOnly(table, "/oci/gvmd/run/ospd"));
    try std.testing.expect(!try mountedReadOnly(table, "/oci/openvas/run/ospd"));
    try std.testing.expectError(error.MountMissing, mountedReadOnly(table, "/oci/gvmd/run"));
    try std.testing.expectError(
        error.MountRecord,
        mountedReadOnly("incomplete", "/oci/gvmd/run/ospd"),
    );
}

test "GMP envelope refuses partial, foreign, duplicate and trailing responses" {
    const tag = "authenticate_response";
    try std.testing.expect(!try complete("<authenticate_response status=\"200\"", tag));
    try std.testing.expect(try complete(
        "<authenticate_response status=\"200\"><role>Admin</role></authenticate_response>",
        tag,
    ));
    try std.testing.expectEqual(
        @as(u16, 400),
        try status(
            "<authenticate_response status_text=\"Authentication failed\" status='400'/>",
            tag,
        ),
    );
    try std.testing.expectError(
        error.ResponseRoot,
        complete("<get_version_response status=\"200\"/>", tag),
    );
    try std.testing.expectError(
        error.TrailingResponse,
        complete("<authenticate_response status=\"200\"/><x/>", tag),
    );
    try std.testing.expectError(
        error.DuplicateStatus,
        status("<authenticate_response status=\"400\" status=\"200\"/>", tag),
    );
    try std.testing.expectError(
        error.MissingStatus,
        status("<authenticate_response status_text=\"200\"/>", tag),
    );
}
