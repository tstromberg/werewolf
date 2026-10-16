//! Solr's HTTP API under a client leash, with seed/reboot/query persistence.
const std = @import("std");
const driver = @import("test-driver");
const linux = std.os.linux;
const Io = std.Io;
const Allocator = std.mem.Allocator;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();
    const args = try init.minimal.args.toSlice(gpa);
    if (args.len != 4 or !std.mem.eql(u8, args[2], "http")) return error.Usage;
    const suite = args[1];
    const ctx = try driver.Run.load(io, gpa, args[3]);
    var ready = false;
    for (0..90) |_| {
        if (available(gpa, std.mem.eql(u8, ctx.phase, "verify"))) {
            ready = true;
            break;
        }
        try io.sleep(.fromSeconds(1), .awake);
    }
    try ctx.result(io, suite, "ready", ready);
    const info = try request(gpa, "/solr/admin/info/system?wt=json", "");
    const value = try std.json.parseFromSliceLeaky(std.json.Value, gpa, info.body, .{});
    const version = value.object.get("lucene").?.object.get("solr-spec-version").?.string;
    try ctx.result(io, suite, "version", std.mem.eql(u8, version, "10.0.0"));
    try ctx.result(io, suite, "private-listener", try driver.tcpPrivate(io, gpa, 8983, true));
    if (std.mem.eql(u8, ctx.phase, "seed")) {
        const created = try request(
            gpa,
            "/solr/admin/cores?action=CREATE&name=native&configSet=_default&wt=json",
            "",
        );
        // Iteration retains its home; the clean seed creates it from nothing.
        const cores = try request(gpa, "/solr/admin/cores?action=STATUS&core=native&wt=json", "");
        try ctx.result(io, suite, "create-core", (created.status == 200 or
            created.status == 400) and
            std.mem.indexOf(u8, cores.body, "\"name\":\"native\"") != null);
        const body = try gpa.print("[{{\"id\":\"{s}\",\"name\":\"native client\"}}]", .{ctx.run});
        const indexed = try request(gpa, "/solr/native/update?commit=true&wt=json", body);
        try ctx.result(io, suite, "index-document", indexed.status == 200);
    }
    const query = try gpa.print("/solr/native/select?q=id:{s}&wt=json", .{ctx.run});
    const found = try request(gpa, query, "");
    try ctx.result(io, suite, "persisted-document", found.status == 200 and
        hasDocument(gpa, found.body, ctx.run));
    const refused = try request(
        gpa,
        "/solr/admin/cores?action=CREATE&name=escape&instanceDir=/etc/native-solr&configSet=_def" ++
            "ault&wt=json",
        "",
    );
    try ctx.result(io, suite, "home-confined", refused.status >= 400);
    const service = try Io.Dir.cwd().readFileAlloc(
        io,
        "/etc/sv/solr/service",
        gpa,
        .limited(16384),
    );
    try ctx.result(io, suite, "no-shell-launcher", std.mem.startsWith(
        u8,
        service,
        "exec /usr/bin/java ",
    ) and
        std.mem.indexOf(u8, service, "run /bin/sh") == null and
        absent(io, "/usr/bin/bash") and absent(io, "/usr/bin/busybox"));
    const packages = try Io.Dir.cwd().readFileAlloc(
        io,
        "/usr/lib/apk/db/installed",
        gpa,
        .limited(4 << 20),
    );
    const prefix = "P:openjdk-27-jre\nV:";
    const at = std.mem.indexOf(u8, packages, prefix) orelse return error.MissingJava;
    const rest = packages[at + prefix.len ..];
    const end = std.mem.findScalar(u8, rest, '\n') orelse return error.PackageVersion;
    const revision = std.mem.indexOf(u8, rest[0..end], "-r") orelse return error.PackageVersion;
    const epoch = try std.fmt.parseInt(u32, rest[revision + 2 .. end], 10);
    try ctx.result(
        io,
        suite,
        "hardened-java",
        std.mem.startsWith(u8, rest[0..end], "27.") and epoch >= 2000,
    );
}

fn available(gpa: Allocator, verify: bool) bool {
    const info = request(gpa, "/solr/admin/info/system?wt=json", "") catch return false;
    if (info.status != 200) return false;
    if (!verify) return true;
    // Jetty answers before persisted cores have reopened. Probe the query
    // handler, without using the stored document as a readiness condition.
    const core = request(gpa, "/solr/native/select?q=*:*&rows=0&wt=json", "") catch return false;
    return core.status == 200;
}

fn hasDocument(gpa: Allocator, body: []const u8, id: []const u8) bool {
    const Search = struct { response: struct { docs: []const struct { id: []const u8 } } };
    const result = std.json.parseFromSliceLeaky(Search, gpa, body, .{
        .ignore_unknown_fields = true,
    }) catch return false;
    return result.response.docs.len == 1 and std.mem.eql(u8, result.response.docs[0].id, id);
}

fn absent(io: Io, path: []const u8) bool {
    Io.Dir.cwd().access(io, path, .{}) catch |err| return err == error.FileNotFound;
    return false;
}

const Response = struct { status: u16, body: []const u8 };

fn request(gpa: Allocator, path: []const u8, body: []const u8) !Response {
    const rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return error.Socket;
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    const address: linux.sockaddr.in = .{
        .port = std.mem.nativeToBig(u16, 8983),
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    if (linux.errno(linux.connect(fd, @ptrCast(&address), @sizeOf(@TypeOf(address)))) != .SUCCESS)
        return error.Connect;
    const raw = try gpa.print("{s} {s} HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n" ++
        "Content-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}", .{
        if (body.len == 0) "GET" else "POST",
        path,
        body.len,
        body,
    });
    var sent: usize = 0;
    while (sent < raw.len) {
        const n = linux.sendto(fd, raw[sent..].ptr, raw.len - sent, linux.MSG.NOSIGNAL, null, 0);
        if (linux.errno(n) == .INTR) continue;
        if (linux.errno(n) != .SUCCESS or n == 0) return error.Write;
        sent += n;
    }
    const buffer = try gpa.alloc(u8, 1 << 20);
    var used: usize = 0;
    while (used < buffer.len) {
        var poll = [_]linux.pollfd{.{ .fd = fd, .events = linux.POLL.IN, .revents = 0 }};
        const p = linux.poll(&poll, 1, 15000);
        if (linux.errno(p) == .INTR) continue;
        if (linux.errno(p) != .SUCCESS or p == 0) return error.Timeout;
        const n = linux.read(fd, buffer[used..].ptr, buffer.len - used);
        if (linux.errno(n) == .INTR) continue;
        if (linux.errno(n) != .SUCCESS) return error.Read;
        if (n == 0) break;
        used += n;
    }
    if (used == buffer.len) return error.ResponseTooLarge;
    const split = std.mem.indexOf(u8, buffer[0..used], "\r\n\r\n") orelse return error.Response;
    var words = std.mem.tokenizeScalar(u8, buffer[0..split], ' ');
    _ = words.next() orelse return error.Response;
    const status = try std.fmt.parseInt(u16, words.next() orelse return error.Response, 10);
    return .{ .status = status, .body = buffer[split + 4 .. used] };
}
