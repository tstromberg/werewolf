//! Complete Langflow editor/API, persistent flows and CPU inference without a shell.
const std = @import("std");
const driver = @import("test-driver");
const linux = std.os.linux;
const Io = std.Io;
const Allocator = std.mem.Allocator;
const demo = false;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();
    const args = try init.minimal.args.toSlice(gpa);
    if (args.len != 4) return error.Usage;
    const suite = args[1];
    const ctx = try driver.Run.load(io, gpa, args[3]);
    const callback = try std.process.run(gpa, io, .{
        .argv = &.{ "/usr/lib/langflow/bin/python", "-B", "/usr/lib/libffi-static/check.py" },
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(16384),
        .timeout = driver.deadline(io, 15),
    });
    try Io.File.stderr().writeStreamingAll(io, callback.stderr);
    try ctx.result(io, suite, "ffi-callback", callback.term == .exited and
        callback.term.exited == 0 and
        std.mem.indexOf(u8, callback.stdout, "ffi-callback: ok") != null);
    var ready = false;
    for (0..120) |_| {
        const health = http(gpa, "GET", "/health_check", "", "") catch {
            try io.sleep(.fromSeconds(1), .awake);
            continue;
        };
        if (health.status == 200) {
            ready = true;
            break;
        }
        try io.sleep(.fromSeconds(1), .awake);
    }
    try ctx.result(io, suite, "ready", ready);
    const editor = try http(gpa, "GET", "/", "", "");
    try ctx.result(
        io,
        suite,
        "editor",
        editor.status == 200 and (std.mem.indexOf(u8, editor.body, "langflow") != null or
            std.mem.indexOf(u8, editor.body, "Langflow") != null),
    );
    if (!demo) {
        const anonymous = try http(gpa, "GET", "/api/v1/flows/", "", "");
        try ctx.result(
            io,
            suite,
            "auth-required",
            anonymous.status == 401 or anonymous.status == 403,
        );
        const signup = try http(
            gpa,
            "POST",
            "/api/v1/users/",
            "Content-Type: application/json\r\n",
            try gpa.print(
                "{{\"username\":\"native-signup-{s}\",\"password\":\"werewolf-check-password\"}}",
                .{ctx.run},
            ),
        );
        try ctx.result(io, suite, "signup-disabled", signup.status == 403);
    }
    const login = if (demo)
        try http(gpa, "GET", "/api/v1/auto_login", "", "")
    else
        try http(
            gpa,
            "POST",
            "/api/v1/login",
            "Content-Type: application/x-www-form-urlencoded\r\n",
            "username=owner&password=werewolf-check-password",
        );
    try ctx.result(io, suite, "login", login.status == 200);
    const tokens = try std.json.parseFromSliceLeaky(std.json.Value, gpa, login.body, .{});
    const token = tokens.object.get("access_token") orelse return error.NoAccessToken;
    const auth = try gpa.print(
        "Authorization: Bearer {s}\r\nContent-Type: application/json\r\n",
        .{token.string},
    );
    const version = try http(gpa, "GET", "/api/v1/version", auth, "");
    const info = try std.json.parseFromSliceLeaky(std.json.Value, gpa, version.body, .{});
    try ctx.result(
        io,
        suite,
        "version",
        version.status == 200 and std.mem.eql(u8, info.object.get("version").?.string, "1.12.6"),
    );
    if (std.mem.eql(u8, ctx.phase, "seed")) {
        const body = try gpa.print(
            "{{\"name\":\"native-{s}\",\"data\":{{\"nodes\":[],\"edges\":[]}}}}",
            .{ctx.run},
        );
        const created = try http(gpa, "POST", "/api/v1/flows/", auth, body);
        if (created.status != 201) try Io.File.stderr().writeStreamingAll(io, created.body);
        try ctx.result(io, suite, "create-flow", created.status == 201);
    }
    const flows = try http(gpa, "GET", "/api/v1/flows/", auth, "");
    const name = try gpa.print("native-{s}", .{ctx.run});
    try ctx.result(
        io,
        suite,
        "persisted-flow",
        flows.status == 200 and std.mem.indexOf(u8, flows.body, name) != null,
    );
    const inference = try std.process.run(gpa, io, .{
        .argv = &.{ "/usr/lib/langflow/bin/python", "-B", "/usr/lib/onnx/check.py", "inference" },
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(16384),
        .timeout = driver.deadline(io, 30),
    });
    try Io.File.stderr().writeStreamingAll(io, inference.stderr);
    try ctx.result(
        io,
        suite,
        "local-inference",
        inference.term == .exited and inference.term.exited == 0 and
            std.mem.indexOf(u8, inference.stdout, "onnx-inference: ok") != null,
    );
    const embedding = try std.process.run(gpa, io, .{
        .argv = &.{ "/usr/lib/langflow/bin/python", "-B", "/usr/lib/langflow/check-embedding.py" },
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(16384),
        .timeout = driver.deadline(io, 60),
    });
    try Io.File.stderr().writeStreamingAll(io, embedding.stderr);
    try ctx.result(
        io,
        suite,
        "local-embedding",
        embedding.term == .exited and embedding.term.exited == 0 and
            std.mem.indexOf(u8, embedding.stdout, "onnx-embedding: ok") != null,
    );
    const service = try Io.Dir.cwd().readFileAlloc(
        io,
        "/etc/sv/langflow/service",
        gpa,
        .limited(16384),
    );
    try ctx.result(
        io,
        suite,
        "direct-python",
        std.mem.startsWith(u8, service, "exec /usr/lib/langflow/bin/python ") and
            std.mem.indexOf(u8, service, "/bin/sh") == null,
    );
    const packages = try Io.Dir.cwd().readFileAlloc(
        io,
        "/usr/lib/apk/db/installed",
        gpa,
        .limited(4 << 20),
    );
    const prefix = "P:python-3.15\nV:";
    const at = std.mem.indexOf(u8, packages, prefix) orelse return error.NoPython;
    const rest = packages[at + prefix.len ..];
    const end = std.mem.findScalar(u8, rest, '\n') orelse return error.PackageVersion;
    const rev = std.mem.indexOf(u8, rest[0..end], "-r") orelse return error.PackageVersion;
    try ctx.result(
        io,
        suite,
        "hardened-python",
        try std.fmt.parseInt(u32, rest[rev + 2 .. end], 10) >= 2000,
    );
    if (!demo) try ctx.result(
        io,
        suite,
        "private-listener",
        try driver.tcpPrivate(io, gpa, 7860, true),
    );
}

const Response = struct { status: u16, body: []const u8 };

fn http(
    gpa: Allocator,
    method: []const u8,
    path: []const u8,
    headers: []const u8,
    body: []const u8,
) !Response {
    const rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return error.Socket;
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    const address: linux.sockaddr.in = .{
        .port = std.mem.nativeToBig(u16, 7860),
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    if (linux.errno(linux.connect(fd, @ptrCast(&address), @sizeOf(@TypeOf(address)))) != .SUCCESS)
        return error.Connect;
    const raw = try gpa.print(
        "{s} {s} HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n{s}Content-Length: " ++
            "{d}\r\n\r\n{s}",
        .{ method, path, headers, body.len, body },
    );
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
    const payload = buffer[split + 4 .. used];
    var lines = std.mem.tokenizeSequence(u8, buffer[0..split], "\r\n");
    while (lines.next()) |line| {
        const colon = std.mem.findScalar(u8, line, ':') orelse continue;
        if (!std.ascii.eqlIgnoreCase(line[0..colon], "Content-Encoding")) continue;
        if (!std.ascii.eqlIgnoreCase(std.mem.trim(u8, line[colon + 1 ..], " \t"), "gzip"))
            return error.UnsupportedEncoding;
        // Langflow compresses flow lists even without Accept-Encoding.
        var input: Io.Reader = .fixed(payload);
        var window: [std.compress.flate.max_window_len]u8 = undefined;
        var gzip: std.compress.flate.Decompress = .init(&input, .gzip, &window);
        return .{
            .status = status,
            .body = try gzip.reader.allocRemaining(gpa, .limited(1 << 20)),
        };
    }
    return .{ .status = status, .body = payload };
}
