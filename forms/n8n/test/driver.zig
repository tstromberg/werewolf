//! Full n8n API, persisted workflows and the separate JavaScript Code runner.
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
    var ready = false;
    for (0..120) |_| {
        const health = http(gpa, "GET", "/healthz/readiness", "", "") catch {
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
    var editor_ready = false;
    for (0..60) |_| {
        const editor = http(gpa, "GET", "/", "", "") catch {
            try io.sleep(.fromSeconds(1), .awake);
            continue;
        };
        if (editor.status == 200 and std.mem.indexOf(u8, editor.body, "n8n") != null) {
            editor_ready = true;
            break;
        }
        try io.sleep(.fromSeconds(1), .awake);
    }
    try ctx.result(io, suite, "editor", editor_ready);
    const anonymous = try http(gpa, "GET", "/rest/workflows", "", "");
    try ctx.result(io, suite, "auth-required", anonymous.status == 401 or anonymous.status == 403);
    const json_header = "Content-Type: application/json\r\n";
    if (std.mem.eql(u8, ctx.phase, "seed")) {
        const setup = try http(
            gpa,
            "POST",
            "/rest/owner/setup",
            json_header,
            "{\"email\":\"owner@example.org\",\"firstName\":\"Native\",\"lastName\":\"Test\",\"p" ++
                "assword\":\"Werewolf-check-123!\"}",
        );
        try ctx.result(io, suite, "owner-setup", setup.status == 200);
    }
    const login = try http(
        gpa,
        "POST",
        "/rest/login",
        json_header,
        "{\"emailOrLdapLoginId\":\"owner@example.org\",\"password\":\"Werewolf-check-123!\"}",
    );
    try ctx.result(io, suite, "login", login.status == 200);
    var cookie: ?[]const u8 = null;
    var headers = std.mem.splitSequence(u8, login.headers, "\r\n");
    while (headers.next()) |line| {
        if (!std.ascii.startsWithIgnoreCase(line, "set-cookie:")) continue;
        const value = std.mem.trim(u8, line[11..], " \t");
        const end = std.mem.findScalar(u8, value, ';') orelse value.len;
        if (std.mem.startsWith(u8, value, "n8n-auth=")) cookie = value[0..end];
    }
    const auth = try gpa.print(
        "Cookie: {s}\r\n{s}",
        .{ cookie orelse return error.NoAuthCookie, json_header },
    );
    const name = try gpa.print("native-{s}", .{ctx.run});
    const graph = "\"nodes\":[{\"id\":\"trigger\",\"name\":\"Manual\",\"type\":\"n8n-nodes-base." ++
        "manualTrigger\",\"typeVersion\":1,\"position\":[0,0],\"parameters\":{}},{\"id\":\"set\"" ++
        ",\"name\":\"Expression\",\"type\":\"n8n-nodes-base.set\",\"typeVersion\":3.4,\"position" ++
        "\":[240,0],\"parameters\":{\"assignments\":{\"assignments\":[{\"id\":\"answer\",\"name" ++
        "\":\"answer\",\"type\":\"number\",\"value\":\"={{ 6 * 7 }}\"},{\"id\":\"sandbox\",\"nam" ++
        "e" ++
        "\":\"sandbox\",\"type\":\"string\",\"value\":\"={{ (function(){ return " ++
        "'werewolf-cve-2025" ++
        "-68613:' + this.process.version; })() }}\"}]},\"options\":{}}},{\"id" ++
        "\":\"code\",\"name\":\"Code\",\"type\":\"n8n-nodes-base.code\",\"typeVersion\":2,\"posi" ++
        "tion\":[480,0],\"parameters\":{\"jsCode\":\"if ($input.first().json.answer !== 42) " ++
        "throw new Error('expression result'); return [{json:{marker:'native-code-ok',answer:42," ++
        "sandbox:$input.first().json.sandbox}" ++
        "}];\"}}],\"connections\":{\"Manual\":{\"main\":[[{\"node\":\"Expression\",\"type\":\"ma" ++
        "in\",\"index\":0}]]},\"Expression\":{\"main\":[[{\"node\":\"Code\",\"type\":\"main\",\"" ++
        "index\":0}]]}},\"settings\":{\"executionOrder\":\"v1\"}";
    if (std.mem.eql(u8, ctx.phase, "seed")) {
        const body = try gpa.print("{{\"name\":\"{s}\",\"active\":false,{s}}}", .{ name, graph });
        const created = try http(gpa, "POST", "/rest/workflows", auth, body);
        if (created.status != 200) try Io.File.stderr().writeStreamingAll(io, created.body);
        try ctx.result(io, suite, "create-workflow", created.status == 200);
    }
    const flows = try http(gpa, "GET", "/rest/workflows", auth, "");
    const listing = try std.json.parseFromSliceLeaky(std.json.Value, gpa, flows.body, .{});
    var id: ?[]const u8 = null;
    for (listing.object.get("data").?.array.items) |flow| {
        if (std.mem.eql(
            u8,
            flow.object.get("name").?.string,
            name,
        )) id = flow.object.get("id").?.string;
    }
    try ctx.result(io, suite, "persisted-workflow", flows.status == 200 and id != null);
    const workflow_id = id orelse return error.NoWorkflow;
    const run_path = try gpa.print("/rest/workflows/{s}/run", .{workflow_id});
    const run_body = if (demo)
        try gpa.print(
            "{{\"workflowData\":{{\"id\":\"{s}\",\"name\":\"{s}\",\"active\":false,{s}}},\"start" ++
                "Nodes\":[{{\"name\":\"Manual\"}}]}}",
            .{ workflow_id, name, graph },
        )
    else
        "{\"triggerToStartFrom\":{\"name\":\"Manual\"}}";
    const run = try http(gpa, "POST", run_path, auth, run_body);
    if (run.status != 200) try Io.File.stderr().writeStreamingAll(io, run.body);
    try ctx.result(io, suite, "run-workflow", run.status == 200);
    const run_result = try std.json.parseFromSliceLeaky(std.json.Value, gpa, run.body, .{});
    const execution_id = run_result.object.get("data").?.object.get("executionId").?.string;
    const execution_path = try gpa.print("/rest/executions/{s}", .{execution_id});
    var ran_code = false;
    var last_execution: []const u8 = "";
    for (0..60) |_| {
        const execution = try http(gpa, "GET", execution_path, auth, "");
        last_execution = execution.body;
        if (execution.status == 200 and
            std.mem.indexOf(u8, execution.body, "native-code-ok") != null and
            std.mem.indexOf(u8, execution.body, "\"status\":\"success\"") != null)
        {
            ran_code = true;
            break;
        }
        try io.sleep(.fromSeconds(1), .awake);
    }
    if (!ran_code) try Io.File.stderr().writeStreamingAll(io, last_execution);
    try ctx.result(io, suite, "code-runner", ran_code);
    try ctx.result(
        io,
        suite,
        "cve-2025-68613-fixed",
        std.mem.indexOf(u8, last_execution, "werewolf-cve-2025-68613:v26.") == null,
    );
    const service = try Io.Dir.cwd().readFileAlloc(io, "/etc/sv/n8n/service", gpa, .limited(16384));
    try ctx.result(
        io,
        suite,
        "direct-node",
        std.mem.startsWith(u8, service, "exec /usr/bin/node ") and
            std.mem.indexOf(u8, service, "/bin/sh") == null,
    );
    const packages = try Io.Dir.cwd().readFileAlloc(
        io,
        "/usr/lib/apk/db/installed",
        gpa,
        .limited(64 << 20), // apk lists every file each package installs
    );
    const at = std.mem.indexOf(u8, packages, "P:nodejs-26\nV:") orelse return error.NoNode;
    const rest = packages[at + "P:nodejs-26\nV:".len ..];
    const end = std.mem.findScalar(u8, rest, '\n') orelse return error.PackageVersion;
    const rev = std.mem.indexOf(u8, rest[0..end], "-r") orelse return error.PackageVersion;
    try ctx.result(
        io,
        suite,
        "hardened-node",
        try std.fmt.parseInt(u32, rest[rev + 2 .. end], 10) >= 2000,
    );
    if (!demo) try ctx.result(
        io,
        suite,
        "private-listener",
        try driver.tcpPrivate(io, gpa, 5678, true),
    );
}

const Response = struct { status: u16, body: []const u8, headers: []const u8 };

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
        .port = std.mem.nativeToBig(u16, 5678),
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
    return .{ .status = status, .body = buffer[split + 4 .. used], .headers = buffer[0..split] };
}
