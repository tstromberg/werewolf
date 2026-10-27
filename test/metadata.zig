//! metadata PAYLOAD PORT_FILE LOG_FILE [HOSTNAME CONTEXT] stands in for GCP's, AWS's,
//! Hetzner Cloud's and Azure's metadata servers in make check's cloud
//! boots (test/cloud-boot). It serves user data only as each cloud does:
//! GCP's with Metadata-Flavor: Google, AWS's only through an IMDSv2
//! session token, Hetzner's plainly, Azure's with Metadata: true. It
//! refuses anything else.
//!
//! PAYLOAD is good (a config tar with a hostname and root's key), people
//! (good, with a users file naming tom, an admin), people2 (tom with a new
//! key) or hostile (a symlink and a ../ entry beside them), base64-encoded
//! as a cloud holds it; or FIRST>THEN@N, which serves FIRST for the first N
//! user-data requests and THEN after, as a config changed at the cloud. It
//! listens on 127.0.0.1, writes its port to PORT_FILE, and logs each
//! request's method, target and the headers that matter to LOG_FILE. Each
//! config names the machine cloud-check, or HOSTNAME; given CONTEXT, the
//! file a native boot's run context is in (native-tests boot), it carries
//! that as tests/context, read as each request is answered.

const std = @import("std");
const host = @import("host");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const mem = std.mem;
const http = host.http;

const token = "werewolf-check-token";
const root_key = "ssh-ed25519 " ++
    "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl werewolf-check-key\n";

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();
    const args = try init.minimal.args.toSlice(gpa);
    if (args.len != 4 and args.len != 6)
        std.process.fatal("usage: metadata PAYLOAD PORT_FILE LOG_FILE [HOSTNAME CONTEXT]", .{});
    var server: Server = .{ .io = io, .log = args[3], .plan = try Plan.parse(args[1]) };
    if (args.len == 6) {
        server.hostname = args[4];
        server.context = args[5];
    }
    var listener: http.Server = undefined;
    try listener.start(io, gpa, .{ .handler = .{ .context = &server, .serve = Server.serve } });
    try Io.Dir.cwd().writeFile(
        io,
        .{ .sub_path = args[2], .data = try gpa.print("{d}\n", .{listener.port()}) },
    );
    // Serve until killed.
    while (true) try io.sleep(.fromSeconds(3600), .awake);
}

/// Plan is which payloads the server gives, and after how many requests
/// it changes from the first to the second.
const Plan = struct {
    first: []const u8,
    then: []const u8,
    switch_at: ?u32 = null,

    fn parse(payload: []const u8) !Plan {
        const arrow = mem.findScalar(
            u8,
            payload,
            '>',
        ) orelse return .{ .first = payload, .then = payload };
        const rest = payload[arrow + 1 ..];
        const at = mem.findScalar(u8, rest, '@') orelse return error.BadPayload;
        return .{
            .first = payload[0..arrow],
            .then = rest[0..at],
            .switch_at = try std.fmt.parseInt(u32, rest[at + 1 ..], 10),
        };
    }
};

/// configTar is payload's config tar, naming the machine hostname, with
/// context as tests/context if there is one, base64-encoded.
fn configTar(
    gpa: Allocator,
    payload: []const u8,
    hostname: []const u8,
    context: ?[]const u8,
) ![]const u8 {
    var out: Io.Writer.Allocating = .init(gpa);
    var tar: std.tar.Writer = .{ .underlying_writer = &out.writer };
    try tar.writeFileBytes("hostname", try gpa.print("{s}\n", .{hostname}), .{ .mode = 0o644 });
    if (context) |c| try tar.writeFileBytes("tests/context", c, .{ .mode = 0o644 });
    if (mem.eql(u8, payload, "hostile")) {
        try tar.writeLink("authorized_keys", "/etc/shadow", .{ .mode = 0o644 });
        try tar.writeFileBytes("../escaped", "out\n", .{ .mode = 0o644 });
    } else try tar.writeFileBytes("authorized_keys", root_key, .{ .mode = 0o644 });
    if (mem.eql(u8, payload, "people")) try tar.writeFileBytes(
        "users",
        "tom admin sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIGx0 " ++
            "tom@yubikey\n",
        .{ .mode = 0o644 },
    );
    if (mem.eql(u8, payload, "people2"))
        try tar.writeFileBytes(
            "users",
            "tom admin sk-ssh-ed25519@openssh.com AAAA2 tom@spare\n",
            .{ .mode = 0o644 },
        );
    try tar.finishPedantically();
    const raw = out.written();
    const encoded = try gpa.alloc(u8, std.base64.standard.Encoder.calcSize(raw.len));
    return std.base64.standard.Encoder.encode(encoded, raw);
}

const Server = struct {
    io: Io,
    log: []const u8,
    plan: Plan,
    hostname: []const u8 = "cloud-check",
    /// context is the file holding a native boot's run context, or null.
    context: ?[]const u8 = null,
    served: std.atomic.Value(u32) = .init(0),
    mutex: Io.Mutex = .init,

    /// payload is the one the next user-data request gets.
    fn payload(s: *Server) []const u8 {
        const n = s.served.fetchAdd(1, .monotonic) + 1;
        const later = if (s.plan.switch_at) |at| n > at else false;
        return if (later) s.plan.then else s.plan.first;
    }

    fn body(s: *Server, gpa: Allocator) ![]const u8 {
        const context = if (s.context) |path|
            try Io.Dir.cwd().readFileAlloc(s.io, path, gpa, .limited(4096))
        else
            null;
        return configTar(gpa, s.payload(), s.hostname, context);
    }

    fn record(s: *Server, gpa: Allocator, r: *const http.Request) !void {
        var line: std.ArrayList(u8) = .empty;
        try line.print(gpa, "{s} {s} {{", .{ r.method, r.target });
        var n: usize = 0;
        for ([_][]const u8{
            "Metadata-Flavor",
            "Metadata",
            "X-aws-ec2-metadata-token",
            "X-aws-ec2-metadata-token-ttl-seconds",
        }) |h| if (r.header(h)) |v| if (v.len > 0) {
            try line.print(gpa, "{s}'{s}': '{s}'", .{ if (n > 0) ", " else "", h, v });
            n += 1;
        };
        try line.appendSlice(gpa, "}\n");
        s.mutex.lockUncancelable(s.io);
        defer s.mutex.unlock(s.io);
        try host.check.append(s.io, s.log, line.items);
    }

    fn serve(context: *anyopaque, gpa: Allocator, r: *const http.Request, w: *http.Response) !void {
        const s: *Server = @ptrCast(@alignCast(context));
        // As an HTTP/1.0 server would, answer once per connection.
        w.close = true;
        const get = mem.eql(u8, r.method, "GET");
        if (!get and !mem.eql(u8, r.method, "PUT")) return w.send(501, &.{}, "");
        try s.record(gpa, r);
        const google: []const http.Header = &.{.{ .name = "Metadata-Flavor", .value = "Google" }};
        const target = r.target;
        if (get) {
            if (mem.eql(u8, target, "/computeMetadata/v1/instance/attributes/user-data")) {
                // GCP marks every answer; cloud-metadata refuses one without it.
                if (eql(
                    r.header("Metadata-Flavor"),
                    "Google",
                )) return w.send(200, google, try s.body(gpa));
                return w.send(403, google, "");
            }
            if (mem.eql(u8, target, "/latest/user-data"))
                return if (eql(r.header("X-aws-ec2-metadata-token"), token))
                    w.send(200, &.{}, try s.body(gpa))
                else
                    w.send(401, &.{}, "");
            if (mem.eql(
                u8,
                target,
                "/hetzner/v1/userdata",
            )) return w.send(200, &.{}, try s.body(gpa));
            if (mem.eql(
                u8,
                target,
                "/metadata/instance/compute/userData?api-version=2021-01-01&format=text",
            ))
                return if (eql(r.header("Metadata"), "true"))
                    w.send(200, &.{}, try s.body(gpa))
                else
                    w.send(400, &.{}, "");
            return w.send(404, &.{}, "");
        }
        if (mem.eql(u8, target, "/latest/api/token") and
            @as([]const u8, r.header("X-aws-ec2-metadata-token-ttl-seconds") orelse "").len > 0)
            return w.send(200, &.{}, token);
        return w.send(400, &.{}, "");
    }
};

fn eql(got: ?[]const u8, want: []const u8) bool {
    return mem.eql(u8, got orelse return false, want);
}

test "a changing payload switches after its count" {
    const plan = try Plan.parse("good>people@2");
    try std.testing.expectEqualStrings("good", plan.first);
    try std.testing.expectEqualStrings("people", plan.then);
    try std.testing.expectEqual(2, plan.switch_at.?);
    var s: Server = .{ .io = std.testing.io, .log = "", .plan = plan };
    for ([_][]const u8{ "good", "good", "people", "people" }) |want|
        try std.testing.expectEqualStrings(want, s.payload());
    try std.testing.expectError(error.BadPayload, Plan.parse("good>people"));
}

test "the hostile tar holds a link and an escape; the good one a key, and a context if given" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    for ([_][]const u8{ "good", "hostile", "people", "context" }) |payload| {
        const context: ?[]const u8 = if (mem.eql(u8, payload, "context")) "{}" else null;
        const encoded = try configTar(
            gpa,
            if (context) |_| "good" else payload,
            "cloud-poll",
            context,
        );
        const raw = try gpa.alloc(u8, try std.base64.standard.Decoder.calcSizeForSlice(encoded));
        try std.base64.standard.Decoder.decode(raw, encoded);
        var reader: Io.Reader = .fixed(raw);
        var name_buf: [256]u8 = undefined;
        var link_buf: [256]u8 = undefined;
        var it: std.tar.Iterator = .init(
            &reader,
            .{ .file_name_buffer = &name_buf, .link_name_buffer = &link_buf },
        );
        var names: std.ArrayList(u8) = .empty;
        while (try it.next()) |f| try names.print(gpa, "{s}:{t} ", .{ f.name, f.kind });
        const want = if (mem.eql(u8, payload, "hostile"))
            "hostname:file authorized_keys:sym_link ../escaped:file "
        else if (mem.eql(u8, payload, "people"))
            "hostname:file authorized_keys:file users:file "
        else if (context != null)
            "hostname:file tests/context:file authorized_keys:file "
        else
            "hostname:file authorized_keys:file ";
        try std.testing.expectEqualStrings(want, names.items);
    }
}
