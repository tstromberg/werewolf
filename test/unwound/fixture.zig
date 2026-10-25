//! fixture is the misbehaving world unwound faces in check-unwound's peer
//! namespace: a resolver that answers, stays silent, forges, truncates and
//! delays on cue, recording every question that reaches it, and the RDAP
//! and crt.sh servers the age writer asks over HTTPS.

const std = @import("std");
const host = @import("host");
const Io = std.Io;
const linux = std.os.linux;
const mem = std.mem;
const netns = host.netns;
const dnswire = host.dnswire;

pub const upstream = "10.53.0.2";
pub const age_https = "8.8.8.8";

/// Replies are the datagrams one question gets: usually one.
const Replies = struct {
    bufs: [3][2048]u8 = undefined,
    msgs: [3]dnswire.Message = undefined,
    n: usize = 0,

    fn add(r: *Replies) *dnswire.Message {
        r.msgs[r.n] = .{ .buf = &r.bufs[r.n] };
        r.n += 1;
        return &r.msgs[r.n - 1];
    }
};

const Answer = struct {
    q: dnswire.Question,
    id: u16,
    replies: *Replies,

    /// reply starts a reply with n answers and ns authority records.
    fn reply(a: Answer, flags: u16, an: u16, ns: u16) !*dnswire.Message {
        const m = a.replies.add();
        try m.header(.{ .id = a.id, .flags = flags, .an = an, .ns = ns });
        try m.put(a.q.raw);
        return m;
    }

    fn one(a: Answer, ip: [4]u8, ttl: u32) !void {
        const m = try a.reply(0x81a0, 1, 0);
        try m.record(a.q.name, 1, ttl, &ip);
    }

    fn none(a: Answer, flags: u16) !void {
        _ = try a.reply(flags, 0, 0);
    }
};

const aliases = [_][2][]const u8{
    .{ "callback-alias.example.test", "token.oastify.com" },
    .{ "prefix-alias.example.test", "192-0-2-1.attacker.example" },
    .{ "alias-to-allowed.example.test", "httpbin.org" },
    .{ "assigned-alias.assigned.test", "young.com" },
    .{ "explicit-alias.example.test", "young.com" },
    .{ "revoked-alias.example.test", "edge.assigned.test" },
    .{ "local-alias.example.com", "edge.example.com" },
    .{ "cross-alias.example.com", "young.com" },
};

/// Rr is a record of an answer: the question's own name unless owner says.
const Rr = struct { owner: ?[]const u8 = null, kind: u16 = 1, data: []const u8 };

const edge = "edge.cdn.example.test";

const table = [_]struct { []const u8, u16, []const Rr }{
    .{ "httpbin.org", 1, &.{.{ .data = &.{ 192, 0, 2, 70 } }} },
    .{ "allowed.ngrok.app", 1, &.{.{ .data = &.{ 192, 0, 2, 71 } }} },
    .{ "api.example.test", 1, &.{.{ .data = &.{ 192, 0, 2, 10 } }} },
    .{ "api.example.test", 28, &.{.{ .kind = 28, .data = &(.{ 0x20, 0x01, 0x0d, 0xb8 } ++
        @as([10]u8, @splat(0)) ++ .{ 0, 0x10 }) }} },
    .{ "x.cdn.example.test", 1, &.{.{ .data = &.{ 192, 0, 2, 11 } }} },
    .{ "alias-ok.example.test", 1, &.{
        .{ .kind = 5, .data = wire(edge) },
        .{ .owner = edge, .data = &.{ 192, 0, 2, 12 } },
    } },
    .{ "alias-bad.example.test", 1, &.{
        .{ .kind = 5, .data = wire("evil.example.net") },
        .{ .owner = "evil.example.net", .data = &.{ 192, 0, 2, 13 } },
    } },
    .{ "open.example.test", 1, &.{.{ .data = &.{ 192, 0, 2, 15 } }} },
    .{ "cached.example.test", 1, &.{.{ .data = &.{ 192, 0, 2, 16 } }} },
    .{ "delayed.example.test", 1, &.{.{ .data = &.{ 192, 0, 2, 17 } }} },
    // Seven addresses behind an alias, two of them private.
    .{ "screened.example.test", 1, &.{
        .{ .kind = 5, .data = wire(edge) },
        .{ .owner = edge, .data = &.{ 10, 0, 0, 1 } },
        .{ .owner = edge, .data = &.{ 127, 0, 0, 1 } },
        .{ .owner = edge, .data = &.{ 192, 0, 2, 20 } },
        .{ .owner = edge, .data = &.{ 192, 0, 2, 21 } },
        .{ .owner = edge, .data = &.{ 192, 0, 2, 22 } },
        .{ .owner = edge, .data = &.{ 192, 0, 2, 23 } },
        .{ .owner = edge, .data = &.{ 192, 0, 2, 24 } },
    } },
    .{ "rebind.example.test", 1, &.{
        .{ .data = &.{ 127, 0, 0, 1 } },
        .{ .data = &.{ 192, 168, 1, 1 } },
    } },
};

/// wire is a name as DNS labels.
fn wire(comptime text: []const u8) []const u8 {
    comptime {
        var out: []const u8 = "";
        var labels = mem.tokenizeScalar(u8, text, '.');
        while (labels.next()) |l| out = out ++ [_]u8{l.len} ++ l;
        return out ++ [_]u8{0};
    }
}

var polls: std.atomic.Value(u32) = .init(0);

/// answer fills replies for query, as the fixture's names say.
fn answer(query: []const u8, tcp: bool, replies: *Replies) !void {
    var name_buf: [255]u8 = undefined;
    const q = try dnswire.question(query, &name_buf);
    var lower_buf: [255]u8 = undefined;
    const name = std.ascii.lowerString(&lower_buf, q.name);
    const a: Answer = .{ .q = q, .id = mem.readInt(u16, query[0..2], .big), .replies = replies };
    const is = struct {
        fn in(n: []const u8, set: []const []const u8) bool {
            for (set) |s| if (mem.eql(u8, n, s)) return true;
            return false;
        }
    }.in;
    if (q.kind == 1 and
        is(name, &.{ "rdap.verisign.com", "rdap.publicinterestregistry.org", "crt.sh" }))
        return a.one(.{ 8, 8, 8, 8 }, 300);
    if (q.kind == 1 and
        is(name, &.{ "expires.com", "ctexpires.com" })) return a.one(.{ 192, 0, 2, 60 }, 300);
    if (mem.eql(u8, name, "slow.example.test")) return;
    if (mem.eql(u8, name, "race.example.test"))
        return if (tcp) a.one(.{ 192, 0, 2, 44 }, 300) else a.none(0x8380);
    if (mem.eql(u8, name, "spoof.example.test")) {
        // A wrong ID, then a lowered question, then the real answer.
        const forged = replies.add();
        try forged.header(.{ .id = a.id ^ 0xff00, .flags = 0x81a0, .an = 1 });
        try forged.put(q.raw);
        try forged.record(q.name, 1, 300, &.{ 192, 0, 2, 66 });
        const lowered = replies.add();
        try lowered.header(.{ .id = a.id, .flags = 0x81a0, .an = 1 });
        try lowered.name(name);
        try lowered.put(q.raw[q.raw.len - 4 ..]);
        try lowered.record(name, 1, 300, &.{ 192, 0, 2, 66 });
        return a.one(.{ 192, 0, 2, 14 }, 300);
    }
    if (mem.eql(u8, name, "poll.example.test"))
        return a.one(.{ 198, 51, 100, @truncate(polls.fetchAdd(1, .monotonic) + 1) }, 300);
    if (mem.eql(u8, name, "short.example.test")) return a.one(.{ 192, 0, 2, 30 }, 1);
    if (mem.eql(u8, name, "zero.example.test")) return a.one(.{ 192, 0, 2, 31 }, 0);
    if (mem.eql(u8, name, "gone.example.test")) {
        // An SOA lets a negative answer be kept min(300, 60) seconds.
        var soa_buf: [128]u8 = undefined;
        var soa: dnswire.Message = .{ .buf = &soa_buf };
        try soa.name("ns.example.test");
        try soa.name("admin.example.test");
        for ([_]u32{ 1, 7200, 900, 86400, 60 }) |v| try soa.int(u32, v);
        const m = try a.reply(0x81a0 | 3, 0, 1);
        return m.record("example.test", 6, 300, soa.bytes());
    }
    if (mem.endsWith(u8, name, ".fill.example.test")) return a.one(.{ 192, 0, 2, 40 }, 300);
    if (mem.eql(u8, name, "big.example.test") and q.kind == 16) {
        if (!tcp) return a.none(0x8380);
        var txt: [256]u8 = @splat('x');
        txt[0] = 255;
        const m = try a.reply(0x81a0, 3, 0);
        for (0..3) |_| try m.record(q.name, 16, 300, &txt);
        return;
    }
    for (aliases) |alias| if (mem.eql(u8, name, alias[0]) and (q.kind == 1 or q.kind == 5)) {
        var target_buf: [255]u8 = undefined;
        var target: dnswire.Message = .{ .buf = &target_buf };
        try target.name(alias[1]);
        const m = try a.reply(0x81a0, if (q.kind == 1) 2 else 1, 0);
        try m.record(q.name, 5, 300, target.bytes());
        if (q.kind == 1) try m.record(alias[1], 1, 300, &.{ 192, 0, 2, 50 });
        return;
    };
    for (table) |entry| if (mem.eql(u8, name, entry[0]) and q.kind == entry[1]) {
        const m = try a.reply(0x81a0, @intCast(entry[2].len), 0);
        for (entry[2]) |rr| try m.record(rr.owner orelse q.name, rr.kind, 300, rr.data);
        return;
    };
    return a.none(0x81a0 | 3);
}

/// resolver serves UDP and TCP on upstream:53 until killed, appending one
/// JSON line per question to log.
pub fn resolver(l: netns.Lab, log: []const u8) !void {
    const out_rc = linux.open(try l.gpa.dupeSentinel(u8, log, 0), .{
        .ACCMODE = .WRONLY,
        .APPEND = true,
        .CREAT = true,
        .CLOEXEC = true,
    }, 0o644);
    if (linux.errno(out_rc) != .SUCCESS) return error.LogUnwritable;
    const out: linux.fd_t = @intCast(out_rc);
    const udp = try netns.socket(linux.SOCK.DGRAM);
    try netns.listen(udp, upstream, 53, null);
    const tcp = try netns.socket(linux.SOCK.STREAM);
    try netns.listen(tcp, upstream, 53, 64);
    var group: Io.Group = .init;
    try group.concurrent(l.io, streams, .{ tcp, out });
    try netns.writeAll(1, "ready\n");
    var race_packets: usize = 0;
    var buf: [2048]u8 = undefined;
    while (true) {
        var from: linux.sockaddr.in = undefined;
        var len: linux.socklen_t = @sizeOf(linux.sockaddr.in);
        const rc = linux.recvfrom(udp, &buf, buf.len, 0, @ptrCast(&from), &len);
        if (linux.errno(rc) != .SUCCESS) continue;
        const query = buf[0..rc];
        note(out, query, "udp");
        var name_buf: [255]u8 = undefined;
        const q = dnswire.question(query, &name_buf) catch continue;
        var delay: u32 = 0;
        if (std.ascii.eqlIgnoreCase(q.name, "race.example.test")) {
            // The first try goes unanswered; later ones are answered late.
            race_packets += 1;
            if (race_packets == 1) continue;
            delay = 500;
        }
        // delayed.example.test is answered half a second later, so the same
        // question asked meanwhile finds it out.
        if (std.ascii.eqlIgnoreCase(q.name, "delayed.example.test")) delay = 500;
        if (delay == 0) {
            send(udp, query, from);
        } else {
            try group.concurrent(l.io, later, .{ udp, try l.gpa.dupe(u8, query), from, delay });
        }
    }
}

fn later(udp: linux.fd_t, query: []const u8, to: linux.sockaddr.in, ms: u32) void {
    netns.nap(ms);
    send(udp, query, to);
}

fn send(udp: linux.fd_t, query: []const u8, to: linux.sockaddr.in) void {
    var replies: Replies = .{};
    answer(query, false, &replies) catch return;
    for (replies.msgs[0..replies.n]) |m|
        _ = linux.sendto(udp, m.bytes().ptr, m.len, 0, @ptrCast(&to), @sizeOf(linux.sockaddr.in));
}

fn streams(tcp: linux.fd_t, out: linux.fd_t) void {
    while (true) {
        const rc = linux.accept4(tcp, null, null, linux.SOCK.CLOEXEC);
        if (linux.errno(rc) != .SUCCESS) continue;
        const client: linux.fd_t = @intCast(rc);
        defer netns.close(client);
        netns.limit(client, 5000);
        var size: [2]u8 = undefined;
        netns.readExact(client, &size) catch continue;
        var buf: [65535]u8 = undefined;
        const query = buf[0..mem.readInt(u16, &size, .big)];
        netns.readExact(client, query) catch continue;
        note(out, query, "tcp");
        var replies: Replies = .{};
        answer(query, true, &replies) catch continue;
        for (replies.msgs[0..replies.n]) |m| {
            var len: [2]u8 = undefined;
            mem.writeInt(u16, &len, @intCast(m.len), .big);
            netns.writeAll(client, &len) catch break;
            netns.writeAll(client, m.bytes()) catch break;
        }
    }
}

/// note logs the question as {"name","proto","flags","arcount"}, one write.
fn note(out: linux.fd_t, query: []const u8, proto: []const u8) void {
    var name_buf: [255]u8 = undefined;
    const q = dnswire.question(query, &name_buf) catch return;
    var buf: [512]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    std.json.Stringify.value(.{
        .name = q.name,
        .proto = proto,
        .flags = mem.readInt(u16, query[2..4], .big),
        .arcount = mem.readInt(u16, query[10..12], .big),
    }, .{}, &w) catch return;
    w.writeByte('\n') catch return;
    netns.writeAll(out, w.buffered()) catch {};
}

/// Registry answers RDAP and crt.sh for the live age check, as each
/// domain's fixture says, and logs each request's host and path.
const Registry = struct {
    io: Io,
    log: linux.fd_t,

    fn serve(
        context: *anyopaque,
        gpa: mem.Allocator,
        request: *const host.http.Request,
        response: *host.http.Response,
    ) !void {
        const r: *Registry = @ptrCast(@alignCast(context));
        const name = request.header("host") orelse "";
        const path = request.path();
        response.close = true;
        const recent = try date(gpa, Io.Clock.real.now(r.io).toSeconds() - 5 * 86400);
        var body: Io.Writer.Allocating = .init(gpa);
        var status: u16 = 200;
        var headers: [2]host.http.Header = .{
            .{ .name = "Content-Type", .value = "application/json" },
            .{ .name = "Location", .value = "https://crt.sh/?q=redirect.com&output=json" },
        };
        var expected = true;
        if (mem.eql(u8, name, "crt.sh")) {
            const domain = param(request.target, "q") orelse "";
            expected = mem.eql(u8, domain, "outage.com") or mem.eql(u8, domain, "ctexpires.com");
            const when = if (mem.eql(u8, domain, "ctexpires.com"))
                recent
            else
                "2020-01-01T00:00:00";
            try std.json.Stringify.value(
                .{.{ .name_value = domain, .min_entry_timestamp = when }},
                .{},
                &body.writer,
            );
        } else {
            const domain = path[(mem.findScalarLast(u8, path, '/') orelse 0) + 1 ..];
            if (mem.eql(u8, domain, "timeout.com")) {
                r.note(name, request.target, true);
                try r.io.sleep(.fromSeconds(16), .awake);
                return error.Stalled;
            }
            if (mem.eql(u8, domain, "outage.com") or
                mem.eql(u8, domain, "ctexpires.com")) status = 503;
            if (mem.eql(u8, domain, "redirect.com")) status = 302;
            const when = if (mem.eql(u8, domain, "young.com") or mem.eql(u8, domain, "expires.com"))
                recent
            else
                "2020-01-01T00:00:00Z";
            try std.json.Stringify.value(.{
                .objectClassName = "domain",
                .ldhName = if (mem.eql(u8, domain, "invalid.com")) "wrong.com" else domain,
                .events = .{.{ .eventAction = "registration", .eventDate = when }},
            }, .{}, &body.writer);
        }
        r.note(name, request.target, expected);
        try response.send(
            status,
            headers[0 .. @as(usize, 1) + @intFromBool(status == 302)],
            body.written(),
        );
    }

    fn note(r: *Registry, name: []const u8, target: []const u8, expected: bool) void {
        var buf: [1024]u8 = undefined;
        var w: Io.Writer = .fixed(&buf);
        std.json.Stringify.value(
            .{ .host = name, .path = target, .expected = expected },
            .{},
            &w,
        ) catch return;
        w.writeByte('\n') catch return;
        netns.writeAll(r.log, w.buffered()) catch {};
    }
};

fn param(target: []const u8, key: []const u8) ?[]const u8 {
    const at = mem.findScalar(u8, target, '?') orelse return null;
    var pairs = mem.tokenizeScalar(u8, target[at + 1 ..], '&');
    while (pairs.next()) |pair| {
        const eq = mem.findScalar(u8, pair, '=') orelse continue;
        if (mem.eql(u8, pair[0..eq], key)) return pair[eq + 1 ..];
    }
    return null;
}

/// date writes seconds since the epoch as RFC 3339 UTC: 2026-10-24T10:00:00Z.
fn date(gpa: mem.Allocator, seconds: i64) ![]const u8 {
    const epoch: std.time.epoch.EpochSeconds = .{ .secs = @intCast(seconds) };
    const day = epoch.getEpochDay().calculateYearDay();
    const month = day.calculateMonthDay();
    const time = epoch.getDaySeconds();
    return gpa.print("{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        day.year,               month.month.numeric(),     month.day_index + 1,
        time.getHoursIntoDay(), time.getMinutesIntoHour(), time.getSecondsIntoMinute(),
    });
}

/// registry serves HTTPS on age_https:443 for the names RDAP and crt.sh use,
/// under a fresh authority whose certificate it writes to work/ca.pem.
pub fn registry(l: netns.Lab, work: []const u8) !void {
    const ca = try host.tls.Authority.init(l.io, l.gpa, "unwound-age-test-ca");
    const identity = try ca.issue(l.io, l.gpa, &.{ "rdap.verisign.com", "crt.sh" });
    const pem = try l.gpa.print("{s}/ca.pem", .{work});
    try l.write(pem, try ca.pem(l.gpa));
    try l.chmod(pem, 0o644);
    const log_rc = linux.open(try l.gpa.printSentinel("{s}/age-https.log", .{work}, 0), .{
        .ACCMODE = .WRONLY,
        .APPEND = true,
        .CREAT = true,
        .CLOEXEC = true,
    }, 0o644);
    if (linux.errno(log_rc) != .SUCCESS) return error.LogUnwritable;
    var r: Registry = .{ .io = l.io, .log = @intCast(log_rc) };
    var server: host.http.Server = undefined;
    try server.start(l.io, std.heap.smp_allocator, .{
        .address = try .parse(age_https, 443),
        .identity = &identity,
        .handler = .{ .context = &r, .serve = Registry.serve },
    });
    try netns.writeAll(1, "ready\n");
    while (true) try l.io.sleep(.fromSeconds(3600), .awake);
}

test "dates are RFC 3339, in UTC" {
    const gpa = std.testing.allocator;
    const text = try date(gpa, 1792889999);
    defer gpa.free(text);
    try std.testing.expectEqualStrings("2026-10-25T00:59:59Z", text);
}
