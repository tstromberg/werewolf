//! check-unwound runs the real unwound behind the real fence, as root, in
//! private mount and network namespaces; nothing on the host changes. A
//! fixture resolver in a peer namespace answers, stays silent, forges and
//! truncates on cue, and records every question that reaches it. The
//! questions and their answers are test/unwound/cases.yaml.
//!
//!     check-unwound FENCE UNWOUND            screening, caching, audit
//!     check-unwound FENCE UNWOUND AGE        with an enforcing age writer
//!     check-unwound --live FENCE UNWOUND AGE with fixture RDAP and crt.sh
//!
//! The binaries are Linux builds for this machine. The age checks read the
//! schema as cmd/unwound/age.sql: run them from the checkout's root.

const std = @import("std");
const builtin = @import("builtin");
const host = @import("host");
const form = @import("form");
const lab = @import("unwound/lab.zig");
const linux = std.os.linux;
const mem = std.mem;
const netns = host.netns;
const sqlite = host.sqlite;
const fixture = lab.fixture;
const Client = lab.Client;
const World = lab.World;
const Case = lab.Case;

const policy =
    \\listen tcp 53 loopback
    \\dns 54
    \\lookup 2001 api.example.test A AAAA
    \\lookup 2001 *.cdn.example.test A AAAA
    \\lookup 2001 big.example.test TXT
    \\lookup 2001 alias-ok.example.test A
    \\lookup 2001 alias-bad.example.test A
    \\lookup 2001 slow.example.test A
    \\lookup 2001 spoof.example.test A
    \\lookup 2002 * A AAAA
    \\lookup 2003 * A AAAA CNAME MX TXT SRV NS PTR CAA TLSA unfiltered
    \\lookup 2001 cached.example.test A
    \\lookup 2001 short.example.test A
    \\lookup 2001 zero.example.test A
    \\lookup 2001 gone.example.test A
    \\lookup 2001 delayed.example.test A
    \\lookup 2001 revoked-alias.example.test A
    \\lookup 2002 explicit-alias.example.test A
    \\lookup 2002 revoked-alias.example.test A
    \\lookup 2005 * A AAAA
    \\dns-direct 2005
    \\connect 2005 udp 53
    \\connect 2005 tcp 53
    \\connect 2005 tcp 853
    \\lookup 2004 httpbin.org A
    \\lookup 2004 *.ngrok.app A
    \\lookup 2004 alias-to-allowed.example.test A
    \\lookup 2002 * CNAME
    \\lookup 2002 token.oastify.com CNAME
    \\
;
/// The live age writer, user 55, resolves through unwound and fetches HTTPS.
const live_policy = "lookup 55 * A AAAA unfiltered\nconnect 55 tcp 443 public\n";

const Mode = enum { plain, age, live };
const age_dir = "/data/svc/unwound-age";

pub fn main(init: std.process.Init) !void {
    const l = lab.Lab.init(init, "check-unwound");
    const args = try init.minimal.args.toSlice(l.gpa);
    if (try lab.role(l, args)) return;
    if (args.len >= 6 and mem.eql(u8, args[1], "--inside")) {
        const mode = std.meta.stringToEnum(Mode, args[2]) orelse return error.Usage;
        return inside(l, mode, args[3], args[4], args[5], args[6..]);
    }
    const live = args.len == 5 and mem.eql(u8, args[1], "--live");
    const rest = args[@intFromBool(live)..];
    if (rest.len != 3 and rest.len != 4 or (live and rest.len != 4)) {
        l.log("usage", .{ .usage = "check-unwound [--live] FENCE UNWOUND [AGE]" });
        std.process.exit(2);
    }
    if (builtin.os.tag != .linux) return l.fail("needs_linux", .{});
    if (linux.geteuid() != 0)
        return l.fail(
            "needs_root",
            .{ .why = "fence sets routing rules and unwound drops to its users" },
        );
    const mode: Mode = if (live) .live else if (rest.len == 4) .age else .plain;
    var inner: std.ArrayList([]const u8) = .empty;
    try inner.appendSlice(l.gpa, &.{ "--inside", @tagName(mode), try l.namespace("net") });
    if (mode != .plain) try inner.append(l.gpa, try real(l, "cmd/unwound/age.sql"));
    for (rest[1..]) |path| try inner.append(l.gpa, try real(l, path));
    try l.enter(&.{ "--net", "--mount" }, inner.items);
}

fn real(l: lab.Lab, path: []const u8) ![]const u8 {
    return std.Io.Dir.cwd().realPathFileAlloc(l.io, path, l.gpa);
}

fn inside(
    l: lab.Lab,
    mode: Mode,
    parent_net: []const u8,
    first: []const u8,
    second: []const u8,
    more: []const [:0]const u8,
) !void {
    if (mem.eql(u8, try l.namespace("net"), parent_net)) return l.fail("shared_network", .{});
    const schema: ?[]const u8 = if (mode == .plain) null else try l.read(first);
    const fence = if (mode == .plain) first else second;
    const unwound = if (mode == .plain) second else more[0];
    const age_binary: ?[]const u8 = if (mode == .plain) null else more[1];
    try l.private();
    var w = try World.init(l, "werewolf-unwound");
    defer w.stop();
    try w.mount(unwound, if (mode == .live) policy ++ live_policy else policy, .{});
    if (schema) |sql| try seed(l, sql, mode == .live);
    try w.network(if (mode == .live)
        &.{ fixture.upstream ++ "/24", fixture.age_https ++ "/32" }
    else
        &.{fixture.upstream ++ "/24"});
    errdefer w.failed();
    var registry: ?netns.Child = null;
    defer if (registry) |*r| r.stop();
    if (mode == .live) {
        const host_route = fixture.age_https ++ "/32";
        try l.run(&.{ "ip", "route", "add", host_route, "via", fixture.upstream, "dev", "client" });
        registry = try l.spawn(
            try w.inPeer(&.{ w.self, "--age-https", w.work }),
            .{ .stdout = .pipe },
        );
        try w.ready(&registry.?, 10_000);
        try l.mkdir("/etc/ssl", 0o755);
        try l.mkdir("/etc/ssl/certs", 0o755);
        try l.copy(try w.path("ca.pem"), "/etc/ssl/certs/ca-certificates.crt", 0o644);
    }
    var writer: ?Writer = if (age_binary) |b| try .start(l, b) else null;
    defer if (writer) |*a| a.stop();
    var c = try w.start(fence);
    const doc = try lab.load(l);
    switch (mode) {
        .plain => try checks(&c, doc),
        .age => try ageChecks(&c, doc),
        .live => try liveChecks(&c, doc),
    }
    l.log("pass", .{ .mode = @tagName(mode), .requests = c.asked });
}

/// seed gives unwound-age its store, as the image's first boot would: the
/// enforcement marker, a /data, and the evidence a fixture domain needs.
fn seed(l: lab.Lab, schema: []const u8, live: bool) !void {
    try l.write("/usr/share/werewolf/age-enforce", "enforce\n");
    _ = linux.mkdir("/data", 0o755);
    try l.tmpfs("/data");
    try l.mkdir("/data/svc", 0o755);
    try l.mkdir(age_dir, 0o755);
    const db = try sqlite.Db.open(l.gpa, age_dir ++ "/age.db", .read_write);
    try db.exec(schema);
    try db.exec("PRAGMA journal_mode=WAL");
    const now = std.Io.Clock.real.now(l.io).toSeconds();
    if (!live) for ([_]struct { []const u8, []const u8, sqlite.Cell }{
        .{ "example.com", "valid", .{ .int = 946684800 } },
        .{ "young.com", "valid", .{ .int = now - 86400 } },
        .{ "example.net", "unknown", .null },
    }) |row| try db.run(
        \\INSERT INTO domain_age (domain,source,status,registered_at,effective_at,fetched_at,
        \\ retry_after,last_used_at,psl_generation,bootstrap_generation)
        \\ VALUES (?,'rdap',?,?,?,?,?,?,'fixture','fixture')
    , &.{
        .{ .text = row[0] },
        .{ .text = row[1] },
        row[2],
        row[2],
        .{ .int = now },
        .{ .int = now + 86400 },
        .{ .int = now },
    });
    // Live evidence expires while the screened DNS answers remain cached.
    if (live) for ([_]struct { []const u8, []const u8, []const u8, i64 }{
        .{ "expires.com", "rdap", "valid", 7 * 86400 },
        .{ "ctexpires.com", "crtsh", "history", 86400 },
    }) |row| {
        const expires = now + 30;
        const date: sqlite.Cell = .{ .int = 946684800 };
        const rdap = mem.eql(u8, row[1], "rdap");
        try db.run(
            \\INSERT INTO domain_age (domain,source,status,registered_at,effective_at,
            \\ ct_first_seen_at,fetched_at,retry_after,last_used_at,psl_generation,
            \\ bootstrap_generation) VALUES (?,?,?,?,?,?,?,?,?,'fixture','fixture')
        , &.{
            .{ .text = row[0] },
            .{ .text = row[1] },
            .{ .text = row[2] },
            if (rdap) date else .null,
            if (rdap) date else .null,
            if (rdap) .null else date,
            .{ .int = expires - row[3] },
            .{ .int = expires + 1 },
            .{ .int = now },
        });
    };
    db.close();
    try l.chown(age_dir, 55, 55);
    try l.chmod(age_dir, 0o700);
    var dir = try std.Io.Dir.cwd().openDir(l.io, age_dir, .{ .iterate = true });
    defer dir.close(l.io);
    var entries = dir.iterate();
    while (try entries.next(l.io)) |e| try l.chown(
        try l.gpa.print("{s}/{s}", .{ age_dir, e.name }),
        55,
        55,
    );
    try l.mkdir("/run/werewolf-age", 0o755);
}

/// Writer is the age writer, unwound-age, started as init starts it: it
/// says R on descriptor 3 once its store is open, and init answers G once
/// root's view of the store is read-only.
const Writer = struct {
    child: netns.Child,
    control: linux.fd_t,
    mounted: usize = 0,
    l: lab.Lab,

    fn start(l: lab.Lab, binary: []const u8) !Writer {
        var pair: [2]linux.fd_t = undefined;
        if (linux.errno(linux.socketpair(
            linux.AF.UNIX,
            linux.SOCK.STREAM | linux.SOCK.CLOEXEC,
            0,
            &pair,
        )) != .SUCCESS)
            return error.SocketPair;
        var w: Writer = .{
            .child = try l.spawn(&.{binary}, .{ .fds = &.{pair[1]}, .stderr = .pipe }),
            .control = pair[0],
            .l = l,
        };
        netns.close(pair[1]);
        errdefer w.stop();
        netns.limit(w.control, 10_000);
        var ready: [1]u8 = undefined;
        if (linux.read(w.control, &ready, 1) != 1 or ready[0] != 'R') {
            w.child.signal(.KILL);
            _ = try w.child.wait(null);
            var stderr: std.ArrayList(u8) = .empty;
            var buf: [4096]u8 = undefined;
            while (true) {
                const n = linux.read(w.child.stderr.?, &buf, buf.len);
                if (linux.errno(n) != .SUCCESS or n == 0) break;
                try stderr.appendSlice(l.gpa, buf[0..n]);
            }
            return l.fail("age_writer_not_ready", .{ .stderr = stderr.items });
        }
        for ([_][]const u8{ age_dir, "/run/werewolf-age" }) |path| {
            try l.bind(path, path);
            w.mounted += 1;
            try l.readOnly(path);
        }
        try netns.writeAll(w.control, "G");
        return w;
    }

    fn stop(w: *Writer) void {
        w.child.signal(.KILL);
        _ = w.child.wait(5000) catch {};
        netns.close(w.control);
        const paths = [_][]const u8{ age_dir, "/run/werewolf-age" };
        var n = w.mounted;
        while (n > 0) : (n -= 1) w.l.unmount(paths[n - 1]) catch {};
        w.mounted = 0;
    }
};

fn checks(c: *Client, doc: form.Node) !void {
    const l = c.l;
    const gpa = l.gpa;
    _ = try c.phase(doc, "grants");
    const piped = (try c.ask(.{
        .op = .pipeline,
        .uid = 2001,
        .name = "api.example.test",
        .second = "x.cdn.example.test",
    })).results;
    if (piped.len != 2 or piped[0].id != 0x4242 or piped[1].id != 0x4243 or
        !lab.same(piped[0].answers, &.{"192.0.2.10"}) or
        !lab.same(piped[1].answers, &.{"192.0.2.11"}))
        return l.fail("pipelined", .{ .results = piped });
    const abandoned = try c.ask(.{ .op = .abandon, .uid = 2001, .name = "api.example.test" });
    if (abandoned.closed != 16) return l.fail("abandoned", .{ .answer = abandoned });
    _ = try c.phase(doc, "types");
    try c.domain("corp.lan.test", .dhcp);
    _ = try c.phase(doc, "dhcp-domain");
    try c.domain("config.lan.test", .config);
    _ = try c.phase(doc, "config-domain");
    try c.domain("", .config);
    try c.domain("", .dhcp);
    _ = try c.phase(doc, "names");
    const endpoints = try lab.list(gpa, doc, "endpoints");
    for (endpoints) |name| for ([_]u16{ 1, 28 }) |kind| for ([_]bool{ false, true }) |tcp| {
        _ = try c.check(.{
            .why = "endpoint denied locally",
            .uid = 2002,
            .name = name,
            .type = kind,
            .tcp = tcp,
            .rcode = 5,
            .answers = &.{},
        });
    };
    _ = try c.phase(doc, "callbacks");
    try c.domain("oastify.com", .config);
    _ = try c.phase(doc, "assigned-callback");
    try c.domain("", .config);
    _ = try c.phase(doc, "explicit-endpoints");

    // A poller learns nothing new while an answer stands; unfiltered, it does.
    const poll = try c.ask(.{ .uid = 2002, .name = "poll.example.test" });
    if (poll.rcode != 0 or poll.answers.len != 1) return l.fail("poll", .{ .answer = poll });
    for ([_]bool{ false, true }) |tcp|
        _ = try c.check(.{
            .why = "a standing answer",
            .uid = 2002,
            .name = "poll.example.test",
            .tcp = tcp,
            .rcode = 0,
            .answers = poll.answers,
        });
    if (lab.same((try c.ask(.{ .uid = 2003, .name = "poll.example.test" })).answers, poll.answers))
        return l.fail("unfiltered_kept_answer", .{ .answer = poll });

    _ = try c.phase(doc, "tunnels");
    // A low-and-slow tunnel gets 32 new names of a site within the hour, then
    // none; names it already asked about still resolve.
    for (0..32) |i|
        _ = try c.check(.{
            .why = "within the budget",
            .uid = 2002,
            .name = try gpa.print("n{d}.tunnel.test", .{i}),
            .rcode = 3,
            .answers = &.{},
        });
    _ = try c.phase(doc, "budget");
    const silent = try lab.count(c.w, "slow.example.test");
    _ = try c.phase(doc, "silence");
    if (try lab.count(c.w, "slow.example.test") < silent + 4) return l.fail("silence_kept", .{});
    _ = try c.phase(doc, "unfiltered");

    // Answers are kept, per service, as long as they say; failures are not.
    const fresh = (try c.phase(doc, "cache"))[0];
    netns.nap(1100);
    const kept = (try c.phase(doc, "cache-kept"))[0];
    if (kept.ttls[0] >= fresh.ttls[0])
        return l.fail("time_left_unchanged", .{ .fresh = fresh, .kept = kept });
    try asked(c, "cached.example.test", 2, "one question per service");
    _ = try c.phase(doc, "short");
    netns.nap(1100);
    _ = try c.phase(doc, "short-expired");
    try asked(c, "short.example.test", 2, "asked again once it expired");
    _ = try c.phase(doc, "negative");
    try asked(c, "zero.example.test", 2, "a TTL of 0 was kept");
    try asked(c, "gone.example.test", 1, "a negative answer with an SOA was not kept");
    try asked(c, "nowhere.example.test", 2, "a negative answer without an SOA was kept");

    // The same question, asked while it is out, waits for its answer.
    const together = (try c.ask(.{
        .op = .many,
        .uid = 2001,
        .name = "delayed.example.test",
        .parallel = 3,
    })).results;
    if (together.len != 3) return l.fail("merged", .{ .results = together });
    for (together) |a| if (!lab.same(
        a.answers,
        &.{"192.0.2.17"},
    )) return l.fail("merged", .{ .results = together });
    try asked(c, "delayed.example.test", 1, "the same question asked twice");
    // A full cache lets the answer least recently given go; it never fails.
    for (0..257) |i|
        _ = try c.check(.{
            .why = "filling the cache",
            .uid = 2003,
            .name = try gpa.print("n{d}.fill.example.test", .{i}),
            .rcode = 0,
            .answers = &.{"192.0.2.40"},
        });
    _ = try c.check(.{
        .why = "asked again, once let go",
        .uid = 2003,
        .name = "n0.fill.example.test",
        .rcode = 0,
        .answers = &.{"192.0.2.40"},
    });
    try asked(c, "n0.fill.example.test", 2, "the least recently given answer kept");
    try asked(c, "n256.fill.example.test", 1, "a recent answer let go");

    // Malformed queries: FORMERR with the ID; a response is not answered.
    const two = try c.ask(.{
        .uid = 2001,
        .raw = "515101000002000000000000" ++ "016104746573740000010001",
    });
    if (two.@"error".len > 0 or two.rcode != 1 or
        two.answers.len != 0) return l.fail("two_questions", .{ .answer = two });
    const response = try c.ask(.{
        .uid = 2001,
        .timeout = 1,
        .raw = "515181800001000000000000" ++ "016104746573740000010001",
    });
    if (!mem.eql(
        u8,
        response.@"error",
        "timeout",
    )) return l.fail("response_answered", .{ .answer = response });
    _ = try c.phase(doc, "labels");

    // No upstream: a kept answer is still given; anything else is SERVFAIL,
    // at once. Restored, it answers again.
    try c.upstream("");
    _ = try c.phase(doc, "no-upstream");
    try c.upstream("nameserver " ++ fixture.upstream ++ "\n");
    _ = try c.phase(doc, "upstream-restored");
    const race = try c.send(.{ .op = .race }, 30_000);
    const revoked: Case = .{
        .why = "revoked resolver is not used for TCP fallback",
        .uid = 2003,
        .name = "race.example.test",
        .rcode = 2,
        .answers = &.{},
    };
    if (race.answer == null or
        !revoked.holds(race.answer.?)) return l.fail(revoked.why, .{ .reply = race });
    if (race.refresh == null or
        !revoked.holds(race.refresh.?)) return l.fail(
        "a new request sees no resolvers",
        .{ .reply = race },
    );
    if (race.exit != null) return l.fail("resolver removal killed unwound", .{ .reply = race });
    for (try lab.upstream(c.w)) |a| if (std.ascii.eqlIgnoreCase(a.name, "race.example.test") and
        mem.eql(u8, a.proto, "tcp"))
        return l.fail("race_reached_tcp", .{ .asked = a });
    try c.upstream("nameserver " ++ fixture.upstream ++ "\n");

    // Upstream saw only what was allowed: canonical questions, no EDNS, in
    // mixed case, and never a denied name.
    const seen = try lab.upstream(c.w);
    for (try lab.list(
        gpa,
        doc,
        "never-asked",
    )) |name| try asked(c, name, 0, "a denied name reached the resolver");
    for (endpoints) |name| if (!mem.eql(
        u8,
        name,
        "httpbin.org",
    )) try asked(c, name, 0, "an endpoint reached the resolver");
    try asked(c, "httpbin.org", 1, "only the explicit grant may forward");
    try asked(c, "allowed.ngrok.app", 1, "only the explicit subtree may forward");
    // A standing answer was asked for once; unfiltered, once more.
    try asked(c, "poll.example.test", 2, "a standing answer asked again");
    var mixed = false;
    var udp = false;
    var tcp = false;
    for (seen) |a| {
        if (a.arcount != 0 or a.flags != 0x0100) return l.fail("not_canonical", .{ .asked = a });
        for (a.name) |ch| mixed = mixed or std.ascii.isUpper(ch);
        udp = udp or mem.eql(u8, a.proto, "udp");
        tcp = tcp or mem.eql(u8, a.proto, "tcp");
    }
    if (!mixed) return l.fail("no_0x20_case", .{});
    if (!udp or !tcp) return l.fail("one_transport", .{ .udp = udp, .tcp = tcp });

    try audited(c, doc);

    // If the upstream side dies, the frontend goes too, for runit to restart.
    const killed = try c.send(.{ .op = .kill_upstream }, 15_000);
    if (killed.exit != 1) return l.fail("upstream_death_kept_frontend", .{ .reply = killed });
    const restarted = try c.send(.{ .op = .restart }, 15_000);
    if (restarted.exit != 1) return l.fail("frontend_exit", .{ .reply = restarted });
    _ = try c.phase(doc, "restarted");
    _ = try c.send(.{ .op = .pause_log }, 15_000);
    const full = try c.send(.{ .op = .audit_full }, 30_000);
    const answered: Case = .{
        .why = "a full log socket does not stop DNS",
        .uid = 2003,
        .name = "audit-proof.example.test",
        .rcode = 3,
        .answers = &.{},
    };
    if (full.answer == null or
        !answered.holds(full.answer.?)) return l.fail(answered.why, .{ .reply = full });
    if (full.exit != null) return l.fail("a full log socket killed unwound", .{ .reply = full });
    if (try lab.count(
        c.w,
        "audit-proof.example.test",
    ) == 0) return l.fail("logging pressure prevented forwarding", .{});
    _ = try c.send(.{ .op = .remove_log }, 15_000);
    _ = try c.phase(doc, "log-removed");
    const missing = try c.send(.{ .op = .start_without_log }, 30_000);
    const fallback: Case = .{
        .why = "DNS starts with stderr logging when syslog is unavailable",
        .uid = 2003,
        .name = "audit-startup.example.test",
        .rcode = 3,
        .answers = &.{},
    };
    if (missing.answer == null or
        !fallback.holds(missing.answer.?)) return l.fail(fallback.why, .{ .reply = missing });
    if (missing.exit != null) return l.fail("DNS startup required syslog", .{ .reply = missing });
    if (mem.find(u8, try l.read(try c.w.path("stderr")), "audit-startup.example.test") == null)
        return l.fail("stderr fallback lost the record", .{});
}

/// asked requires that name reached the resolver n times.
fn asked(c: *Client, name: []const u8, n: usize, why: []const u8) !void {
    const got = try lab.count(c.w, name);
    if (got != n) return c.l.fail(why, .{ .name = name, .asked = got, .want = n });
}

/// audited requires every decision's record: who, what, why and the rule.
fn audited(c: *Client, doc: form.Node) !void {
    const l = c.l;
    var records: []const std.json.Value = &.{};
    // The observer's record of poll.example.test may trail its answer.
    wait: for (0..50) |_| {
        records = try lab.audit(c.w);
        for (records) |r| if (lab.isEvent(r, "age_observe") and
            text(r, "qname", "poll.example.test")) break :wait;
        netns.nap(20);
    }
    var observed = false;
    for (records) |r| {
        if (!lab.isEvent(r, "age_observe")) continue;
        if (text(r, "qname", "host.config.lan.test") or text(r, "qname", "open.example.test"))
            return l.fail("observed_unscreened", .{ .record = r });
        const domain = lab.field(r, "domain");
        observed = observed or (int(r, "uid", 2002) and text(r, "qname", "poll.example.test") and
            text(r, "boundary", "unknown") and (domain == null or domain.? == .null) and
            int(r, "dns_id", 0x4242) and int(r, "qtype", 1) and text(r, "transport", "udp") and
            text(r, "source", "127.53.0.2") and int(r, "rule", 10));
    }
    if (!observed) return l.fail("unobserved", .{ .qname = "poll.example.test" });
    try lab.audited(c.w, doc, "audit");
    const queries = try lab.queries(l.gpa, records);
    var merged: usize = 0;
    var bits: ?f64 = null;
    for (queries) |q| {
        merged += @intFromBool(int(q, "uid", 2001) and text(q, "name", "delayed.example.test") and
            text(q, "why", "granted") and flag(q, "merged"));
        if (bits == null and int(q, "uid", 2002) and text(q, "why", "tunnel") and
            text(q, "name", "9b7e01c7da2a5d06c3a1f4e2b8d90c13ab.tunnel.test") and
            text(q, "detail", "random_label"))
            bits = number(q, "bits");
    }
    if (merged != 2) return l.fail("merged_unaudited", .{ .merged = merged });
    if ((bits orelse 0) < 3.5) return l.fail("random_label_bits", .{ .bits = bits });
    for (records) |r| {
        if (lab.isEvent(r, "start")) break;
    } else return l.fail("start_unaudited", .{});
}

fn text(r: std.json.Value, key: []const u8, want: []const u8) bool {
    const v = lab.field(r, key) orelse return false;
    return v == .string and mem.eql(u8, v.string, want);
}

fn int(r: std.json.Value, key: []const u8, want: i64) bool {
    const v = lab.field(r, key) orelse return false;
    return v == .integer and v.integer == want;
}

fn flag(r: std.json.Value, key: []const u8) bool {
    const v = lab.field(r, key) orelse return false;
    return v == .bool and v.bool;
}

fn number(r: std.json.Value, key: []const u8) ?f64 {
    const v = lab.field(r, key) orelse return null;
    return switch (v) {
        .float => |f| f,
        .integer => |n| @floatFromInt(n),
        else => null,
    };
}

fn ageChecks(c: *Client, doc: form.Node) !void {
    _ = try c.phase(doc, "age");
    try asked(c, "young.com", 0, "a young domain reached the resolver");
    try lab.audited(c.w, doc, "age-audit");
    // Untrusted DHCP Option 15 must never bypass domain-age enforcement.
    try c.domain("assigned.test", .dhcp);
    _ = try c.phase(doc, "age-dhcp-ignored");
    try c.domain("", .dhcp);
    try c.domain("assigned.test", .config);
    _ = try c.phase(doc, "age-assigned");
    try c.domain("", .config);
    _ = try c.phase(doc, "age-revoked");
    try asked(c, "revoked-alias.example.test", 2, "a revoked alias asked again");
}

fn liveChecks(c: *Client, doc: form.Node) !void {
    const l = c.l;
    _ = try c.phase(doc, "age-live");
    const db = try sqlite.Db.open(l.gpa, age_dir ++ "/age.db", .read_only);
    defer db.close();
    try evidence(
        c,
        db,
        "SELECT source,status FROM domain_age WHERE domain=?",
        "mature.com",
        &.{ str("rdap"), str("valid") },
    );
    try evidence(c, db, "SELECT qname,qtype,transport,service_uid,policy_namespace FROM " ++
        "age_check WHERE domain=?", "mature.com", &.{
        str("a.mature.com"), .{ .int = 1 }, str("udp"), .{ .int = 2002 }, str("uid:2002"),
    });
    for ([_][2][]const u8{
        .{ "handoff.com", "udp" },
        .{ "handofftcp.com", "tcp" },
    }) |h| try evidence(c, db,
        \\SELECT qname,transport,source_label,service_uid,policy_namespace,provenance,process_pid,
        \\ process_start_ticks,process_exe,netns_inode FROM age_check WHERE domain=?
    , h[0], &.{
        str(
            h[0],
        ),
        str(h[1]),
        str("127.53.0.2"),
        .{ .int = 2002 },
        str("uid:2002"),
        str("uid_only"),
        .null,
        .null,
        .null,
        .null,
    });
    try evidence(
        c,
        db,
        "SELECT source,status FROM domain_age WHERE domain=?",
        "young.com",
        &.{ str("rdap"), str("valid") },
    );
    try evidence(
        c,
        db,
        "SELECT source,status FROM domain_age WHERE domain=?",
        "outage.com",
        &.{ str("crtsh"), str("history") },
    );
    try evidence(
        c,
        db,
        "SELECT rdap_result,crtsh_result FROM age_check WHERE domain=?",
        "outage.com",
        &.{ str("error"), str("history") },
    );
    try evidence(
        c,
        db,
        "SELECT source,status FROM domain_age WHERE domain=?",
        "invalid.com",
        &.{ str("rdap"), str("unknown") },
    );
    try evidence(
        c,
        db,
        "SELECT source,status FROM domain_age WHERE domain=?",
        "invalidtls.org",
        &.{ str("rdap"), str("unknown") },
    );
    const refresh = (try db.one(
        "SELECT retry_after FROM domain_age WHERE domain=?",
        &.{str("expires.com")},
    )) orelse
        return l.fail("no_evidence", .{ .domain = "expires.com" });

    const Fetch = struct { host: []const u8, path: []const u8, expected: bool };
    var mature: usize = 0;
    var crtsh: usize = 0;
    var lines = mem.tokenizeScalar(u8, try l.read(try c.w.path("age-https.log")), '\n');
    while (lines.next()) |line| {
        const f = try std.json.parseFromSliceLeaky(Fetch, l.gpa, line, .{});
        if (!f.expected) return l.fail("unexpected_fetch", .{ .fetch = f });
        if (mem.find(
            u8,
            f.path,
            "expires.com",
        ) != null) return l.fail("fresh_evidence_fetched", .{ .fetch = f });
        mature += @intFromBool(mem.eql(u8, f.host, "rdap.verisign.com") and
            mem.endsWith(u8, f.path, "/mature.com"));
        crtsh += @intFromBool(mem.eql(u8, f.host, "crt.sh"));
    }
    if (mature != 1 or crtsh != 1) return l.fail("fetches", .{ .mature = mature, .crtsh = crtsh });
    try asked(c, "young.com", 0, "young reached upstream");

    const wait = refresh[0].int - std.Io.Clock.real.now(l.io).toSeconds();
    if (wait > 0) netns.nap(@intCast(wait * 1000));
    _ = try c.phase(doc, "age-live-expired");
    for ([_][]const u8{ "expires.com", "ctexpires.com" }) |domain| {
        const rows = try db.rows(
            "SELECT cause,qname,transport FROM age_check WHERE domain=?",
            &.{str(domain)},
        );
        if (rows.len != 1 or !sqlite.eqlRow(rows[0], &.{ str("retry"), str(domain), str("tcp") }))
            return l.fail("retry_unrecorded", .{ .domain = domain, .rows = rows });
    }
    try evidence(
        c,
        db,
        "SELECT rdap_result,crtsh_result FROM age_check WHERE domain=?",
        "ctexpires.com",
        &.{ str("error"), str("history") },
    );
    try asked(c, "expires.com", 1, "expired evidence asked again");
    try asked(c, "ctexpires.com", 0, "CT history alone reached the resolver");
    // A stalled registry is refused at the fetch deadline, before unwound's
    // own, and unwound keeps running: nothing restarts or forgets budgets.
    _ = try c.phase(doc, "age-live-stalled");
    const restarted = try c.send(.{ .op = .restart }, 6000);
    if (restarted.exit != null) return l.fail("unwound_exited", .{ .reply = restarted });
    _ = try c.phase(doc, "age-live-restarted");
    try evidence(
        c,
        db,
        "SELECT rdap_result FROM age_check WHERE domain=?",
        "timeout.com",
        &.{str("error")},
    );
    try evidence(
        c,
        db,
        "SELECT source,status FROM domain_age WHERE domain=?",
        "timeout.com",
        &.{ str("none"), str("error") },
    );
    const invented = try db.one(
        \\SELECT count(*) FROM age_check WHERE provenance != 'uid_only' OR process_pid IS NOT NULL
        \\ OR process_start_ticks IS NOT NULL OR process_exe IS NOT NULL OR netns_inode IS NOT NULL
    , &.{});
    if (!sqlite.eqlRow(
        invented.?,
        &.{.{ .int = 0 }},
    )) return l.fail("invented_provenance", .{ .rows = invented });
}

fn str(s: []const u8) sqlite.Cell {
    return .{ .text = s };
}

/// evidence requires that sql's first row, for domain, is want.
fn evidence(
    c: *Client,
    db: sqlite.Db,
    sql: []const u8,
    domain: []const u8,
    want: []const sqlite.Cell,
) !void {
    const got = try db.one(sql, &.{str(domain)});
    if (got == null or !sqlite.eqlRow(got.?, want))
        return c.l.fail("evidence", .{ .sql = sql, .domain = domain, .got = got, .want = want });
}
