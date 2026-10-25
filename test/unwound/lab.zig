//! lab is what check-unwound and its lab checks share: the private world
//! unwound runs in, the driver that asks it under fence, the YAML cases the
//! questions come from, and the logs the answers leave.

const std = @import("std");
const host = @import("host");
const form = @import("form");
const linux = std.os.linux;
const mem = std.mem;
const netns = host.netns;
const dnswire = host.dnswire;
pub const driver = @import("driver.zig");
pub const fixture = @import("fixture.zig");

pub const Lab = netns.Lab;
pub const Answer = driver.Answer;
pub const Request = driver.Request;

const peer = "unwound-peer";

/// role runs this program as one of the lab's own processes, if args name
/// one, and says whether it did.
pub fn role(l: Lab, args: []const [:0]const u8) !bool {
    const is = struct {
        fn is(a: []const [:0]const u8, flag: []const u8, n: usize) bool {
            return a.len == n and mem.eql(u8, a[1], flag);
        }
    }.is;
    if (is(args, "--server", 3)) {
        try fixture.resolver(l, args[2]);
    } else if (is(args, "--age-https", 3)) {
        try fixture.registry(l, args[2]);
    } else if (is(args, "--driver", 5)) {
        try driver.run(l, args[2], args[3], args[4]);
    } else return false;
    return true;
}

/// World is the private world one check makes: a work directory, empty
/// /run, /etc, /usr/share and /var, a peer namespace, and the driver.
pub const World = struct {
    l: Lab,
    work: []const u8,
    /// self is this program as fence's children see it, under /usr.
    self: []const u8 = "",
    resolver: ?netns.Child = null,
    joined: bool = false,
    driver: ?netns.Child = null,

    pub const Mount = struct {
        upstream: []const u8 = "nameserver " ++ fixture.upstream ++ "\n",
        /// resolv_file writes /etc/resolv.conf instead of linking it, for
        /// BIND's tools, which refuse the link.
        resolv_file: bool = false,
        /// binaries go beside unwound, each as its base name.
        binaries: []const []const u8 = &.{},
    };

    pub fn init(l: Lab, prefix: []const u8) !World {
        return .{ .l = l, .work = try l.temporary(prefix) };
    }

    pub fn path(w: *const World, name: []const u8) ![]const u8 {
        return w.l.gpa.print("{s}/{s}", .{ w.work, name });
    }

    /// mount puts this program, unwound and o.binaries on /usr/local/bin,
    /// covers /run, /etc, /usr/share and /var, and writes the policy and
    /// the resolver files. fence lets programs run only from /usr.
    pub fn mount(w: *World, unwound: []const u8, policy: []const u8, o: Mount) !void {
        const l = w.l;
        const bin = try w.path("bin");
        try l.mkdir(bin, 0o755);
        try l.copy(unwound, try l.gpa.print("{s}/unwound", .{bin}), 0o755);
        try l.copy(try l.self(), try l.gpa.print("{s}/{s}", .{ bin, l.name }), 0o755);
        for (o.binaries) |b|
            try l.copy(b, try l.gpa.print("{s}/{s}", .{ bin, std.fs.path.basename(b) }), 0o755);
        w.self = try l.gpa.print("/usr/local/bin/{s}", .{l.name});
        for ([_][]const u8{ "audit", "stderr", "upstream.log" }) |name| {
            try l.write(try w.path(name), "");
            try l.chmod(try w.path(name), 0o666);
        }
        try l.bind(bin, "/usr/local/bin");
        for ([_][]const u8{ "/run", "/etc", "/usr/share", "/var" }) |dir| try l.tmpfs(dir);
        try l.mkdir("/var/empty", 0o755);
        try l.mkdir("/usr/share/werewolf", 0o755);
        try l.write("/usr/share/werewolf/net", policy);
        try l.mkdir("/run/werewolf", 0o755);
        try l.mkdir("/run/werewolf/network", 0o755);
        try l.write("/run/werewolf/network/resolv.conf", "nameserver 127.0.0.53\n");
        try l.write("/run/werewolf/network/upstream", o.upstream);
        if (o.resolv_file)
            try l.write("/etc/resolv.conf", "nameserver 127.0.0.53\n")
        else
            try l.symlink("/run/werewolf/network/resolv.conf", "/etc/resolv.conf");
    }

    /// network joins the peer namespace, where addresses go, and starts the
    /// fixture resolver there.
    pub fn network(w: *World, addresses: []const []const u8) !void {
        const l = w.l;
        // werewolf leaves reverse-path filtering off (cmd/posture): its check
        // would look up a reply's reverse as unlabeled DNS, which fence
        // refuses. RP_FILTER=1 or 2 tries it anyway.
        try l.veth(.{
            .peer = peer,
            .client = "10.53.0.1/24",
            .addresses = addresses,
            .rp_filter = l.environ.getPosix("RP_FILTER") orelse "0",
        });
        w.joined = true;
        w.resolver = try l.spawn(
            try w.inPeer(&.{ w.self, "--server", try w.path("upstream.log") }),
            .{ .stdout = .pipe },
        );
        try w.ready(&w.resolver.?, 10_000);
    }

    /// inPeer is argv run in the peer namespace.
    pub fn inPeer(w: *const World, argv: []const []const u8) ![]const []const u8 {
        var all: std.ArrayList([]const u8) = .empty;
        try all.appendSlice(w.l.gpa, &.{ "ip", "netns", "exec", peer });
        try all.appendSlice(w.l.gpa, argv);
        return all.items;
    }

    /// ready waits for a child's ready line.
    pub fn ready(w: *World, child: *netns.Child, ms: u32) !void {
        const lines = try w.l.gpa.create(netns.Lines);
        lines.* = .{ .fd = child.stdout.? };
        lines.ready(ms) catch |err| return w.l.fail(
            "not_ready",
            .{ .pid = child.pid, .@"error" = @errorName(err) },
        );
    }

    /// start runs the driver under fence and waits for unwound.
    pub fn start(w: *World, fence: []const u8) !Client {
        const l = w.l;
        w.driver = try l.spawn(&.{
            fence,                    w.self,              "--driver",
            "/usr/local/bin/unwound", try w.path("audit"), try w.path("stderr"),
        }, .{ .stdin = .pipe, .stdout = .pipe, .group = true });
        const lines = try l.gpa.create(netns.Lines);
        lines.* = .{ .fd = w.driver.?.stdout.? };
        const announcement = lines.next(10_000) catch |err|
            return l.fail("fence_silent", .{ .@"error" = @errorName(err) });
        if (mem.find(u8, announcement, "\"event\":\"fence\"") == null)
            return l.fail("fence_announcement", .{ .line = announcement });
        lines.ready(10_000) catch |err| {
            l.dump(try w.path("stderr"));
            return l.fail("unwound_not_ready", .{ .@"error" = @errorName(err) });
        };
        return .{ .l = l, .w = w, .child = &w.driver.?, .lines = lines };
    }

    /// failed shows what a failure needs: the logs, and the routing.
    pub fn failed(w: *World) void {
        for ([_][]const u8{ "stderr", "audit", "upstream.log" }) |name|
            w.l.dump(w.path(name) catch continue);
        for ([_][]const []const u8{
            &.{ "ip", "rule" },
            &.{ "ip", "route", "show", "table", "all" },
            &.{ "ss", "-uanp" },
        }) |argv| {
            const text = w.l.output(argv) catch continue;
            w.l.log("command", .{ .argv = argv });
            netns.writeAll(2, text) catch {};
        }
    }

    /// stop ends the driver and the peer, and removes the work directory.
    pub fn stop(w: *World) void {
        if (w.driver) |*d| {
            // Its end of requests lets the driver end unwound too.
            d.closeStdin();
            if (d.wait(5000) catch null == null) {
                d.signal(.KILL);
                _ = d.wait(null) catch {};
            }
            d.sweep();
        }
        if (w.resolver) |*r| r.stop();
        if (w.joined) w.l.run(&.{ "ip", "netns", "delete", peer }) catch {};
        w.l.remove(w.work);
    }
};

/// Client asks unwound through the driver.
pub const Client = struct {
    l: Lab,
    w: *World,
    child: *netns.Child,
    lines: *netns.Lines,
    /// asked counts the questions asked.
    asked: usize = 0,

    /// send sends r and waits up to ms for its reply.
    pub fn send(c: *Client, r: Request, ms: u32) !driver.Reply {
        var out: std.Io.Writer.Allocating = .init(c.l.gpa);
        try std.json.Stringify.value(r, .{}, &out.writer);
        try out.writer.writeByte('\n');
        try netns.writeAll(c.child.stdin.?, out.written());
        const line = c.lines.next(ms) catch |err| {
            c.l.dump(try c.w.path("stderr"));
            return c.l.fail("driver_silent", .{ .request = r, .@"error" = @errorName(err) });
        };
        c.asked += 1;
        return std.json.parseFromSliceLeaky(driver.Reply, c.l.gpa, try c.l.gpa.dupe(u8, line), .{});
    }

    /// ask asks r and returns unwound's answer.
    pub fn ask(c: *Client, r: Request) !Answer {
        const reply = try c.send(r, @max(15, r.timeout + 3) * 1000);
        return reply.answer orelse c.l.fail("no_answer", .{ .request = r });
    }

    /// check asks case's question and requires what it expects.
    pub fn check(c: *Client, case: Case) !Answer {
        const a = try c.ask(case.request());
        if (!case.holds(a)) return c.l.fail(
            "unexpected_answer",
            .{ .why = case.why, .case = case, .answer = a },
        );
        return a;
    }

    /// phase checks each case of the YAML phase name, in order,
    /// and returns their answers.
    pub fn phase(c: *Client, doc: form.Node, name: []const u8) ![]const Answer {
        const all = try cases(c.l.gpa, doc, name);
        const answers = try c.l.gpa.alloc(Answer, all.len);
        for (all, answers) |case, *a| a.* = try c.check(case);
        return answers;
    }

    /// domain publishes a system domain, from DHCP or the configuration.
    pub fn domain(c: *Client, text: []const u8, source: @FieldType(Request, "source")) !void {
        _ = try c.send(.{ .op = .domain, .text = text, .source = source }, 15_000);
    }

    pub fn upstream(c: *Client, text: []const u8) !void {
        _ = try c.send(.{ .op = .upstream, .text = text }, 15_000);
    }
};

/// Case is one question and what its answer must hold; see cases.yaml.
pub const Case = struct {
    why: []const u8,
    uid: u32,
    name: []const u8,
    type: u16 = 1,
    tcp: bool = false,
    server: []const u8 = "127.0.0.53",
    bind: []const u8 = "",
    timeout: u32 = 8,
    socket_uid: ?u32 = null,
    rcode: ?u4 = null,
    answers: ?[]const []const u8 = null,
    ad: ?bool = null,
    tc: ?bool = null,
    @"error": ?[]const u8 = null,
    within: ?u32 = null,
    rdata: ?[]const []const u8 = null,
    sender_uid: ?u32 = null,

    pub fn request(c: Case) Request {
        return .{
            .uid = c.uid,
            .name = c.name,
            .type = c.type,
            .tcp = c.tcp,
            .server = c.server,
            .bind = c.bind,
            .timeout = c.timeout,
            .socket_uid = c.socket_uid,
        };
    }

    pub fn holds(c: Case, a: Answer) bool {
        // An answer with an error has no rcode, so no expected one holds.
        if (c.rcode) |r| if (a.@"error".len > 0 or a.rcode != r) return false;
        if (c.@"error") |e| if (!mem.eql(u8, a.@"error", e)) return false;
        if (c.answers) |want| if (!same(a.answers, want)) return false;
        if (c.rdata) |want| if (!same(a.rdata, want)) return false;
        if (c.ad) |ad| if (a.ad != ad) return false;
        if (c.tc) |tc| if (a.tc != tc) return false;
        if (c.within) |ms| if (a.ms >= ms) return false;
        if (c.sender_uid) |uid| if (a.sender_uid != uid) return false;
        return true;
    }
};

pub fn same(a: []const []const u8, b: []const []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| if (!mem.eql(u8, x, y)) return false;
    return true;
}

pub const cases_yaml = @embedFile("cases.yaml");

/// load parses cases.yaml.
pub fn load(l: Lab) !form.Node {
    var diag: form.Diagnostic = .{};
    return form.parse(l.gpa, cases_yaml, &diag) catch |err|
        l.fail(
            "cases_unparsed",
            .{ .line = diag.line, .why = diag.why, .@"error" = @errorName(err) },
        );
}

/// cases reads the phase name as Cases, refusing a key it does not know.
pub fn cases(gpa: mem.Allocator, doc: form.Node, name: []const u8) ![]const Case {
    const items = doc.get(name) orelse return error.NoSuchPhase;
    if (items != .list) return error.BadPhase;
    const out = try gpa.alloc(Case, items.list.len);
    for (items.list, out) |item, *case| {
        if (item != .map) return error.BadCase;
        case.* = .{ .why = "", .uid = 0, .name = "" };
        var named = false;
        for (item.map) |e| {
            const v = e.value;
            const k = e.key;
            if (mem.eql(u8, k, "why")) {
                case.why = try scalar(v);
            } else if (mem.eql(u8, k, "uid")) {
                case.uid = try integer(u32, v);
            } else if (mem.eql(u8, k, "name")) {
                case.name = try scalar(v);
                named = true;
            } else if (mem.eql(u8, k, "type")) {
                case.type = dnswire.typeNamed(try scalar(v)) orelse return error.BadType;
            } else if (mem.eql(u8, k, "tcp")) {
                case.tcp = try boolean(v);
            } else if (mem.eql(u8, k, "server")) {
                case.server = try scalar(v);
            } else if (mem.eql(u8, k, "bind")) {
                case.bind = try scalar(v);
            } else if (mem.eql(u8, k, "timeout")) {
                case.timeout = try integer(u32, v);
            } else if (mem.eql(u8, k, "socket_uid")) {
                case.socket_uid = try integer(u32, v);
            } else if (mem.eql(u8, k, "rcode")) {
                case.rcode = dnswire.rcodeNamed(try scalar(v)) orelse return error.BadRcode;
            } else if (mem.eql(u8, k, "answers")) {
                case.answers = try scalars(gpa, v);
            } else if (mem.eql(u8, k, "ad")) {
                case.ad = try boolean(v);
            } else if (mem.eql(u8, k, "tc")) {
                case.tc = try boolean(v);
            } else if (mem.eql(u8, k, "error")) {
                case.@"error" = try scalar(v);
            } else if (mem.eql(u8, k, "within")) {
                case.within = try integer(u32, v);
            } else if (mem.eql(u8, k, "rdata")) {
                case.rdata = try scalars(gpa, v);
            } else if (mem.eql(u8, k, "sender_uid")) {
                case.sender_uid = try integer(u32, v);
            } else return error.UnknownCaseKey;
        }
        if (case.why.len == 0 or !named) return error.IncompleteCase;
    }
    return out;
}

/// list reads the phase name as a list of scalars.
pub fn list(gpa: mem.Allocator, doc: form.Node, name: []const u8) ![]const []const u8 {
    return scalars(gpa, doc.get(name) orelse return error.NoSuchPhase);
}

fn scalar(v: form.Node) ![]const u8 {
    return if (v == .scalar) v.scalar.text else error.NotScalar;
}

fn scalars(gpa: mem.Allocator, v: form.Node) ![]const []const u8 {
    if (v != .list) return error.NotList;
    const out = try gpa.alloc([]const u8, v.list.len);
    for (v.list, out) |item, *o| o.* = try scalar(item);
    return out;
}

fn integer(comptime T: type, v: form.Node) !T {
    return std.fmt.parseInt(T, try scalar(v), 10);
}

fn boolean(v: form.Node) !bool {
    const t = try scalar(v);
    if (mem.eql(u8, t, "true")) return true;
    if (mem.eql(u8, t, "false")) return false;
    return error.NotBool;
}

/// audit reads the audit log: each record's JSON, after its program's name.
pub fn audit(w: *const World) ![]const std.json.Value {
    var out: std.ArrayList(std.json.Value) = .empty;
    var lines = mem.tokenizeScalar(u8, try w.l.read(try w.path("audit")), '\n');
    while (lines.next()) |line| {
        const at = mem.find(u8, line, ": {") orelse continue;
        try out.append(
            w.l.gpa,
            try std.json.parseFromSliceLeaky(std.json.Value, w.l.gpa, line[at + 2 ..], .{}),
        );
    }
    return out.items;
}

/// field is record's key, if it is an object that has it.
pub fn field(record: std.json.Value, key: []const u8) ?std.json.Value {
    return if (record == .object) record.object.get(key) else null;
}

/// matches says whether each key of want, a YAML map, matches record's.
pub fn matches(record: std.json.Value, want: form.Node) bool {
    for (want.map) |e| {
        const got = field(record, e.key) orelse return false;
        const t = scalar(e.value) catch return false;
        const ok = switch (got) {
            .string => |s| mem.eql(u8, s, t),
            .integer => |n| n == std.fmt.parseInt(i64, t, 10) catch return false,
            .bool => |b| mem.eql(u8, t, if (b) "true" else "false"),
            else => false,
        };
        if (!ok) return false;
    }
    return true;
}

/// queries keeps the query events of records.
pub fn queries(gpa: mem.Allocator, records: []const std.json.Value) ![]const std.json.Value {
    var out: std.ArrayList(std.json.Value) = .empty;
    for (records) |r| if (isEvent(r, "query")) try out.append(gpa, r);
    return out.items;
}

pub fn isEvent(r: std.json.Value, event: []const u8) bool {
    const e = field(r, "event") orelse return false;
    return e == .string and mem.eql(u8, e.string, event);
}

/// audited requires that each matcher of the YAML phase name matches a
/// query event.
pub fn audited(w: *const World, doc: form.Node, name: []const u8) !void {
    const found = try queries(w.l.gpa, try audit(w));
    const want = doc.get(name) orelse return error.NoSuchPhase;
    for (want.list) |m| {
        for (found) |r| {
            if (matches(r, m)) break;
        } else return w.l.fail("unaudited", .{ .want = try matcher(w.l.gpa, m) });
    }
}

/// matcher is a YAML matcher as JSON, for a log line.
fn matcher(gpa: mem.Allocator, m: form.Node) !std.json.Value {
    var object: std.json.ObjectMap = .empty;
    for (m.map) |e| try object.put(gpa, e.key, .{ .string = scalar(e.value) catch "" });
    return .{ .object = object };
}

/// Asked is one question the fixture resolver logged.
pub const Asked = struct { name: []const u8, proto: []const u8, flags: u16, arcount: u16 };

pub fn upstream(w: *const World) ![]const Asked {
    var out: std.ArrayList(Asked) = .empty;
    var lines = mem.tokenizeScalar(u8, try w.l.read(try w.path("upstream.log")), '\n');
    while (lines.next()) |line|
        try out.append(w.l.gpa, try std.json.parseFromSliceLeaky(Asked, w.l.gpa, line, .{}));
    return out.items;
}

/// count is how often name, in any case, reached the resolver.
pub fn count(w: *const World, name: []const u8) !usize {
    var n: usize = 0;
    for (try upstream(w)) |a| n += @intFromBool(std.ascii.eqlIgnoreCase(a.name, name));
    return n;
}

test {
    _ = fixture;
}

test "every phase of cases.yaml parses, and a case refuses unknown keys" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var diag: form.Diagnostic = .{};
    const doc = try form.parse(gpa, cases_yaml, &diag);
    for (doc.map) |e| {
        if (mem.eql(u8, e.key, "endpoints") or mem.eql(u8, e.key, "never-asked")) {
            _ = try list(gpa, doc, e.key);
        } else if (mem.eql(u8, e.key, "audit") or mem.eql(u8, e.key, "age-audit")) {
            for (e.value.list) |m| try std.testing.expect(m == .map);
        } else _ = try cases(gpa, doc, e.key);
    }
    const bad = try form.parse(
        gpa,
        "p:\n  - why: x\n    name: y\n    uid: 1\n    colour: red\n",
        &diag,
    );
    try std.testing.expectError(error.UnknownCaseKey, cases(gpa, bad, "p"));
    const big = (try cases(gpa, doc, "names"))[5];
    try std.testing.expect(big.tc.? and big.type == 16 and big.answers.?.len == 0);
    try std.testing.expect(big.holds(.{ .tc = true }));
    try std.testing.expect(!big.holds(.{ .tc = true, .@"error" = "timeout" }));
}
