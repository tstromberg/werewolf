//! check-dns exercises fence's DNS rules, DHCP renewal, HTTPS by hostname
//! and the posture egress checks against the real kernel:
//!
//!     check-dns FENCE DNS-POLICY [DHCP-CLIENT [POSTURE-EGRESS]]
//!
//! The binaries are Linux builds. Everything runs in private mount and
//! network namespaces, as root or with subordinate ids; no host interface,
//! routing rule, resolver or /run state changes, and nothing leaves the
//! machine. The cases are test/dns/cases.yaml. This program plays every
//! role: --inside the namespaces, --server in the peer namespace, --probe
//! under fence, and --ask for one request, as its uid.

const std = @import("std");
const form = @import("form");
const host = @import("host");
const netns = host.netns;
const dnswire = host.dnswire;
const Io = std.Io;
const linux = std.os.linux;
const mem = std.mem;

const first = "10.77.0.2";
const second = "10.77.0.3";
const gcp = "169.254.169.254";
const azure = "168.63.129.16";
const fixture_answer = [4]u8{ 203, 0, 113, 7 };
const update_name = "update.werewolf.test";
const update_body = "signed-update-fixture\n";
/// Programs under fence run only from /usr: these are bound there.
const installed = "/usr/local/bin/check-dns";
const posture_egress = "/usr/local/bin/werewolf-posture-egress";
const upstream = "/run/werewolf/network/upstream";
const dhcp_domain = "/run/werewolf/network/dhcp-domain";
const policy_path = "/usr/share/werewolf/net";
const cases_yaml = @embedFile("dns/cases.yaml");

pub fn main(init: std.process.Init) !void {
    const l = netns.Lab.init(init, "check-dns");
    const args = try init.minimal.args.toSlice(l.gpa);
    if (args.len == 3 and eql(args[1], "--server")) return server(l, args[2]);
    if (args.len == 3 and eql(args[1], "--probe")) return probe(l, args[2]);
    if (args.len >= 6 and eql(args[1], "--ask")) return ask(l, args[2..]);
    if (args.len >= 6 and args.len <= 8 and eql(args[1], "--inside")) return inside(l, args[2..]);
    if (args.len < 3 or args.len > 5 or args[1][0] == '-') {
        l.log("usage", .{ .usage = "check-dns FENCE DNS-POLICY [DHCP-CLIENT [POSTURE-EGRESS]]" });
        std.process.exit(2);
    }
    var forward: std.ArrayList([]const u8) = .empty;
    try forward.appendSlice(
        l.gpa,
        &.{ "--inside", try l.namespace("net"), try l.namespace("mnt") },
    );
    for (args[1..]) |path| try forward.append(
        l.gpa,
        try Io.Dir.cwd().realPathFileAlloc(l.io, path, l.gpa),
    );
    // Root sets the rules itself; anyone else maps root from subordinate ids.
    const user: []const []const u8 = if (linux.geteuid() == 0)
        &.{}
    else
        &.{ "--user", "--map-auto", "--map-root-user" };
    var flags: std.ArrayList([]const u8) = .empty;
    try flags.appendSlice(l.gpa, user);
    try flags.appendSlice(l.gpa, &.{ "--net", "--mount" });
    try l.enter(flags.items, forward.items);
}

fn eql(a: []const u8, b: []const u8) bool {
    return mem.eql(u8, a, b);
}

/// Case is a row of test/dns/cases.yaml.
const Case = struct { uid: u32, mode: []const u8, server: []const u8, allowed: bool };

fn phase(gpa: std.mem.Allocator, doc: form.Node, name: []const u8) ![]const Case {
    const rows = doc.get(name) orelse return error.NoSuchPhase;
    if (rows != .list) return error.BadCases;
    const out = try gpa.alloc(Case, rows.list.len);
    for (rows.list, out) |row, *c| {
        if (row != .list or row.list.len != 4) return error.BadCases;
        var words: [4][]const u8 = undefined;
        for (row.list, &words) |cell, *w| {
            if (cell != .scalar) return error.BadCases;
            w.* = cell.scalar.text;
        }
        const servers = [_][2][]const u8{
            .{ "first", first }, .{ "second", second }, .{ "gcp", gcp }, .{ "azure", azure },
        };
        c.* = .{
            .uid = std.fmt.parseInt(u32, words[0], 10) catch return error.BadCases,
            .mode = words[1],
            .server = for (servers) |s| {
                if (eql(s[0], words[2])) break s[1];
            } else words[2],
            .allowed = eql(words[3], "allowed"),
        };
        for ([_][]const u8{ "udp", "tcp", "http", "metadata", "https" }) |m| {
            if (eql(m, c.mode)) break;
        } else return error.BadCases;
        if (!c.allowed and !eql(words[3], "refused")) return error.BadCases;
    }
    return out;
}

fn loadCases(gpa: std.mem.Allocator) !form.Node {
    var diag: form.Diagnostic = .{};
    return form.parse(gpa, cases_yaml, &diag) catch |err| {
        std.debug.print("check-dns: dns/cases.yaml:{d}: {s}\n", .{ diag.line, diag.why });
        return err;
    };
}

// --- inside the namespaces ---------------------------------------------------

const Fixture = struct {
    l: netns.Lab,
    work: []const u8,
    driver: []const u8,
    peer: ?netns.Child = null,
    client: ?netns.Child = null,
    replies: *netns.Lines,
    watcher: ?netns.Child = null,
    watched_lines: *netns.Lines,
    keeper: ?netns.Child = null,
    /// resolvers is the upstream file's text, as the rules stand.
    resolvers: []const u8,
    checks: usize = 0,

    fn path(f: *Fixture, name: []const u8) ![]const u8 {
        return f.l.gpa.print("{s}/{s}", .{ f.work, name });
    }

    /// request sends the probe a request and requires it to hold.
    fn request(f: *Fixture, line: []const u8) !void {
        try netns.writeAll(f.client.?.stdin.?, try f.l.gpa.print("{s}\n", .{line}));
        const reply = f.replies.next(10_000) catch |err|
            return f.l.fail("probe_unanswered", .{ .request = line, .@"error" = @errorName(err) });
        if (!eql(
            reply,
            "result 0",
        )) return f.l.fail("probe_failed", .{ .request = line, .reply = reply });
        f.checks += 1;
    }

    fn cases(f: *Fixture, doc: form.Node, name: []const u8) !void {
        for (try phase(
            f.l.gpa,
            doc,
            name,
        )) |c| try f.request(try f.l.gpa.print("{d} {s} {s} {s}", .{
            c.uid, c.mode, c.server, if (c.allowed) "allowed" else "refused",
        }));
    }

    /// posture runs the egress checks as root and requires these results.
    fn posture(f: *Fixture, assigned: []const u8, arbitrary: []const u8, https: []const u8) !void {
        if (f.watcher == null) return;
        try f.request(try f.l.gpa.print(
            "0 posture - allowed {s} {s} {s}",
            .{ assigned, arbitrary, https },
        ));
    }

    /// watched requires posture's resolver floor, which holds its directory
    /// across DHCP's atomic replacements, to read the resolvers as text.
    fn watched(f: *Fixture, text: []const u8) !void {
        const w = if (f.watcher) |*w| w else return;
        try netns.writeAll(w.stdin.?, "\n");
        const got = f.watched_lines.next(5000) catch |err|
            return f.l.fail("resolver_floor_timed_out", .{ .@"error" = @errorName(err) });
        const seen = std.json.parseFromSliceLeaky([]const u8, f.l.gpa, got, .{}) catch
            return f.l.fail("resolver_floor_unreadable", .{ .line = got });
        if (!eql(
            seen,
            text,
        )) return f.l.fail("resolver_floor_differs", .{ .want = text, .got = seen });
    }

    /// renew moves the resolvers to addresses: through real DHCP renewal,
    /// under its own sandbox, the first time it can, else with the driver.
    fn renew(f: *Fixture, addresses: []const []const u8) !void {
        var text: std.ArrayList(u8) = .empty;
        for (addresses) |a| try text.print(f.l.gpa, "nameserver {s}\n", .{a});
        const new = text.items;
        const log = try f.path("dhcp.log");
        if (f.keeper) |*keeper| if (addresses.len == 1 and eql(addresses[0], second)) {
            try f.l.write(try f.path("lease-dns"), second ++ "\n");
            try f.l.write(try f.path("lease-domain"), "renewed.example.test\n");
            const deadline = netns.now() + 45_000;
            while (netns.now() < deadline) {
                const current = f.l.read(upstream) catch "";
                const domain = f.l.read(dhcp_domain) catch "";
                if (eql(current, new) and eql(domain, "renewed.example.test")) break;
                if (try keeper.wait(0) != null) {
                    f.l.dump(log);
                    return f.l.fail("dhcp_keeper_exited", .{ .exit = keeper.exit });
                }
                netns.nap(100);
            }
            if (!eql(try f.l.read(upstream), new)) {
                f.l.dump(log);
                return f.l.fail("dhcp_renewal_missed", .{ .want = new });
            }
            if (!eql(try f.l.read(dhcp_domain), "renewed.example.test"))
                return f.l.fail("dhcp_domain_not_renewed", .{});
            if (mem.find(u8, try f.l.read(log), "\"event\":\"renewed\"") == null)
                return f.l.fail("dhcp_renewal_not_logged", .{});
            keeper.signal(.TERM);
            if (try keeper.wait(5000) == null) return f.l.fail("dhcp_keeper_lingers", .{});
            f.keeper = null;
            f.l.log(
                "pass",
                .{ .what = "real DHCP renewal changed resolver rules under the parent sandbox" },
            );
            f.resolvers = new;
            return f.watched(new);
        };
        try f.l.run(&.{ f.driver, f.resolvers, new });
        try f.l.write(upstream, new);
        f.resolvers = new;
        try f.watched(new);
    }

    fn deinit(f: *Fixture) void {
        if (f.watcher) |*w| {
            w.closeStdin();
            _ = w.wait(5000) catch {};
        }
        if (f.client) |*c| if (c.exit == null) {
            c.closeStdin();
            if (c.wait(5000) catch null == null) {
                c.signal(.KILL);
                _ = c.wait(null) catch {};
            }
        };
        if (f.keeper) |*k| k.stop();
        if (f.peer) |*p| p.stop();
        f.l.run(&.{ "ip", "netns", "delete", "dns-peer" }) catch {};
    }
};

/// inside runs as root of new mount and network namespaces: args are the
/// parent's namespaces, then FENCE DNS-POLICY [DHCP-CLIENT [POSTURE-EGRESS]].
fn inside(l: netns.Lab, args: []const [:0]const u8) !void {
    if (eql(try l.namespace("net"), args[0]) or eql(try l.namespace("mnt"), args[1]))
        return l.fail("namespace_shared", .{ .net = args[0], .mnt = args[1] });
    const fence = args[2];
    const dhcp: ?[]const u8 = if (args.len > 4) args[4] else null;
    const posture: ?[]const u8 = if (args.len > 5) args[5] else null;
    const doc = try loadCases(l.gpa);
    try l.private();
    const work = try l.temporary("werewolf-dns");
    defer l.remove(work);
    const bin = try l.gpa.print("{s}/bin", .{work});
    try l.mkdir(bin, 0o755);
    try l.copy(try l.self(), try l.gpa.print("{s}/check-dns", .{bin}), 0o755);
    if (posture) |p| try l.copy(p, try l.gpa.print("{s}/werewolf-posture-egress", .{bin}), 0o755);
    try l.bind(bin, "/usr/local/bin");
    try l.write(try l.gpa.print("{s}/lease-dns", .{work}), first ++ "\n");
    try l.write(try l.gpa.print("{s}/lease-domain", .{work}), "corp.example.test\n");
    for ([_][]const u8{ "/run", "/etc", "/usr/share", "/var" }) |dir| try l.tmpfs(dir);
    try l.mkdir("/var/empty", 0o755);
    try l.symlink("/run", "/var/run");
    try l.mkdir("/usr/share/werewolf", 0o755);
    try l.write(policy_path, "dns 69\nconnect 69 tcp 443\n" ++
        "dns-direct 207\nconnect 207 tcp 53\nconnect 207 udp 53\n");
    // fence and DHCP keep a dns user's grants on the upstream file's
    // resolvers: on a machine, unwound's upstream user. The probes here
    // read that file as their resolv.conf, to reach them directly.
    try l.mkdir("/run/werewolf", 0o755);
    try l.mkdir("/run/werewolf/network", 0o755);
    // The OCI resolver view binds the directory, never the old file inode.
    try l.mkdir("/etc/werewolf-network", 0o755);
    try l.bind("/run/werewolf/network", "/etc/werewolf-network");
    if (linux.errno(linux.mount(null, "/etc/werewolf-network", null, linux.MS.REMOUNT |
        linux.MS.BIND | linux.MS.RDONLY, 0)) != .SUCCESS) return l.fail("remount_failed", .{});
    try l.symlink("/etc/werewolf-network/upstream", "/etc/resolv.conf");
    try l.write(upstream, "nameserver " ++ first ++ "\n");

    try l.veth(.{
        .peer = "dns-peer",
        .client = "10.77.0.1/24",
        .addresses = &.{
            first ++ "/24",
            second ++ "/32",
            gcp ++ "/32",
            azure ++ "/32",
            "203.0.113.7/32",
        },
        .gateway = first,
        .peer_default = true,
    });
    const ipv6 = linux.errno(linux.access("/proc/net/if_inet6", linux.F_OK)) == .SUCCESS;
    if (ipv6) {
        try l.run(&.{ "ip", "-6", "addr", "add", "2001:db8:77::1/64", "dev", "client" });
        try l.run(&.{ "ip", "-6", "route", "add", "default", "via", "2001:db8:77::2" });
        try l.run(&.{
            "ip",
            "-n",
            "dns-peer",
            "-6",
            "addr",
            "add",
            "2001:db8:77::2/64",
            "dev",
            "peer",
        });
        try l.run(&.{ "ip", "-n", "dns-peer", "-6", "route", "add", "default", "dev", "peer" });
    }

    var f: Fixture = .{
        .l = l,
        .work = work,
        .driver = args[3],
        .replies = try l.gpa.create(netns.Lines),
        .watched_lines = try l.gpa.create(netns.Lines),
        .resolvers = "nameserver " ++ first ++ "\n",
    };
    defer f.deinit();
    f.peer = try l.spawn(
        &.{ "ip", "netns", "exec", "dns-peer", installed, "--server", work },
        .{ .stdout = .pipe },
    );
    var peer_lines: netns.Lines = .{ .fd = f.peer.?.stdout.? };
    peer_lines.ready(10_000) catch |err| return l.fail(
        "fixture_not_ready",
        .{ .@"error" = @errorName(err) },
    );
    if (posture != null) {
        f.watcher = try l.spawn(
            &.{ posture_egress, "--watch-resolvers" },
            .{ .stdin = .pipe, .stdout = .pipe },
        );
        f.watched_lines.* = .{ .fd = f.watcher.?.stdout.? };
    }
    try f.watched(f.resolvers);
    if (dhcp) |client| {
        const up = try std.process.run(l.gpa, l.io, .{
            .argv = &.{ client, "up", "client" },
            .timeout = (Io.Timeout{ .duration = .{ .raw = .fromSeconds(35), .clock = .awake } })
                .toDeadline(l.io),
        });
        if (up.term != .exited or up.term.exited != 0)
            return l.fail("dhcp_up_failed", .{ .stdout = up.stdout, .stderr = up.stderr });
        if (!eql(
            try l.read(dhcp_domain),
            "corp.example.test",
        )) return l.fail("dhcp_domain_missed", .{});
        const log = try l.gpa.dupeSentinel(u8, try f.path("dhcp.log"), 0);
        const rc = linux.open(
            log,
            .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true, .CLOEXEC = true },
            0o644,
        );
        if (linux.errno(rc) != .SUCCESS) return l.fail("dhcp_log_unwritable", .{});
        const fd: linux.fd_t = @intCast(rc);
        defer netns.close(fd);
        f.keeper = try l.spawn(
            &.{ client, "keep" },
            .{ .stdout = .{ .fd = fd }, .stderr = .{ .fd = fd } },
        );
    }
    f.client = try l.spawn(
        &.{ fence, installed, "--probe", try f.path("ca.pem") },
        .{ .stdin = .pipe, .stdout = .pipe },
    );
    f.replies.* = .{ .fd = f.client.?.stdout.? };
    const announcement = f.replies.next(10_000) catch |err|
        return l.fail("fence_timed_out", .{ .@"error" = @errorName(err) });
    if (!mem.startsWith(u8, announcement, "fence: ") or
        mem.find(u8, announcement, "\"event\":\"fence\"") == null)
        return l.fail("fence_unannounced", .{ .line = announcement });

    try f.posture("pass", "pass", "pass");
    try f.cases(doc, "production");
    // Renewal closes the old resolver, keeps the uid's grant and still
    // resolves HTTPS.
    try f.renew(&.{second});
    try f.cases(doc, "renewed");
    try f.renew(&.{ gcp, azure });
    try f.cases(doc, "cloud");
    try f.renew(&.{});
    try f.posture("skip", "pass", "pass");
    try f.cases(doc, "none");
    try l.write(policy_path, "dns 0\ndns 69\nconnect 69 tcp 443\n");
    try f.renew(&.{first});
    try f.cases(doc, "root");
    try f.posture("fail", "pass", "pass");
    if (posture != null) {
        // Broad grants open HTTPS, but never DNS past unwound: fence refuses
        // ports 53 and 853 before any connect grant.
        if (ipv6) {
            try l.run(&.{ f.driver, "--root-https-v6" });
            try f.posture("fail", "pass", "fail");
            try l.run(&.{ f.driver, "--root-dns-v6" });
            try f.posture("fail", "pass", "fail");
        }
        try l.run(&.{ f.driver, "--broad-root" });
        try f.posture("fail", "pass", "fail");
    }
    l.log("pass", .{
        .checks = f.checks,
        .what = "real-kernel DNS/HTTPS allow-deny checks, including renewal and cloud resolvers",
    });
}

// --- the probe, under fence ----------------------------------------------------

/// probe answers each request, `UID MODE SERVER OUTCOME [POSTURE...]`, with
/// `result EXIT`: a child drops to UID and runs it as --ask. The probe
/// starts no threads, so its children may run code before exec.
fn probe(l: netns.Lab, ca: []const u8) !void {
    const requests = try l.gpa.create(netns.Lines);
    requests.* = .{ .fd = 0 };
    while (true) {
        const line = requests.next(30 * 60_000) catch |err| switch (err) {
            error.EndOfStream => return,
            else => |e| return e,
        };
        var words = mem.tokenizeScalar(u8, line, ' ');
        const uid = try std.fmt.parseInt(u32, words.next() orelse return error.BadRequest, 10);
        var argv: std.ArrayList(?[*:0]const u8) = .empty;
        try argv.appendSlice(l.gpa, &.{ "check-dns", "--ask", try l.gpa.dupeSentinel(u8, ca, 0) });
        while (words.next()) |w| try argv.append(l.gpa, try l.gpa.dupeSentinel(u8, w, 0));
        try argv.append(l.gpa, null);
        const argv_z = argv.items[0 .. argv.items.len - 1 :null];
        const rc = linux.fork();
        if (linux.errno(rc) != .SUCCESS) return error.ForkFailed;
        if (rc == 0) {
            // An unprivileged user namespace may deny setgroups.
            const none: [0]linux.gid_t = .{};
            const groups = linux.errno(linux.setgroups(0, &none));
            if (groups != .SUCCESS and groups != .PERM) linux.exit_group(126);
            if (linux.errno(linux.setgid(uid)) != .SUCCESS) linux.exit_group(126);
            if (linux.errno(linux.setuid(uid)) != .SUCCESS) linux.exit_group(126);
            _ = linux.execve(installed, argv_z.ptr, l.environ.block.slice.ptr);
            linux.exit_group(127);
        }
        var child: netns.Child = .{ .pid = @intCast(rc) };
        const exit = try child.wait(8000) orelse blk: {
            child.signal(.KILL);
            break :blk try child.wait(null);
        };
        try netns.writeAll(1, try l.gpa.print("result {d}\n", .{exit.?}));
    }
}

/// ask makes one request: CA MODE SERVER OUTCOME [ASSIGNED ARBITRARY HTTPS].
/// It exits 0 if the traffic was allowed or refused as OUTCOME says.
fn ask(l: netns.Lab, args: []const [:0]const u8) !void {
    const ca, const mode, const address, const outcome = args[0..4].*;
    const allowed = eql(outcome, "allowed");
    if (eql(mode, "posture")) {
        if (args.len != 7) return error.BadRequest;
        return egress(l, .{ args[4], args[5], args[6] });
    }
    const result = if (eql(mode, "https"))
        fetch(l, ca, address)
    else if (eql(mode, "udp") or eql(mode, "tcp"))
        exchange(l, address, 53, eql(mode, "tcp"))
    else
        exchange(l, address, 80, true);
    if (result) |_| {
        if (!allowed) return l.fail(
            "undeclared_traffic_succeeded",
            .{ .mode = mode, .server = address },
        );
    } else |err| {
        if (allowed or err != error.Refused) return l.fail("unexpected_outcome", .{
            .mode = mode,
            .server = address,
            .want = outcome,
            .@"error" = @errorName(err),
        });
    }
}

/// egress runs posture's egress checks and requires exactly these results.
fn egress(l: netns.Lab, want: [3][]const u8) !void {
    const ids = [3][]const u8{
        "network-root-dns-assigned", "network-root-dns-arbitrary", "network-root-https-arbitrary",
    };
    const r = try std.process.run(l.gpa, l.io, .{
        .argv = &.{posture_egress},
        .stdout_limit = .limited(1 << 20),
        .timeout = (Io.Timeout{ .duration = .{ .raw = .fromSeconds(3), .clock = .awake } })
            .toDeadline(l.io),
    });
    if (r.term != .exited or
        r.term.exited != 0) return l.fail("posture_failed", .{ .stderr = r.stderr });
    const report = std.json.parseFromSliceLeaky(std.json.Value, l.gpa, r.stdout, .{}) catch
        return l.fail("posture_unreadable", .{ .report = r.stdout });
    if (report != .array) return l.fail("posture_unreadable", .{ .report = r.stdout });
    var results: std.array_hash_map.String([]const u8) = .empty;
    for (report.array.items) |item| {
        const id = if (item == .object) item.object.get("id") else null;
        const result = if (item == .object) item.object.get("result") else null;
        if (id == null or id.? != .string or result == null or result.? != .string)
            return l.fail("posture_unreadable", .{ .report = r.stdout });
        try results.put(l.gpa, id.?.string, result.?.string);
    }
    var same = results.count() == ids.len;
    for (ids, want) |id, w| same = same and eql(results.get(id) orelse "", w);
    if (!same) return l.fail("posture_differs", .{ .want = want, .report = r.stdout });
}

fn fetch(l: netns.Lab, ca: []const u8, name: []const u8) !void {
    const now = Io.Clock.real.now(l.io);
    var bundle: std.crypto.Certificate.Bundle = .empty;
    try bundle.addCertsFromFilePathAbsolute(l.gpa, l.io, now, ca);
    var client: std.http.Client = .{
        .allocator = l.gpa,
        .io = l.io,
        .ca_bundle = bundle,
        .now = now,
    };
    var body: Io.Writer.Allocating = .init(l.gpa);
    const reply = client.fetch(.{
        .location = .{ .url = try l.gpa.print("https://{s}/latest.json", .{name}) },
        .response_writer = &body.writer,
        .keep_alive = false,
    }) catch |err| return switch (err) {
        error.AccessDenied => error.Refused,
        else => |e| e,
    };
    if (reply.status != .ok or !eql(body.written(), update_body)) return error.WrongAnswer;
}

/// exchange asks the fixture's question of address:port, over TCP or UDP,
/// within two seconds, and requires the fixture's answer.
fn exchange(l: netns.Lab, address: []const u8, port: u16, tcp: bool) !void {
    const fd = try netns.socket(if (tcp) linux.SOCK.STREAM else linux.SOCK.DGRAM);
    defer netns.close(fd);
    netns.limit(fd, 2000);
    const to = try netns.address(address, port);
    try check(l, "connect", linux.connect(fd, @ptrCast(&to), @sizeOf(@TypeOf(to))));
    var buf: [512]u8 = undefined;
    const question = try dnswire.query(&buf, 0x1234, update_name, 1);
    var reply: [2048]u8 = undefined;
    var answer: []const u8 = undefined;
    if (tcp) {
        var framed: [514]u8 = undefined;
        mem.writeInt(u16, framed[0..2], @intCast(question.len), .big);
        @memcpy(framed[2..][0..question.len], question);
        try check(l, "send", linux.sendto(fd, &framed, question.len + 2, 0, null, 0));
        var size: [2]u8 = undefined;
        try netns.readExact(fd, &size);
        const n = mem.readInt(u16, &size, .big);
        if (n > reply.len) return error.WrongAnswer;
        try netns.readExact(fd, reply[0..n]);
        answer = reply[0..n];
    } else {
        try check(l, "send", linux.sendto(fd, question.ptr, question.len, 0, null, 0));
        const n = linux.recvfrom(fd, &reply, reply.len, 0, null, null);
        try check(l, "recv", n);
        answer = reply[0..n];
    }
    if (answer.len < 6 or !eql(answer[0..2], question[0..2]) or
        !eql(answer[answer.len - 4 ..], &fixture_answer)) return error.WrongAnswer;
}

/// check turns a refused system call into error.Refused: fence refuses
/// with EACCES, or EPERM.
fn check(l: netns.Lab, call: []const u8, rc: usize) !void {
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        .ACCES, .PERM => return error.Refused,
        else => |e| {
            l.log("socket_error", .{ .call = call, .errno = @tagName(e) });
            return error.SocketFailed;
        },
    }
}

// --- the peer: resolvers, DHCP and HTTPS ---------------------------------------

/// server answers DNS on the four resolvers' UDP port 53 and TCP 53 on
/// every address, DHCP on the peer link, and HTTPS for update.werewolf.test,
/// whose authority it writes to WORK/ca.pem.
fn server(l: netns.Lab, work: []const u8) !void {
    const ca = try host.tls.Authority.init(l.io, l.gpa, "werewolf check-dns authority");
    const identity = try ca.issue(l.io, l.gpa, &.{update_name});
    const pem = try l.gpa.print("{s}/ca.pem", .{work});
    try l.write(pem, try ca.pem(l.gpa));
    try l.chmod(pem, 0o644);
    var https: host.http.Server = undefined;
    var unused: u8 = 0;
    try https.start(l.io, l.gpa, .{
        .address = .{ .ip4 = .unspecified(443) },
        .identity = &identity,
        .handler = .{ .context = &unused, .serve = update },
    });
    defer https.stop();

    var fds: [6]linux.pollfd = undefined;
    for ([_][]const u8{ first, second, gcp, azure }, 0..) |address, i| {
        fds[i].fd = try netns.socket(linux.SOCK.DGRAM);
        try netns.listen(fds[i].fd, address, 53, null);
    }
    fds[4].fd = try netns.socket(linux.SOCK.STREAM);
    try netns.listen(fds[4].fd, "0.0.0.0", 53, 16);
    const dhcp = try netns.socket(linux.SOCK.DGRAM);
    const one: c_int = 1;
    try check(
        l,
        "broadcast",
        linux.setsockopt(dhcp, linux.SOL.SOCKET, linux.SO.BROADCAST, @ptrCast(&one), 4),
    );
    try check(
        l,
        "bind to peer",
        linux.setsockopt(dhcp, linux.SOL.SOCKET, linux.SO.BINDTODEVICE, "peer", 5),
    );
    try netns.listen(dhcp, "0.0.0.0", 67, null);
    fds[5].fd = dhcp;
    for (&fds) |*p| p.events = linux.POLL.IN;
    try netns.writeAll(1, "ready\n");
    while (true) {
        for (&fds) |*p| p.revents = 0;
        const n = linux.poll(&fds, fds.len, -1);
        if (linux.errno(n) == .INTR) continue;
        try check(l, "poll", n);
        for (fds[0..4]) |p| if (p.revents != 0) datagram(p.fd);
        if (fds[4].revents != 0) stream(fds[4].fd);
        if (fds[5].revents != 0) lease(l, fds[5].fd, work);
    }
}

fn update(
    _: *anyopaque,
    _: std.mem.Allocator,
    request: *const host.http.Request,
    response: *host.http.Response,
) !void {
    if (!eql(request.method, "GET")) return response.send(501, &.{}, "");
    try response.send(200, &.{}, update_body);
}

/// respond answers any question: NOERROR, with 203.0.113.7 for an A query.
fn respond(query: []const u8, out: []u8) ?[]const u8 {
    var name: [255]u8 = undefined;
    const q = dnswire.question(query, &name) catch return null;
    const a = q.kind == 1;
    var m: dnswire.Message = .{ .buf = out };
    m.header(.{
        .id = mem.readInt(u16, query[0..2], .big),
        .flags = 0x8180,
        .an = @intFromBool(a),
    }) catch
        return null;
    m.put(q.raw) catch return null;
    if (a) m.put(&[_]u8{ 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0x3c, 0, 4 } ++
        fixture_answer) catch return null;
    return m.bytes();
}

fn datagram(fd: linux.fd_t) void {
    var query: [2048]u8 = undefined;
    var from: linux.sockaddr.in = undefined;
    var len: linux.socklen_t = @sizeOf(linux.sockaddr.in);
    const n = linux.recvfrom(fd, &query, query.len, 0, @ptrCast(&from), &len);
    if (linux.errno(n) != .SUCCESS) return;
    var out: [2048]u8 = undefined;
    const answer = respond(query[0..n], &out) orelse return;
    _ = linux.sendto(fd, answer.ptr, answer.len, 0, @ptrCast(&from), len);
}

/// stream answers one TCP client. Posture closes permitted TCP probes
/// without asking anything; the next connection is still served.
fn stream(listener: linux.fd_t) void {
    const rc = linux.accept4(listener, null, null, linux.SOCK.CLOEXEC);
    if (linux.errno(rc) != .SUCCESS) return;
    const fd: linux.fd_t = @intCast(rc);
    defer netns.close(fd);
    netns.limit(fd, 2000);
    var size: [2]u8 = undefined;
    netns.readExact(fd, &size) catch return;
    var query: [65535]u8 = undefined;
    const q = query[0..mem.readInt(u16, &size, .big)];
    netns.readExact(fd, q) catch return;
    var out: [2050]u8 = undefined;
    const answer = respond(q, out[2..]) orelse return;
    mem.writeInt(u16, out[0..2], @intCast(answer.len), .big);
    netns.writeAll(fd, out[0 .. answer.len + 2]) catch {};
}

/// lease offers and acknowledges 10.77.0.1 for a minute, renewing at 30 s,
/// with the resolvers in WORK/lease-dns and the domain in WORK/lease-domain.
fn lease(l: netns.Lab, fd: linux.fd_t, work: []const u8) void {
    var data: [2048]u8 = undefined;
    const n = linux.recvfrom(fd, &data, data.len, 0, null, null);
    if (linux.errno(n) != .SUCCESS or n < 240) return;
    var kind: ?u8 = null;
    var at: usize = 240;
    while (at + 1 < n and data[at] != 255) {
        if (data[at] == 0) {
            at += 1;
            continue;
        }
        if (data[at] == 53 and data[at + 1] == 1 and at + 2 < n) kind = data[at + 2];
        at += 2 + data[at + 1];
    }
    if (kind != 1 and kind != 3) return;
    var reply: [1024]u8 = @splat(0);
    reply[0..3].* = .{ 2, 1, 6 };
    reply[4..8].* = data[4..8].*;
    reply[16..20].* = .{ 10, 77, 0, 1 };
    reply[28..34].* = data[28..34].*;
    reply[236..240].* = data[236..240].*;
    var m: dnswire.Message = .{ .buf = &reply, .len = 240 };
    const server_ip = [4]u8{ 10, 77, 0, 2 };
    option(&m, 53, &.{if (kind == 1) 2 else 5});
    option(&m, 54, &server_ip);
    option(&m, 1, &.{ 255, 255, 255, 0 });
    option(&m, 3, &server_ip);
    for ([_]struct { u8, u32 }{ .{ 51, 60 }, .{ 58, 30 }, .{ 59, 45 } }) |o| {
        var v: [4]u8 = undefined;
        mem.writeInt(u32, &v, o[1], .big);
        option(&m, o[0], &v);
    }
    const servers = l.read(l.gpa.print("{s}/lease-dns", .{work}) catch return) catch "";
    var addresses: [16]u8 = undefined;
    var count: usize = 0;
    var words = mem.tokenizeAny(u8, servers, " \t\r\n");
    while (words.next()) |w| {
        if (count == addresses.len) break;
        const ip = Io.net.Ip4Address.parse(w, 0) catch return;
        addresses[count..][0..4].* = ip.bytes;
        count += 4;
    }
    if (count > 0) option(&m, 6, addresses[0..count]);
    const domain_text = l.read(l.gpa.print("{s}/lease-domain", .{work}) catch return) catch "";
    const domain = mem.trim(u8, domain_text, " \t\r\n");
    if (domain.len > 0) option(&m, 15, domain);
    m.put(&.{255}) catch return;
    const to: linux.sockaddr.in = .{ .addr = 0xffffffff, .port = mem.nativeToBig(u16, 68) };
    _ = linux.sendto(fd, &reply, m.len, 0, @ptrCast(&to), @sizeOf(linux.sockaddr.in));
}

fn option(m: *dnswire.Message, code: u8, value: []const u8) void {
    m.put(&.{ code, @intCast(value.len) }) catch return;
    m.put(value) catch return;
}

test "every case in dns/cases.yaml is well formed" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const doc = try loadCases(arena.allocator());
    var total: usize = 0;
    for ([_][]const u8{ "production", "renewed", "cloud", "none", "root" }) |name|
        total += (try phase(arena.allocator(), doc, name)).len;
    try std.testing.expectEqual(5, doc.map.len);
    try std.testing.expectEqual(28, total);
    const production = try phase(arena.allocator(), doc, "production");
    try std.testing.expectEqualStrings(first, production[0].server);
    try std.testing.expect(production[0].allowed and !production[1].allowed);
}
