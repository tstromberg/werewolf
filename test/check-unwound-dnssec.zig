//! check-unwound-dnssec verifies real DNSSEC validation, TLSA and AD through
//! fence and unwound: a zone signed afresh, served by BIND and validated by
//! Unbound, all in private network and mount namespaces, as root.
//!
//!     check-unwound-dnssec FENCE UNWOUND [MOX]
//!
//! It needs named, unbound, dig and BIND's dnssec-keygen and dnssec-signzone,
//! as the unwound-lab VM has them. MOX, if given, must find the TLSA record
//! validated too. The questions are test/unwound/cases.yaml's dnssec phases.

const std = @import("std");
const builtin = @import("builtin");
const host = @import("host");
const lab = @import("unwound/lab.zig");
const linux = std.os.linux;
const mem = std.mem;
const netns = host.netns;

const tlsa_hex = "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5";
const policy = "listen tcp 53 loopback\ndns 54\n" ++
    "lookup 2001 * A AAAA TLSA NS unfiltered\n" ++
    "lookup 2002 * A AAAA TLSA NS\n";
const marker = "nameserver 127.0.0.1\n";

pub fn main(init: std.process.Init) !void {
    const l = lab.Lab.init(init, "check-unwound-dnssec");
    const args = try init.minimal.args.toSlice(l.gpa);
    if (try lab.role(l, args)) return;
    if (args.len >= 5 and mem.eql(u8, args[1], "--inside"))
        return inside(l, args[2], args[3], args[4], if (args.len == 6) args[5] else null);
    if (args.len != 3 and args.len != 4) {
        l.log("usage", .{ .usage = "check-unwound-dnssec FENCE UNWOUND [MOX]" });
        std.process.exit(2);
    }
    if (builtin.os.tag != .linux or linux.geteuid() != 0) return l.fail("needs_linux_root", .{});
    var inner: std.ArrayList([]const u8) = .empty;
    try inner.appendSlice(l.gpa, &.{ "--inside", try l.namespace("net") });
    for (args[1..]) |path| try inner.append(
        l.gpa,
        try std.Io.Dir.cwd().realPathFileAlloc(l.io, path, l.gpa),
    );
    try l.enter(&.{ "--net", "--mount" }, inner.items);
}

fn inside(
    l: lab.Lab,
    parent_net: []const u8,
    fence: []const u8,
    unwound: []const u8,
    mox: ?[]const u8,
) !void {
    if (mem.eql(u8, try l.namespace("net"), parent_net)) return l.fail("shared_network", .{});
    try l.private();
    var w = try lab.World.init(l, "werewolf-dnssec");
    defer w.stop();
    const key = try signedZone(&w);
    // BIND's dig in the lab VM rejects the usual /etc tmpfs symlink.
    try w.mount(unwound, policy, .{
        .upstream = marker,
        .resolv_file = true,
        .binaries = if (mox) |m| &.{m} else &.{},
    });
    try l.write("/etc/passwd", "root:x:0:0:root:/root:/bin/sh\n");
    try l.write("/etc/group", "root:x:0:\n");
    try l.mkdir("/etc/bind", 0o755);
    try l.mkdir("/etc/unbound", 0o755);
    try l.copy(key, "/etc/unbound/zone.key", 0o644);
    try l.mkdir("/var/cache", 0o755);
    try l.mkdir("/var/cache/bind", 0o755);
    try l.copy(try w.path("signed.zone"), "/var/cache/bind/signed.zone", 0o644);
    try l.write("/usr/share/werewolf/dnssec-local", marker);
    try l.run(&.{ "ip", "link", "set", "lo", "up" });
    try l.run(&.{ "ip", "addr", "add", "127.0.0.2/8", "dev", "lo" });
    try l.write("/etc/bind/named.conf",
        \\options { directory "/var/cache/bind"; listen-on port 53 { 127.0.0.2; };
        \\ listen-on-v6 { none; }; recursion no; dnssec-validation no;
        \\ allow-query { any; }; pid-file "/run/named.pid"; };
        \\zone "signed.test" { type primary; file "/var/cache/bind/signed.zone"; };
        \\
    );
    try l.write("/etc/unbound/unbound.conf", try l.gpa.print(
        \\server:
        \\ interface: 127.0.0.1
        \\ port: 53
        \\ do-ip6: no
        \\ username: ""
        \\ chroot: ""
        \\ directory: "{s}"
        \\ use-syslog: no
        \\ logfile: ""
        \\ do-not-query-localhost: no
        \\ access-control: 127.0.0.0/8 allow
        \\ local-zone: "test." nodefault
        \\ local-zone: "signed.test." nodefault
        \\ module-config: "validator iterator"
        \\ trust-anchor-file: "/etc/unbound/zone.key"
        \\stub-zone:
        \\ name: "signed.test."
        \\ stub-addr: 127.0.0.2@53
        \\
    , .{w.work}));

    var named: ?netns.Child = null;
    var unbound: ?netns.Child = null;
    defer for ([_]*?netns.Child{ &unbound, &named }) |child| if (child.*) |*c| c.stop();
    errdefer for ([_][]const u8{ "named.log", "unbound.log", "stderr", "audit" }) |name|
        l.dump(w.path(name) catch continue);
    const named_log = try l.create(try w.path("named.log"));
    named = try l.spawn(
        &.{ "/usr/sbin/named", "-g", "-c", "/etc/bind/named.conf", "-u", "root" },
        .{ .stdout = .{ .fd = named_log }, .stderr = .{ .fd = named_log } },
    );
    netns.close(named_log);
    try ready(l, "127.0.0.2");
    const unbound_log = try l.create(try w.path("unbound.log"));
    unbound = try l.spawn(
        &.{ "/usr/sbin/unbound", "-d", "-c", "/etc/unbound/unbound.conf" },
        .{ .stdout = .{ .fd = unbound_log }, .stderr = .{ .fd = unbound_log } },
    );
    netns.close(unbound_log);
    try ready(l, "127.0.0.1");

    // Unbound itself validates the good answer, sets AD for a client that
    // asks without EDNS, and refuses the forged signature.
    const tlsa = [_][]const u8{ "dig", "@127.0.0.1", "_25._tcp.mail.signed.test", "TLSA" };
    const good = try l.output(&(tlsa ++
        [_][]const u8{ "+dnssec", "+noall", "+comments", "+answer" }));
    if (mem.find(u8, good, " ad;") == null or
        !hasTlsa(l, good)) return l.fail("unbound_unvalidated", .{ .dig = good });
    const plain = try l.output(&(tlsa ++
        [_][]const u8{ "+noedns", "+adflag", "+noall", "+comments", "+answer" }));
    if (mem.find(u8, plain, " ad;") == null) return l.fail("unbound_no_ad", .{ .dig = plain });
    const bad = try l.output(&.{
        "dig",
        "@127.0.0.1",
        "bad.signed.test",
        "A",
        "+noall",
        "+comments",
    });
    if (mem.find(
        u8,
        bad,
        "SERVFAIL",
    ) == null) return l.fail("unbound_took_forgery", .{ .dig = bad });

    var c = try w.start(fence);
    const doc = try lab.load(l);
    _ = try c.phase(doc, "dnssec");
    if (mox != null) {
        const out = try w.path("mox.out");
        const fd = try l.create(out);
        var lookup = try l.spawn(
            &.{
                "timeout",
                "10",
                "/usr/local/bin/mox",
                "dns",
                "lookup",
                "tlsa",
                "_25._tcp.mail.signed.test",
            },
            .{ .uid = 2001, .stdout = .{ .fd = fd }, .stderr = .{ .fd = fd } },
        );
        netns.close(fd);
        const exit = try lookup.wait(null);
        const said = try l.read(out);
        const lower = try std.ascii.allocLowerString(l.gpa, said);
        if (exit != 0 or !hasTlsa(l, said) or mem.find(u8, lower, "with dnssec") == null)
            return l.fail("mox_unvalidated", .{ .exit = exit, .output = said });
        l.log("mox", .{ .lookup = mem.trim(u8, said, " \n") });
    }
    _ = try c.phase(doc, "dnssec-root");
    if (mem.find(u8, try l.read(try w.path("audit")), "\"dnssec\":true") == null)
        return l.fail("dnssec_unaudited", .{});
    l.log("pass", .{ .requests = c.asked });
}

/// hasTlsa says whether text holds the record's data, however it is spaced.
fn hasTlsa(l: lab.Lab, text: []const u8) bool {
    var squeezed: std.ArrayList(u8) = .empty;
    for (text) |ch| if (!std.ascii.isWhitespace(ch)) squeezed.append(
        l.gpa,
        std.ascii.toLower(ch),
    ) catch return false;
    return mem.find(u8, squeezed.items, tlsa_hex) != null;
}

/// ready waits for the server at address to answer the TLSA question.
fn ready(l: lab.Lab, address: []const u8) !void {
    const at = try l.gpa.print("@{s}", .{address});
    for (0..20) |_| {
        const out = try l.attempt(&.{
            "dig",       at,        "_25._tcp.mail.signed.test", "TLSA",     "+noall",
            "+comments", "+answer", "+time=1",                   "+tries=1",
        }, .{ .quiet = true });
        if (out) |text| if (hasTlsa(l, text)) return;
        netns.nap(100);
    }
    return l.fail("no_tlsa_answer", .{ .server = address });
}

/// signedZone signs signed.test with a fresh KSK and ZSK, then breaks the
/// signature of bad.signed.test, and returns the KSK's public key file.
fn signedZone(w: *lab.World) ![]const u8 {
    const l = w.l;
    const unsigned = try w.path("unsigned.zone");
    const keygen = [_][]const u8{ "dnssec-keygen", "-a", "ECDSAP256SHA256", "-n", "ZONE" };
    const ksk = mem.trim(u8, (try l.attempt(
        &(keygen ++ [_][]const u8{ "-f", "KSK", "signed.test" }),
        .{ .cwd = w.work },
    )) orelse
        return error.KeygenFailed, " \n");
    const zsk = mem.trim(u8, (try l.attempt(
        &(keygen ++ [_][]const u8{"signed.test"}),
        .{ .cwd = w.work },
    )) orelse
        return error.KeygenFailed, " \n");
    try l.write(unsigned, try l.gpa.print(
        \\$ORIGIN signed.test.
        \\$TTL 300
        \\@ IN SOA ns.signed.test. hostmaster.signed.test. (1 3600 600 86400 300)
        \\@ IN NS ns.signed.test.
        \\ns IN A 127.0.0.2
        \\mail IN A 192.0.2.10
        \\bad IN A 192.0.2.33
        \\_25._tcp.mail IN TLSA 3 1 1 {s}
        \\$INCLUDE {s}.key
        \\$INCLUDE {s}.key
        \\
    , .{ tlsa_hex, ksk, zsk }));
    const ksk_key = try l.gpa.print("{s}.key", .{ksk});
    const zsk_key = try l.gpa.print("{s}.key", .{zsk});
    _ = try l.attempt(
        &.{
            "dnssec-signzone",
            "-o",
            "signed.test",
            "-f",
            "signed.zone",
            "unsigned.zone",
            ksk_key,
            zsk_key,
        },
        .{ .cwd = w.work },
    ) orelse
        return error.SignzoneFailed;
    const zone = try l.read(try w.path("signed.zone"));
    if (mem.find(u8, zone, "192.0.2.33") == null) return l.fail("unsigned_address_missing", .{});
    try l.write(
        try w.path("signed.zone"),
        try mem.replaceOwned(u8, l.gpa, zone, "192.0.2.33", "192.0.2.34"),
    );
    return w.path(ksk_key);
}
