//! fence: the machine's network policy, from the image, then runit.
//!
//!     fence PROGRAM [ARG...]
//!
//! init's last step, as `exec fence runit`. As root it reads
//! /usr/share/werewolf/net, which the build compiled from the forms' .net
//! files, and sets a default-deny policy in both directions:
//!
//!   1. Policy-routing rules, which the kernel consults on every route
//!      lookup, the same for IPv4 and IPv6. A packet the machine sends passes only if its
//!      user declared it (`connect`): its protocol and port, or as a reply
//!      from a port it serves (`listen`); the metadata server's port 80 only
//!      for the users named (`metadata`). Anything else is refused with
//!      EACCES. A packet arriving passes only to a port it serves, from a
//!      port it connects to (a reply), or as ICMP; anything else is dropped
//!      without an answer. Local and loopback traffic always pass, and so
//!      does ICMPv6, which IPv6 cannot work without (neighbour discovery,
//!      router advertisements). DHCP's packet socket and ARP are below IP
//!      routing and do not see this.
//!   2. Landlock: a TCP socket may be bound only to a port the policy names,
//!      or to port 0, as some clients do before connecting (busybox's nc).
//!      A socket that then listens on the port the kernel picked hears only
//!      what step 1 lets arrive: replies from ports the machine connects to.
//!      And the files, for every process, root included: read anywhere;
//!      run only what is beneath /usr, the image's; write only in /run,
//!      /tmp, /var/tmp, /dev/shm and /data, and to terminals and the likes
//!      of /dev/null, so never /proc, /sys or a disk itself; sockets and
//!      FIFOs only in /run; device ioctls only on terminals. A domain that
//!      handles files also refuses mount, umount and pivot_root to every
//!      process in it: the few mounts werewolf makes after boot are made by
//!      the mount broker, which init starts before it becomes fence, outside
//!      the domain (docs/design/pledge.md).
//!   3. CAP_NET_ADMIN, which could change the rules, and CAP_NET_RAW, whose
//!      packet sockets are below them, leave the bounding set, so no process
//!      after it, root included, holds either until the machine reboots;
//!      but for a form that allows them (etc/werewolf/allow/netadmin,
//!      packet), as dhcp does, whose client renews its lease with both.
//!   4. It execs PROGRAM, which every process on the machine descends from.
//!
//! Landlock's restriction is inherited and cannot be lifted, by root or
//! anyone, until the machine reboots. The routing rules can be changed by
//! whoever holds CAP_NET_ADMIN, which the seal takes away (docs/design/fence.md).
//! Nothing here reads anything but the image's own file, so fence runs as
//! one process, without a sandbox of its own: whatever it set up, it hands
//! to runit.
//!
//! It fails closed. Any step that fails exits 1, and init is PID 1: the
//! kernel panics, and the machine comes back on the slot that last worked.
//!
//! The policy, one entry a line, numbers only, `all` for every user:
//!
//!     listen tcp 22
//!     connect 0 tcp 443
//!     connect all udp 53
//!     connect 0 icmp
//!     metadata 68

const std = @import("std");
const linux = std.os.linux;
const Io = std.Io;

const policy_path = "/usr/share/werewolf/net";
const max_args = 16;
const max_entries = 64;

/// The metadata server's addresses: the one every cloud uses, and AWS's
/// IPv6 one.
const metadata_ip = [4]u8{ 169, 254, 169, 254 };
const metadata_ip6 = [16]u8{ 0xfd, 0x00, 0x0e, 0xc2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x54 };
const IPPROTO_ICMPV6 = 58;
const metadata_port: u16 = 80;

/// The rules' priorities, in the order the kernel tries them. The kernel's
/// own rule for its local table, at 0, moves to 400: arriving packets meet
/// the policy first. Its rules for the main and default tables, at 32766
/// and 32767, are never reached.
const pref = struct {
    const local_out: u32 = 10;
    const metadata_allow: u32 = 100;
    const metadata_refuse: u32 = 101;
    const out_allow: u32 = 200;
    const out_refuse: u32 = 299;
    const in_allow: u32 = 300;
    const in_drop: u32 = 399;
    const local: u32 = 400;
};

pub fn main(init: std.process.Init) !void {
    const argv = init.minimal.args.vector;
    var log: Log = .{};
    if (argv.len < 2 or argv.len - 1 > max_args) {
        log.event("error", .{ .@"error" = "usage: fence PROGRAM [ARG...]" });
        linux.exit_group(2);
    }
    const p = apply() catch |err| {
        log.event(
            "error",
            .{
                .step = step,
                .@"error" = @errorName(err),
                .detail = detail,
                .errno = errnoName(detail_errno),
            },
        );
        linux.exit_group(1);
    };
    step = "capabilities";
    var kept_buf: [net_caps.len][]const u8 = undefined;
    const kept = dropNetCaps(&kept_buf) catch |err| {
        log.event(
            "error",
            .{
                .step = step,
                .@"error" = @errorName(err),
                .detail = detail,
                .errno = errnoName(detail_errno),
            },
        );
        linux.exit_group(1);
    };
    var out: [max_entries][]const u8 = undefined;
    var text: [max_entries * 24]u8 = undefined;
    log.event(
        "fence",
        .{
            .listen = p.listen[0..p.nlisten],
            .connect = p.connectText(&out, &text),
            .metadata = p.metadata[0..p.nmetadata],
            .kept = kept,
        },
    );
    // The program runs under its own name, as a shell's exec would give it:
    // runit is "runit" in ps and in the kernel's log, not its path.
    var next: [max_args + 1]?[*:0]const u8 = @splat(null);
    next[0] = baseName(argv[1]);
    for (argv[2..], 1..) |a, i| next[i] = a;
    const rc = linux.execve(
        argv[1],
        @ptrCast(&next),
        @ptrCast(init.minimal.environ.block.slice.ptr),
    );
    _ = sys(rc, "execve") catch {};
    log.event("error", .{ .step = "exec", .detail = detail, .errno = errnoName(detail_errno) });
    linux.exit_group(1);
}

/// The last component of a path: what a shell would call the program.
fn baseName(path: [*:0]const u8) [*:0]const u8 {
    const s = std.mem.span(path);
    const slash = std.mem.findScalarLast(u8, s, '/') orelse return path;
    return s[slash + 1 ..].ptr;
}

var step: []const u8 = "start";
var detail: []const u8 = "";
var detail_errno: linux.E = .SUCCESS;

fn errnoName(e: linux.E) []const u8 {
    return std.enums.tagName(linux.E, e) orelse "unknown";
}

/// The capabilities the policy rests on, and the allowance that keeps each.
const net_caps = [_]struct { name: []const u8, n: u6, allow: [:0]const u8 }{
    .{ .name = "net_admin", .n = 12, .allow = "/etc/werewolf/allow/netadmin" },
    .{ .name = "net_raw", .n = 13, .allow = "/etc/werewolf/allow/packet" },
};

/// Drop each of net_caps from the bounding set but those the form allows;
/// the names of those kept.
fn dropNetCaps(kept: *[net_caps.len][]const u8) ![]const []const u8 {
    const PR_CAPBSET_DROP = 24;
    var n: usize = 0;
    for (net_caps) |c| {
        if (linux.errno(linux.access(c.allow, linux.F_OK)) == .SUCCESS) {
            kept[n] = c.name;
            n += 1;
        } else _ = try sys(linux.prctl(PR_CAPBSET_DROP, c.n, 0, 0, 0), "prctl");
    }
    return kept[0..n];
}

fn apply() !Policy {
    step = "policy";
    var buf: [4096]u8 = undefined;
    const p = try parsePolicy(try readFile(policy_path, &buf));
    step = "routes";
    try routeRules(p);
    step = "landlock";
    try restrict(p);
    return p;
}

// --- the policy --------------------------------------------------------------

/// The IP protocols fence names: those a policy may declare, ICMP, TCP and
/// UDP, and the other transports with ports, dropped when they arrive.
const Proto = enum(u8) { icmp = 1, tcp = 6, udp = 17, dccp = 33, sctp = 132, udplite = 136 };

const Connect = struct {
    /// null: every user.
    uid: ?u32,
    proto: Proto,
    /// 0 for ICMP, which has no ports.
    port: u16,
};

const Policy = struct {
    listen: [max_entries]u16 = undefined,
    nlisten: usize = 0,
    connect: [max_entries]Connect = undefined,
    nconnect: usize = 0,
    metadata: [max_entries]u32 = undefined,
    nmetadata: usize = 0,

    /// The connect entries as text, for the log: "0 tcp 443", "all udp 53".
    fn connectText(p: *const Policy, out: *[max_entries][]const u8, buf: []u8) []const []const u8 {
        var w: Io.Writer = .fixed(buf);
        for (p.connect[0..p.nconnect], 0..) |c, i| {
            const start = w.end;
            if (c.uid) |u|
                w.print("{d}", .{u}) catch return out[0..i]
            else
                w.writeAll("all") catch return out[0..i];
            w.print(" {s}", .{@tagName(c.proto)}) catch return out[0..i];
            if (c.proto != .icmp) w.print(" {d}", .{c.port}) catch return out[0..i];
            out[i] = buf[start..w.end];
        }
        return out[0..p.nconnect];
    }
};

/// The compiled policy: `listen tcp PORT`, `connect UID|all PROTO [PORT]`
/// and `metadata UID` lines, and nothing else. The build wrote it; anything
/// it does not expect is an error, not a guess.
fn parsePolicy(text: []const u8) !Policy {
    var p: Policy = .{};
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var words = std.mem.tokenizeScalar(u8, line, ' ');
        const key = words.next() orelse continue;
        if (std.mem.eql(u8, key, "listen")) {
            if (!std.mem.eql(u8, words.next() orelse "", "tcp")) return error.BadPolicy;
            if (p.nlisten == max_entries) return error.BadPolicy;
            p.listen[p.nlisten] = try port(words.next());
            p.nlisten += 1;
        } else if (std.mem.eql(u8, key, "connect")) {
            const who = words.next() orelse return error.BadPolicy;
            const uid: ?u32 = if (std.mem.eql(u8, who, "all")) null else try user(who);
            const proto = std.meta.stringToEnum(
                Proto,
                words.next() orelse "",
            ) orelse return error.BadPolicy;
            if (proto != .icmp and proto != .tcp and proto != .udp) return error.BadPolicy;
            if (p.nconnect == max_entries) return error.BadPolicy;
            p.connect[p.nconnect] = .{
                .uid = uid,
                .proto = proto,
                .port = if (proto == .icmp) 0 else try port(words.next()),
            };
            p.nconnect += 1;
        } else if (std.mem.eql(u8, key, "metadata")) {
            if (p.nmetadata == max_entries) return error.BadPolicy;
            p.metadata[p.nmetadata] = try user(words.next() orelse "");
            p.nmetadata += 1;
        } else return error.BadPolicy;
        if (words.next() != null) return error.BadPolicy;
    }
    return p;
}

fn port(word: ?[]const u8) !u16 {
    const n = std.fmt.parseInt(u16, word orelse "", 10) catch return error.BadPolicy;
    return if (n == 0) error.BadPolicy else n;
}

fn user(word: []const u8) !u32 {
    const n = std.fmt.parseInt(u32, word, 10) catch return error.BadPolicy;
    return if (n == std.math.maxInt(u32)) error.BadPolicy else n;
}

// --- the rules ---------------------------------------------------------------

const FR_ACT_TO_TBL = 1;
const FR_ACT_BLACKHOLE = 6;
const FR_ACT_UNREACHABLE = 7;
const FR_ACT_PROHIBIT = 8;
const RT_TABLE_MAIN = 254;
const RT_TABLE_LOCAL = 255;

/// One policy-routing rule, as `ip rule` would show it.
const Rule = struct {
    family: u8 = linux.AF.INET,
    priority: u32,
    action: u8,
    /// For FR_ACT_TO_TBL.
    table: u8 = 0,
    /// Locally sent traffic only: its lookups come from lo.
    from_here: bool = false,
    /// An address of the rule's family: 4 bytes, or 16.
    src: ?[]const u8 = null,
    dst: ?[]const u8 = null,
    proto: ?Proto = null,
    sport: ?u16 = null,
    dport: ?u16 = null,
    uid: ?u32 = null,
};

/// Eight per entry at most: metadata, connect and listen each make a
/// sending rule and its twin, and connect and listen an arriving rule; and
/// the fixed ones.
const max_rules = 16 + 8 * max_entries;

/// The policy as rules, in the order the kernel will try them:
///
///   10    sent here, to this machine or over loopback: local table
///   100   sent to the metadata server's TCP 80 by a user named: main
///   101   sent to it by anyone else: refused
///   200   sent as declared (user, protocol, port), or from a served port: main
///   299   anything else sent: refused (EACCES)
///   300   arriving to a served port, from a connected port, or ICMP: local
///   399   anything else arriving by TCP, UDP, UDP-Lite, SCTP or DCCP: dropped
///   400   the kernel's own local rule, moved here from 0
///
/// The drops name their protocols because a rule that dropped everything
/// would drop ARP too: answering a request, the kernel asks the rules
/// whether the address is local with a lookup that has no protocol, and a
/// machine that does not answer is soon reachable by no one.
///
/// The same for IPv4 and IPv6, with the family's metadata address, and for
/// IPv6, ICMPv6 sent by anyone: neighbour discovery and router
/// solicitations are how IPv6 finds its way at all.
///
/// Each rule that lets traffic out is followed by a twin with the same
/// match, unreachable. Allowed traffic with no route (IPv6 on a network
/// without it, say) then fails as it would without fence, "network
/// unreachable", and a client goes on to the next address, rather than
/// falling through to the refusal, whose EACCES many clients take as final.
fn plan(p: Policy, family: u8, out: *[max_rules]Rule) []const Rule {
    var n: usize = 0;
    const md: []const u8 = if (family == linux.AF.INET6) &metadata_ip6 else &metadata_ip;
    const add = struct {
        fn f(o: *[max_rules]Rule, i: *usize, fam: u8, r: Rule) void {
            var x = r;
            x.family = fam;
            o[i.*] = x;
            i.* += 1;
            if (x.from_here and x.action == FR_ACT_TO_TBL and x.table == RT_TABLE_MAIN) {
                x.action = FR_ACT_UNREACHABLE;
                x.table = 0;
                o[i.*] = x;
                i.* += 1;
            }
        }
    }.f;
    add(
        out,
        &n,
        family,
        .{
            .priority = pref.local_out,
            .action = FR_ACT_TO_TBL,
            .table = RT_TABLE_LOCAL,
            .from_here = true,
        },
    );
    for (p.metadata[0..p.nmetadata]) |uid| add(
        out,
        &n,
        family,
        .{
            .priority = pref.metadata_allow,
            .action = FR_ACT_TO_TBL,
            .table = RT_TABLE_MAIN,
            .from_here = true,
            .dst = md,
            .proto = .tcp,
            .dport = metadata_port,
            .uid = uid,
        },
    );
    add(
        out,
        &n,
        family,
        .{
            .priority = pref.metadata_refuse,
            .action = FR_ACT_PROHIBIT,
            .from_here = true,
            .dst = md,
            .proto = .tcp,
            .dport = metadata_port,
        },
    );
    for (p.connect[0..p.nconnect]) |c| add(
        out,
        &n,
        family,
        .{
            .priority = pref.out_allow,
            .action = FR_ACT_TO_TBL,
            .table = RT_TABLE_MAIN,
            .from_here = true,
            .proto = c.proto,
            .dport = if (c.proto == .icmp) null else c.port,
            .uid = c.uid,
        },
    );
    for (p.listen[0..p.nlisten]) |l| add(
        out,
        &n,
        family,
        .{
            .priority = pref.out_allow,
            .action = FR_ACT_TO_TBL,
            .table = RT_TABLE_MAIN,
            .from_here = true,
            .proto = .tcp,
            .sport = l,
        },
    );
    if (family == linux.AF.INET6) add(
        out,
        &n,
        family,
        .{
            .priority = pref.out_allow,
            .action = FR_ACT_TO_TBL,
            .table = RT_TABLE_MAIN,
            .from_here = true,
            .proto = .icmp,
        },
    );
    add(
        out,
        &n,
        family,
        .{ .priority = pref.out_refuse, .action = FR_ACT_PROHIBIT, .from_here = true },
    );

    for (p.listen[0..p.nlisten]) |l| add(
        out,
        &n,
        family,
        .{
            .priority = pref.in_allow,
            .action = FR_ACT_TO_TBL,
            .table = RT_TABLE_LOCAL,
            .proto = .tcp,
            .dport = l,
        },
    );
    // Replies: from each protocol and port some user connects to, once.
    for (p.connect[0..p.nconnect], 0..) |c, i| {
        if (c.proto == .icmp) continue;
        const seen = for (p.connect[0..i]) |d| {
            if (d.proto == c.proto and d.port == c.port) break true;
        } else false;
        if (!seen) add(
            out,
            &n,
            family,
            .{
                .priority = pref.in_allow,
                .action = FR_ACT_TO_TBL,
                .table = RT_TABLE_LOCAL,
                .proto = c.proto,
                .sport = c.port,
            },
        );
    }
    if (p.nmetadata > 0) add(
        out,
        &n,
        family,
        .{
            .priority = pref.in_allow,
            .action = FR_ACT_TO_TBL,
            .table = RT_TABLE_LOCAL,
            .src = md,
            .proto = .tcp,
            .sport = metadata_port,
        },
    );
    // ICMP in: errors a connection needs (path MTU, unreachable). An echo
    // request gets no reply unless root declared `connect root icmp`.
    add(
        out,
        &n,
        family,
        .{
            .priority = pref.in_allow,
            .action = FR_ACT_TO_TBL,
            .table = RT_TABLE_LOCAL,
            .proto = .icmp,
        },
    );
    for ([_]Proto{
        .tcp,
        .udp,
        .udplite,
        .sctp,
        .dccp,
    }) |pr| add(
        out,
        &n,
        family,
        .{ .priority = pref.in_drop, .action = FR_ACT_BLACKHOLE, .proto = pr },
    );
    add(
        out,
        &n,
        family,
        .{ .priority = pref.local, .action = FR_ACT_TO_TBL, .table = RT_TABLE_LOCAL },
    );
    return out[0..n];
}

/// Add every rule, then delete the kernel's local rule at 0, which would
/// otherwise deliver anything arriving before the policy is consulted.
fn routeRules(p: Policy) !void {
    const nl: i32 = @intCast(try sys(
        linux.socket(linux.AF.NETLINK, linux.SOCK.RAW | linux.SOCK.CLOEXEC, linux.NETLINK.ROUTE),
        "netlink socket",
    ));
    defer _ = linux.close(nl);
    var seq: u32 = 1;
    for ([_]u8{ linux.AF.INET, linux.AF.INET6 }) |family| {
        var rules: [max_rules]Rule = undefined;
        for (plan(p, family, &rules)) |r| {
            var msg: [256]u8 = undefined;
            try send(nl, ruleMessage(&msg, seq, RTM_NEWRULE, r), seq, "add rule");
            seq += 1;
        }
        var msg: [256]u8 = undefined;
        try send(
            nl,
            ruleMessage(
                &msg,
                seq,
                RTM_DELRULE,
                .{
                    .family = family,
                    .priority = 0,
                    .action = FR_ACT_TO_TBL,
                    .table = RT_TABLE_LOCAL,
                },
            ),
            seq,
            "delete the local rule",
        );
        seq += 1;
    }
}

const NLMSG_ERROR = 2;
const RTM_NEWRULE = 32;
const RTM_DELRULE = 33;
const NLM_F_REQUEST = 0x1;
const NLM_F_ACK = 0x4;
const NLM_F_EXCL = 0x200;
const NLM_F_CREATE = 0x400;
const FRA_DST = 1;
const FRA_SRC = 2;
const FRA_IIFNAME = 3;
const FRA_PRIORITY = 6;
const FRA_TABLE = 15;
const FRA_UID_RANGE = 20;
const FRA_IP_PROTO = 22;
const FRA_SPORT_RANGE = 23;
const FRA_DPORT_RANGE = 24;

/// An RTM_NEWRULE or RTM_DELRULE: nlmsghdr, fib_rule_hdr, attributes.
fn ruleMessage(buf: *[256]u8, seq: u32, kind: u16, r: Rule) []const u8 {
    @memset(buf, 0);
    var b: Builder = .{ .buf = buf, .len = 16 };
    // struct fib_rule_hdr: family, dst_len, src_len, tos, table, res1,
    // res2, action, flags.
    const dst_len: u8 = if (r.dst) |a| @intCast(a.len * 8) else 0;
    const src_len: u8 = if (r.src) |a| @intCast(a.len * 8) else 0;
    b.bytes(&.{ r.family, dst_len, src_len, 0, r.table, 0, 0, r.action, 0, 0, 0, 0 });
    b.attr(FRA_PRIORITY, std.mem.asBytes(&r.priority));
    if (r.table != 0) {
        const table: u32 = r.table;
        b.attr(FRA_TABLE, std.mem.asBytes(&table));
    }
    if (r.from_here) b.attr(FRA_IIFNAME, "lo\x00");
    if (r.src) |a| b.attr(FRA_SRC, a);
    if (r.dst) |a| b.attr(FRA_DST, a);
    if (r.proto) |pr| b.attr(
        FRA_IP_PROTO,
        &.{if (pr == .icmp and r.family == linux.AF.INET6) IPPROTO_ICMPV6 else @backingInt(pr)},
    );
    if (r.sport) |s| b.attr(FRA_SPORT_RANGE, std.mem.sliceAsBytes(&[2]u16{ s, s }));
    if (r.dport) |d| b.attr(FRA_DPORT_RANGE, std.mem.sliceAsBytes(&[2]u16{ d, d }));
    if (r.uid) |u| b.attr(FRA_UID_RANGE, std.mem.sliceAsBytes(&[2]u32{ u, u }));
    // struct nlmsghdr: length, type, flags, sequence, port.
    std.mem.writeInt(u32, buf[0..4], @intCast(b.len), .little);
    std.mem.writeInt(u16, buf[4..6], kind, .little);
    const flags: u16 = if (kind == RTM_NEWRULE)
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE
    else
        NLM_F_REQUEST | NLM_F_ACK;
    std.mem.writeInt(u16, buf[6..8], flags, .little);
    std.mem.writeInt(u32, buf[8..12], seq, .little);
    return buf[0..b.len];
}

/// Netlink attributes, four-byte aligned. The buffer is sized for the
/// largest message this program builds.
const Builder = struct {
    buf: *[256]u8,
    len: usize,

    fn bytes(b: *Builder, v: []const u8) void {
        @memcpy(b.buf[b.len..][0..v.len], v);
        b.len += v.len;
    }

    fn attr(b: *Builder, kind: u16, v: []const u8) void {
        std.mem.writeInt(u16, b.buf[b.len..][0..2], @intCast(4 + v.len), .little);
        std.mem.writeInt(u16, b.buf[b.len + 2 ..][0..2], kind, .little);
        @memcpy(b.buf[b.len + 4 ..][0..v.len], v);
        b.len += std.mem.alignForward(usize, 4 + v.len, 4);
    }
};

/// Send a request and read its acknowledgement: success, or the kernel's
/// errno as the error.
fn send(nl: i32, msg: []const u8, seq: u32, comptime what: []const u8) !void {
    const kernel: linux.sockaddr.nl = .{ .pid = 0, .groups = 0 };
    _ = try sys(
        linux.sendto(nl, msg.ptr, msg.len, 0, @ptrCast(&kernel), @sizeOf(linux.sockaddr.nl)),
        "netlink send",
    );
    var reply: [512]u8 align(4) = undefined;
    const n = try sys(linux.recvfrom(nl, &reply, reply.len, 0, null, null), "netlink receive");
    const e = ackError(reply[0..n], seq) orelse return error.BadAck;
    if (e == 0) return;
    _ = try sys(@bitCast(@as(isize, e)), what);
}

/// The error in an NLMSG_ERROR acknowledging `seq`: 0 for success, a
/// negative errno for failure, null if the reply is not that.
fn ackError(reply: []const u8, seq: u32) ?i32 {
    if (reply.len < 20) return null;
    if (std.mem.readInt(u16, reply[4..6], .little) != NLMSG_ERROR) return null;
    if (std.mem.readInt(u32, reply[8..12], .little) != seq) return null;
    return std.mem.readInt(i32, reply[16..20], .little);
}

// --- the ports: Landlock -----------------------------------------------------

const LANDLOCK_ACCESS_NET_BIND_TCP = 1;
const LANDLOCK_RULE_NET_PORT = 2;

/// Restrict this process, and so everything it execs, to binding TCP only
/// to the policy's ports and to port 0. Only BIND_TCP is handled: files,
/// connections and everything else are left to the rules above and each
/// service's jail.
fn restrict(p: Policy) !void {
    const abi = linux.syscall3(
        .landlock_create_ruleset,
        0,
        0,
        1,
    ); // LANDLOCK_CREATE_RULESET_VERSION
    _ = try sys(abi, "landlock version");
    if (abi < 4) {
        detail = "Landlock without network rules (ABI 4)";
        return error.LandlockTooOld;
    }
    // Every filesystem right this kernel knows: TRUNCATE from ABI 3,
    // IOCTL_DEV from 5.
    const fs_all: u64 = if (abi >= 5) 0xffff else 0x7fff;
    const attr = [2]u64{
        fs_all,
        LANDLOCK_ACCESS_NET_BIND_TCP,
    }; // handled_access_fs, handled_access_net
    const ruleset: i32 = @intCast(try sys(
        linux.syscall3(.landlock_create_ruleset, @intFromPtr(&attr), @sizeOf(@TypeOf(attr)), 0),
        "landlock ruleset",
    ));
    defer _ = linux.close(ruleset);
    var ports: [max_entries + 1]u16 = undefined;
    ports[0] = 0;
    @memcpy(ports[1 .. p.nlisten + 1], p.listen[0..p.nlisten]);
    for (ports[0 .. p.nlisten + 1]) |l| {
        const rule = [2]u64{ LANDLOCK_ACCESS_NET_BIND_TCP, l }; // struct landlock_net_port_attr
        _ = try sys(
            linux.syscall4(
                .landlock_add_rule,
                @intCast(ruleset),
                LANDLOCK_RULE_NET_PORT,
                @intFromPtr(&rule),
                0,
            ),
            "landlock rule",
        );
    }
    for (files) |f| try allowPath(ruleset, linux.AT.FDCWD, f.path, f.access & fs_all);
    // Every terminal: the console the kernel was given (ttyS0, ttyAMA0,
    // hvc0, whichever the machine has), the virtual consoles, and the rest.
    const dev: i32 = @intCast(try sys(
        linux.openat(linux.AT.FDCWD, "/dev", .{ .DIRECTORY = true, .CLOEXEC = true }, 0),
        "open /dev",
    ));
    defer _ = linux.close(dev);
    var buf: [8192]u8 align(8) = undefined;
    while (true) {
        const n = try sys(linux.getdents64(dev, &buf, buf.len), "read /dev");
        if (n == 0) break;
        var off: usize = 0;
        while (off < n) {
            const ent: *align(1) const linux.dirent64 = @ptrCast(&buf[off]);
            off += ent.reclen;
            const name: [*:0]const u8 = @ptrCast(&ent.name);
            const s_name = std.mem.sliceTo(name, 0);
            if (ent.type != linux.DT.CHR) continue;
            if (!std.mem.startsWith(u8, s_name, "tty") and
                !std.mem.startsWith(u8, s_name, "hvc")) continue;
            try allowPath(ruleset, dev, name, fs_terminal & fs_all);
        }
    }
    // As root, with CAP_SYS_ADMIN, no_new_privs is not needed, and is not
    // set: it would follow into every process on the machine.
    _ = try sys(linux.syscall2(.landlock_restrict_self, @intCast(ruleset), 0), "landlock restrict");
}

/// access to path, beneath dir, in ruleset; nothing if there is no such
/// place, as a form may lack /data or /dev/ptmx.
fn allowPath(ruleset: i32, dir: i32, path: [*:0]const u8, access: u64) !void {
    const fd = linux.openat(dir, path, .{ .PATH = true, .CLOEXEC = true }, 0);
    if (linux.errno(fd) == .NOENT) return;
    const rule = PathBeneath{
        .allowed_access = access,
        .parent_fd = @intCast(try sys(fd, "open a place for Landlock")),
    };
    defer _ = linux.close(rule.parent_fd);
    _ = try sys(
        linux.syscall4(
            .landlock_add_rule,
            @intCast(ruleset),
            LANDLOCK_RULE_PATH_BENEATH,
            @intFromPtr(&rule),
            0,
        ),
        "landlock path rule",
    );
}

/// struct landlock_path_beneath_attr, packed as the kernel declares it.
const PathBeneath = extern struct {
    allowed_access: u64 align(4),
    parent_fd: i32,

    comptime {
        std.debug.assert(@sizeOf(PathBeneath) == 12);
    }
};

const LANDLOCK_RULE_PATH_BENEATH = 1;

// Landlock's filesystem rights (linux/landlock.h).
const fs_execute: u64 = 0x1;
const fs_write_file: u64 = 0x2;
const fs_read_file: u64 = 0x4;
const fs_read_dir: u64 = 0x8;
const fs_remove_dir: u64 = 0x10;
const fs_remove_file: u64 = 0x20;
const fs_make_char: u64 = 0x40;
const fs_make_dir: u64 = 0x80;
const fs_make_reg: u64 = 0x100;
const fs_make_sock: u64 = 0x200;
const fs_make_fifo: u64 = 0x400;
const fs_make_block: u64 = 0x800;
const fs_make_sym: u64 = 0x1000;
const fs_refer: u64 = 0x2000;
const fs_truncate: u64 = 0x4000;
const fs_ioctl_dev: u64 = 0x8000;

/// What a writable place allows: everything a directory's owner does with
/// files and directories, and links between them.
const fs_writable: u64 = fs_read_file | fs_write_file | fs_read_dir | fs_remove_dir |
    fs_remove_file |
    fs_make_dir | fs_make_reg | fs_make_sym | fs_refer | fs_truncate;
const fs_device: u64 = fs_read_file | fs_write_file;
const fs_terminal: u64 = fs_device | fs_ioctl_dev;

/// The machine's files, as every process sees them. Rights are added up
/// along the path, so / reading everything and /run writing everything
/// beneath it make /run read-write.
const files = [_]struct { path: [*:0]const u8, access: u64 }{
    .{ .path = "/", .access = fs_read_file | fs_read_dir },
    .{ .path = "/usr", .access = fs_execute },
    // runit's FIFOs and the services' sockets.
    .{ .path = "/run", .access = fs_writable | fs_make_sock | fs_make_fifo },
    .{ .path = "/tmp", .access = fs_writable },
    .{ .path = "/var/tmp", .access = fs_writable },
    .{ .path = "/dev/shm", .access = fs_writable },
    // nodev, so a device node made here, as apk may unpack one for a slot
    // being built, opens nothing.
    .{ .path = "/data", .access = fs_writable | fs_make_char | fs_make_block },
    .{ .path = "/dev/null", .access = fs_device },
    .{ .path = "/dev/zero", .access = fs_device },
    .{ .path = "/dev/full", .access = fs_device },
    .{ .path = "/dev/random", .access = fs_device },
    .{ .path = "/dev/urandom", .access = fs_device },
    .{ .path = "/dev/kmsg", .access = fs_device },
    .{ .path = "/dev/console", .access = fs_terminal },
    .{ .path = "/dev/ptmx", .access = fs_terminal },
    .{ .path = "/dev/pts", .access = fs_terminal },
};

// --- files, errors, logging ----------------------------------------------------

fn readFile(path: [*:0]const u8, buf: []u8) ![]const u8 {
    const fd: i32 = @intCast(try sys(
        linux.openat(linux.AT.FDCWD, path, .{ .CLOEXEC = true, .NOFOLLOW = true }, 0),
        "open " ++ policy_path,
    ));
    defer _ = linux.close(fd);
    var got: usize = 0;
    while (true) {
        if (got == buf.len) return error.PolicyTooLarge;
        const n = try sys(linux.read(fd, buf[got..].ptr, buf.len - got), "read " ++ policy_path);
        if (n == 0) return buf[0..got];
        got += n;
    }
}

fn sys(rc: usize, comptime what: []const u8) !usize {
    const err = linux.errno(rc);
    if (err == .SUCCESS) return rc;
    detail = what;
    detail_errno = err;
    return error.SystemCall;
}

/// JSON lines on stdout: `fence: {"time":...,"event":...,...}`.
const Log = struct {
    buf: [4 << 10]u8 = undefined,

    fn event(l: *Log, name: []const u8, fields: anytype) void {
        var w: Io.Writer = .fixed(&l.buf);
        var ts: linux.timespec = undefined;
        _ = linux.clock_gettime(.REALTIME, &ts);
        var time: [20]u8 = undefined;
        w.print(
            "fence: {{\"time\":\"{s}\",\"event\":\"{s}\",",
            .{ rfc3339(&time, @intCast(ts.sec)), name },
        ) catch return;
        const mark = w.end;
        std.json.Stringify.value(fields, .{}, &w) catch return;
        @memmove(l.buf[mark .. w.end - 1], l.buf[mark + 1 .. w.end]);
        w.end -= 1;
        w.writeByte('\n') catch return;
        _ = linux.write(1, w.buffered().ptr, w.buffered().len);
    }
};

fn rfc3339(buf: *[20]u8, secs: u64) []const u8 {
    const es: std.time.epoch.EpochSeconds = .{ .secs = secs };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    return std.mem.print(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        yd.year,              md.month.numeric(),      md.day_index + 1,
        ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
    }) catch unreachable;
}

// --- tests -------------------------------------------------------------------

const example = "connect 0 tcp 443\nconnect 0 udp 53\nconnect all udp 53\nconnect 0 " ++
    "icmp\nlisten tcp 22\nmetadata 68\n";

test "a program runs under its own name" {
    try std.testing.expectEqualStrings("runit", std.mem.span(baseName("/usr/bin/runit")));
    try std.testing.expectEqualStrings("runit", std.mem.span(baseName("runit")));
}

test "policies" {
    const p = try parsePolicy(example);
    try std.testing.expectEqualSlices(u16, &.{22}, p.listen[0..p.nlisten]);
    try std.testing.expectEqualSlices(u32, &.{68}, p.metadata[0..p.nmetadata]);
    try std.testing.expectEqual(4, p.nconnect);
    try std.testing.expectEqual(null, p.connect[2].uid);
    try std.testing.expectEqual(.icmp, p.connect[3].proto);
    var out: [max_entries][]const u8 = undefined;
    var text: [max_entries * 24]u8 = undefined;
    const t = p.connectText(&out, &text);
    try std.testing.expectEqualStrings("0 tcp 443", t[0]);
    try std.testing.expectEqualStrings("all udp 53", t[2]);
    try std.testing.expectEqualStrings("0 icmp", t[3]);
    const none = try parsePolicy("");
    try std.testing.expectEqual(0, none.nlisten + none.nconnect + none.nmetadata);
    for ([_][]const u8{
        "listen udp 53\n",
        "listen tcp 0\n",
        "listen tcp 70000\n",
        "listen tcp 22 23\n",
        "metadata _cloud\n",
        "allow everything\n",
        "listen tcp\n",
        "connect 0 sctp 1\n",
        "connect 0 tcp\n",
        "connect 0 icmp 8\n",
        "connect nobody tcp 1\n",
    }) |bad| {
        try std.testing.expectError(error.BadPolicy, parsePolicy(bad));
    }
}

test "the plan, in the order the kernel tries it" {
    var rules: [max_rules]Rule = undefined;
    const r = plan(try parsePolicy(example), linux.AF.INET, &rules);
    var last: u32 = 0;
    for (r) |x| {
        try std.testing.expect(x.priority >= last); // ascending
        last = x.priority;
    }
    // First, local traffic; last before the moved local rule, the drops.
    try std.testing.expectEqual(pref.local_out, r[0].priority);
    try std.testing.expect(r[0].from_here);
    try std.testing.expectEqual(FR_ACT_BLACKHOLE, r[r.len - 2].action);
    try std.testing.expectEqual(pref.local, r[r.len - 1].priority);

    // TCP and UDP arriving are dropped. A lookup from outside with no
    // protocol or port, ARP's, is first matched by the local rule, so the
    // machine still answers for its address.
    var drops: usize = 0;
    for (r) |x| {
        if (x.action == FR_ACT_BLACKHOLE and (x.proto == .tcp or x.proto == .udp)) drops += 1;
    }
    try std.testing.expectEqual(2, drops);
    const first = for (r) |x| {
        if (!x.from_here and x.proto == null and x.sport == null and x.dport == null and
            x.src == null and x.dst == null and x.uid == null) break x;
    } else unreachable;
    try std.testing.expectEqual(pref.local, first.priority);
    try std.testing.expectEqual(RT_TABLE_LOCAL, first.table);

    // Every rule for traffic sent here is from lo; none for arriving traffic is.
    var refused_out = false;
    var dns_replies: usize = 0;
    for (r) |x| {
        if (x.priority < pref.in_allow)
            try std.testing.expect(x.from_here)
        else
            try std.testing.expect(!x.from_here);
        if (x.priority == pref.out_refuse and x.action == FR_ACT_PROHIBIT and x.uid == null and
            x.proto == null) refused_out = true;
        if (x.priority == pref.in_allow and x.proto == .udp and x.sport == 53) dns_replies += 1;
    }
    try std.testing.expect(refused_out);
    try std.testing.expectEqual(1, dns_replies); // two users connect to udp 53: one reply rule

    // Every rule that routes traffic out is followed by its unreachable twin.
    for (r, 0..) |x, i| {
        if (!(x.from_here and x.action == FR_ACT_TO_TBL and x.table == RT_TABLE_MAIN)) continue;
        const t = r[i + 1];
        try std.testing.expectEqual(FR_ACT_UNREACHABLE, t.action);
        try std.testing.expectEqual(x.priority, t.priority);
        try std.testing.expectEqual(x.uid, t.uid);
        try std.testing.expectEqual(x.dport, t.dport);
        try std.testing.expectEqual(x.proto, t.proto);
    }
}

test "an empty policy refuses everything but local traffic" {
    var rules: [max_rules]Rule = undefined;
    const r = plan(.{}, linux.AF.INET, &rules);
    for (r) |x| {
        if (x.action != FR_ACT_TO_TBL) continue;
        // What passes: local traffic, ICMP in, and the moved local rule.
        try std.testing.expect(x.table == RT_TABLE_LOCAL);
        try std.testing.expect(x.from_here or x.proto == .icmp or x.priority == pref.local);
    }
}

test "IPv6: the same rules, its metadata address, and ICMPv6 sent by anyone" {
    var rules: [max_rules]Rule = undefined;
    const r = plan(try parsePolicy(example), linux.AF.INET6, &rules);
    var icmp_out = false;
    var md_refused = false;
    for (r) |x| {
        try std.testing.expectEqual(linux.AF.INET6, x.family);
        if (x.priority == pref.out_allow and x.proto == .icmp and x.uid == null) icmp_out = true;
        if (x.priority == pref.metadata_refuse) md_refused = std.mem.eql(
            u8,
            x.dst.?,
            &metadata_ip6,
        );
    }
    try std.testing.expect(icmp_out and md_refused);
    var buf: [256]u8 = undefined;
    const m = ruleMessage(
        &buf,
        3,
        RTM_NEWRULE,
        .{
            .family = linux.AF.INET6,
            .priority = pref.metadata_refuse,
            .action = FR_ACT_PROHIBIT,
            .from_here = true,
            .dst = &metadata_ip6,
            .proto = .tcp,
            .dport = 80,
        },
    );
    try std.testing.expectEqualSlices(u8, &.{ linux.AF.INET6, 128 }, m[16..18]);
    try std.testing.expect(hasAttr(m, FRA_DST, &metadata_ip6));
    const icmp = ruleMessage(
        &buf,
        4,
        RTM_NEWRULE,
        .{
            .family = linux.AF.INET6,
            .priority = pref.in_allow,
            .action = FR_ACT_TO_TBL,
            .table = RT_TABLE_LOCAL,
            .proto = .icmp,
        },
    );
    try std.testing.expect(hasAttr(icmp, FRA_IP_PROTO, &.{IPPROTO_ICMPV6}));
}

test "a full policy fits its rules" {
    var p: Policy = .{};
    for (0..max_entries) |i| {
        p.listen[i] = @intCast(1000 + i);
        p.connect[i] = .{ .uid = @intCast(i), .proto = .udp, .port = @intCast(2000 + i) };
        p.metadata[i] = @intCast(i);
    }
    p.nlisten = max_entries;
    p.nconnect = max_entries;
    p.nmetadata = max_entries;
    var rules: [max_rules]Rule = undefined;
    _ = plan(p, linux.AF.INET6, &rules);
}

test "rule messages" {
    var buf: [256]u8 = undefined;
    const m = ruleMessage(
        &buf,
        7,
        RTM_NEWRULE,
        .{
            .priority = pref.metadata_allow,
            .action = FR_ACT_TO_TBL,
            .table = RT_TABLE_MAIN,
            .from_here = true,
            .dst = &metadata_ip,
            .proto = .tcp,
            .dport = 80,
            .uid = 68,
        },
    );
    try std.testing.expectEqual(m.len, std.mem.readInt(u32, m[0..4], .little));
    try std.testing.expectEqual(RTM_NEWRULE, std.mem.readInt(u16, m[4..6], .little));
    try std.testing.expectEqual(7, std.mem.readInt(u32, m[8..12], .little));
    // fib_rule_hdr: IPv4, a /32 destination, the main table, FR_ACT_TO_TBL.
    try std.testing.expectEqualSlices(
        u8,
        &.{ linux.AF.INET, 32, 0, 0, RT_TABLE_MAIN, 0, 0, FR_ACT_TO_TBL },
        m[16..24],
    );
    try std.testing.expect(hasAttr(m, FRA_IIFNAME, "lo\x00"));
    try std.testing.expect(hasAttr(m, FRA_DST, &metadata_ip));
    try std.testing.expect(hasAttr(m, FRA_IP_PROTO, &.{6}));
    try std.testing.expect(hasAttr(m, FRA_DPORT_RANGE, std.mem.sliceAsBytes(&[2]u16{ 80, 80 })));
    try std.testing.expect(hasAttr(m, FRA_UID_RANGE, std.mem.sliceAsBytes(&[2]u32{ 68, 68 })));

    const drop = ruleMessage(
        &buf,
        8,
        RTM_NEWRULE,
        .{ .priority = pref.in_drop, .action = FR_ACT_BLACKHOLE, .proto = .sctp },
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ linux.AF.INET, 0, 0, 0, 0, 0, 0, FR_ACT_BLACKHOLE },
        drop[16..24],
    );
    try std.testing.expect(!hasAttr(drop, FRA_IIFNAME, "lo\x00"));
    try std.testing.expect(hasAttr(drop, FRA_IP_PROTO, &.{132}));

    const del = ruleMessage(
        &buf,
        9,
        RTM_DELRULE,
        .{ .priority = 0, .action = FR_ACT_TO_TBL, .table = RT_TABLE_LOCAL },
    );
    try std.testing.expectEqual(RTM_DELRULE, std.mem.readInt(u16, del[4..6], .little));
    try std.testing.expect(hasAttr(del, FRA_PRIORITY, std.mem.asBytes(&@as(u32, 0))));
}

/// Whether netlink message `m` carries attribute `kind` with value `v`.
fn hasAttr(m: []const u8, kind: u16, v: []const u8) bool {
    var off: usize = 16 + 12;
    while (off + 4 <= m.len) {
        const len = std.mem.readInt(u16, m[off..][0..2], .little);
        if (len < 4 or off + len > m.len) return false;
        if (std.mem.readInt(u16, m[off + 2 ..][0..2], .little) == kind and
            std.mem.eql(u8, m[off + 4 .. off + len], v)) return true;
        off += std.mem.alignForward(usize, len, 4);
    }
    return false;
}

test "acknowledgements" {
    var ok: [36]u8 = @splat(0);
    std.mem.writeInt(u16, ok[4..6], NLMSG_ERROR, .little);
    std.mem.writeInt(u32, ok[8..12], 3, .little);
    try std.testing.expectEqual(0, ackError(&ok, 3).?);
    try std.testing.expectEqual(null, ackError(&ok, 4));
    std.mem.writeInt(i32, ok[16..20], -17, .little); // EEXIST
    try std.testing.expectEqual(-17, ackError(&ok, 3).?);
    try std.testing.expectEqual(null, ackError(ok[0..19], 3));
}
