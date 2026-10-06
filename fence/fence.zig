//! fence: the machine's network policy, from the image, then runit.
//!
//!     fence PROGRAM [ARG...]
//!
//! init's last step, as `exec fence runit`. As root it reads
//! /usr/share/werewolf/net, which the build compiled from the forms' .net
//! files, and:
//!
//!   1. adds policy-routing rules, for IPv4 and IPv6, so that TCP to the
//!      metadata server's port 80 (169.254.169.254, fd00:ec2::254) is
//!      refused with EACCES to every user but those the policy names;
//!   2. restricts itself with Landlock so that a TCP socket may be bound
//!      only to a port the policy names. Not port 0 either: bind(0), then
//!      listen(), would serve on whatever port the kernel picked. A client
//!      that connects without binding, as clients do, is untouched;
//!   3. execs PROGRAM, which every process on the machine descends from.
//!
//! Landlock's restriction is inherited and cannot be lifted, by root or
//! anyone, until the machine reboots. The routing rules can be deleted by
//! whoever holds CAP_NET_ADMIN, which the seal takes away (design/fence.md).
//! Nothing here reads anything but the image's own file, so fence runs as
//! one process, without a sandbox of its own: whatever it set up, it hands
//! to runit.
//!
//! It fails closed. Any step that fails exits 1, and init is PID 1: the
//! kernel panics, and the machine comes back on the slot that last worked.
//!
//! The policy, one entry a line, numbers only:
//!
//!     listen tcp 22
//!     metadata 68

const std = @import("std");
const linux = std.os.linux;
const Io = std.Io;

const policy_path = "/usr/share/werewolf/net";
const max_entries = 64;

/// The metadata servers' addresses: the one every cloud uses, and AWS's
/// IPv6 one.
const metadata_v4 = [4]u8{ 169, 254, 169, 254 };
const metadata_v6 = [16]u8{ 0xfd, 0x00, 0x0e, 0xc2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x54 };
const metadata_port: u16 = 80;
/// Below the kernel's own rules for the main and default tables (32766,
/// 32767), above its local one (0).
const allow_priority: u32 = 100;
const refuse_priority: u32 = 101;

pub fn main(init: std.process.Init) !void {
    const argv = init.minimal.args.vector;
    var log: Log = .{};
    if (argv.len < 2) {
        log.event("error", .{ .@"error" = "usage: fence PROGRAM [ARG...]" });
        linux.exit_group(2);
    }
    const p = apply() catch |err| {
        log.event("error", .{ .step = step, .@"error" = @errorName(err), .detail = detail, .errno = errnoName(detail_errno) });
        linux.exit_group(1);
    };
    log.event("fence", .{ .listen = p.listen[0..p.nlisten], .metadata = p.metadata[0..p.nmetadata] });
    const rc = linux.execve(argv[1], @ptrCast(argv[1..].ptr), @ptrCast(init.minimal.environ.block.slice.ptr));
    _ = sys(rc, "execve") catch {};
    log.event("error", .{ .step = "exec", .detail = detail, .errno = errnoName(detail_errno) });
    linux.exit_group(1);
}

var step: []const u8 = "start";
var detail: []const u8 = "";
var detail_errno: linux.E = .SUCCESS;

fn errnoName(e: linux.E) []const u8 {
    return std.enums.tagName(linux.E, e) orelse "unknown";
}

fn apply() !Policy {
    step = "policy";
    var buf: [4096]u8 = undefined;
    const p = try parsePolicy(try readFile(policy_path, &buf));
    step = "routes";
    try metadataRules(p);
    step = "landlock";
    try restrictBind(p);
    return p;
}

// --- the policy --------------------------------------------------------------

const Policy = struct {
    listen: [max_entries]u16 = undefined,
    nlisten: usize = 0,
    metadata: [max_entries]u32 = undefined,
    nmetadata: usize = 0,
};

/// The compiled policy: `listen tcp PORT` and `metadata UID` lines, and
/// nothing else. The build wrote it; anything it does not expect is an
/// error, not a guess.
fn parsePolicy(text: []const u8) !Policy {
    var p: Policy = .{};
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var words = std.mem.tokenizeScalar(u8, line, ' ');
        const key = words.next() orelse continue;
        if (std.mem.eql(u8, key, "listen")) {
            if (!std.mem.eql(u8, words.next() orelse "", "tcp")) return error.BadPolicy;
            const port = std.fmt.parseInt(u16, words.next() orelse "", 10) catch return error.BadPolicy;
            if (port == 0 or p.nlisten == max_entries) return error.BadPolicy;
            p.listen[p.nlisten] = port;
            p.nlisten += 1;
        } else if (std.mem.eql(u8, key, "metadata")) {
            const uid = std.fmt.parseInt(u32, words.next() orelse "", 10) catch return error.BadPolicy;
            if (uid == std.math.maxInt(u32) or p.nmetadata == max_entries) return error.BadPolicy;
            p.metadata[p.nmetadata] = uid;
            p.nmetadata += 1;
        } else return error.BadPolicy;
        if (words.next() != null) return error.BadPolicy;
    }
    return p;
}

// --- the metadata server: policy routing -------------------------------------

/// For each family: a rule that sends each allowed user's TCP to the
/// metadata server's port 80 on to the main table as usual, and after
/// them one that refuses everyone else's (FR_ACT_PROHIBIT: EACCES).
/// Nothing else to that address is touched, so DNS to it, which GCP hands
/// out, still works.
fn metadataRules(p: Policy) !void {
    const nl: i32 = @intCast(try sys(linux.socket(linux.AF.NETLINK, linux.SOCK.RAW | linux.SOCK.CLOEXEC, linux.NETLINK.ROUTE), "netlink socket"));
    defer _ = linux.close(nl);
    var seq: u32 = 1;
    for ([_]Family{ .{ .af = linux.AF.INET, .dst = &metadata_v4 }, .{ .af = linux.AF.INET6, .dst = &metadata_v6 } }) |f| {
        for (p.metadata[0..p.nmetadata]) |uid| {
            var msg: [256]u8 = undefined;
            try send(nl, ruleMessage(&msg, seq, f, .{ .uid = uid }), seq);
            seq += 1;
        }
        var msg: [256]u8 = undefined;
        try send(nl, ruleMessage(&msg, seq, f, .refuse), seq);
        seq += 1;
    }
}

const Family = struct { af: u8, dst: []const u8 };
const RuleKind = union(enum) { uid: u32, refuse };

const NLMSG_ERROR = 2;
const RTM_NEWRULE = 32;
const NLM_F_REQUEST = 0x1;
const NLM_F_ACK = 0x4;
const NLM_F_EXCL = 0x200;
const NLM_F_CREATE = 0x400;
const FR_ACT_TO_TBL = 1;
const FR_ACT_PROHIBIT = 8;
const RT_TABLE_MAIN = 254;
const FRA_DST = 1;
const FRA_PRIORITY = 6;
const FRA_TABLE = 15;
const FRA_UID_RANGE = 20;
const FRA_IP_PROTO = 22;
const FRA_DPORT_RANGE = 24;

/// An RTM_NEWRULE: nlmsghdr, fib_rule_hdr, then the attributes.
fn ruleMessage(buf: *[256]u8, seq: u32, f: Family, kind: RuleKind) []const u8 {
    @memset(buf, 0);
    var b: Builder = .{ .buf = buf, .len = 16 };
    // struct fib_rule_hdr: family, dst_len, src_len, tos, table, res1,
    // res2, action, flags.
    b.bytes(&.{
        f.af,                                   @intCast(f.dst.len * 8), 0, 0,
        if (kind == .uid) RT_TABLE_MAIN else 0, 0,                       0, if (kind == .uid) FR_ACT_TO_TBL else FR_ACT_PROHIBIT,
        0,                                      0,                       0, 0,
    });
    b.attr(FRA_DST, f.dst);
    b.attr(FRA_PRIORITY, std.mem.asBytes(&(if (kind == .uid) allow_priority else refuse_priority)));
    b.attr(FRA_IP_PROTO, &.{6}); // TCP
    const ports = [2]u16{ metadata_port, metadata_port };
    b.attr(FRA_DPORT_RANGE, std.mem.sliceAsBytes(&ports));
    switch (kind) {
        .uid => |uid| {
            const range = [2]u32{ uid, uid };
            b.attr(FRA_UID_RANGE, std.mem.sliceAsBytes(&range));
            const table: u32 = RT_TABLE_MAIN;
            b.attr(FRA_TABLE, std.mem.asBytes(&table));
        },
        .refuse => {},
    }
    // struct nlmsghdr: length, type, flags, sequence, port.
    std.mem.writeInt(u32, buf[0..4], @intCast(b.len), .little);
    std.mem.writeInt(u16, buf[4..6], RTM_NEWRULE, .little);
    std.mem.writeInt(u16, buf[6..8], NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE, .little);
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
fn send(nl: i32, msg: []const u8, seq: u32) !void {
    const kernel: linux.sockaddr.nl = .{ .pid = 0, .groups = 0 };
    _ = try sys(linux.sendto(nl, msg.ptr, msg.len, 0, @ptrCast(&kernel), @sizeOf(linux.sockaddr.nl)), "netlink send");
    var reply: [512]u8 align(4) = undefined;
    const n = try sys(linux.recvfrom(nl, &reply, reply.len, 0, null, null), "netlink receive");
    const e = ackError(reply[0..n], seq) orelse return error.BadAck;
    if (e == 0) return;
    _ = try sys(@bitCast(@as(isize, e)), "add rule");
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
/// to the policy's ports. Only BIND_TCP is handled: files, connections and
/// everything else are left to each service's own jail.
fn restrictBind(p: Policy) !void {
    const abi = linux.syscall3(.landlock_create_ruleset, 0, 0, 1); // LANDLOCK_CREATE_RULESET_VERSION
    _ = try sys(abi, "landlock version");
    if (abi < 4) {
        detail = "Landlock without network rules (ABI 4)";
        return error.LandlockTooOld;
    }
    const attr = [2]u64{ 0, LANDLOCK_ACCESS_NET_BIND_TCP }; // handled_access_fs, handled_access_net
    const ruleset: i32 = @intCast(try sys(linux.syscall3(.landlock_create_ruleset, @intFromPtr(&attr), @sizeOf(@TypeOf(attr)), 0), "landlock ruleset"));
    defer _ = linux.close(ruleset);
    for (p.listen[0..p.nlisten]) |port| try allowPort(ruleset, port);
    // As root, with CAP_SYS_ADMIN, no_new_privs is not needed, and is not
    // set: it would follow into every process on the machine.
    _ = try sys(linux.syscall2(.landlock_restrict_self, @intCast(ruleset), 0), "landlock restrict");
}

fn allowPort(ruleset: i32, port: u16) !void {
    const rule = [2]u64{ LANDLOCK_ACCESS_NET_BIND_TCP, port }; // struct landlock_net_port_attr
    _ = try sys(linux.syscall4(.landlock_add_rule, @intCast(ruleset), LANDLOCK_RULE_NET_PORT, @intFromPtr(&rule), 0), "landlock rule");
}

// --- files, errors, logging ----------------------------------------------------

fn readFile(path: [*:0]const u8, buf: []u8) ![]const u8 {
    const fd: i32 = @intCast(try sys(linux.openat(linux.AT.FDCWD, path, .{ .CLOEXEC = true, .NOFOLLOW = true }, 0), "open " ++ policy_path));
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
        w.print("fence: {{\"time\":\"{s}\",\"event\":\"{s}\",", .{ rfc3339(&time, @intCast(ts.sec)), name }) catch return;
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
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        yd.year, md.month.numeric(), md.day_index + 1, ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
    }) catch unreachable;
}

// --- tests -------------------------------------------------------------------

test "policies" {
    const p = try parsePolicy("listen tcp 22\nlisten tcp 80\nmetadata 68\n");
    try std.testing.expectEqualSlices(u16, &.{ 22, 80 }, p.listen[0..p.nlisten]);
    try std.testing.expectEqualSlices(u32, &.{68}, p.metadata[0..p.nmetadata]);
    const none = try parsePolicy("");
    try std.testing.expectEqual(0, none.nlisten + none.nmetadata);
    for ([_][]const u8{ "listen udp 53\n", "listen tcp 0\n", "listen tcp 70000\n", "listen tcp 22 23\n", "metadata _cloud\n", "allow everything\n", "listen tcp\n" }) |bad| {
        try std.testing.expectError(error.BadPolicy, parsePolicy(bad));
    }
}

test "the rule that lets a user reach the metadata server" {
    var buf: [256]u8 = undefined;
    const m = ruleMessage(&buf, 7, .{ .af = linux.AF.INET, .dst = &metadata_v4 }, .{ .uid = 68 });
    try std.testing.expectEqual(m.len, std.mem.readInt(u32, m[0..4], .little));
    try std.testing.expectEqual(RTM_NEWRULE, std.mem.readInt(u16, m[4..6], .little));
    try std.testing.expectEqual(7, std.mem.readInt(u32, m[8..12], .little));
    // fib_rule_hdr: IPv4, a /32, the main table, FR_ACT_TO_TBL.
    try std.testing.expectEqualSlices(u8, &.{ linux.AF.INET, 32, 0, 0, RT_TABLE_MAIN, 0, 0, FR_ACT_TO_TBL }, m[16..24]);
    try std.testing.expect(hasAttr(m, FRA_DST, &metadata_v4));
    try std.testing.expect(hasAttr(m, FRA_IP_PROTO, &.{6}));
    try std.testing.expect(hasAttr(m, FRA_DPORT_RANGE, std.mem.sliceAsBytes(&[2]u16{ 80, 80 })));
    try std.testing.expect(hasAttr(m, FRA_UID_RANGE, std.mem.sliceAsBytes(&[2]u32{ 68, 68 })));
    try std.testing.expect(hasAttr(m, FRA_PRIORITY, std.mem.asBytes(&allow_priority)));
}

test "the rule that refuses everyone else" {
    var buf: [256]u8 = undefined;
    const m = ruleMessage(&buf, 8, .{ .af = linux.AF.INET6, .dst = &metadata_v6 }, .refuse);
    try std.testing.expectEqualSlices(u8, &.{ linux.AF.INET6, 128, 0, 0, 0, 0, 0, FR_ACT_PROHIBIT }, m[16..24]);
    try std.testing.expect(hasAttr(m, FRA_DST, &metadata_v6));
    try std.testing.expect(!hasAttr(m, FRA_UID_RANGE, std.mem.sliceAsBytes(&[2]u32{ 68, 68 })));
    try std.testing.expect(hasAttr(m, FRA_PRIORITY, std.mem.asBytes(&refuse_priority)));
}

/// Whether netlink message `m` carries attribute `kind` with value `v`.
fn hasAttr(m: []const u8, kind: u16, v: []const u8) bool {
    var off: usize = 16 + 12;
    while (off + 4 <= m.len) {
        const len = std.mem.readInt(u16, m[off..][0..2], .little);
        if (len < 4 or off + len > m.len) return false;
        if (std.mem.readInt(u16, m[off + 2 ..][0..2], .little) == kind and std.mem.eql(u8, m[off + 4 .. off + len], v)) return true;
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
