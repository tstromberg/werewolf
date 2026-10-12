//! pcap-feed copies one interface's packets to a pcap fifo, then gives up
//! the ability to do anything else. Suricata and Zeek read the fifo. They
//! never hold CAP_NET_RAW or CAP_NET_ADMIN: pcap-feed opens the socket,
//! sets promiscuous mode, writes a pcap header, drops to _pcap, and from
//! then on may only read that socket, learn that the fifo was opened or
//! closed, and write it. A reader consumes its header. The next open gets
//! a new one, or it would block in the header forever.
//!
//!     pcap-feed
//!
//! /etc/werewolf/pcap-feed names the fifo and the user who may read it:
//!
//!     feed /run/svc/suricata/feed
//!     user suricata
//!
//! runit starts it as root (forms/suricata/rootfs/etc/sv/pcap-feed/run). See
//! forms/suricata/README.md.

const std = @import("std");
const sandbox = @import("sandbox");
const Io = std.Io;
const linux = std.os.linux;
const Allocator = std.mem.Allocator;

const config_path = "/etc/werewolf/pcap-feed";
const drop_user = "_pcap";
const snaplen: u32 = 65535;
const sol_packet: i32 = 263;
const packet_add_membership: i32 = 1;
const packet_mr_promisc: u16 = 1;
const eth_p_all: u16 = 0x0003;

const Config = struct { feed: []const u8, user: []const u8 };

const SockaddrLl = extern struct {
    family: u16,
    protocol: u16,
    ifindex: i32,
    hatype: u16 = 0,
    pkttype: u8 = 0,
    halen: u8 = 0,
    addr: [8]u8 = @splat(0),
};

const PacketMreq = extern struct {
    ifindex: i32,
    typ: u16,
    alen: u16 = 0,
    address: [8]u8 = @splat(0),
};

comptime {
    std.debug.assert(@sizeOf(SockaddrLl) == 20);
    std.debug.assert(@sizeOf(PacketMreq) == 16);
}

var frame: [65536]u8 = undefined;

pub fn main(init: std.process.Init) void {
    const io = init.io;
    run(io, init.arena.allocator()) catch |err| {
        say(io, "{{\"event\":\"down\",\"why\":\"{s}\"}}", .{@errorName(err)});
        std.process.exit(1);
    };
}

fn run(io: Io, gpa: Allocator) !void {
    // runsv execs the ./run link, so the kernel names this process run.
    // An administrator should see the program.
    if (linux.errno(linux.prctl(@backingInt(linux.PR.SET_NAME), @intFromPtr("pcap-feed"), 0, 0, 0)) != .SUCCESS)
        return error.SetName;
    const cfg = try parse(try readFile(io, gpa, config_path, 512));
    const reader = try account(io, gpa, cfg.user);
    const self = try account(io, gpa, drop_user);
    const iface = try chooseInterface(io, gpa);
    const packet = try openPacket(iface);
    const feed = try openFeed(cfg.feed);
    // The watch is in place before the reader is allowed to open the fifo,
    // so the first open is seen and a later one still gets a header.
    const notes = try watchFeed(io, cfg.feed);
    try giveFeed(feed, reader);
    say(io, "{{\"event\":\"start\",\"iface\":\"{s}\",\"feed\":\"{s}\",\"user\":\"{s}\"}}", .{
        iface.name, cfg.feed, cfg.user,
    });
    try sandbox.dropTo(self.uid, null);
    var filter: sandbox.Filter = .{};
    filter.allow("read");
    filter.allow("write");
    // aarch64 has no poll, so the libc call is ppoll. Allow both.
    filter.allow("poll");
    filter.allow("ppoll");
    filter.allow("clock_gettime");
    filter.allow("exit_group");
    try filter.install();
    copy(packet, notes, feed);
}

const Iface = struct { name: []const u8, index: i32 };

/// chooseInterface picks the interface that is up, or else the first that
/// is not loopback. A machine with none has nothing to watch.
fn chooseInterface(io: Io, gpa: Allocator) !Iface {
    var dir = try Io.Dir.cwd().openDir(io, "/sys/class/net", .{ .iterate = true });
    defer dir.close(io);
    var fallback: ?Iface = null;
    var it = dir.iterate();
    while (try it.next(io)) |e| {
        if (std.mem.eql(u8, e.name, "lo")) continue;
        const index = try ifindex(io, gpa, e.name);
        const up = blk: {
            const path = try std.fmt.allocPrint(gpa, "/sys/class/net/{s}/operstate", .{e.name});
            const text = readFile(io, gpa, path, 32) catch break :blk false;
            break :blk std.mem.eql(u8, std.mem.trim(u8, text, " \t\r\n"), "up");
        };
        const found: Iface = .{ .name = try gpa.dupe(u8, e.name), .index = index };
        if (up) return found;
        if (fallback == null) fallback = found;
    }
    return fallback orelse error.NoInterface;
}

fn ifindex(io: Io, gpa: Allocator, name: []const u8) !i32 {
    const path = try std.fmt.allocPrint(gpa, "/sys/class/net/{s}/ifindex", .{name});
    const text = try readFile(io, gpa, path, 32);
    return std.fmt.parseInt(i32, std.mem.trim(u8, text, " \t\r\n"), 10) catch error.BadIfindex;
}

/// openPacket opens a raw packet socket on iface, bound to every ethertype,
/// and asks for a copy of traffic not addressed to this machine. Promiscuous
/// mode wants CAP_NET_ADMIN; without it the socket still sees what the host
/// itself sends and receives.
fn openPacket(iface: Iface) !i32 {
    const rc = linux.socket(linux.AF.PACKET, linux.SOCK.RAW | linux.SOCK.CLOEXEC, htons(eth_p_all));
    if (linux.errno(rc) != .SUCCESS) return error.PacketSocket;
    const fd: i32 = @intCast(rc);
    var addr: SockaddrLl = .{
        .family = linux.AF.PACKET,
        .protocol = htons(eth_p_all),
        .ifindex = iface.index,
    };
    if (linux.errno(linux.bind(fd, @ptrCast(&addr), @sizeOf(SockaddrLl))) != .SUCCESS)
        return error.PacketBind;
    var mreq: PacketMreq = .{ .ifindex = iface.index, .typ = packet_mr_promisc };
    _ = linux.setsockopt(fd, sol_packet, packet_add_membership, @ptrCast(&mreq), @sizeOf(PacketMreq));
    return fd;
}

/// openFeed creates the fifo and opens it for read and write, so this
/// process does not wait for the reader. The header is written while the
/// fifo is still root's, mode 0600, so the reader cannot see a partial
/// header. giveFeed hands the reader the only permission to open it.
fn openFeed(path: []const u8) !i32 {
    if (std.fs.path.dirname(path)) |dir| {
        var dz: [129]u8 = undefined;
        const made = linux.mkdir(try z(dir, &dz), 0o755);
        if (linux.errno(made) != .SUCCESS and linux.errno(made) != .EXIST) return error.FeedDirectory;
    }
    var pzbuf: [129]u8 = undefined;
    const pz = try z(path, &pzbuf);
    const made = linux.mknod(pz, linux.S.IFIFO | 0o600, 0);
    if (linux.errno(made) != .SUCCESS and linux.errno(made) != .EXIST) return error.FeedCreate;
    const rc = linux.open(pz, .{ .ACCMODE = .RDWR, .NONBLOCK = true, .CLOEXEC = true }, 0);
    if (linux.errno(rc) != .SUCCESS) return error.FeedOpen;
    const fd: i32 = @intCast(rc);
    try writeAll(fd, &pcapHeader());
    return fd;
}

fn giveFeed(fd: i32, reader: Account) !void {
    if (linux.errno(linux.fchown(fd, reader.uid, reader.gid)) != .SUCCESS) return error.FeedOwner;
    if (linux.errno(linux.fchmod(fd, 0o400)) != .SUCCESS) return error.FeedMode;
}

/// watchFeed reports each open and close of the fifo. The watch is taken
/// before the reader can be the first to open it after the mode change.
fn watchFeed(io: Io, path: []const u8) !i32 {
    const fd = linux.inotify_init1(linux.IN.CLOEXEC | linux.IN.NONBLOCK);
    if (linux.errno(fd) != .SUCCESS) {
        say(io, "inotify_init1 errno {s}", .{@tagName(linux.errno(fd))});
        return error.Watch;
    }
    var pzbuf: [129]u8 = undefined;
    const wd = linux.inotify_add_watch(@intCast(fd), try z(path, &pzbuf), linux.IN.OPEN | linux.IN.CLOSE_NOWRITE);
    if (linux.errno(wd) != .SUCCESS) {
        say(io, "inotify_add_watch errno {s}", .{@tagName(linux.errno(wd))});
        return error.Watch;
    }
    return @intCast(fd);
}

/// Watch is how many readers hold the fifo, and whether the next bytes
/// they read must be a pcap header.
const Watch = struct {
    readers: u32 = 0,
    /// primed means a header is already in the pipe, or the current reader
    /// has taken it. The first header is written before the loop.
    primed: bool = true,
    header_due: bool = false,

    /// saw applies one inotify mask. It returns true when leftover bytes
    /// have to be discarded: the last reader closed, and those bytes would
    /// be the next reader's file header.
    fn saw(w: *Watch, mask: u32) bool {
        if (mask & linux.IN.Q_OVERFLOW != 0) {
            w.readers = 0;
            w.primed = false;
            w.header_due = true;
            return true;
        }
        var drain = false;
        if (mask & linux.IN.OPEN != 0) {
            w.readers += 1;
            if (w.readers == 1 and !w.primed) w.header_due = true;
        }
        if (mask & linux.IN.CLOSE_NOWRITE != 0 and w.readers > 0) {
            w.readers -= 1;
            if (w.readers == 0) {
                w.primed = false;
                w.header_due = false;
                drain = true;
            }
        }
        return drain;
    }
};

/// copy writes packets for whichever reader currently holds the fifo, and
/// a header when a new reader is the one that needs it. Packets that arrive
/// with nobody reading are dropped, so the socket does not stall the watch.
fn copy(packet: i32, notes: i32, feed: i32) void {
    var watch: Watch = .{};
    const header = pcapHeader();
    var header_off: usize = 0;
    var rec: [16 + 65535]u8 = undefined;
    var rec_len: usize = 0;
    var rec_off: usize = 0;
    var scratch: [8192]u8 = undefined;
    while (true) {
        const writing = watch.header_due or rec_off < rec_len;
        var fds = [3]linux.pollfd{
            .{ .fd = notes, .events = linux.POLL.IN, .revents = 0 },
            .{ .fd = packet, .events = linux.POLL.IN, .revents = 0 },
            .{ .fd = feed, .events = linux.POLL.OUT, .revents = 0 },
        };
        const nfd: u32 = if (writing) 3 else 2;
        const ready = linux.poll(&fds, nfd, -1);
        if (linux.errno(ready) == .INTR) continue;
        if (linux.errno(ready) != .SUCCESS) linux.exit_group(1);
        if (fds[0].revents & linux.POLL.IN != 0) {
            if (takeNotes(notes, &watch, feed, &scratch)) {
                header_off = 0;
                rec_len = 0;
                rec_off = 0;
            }
        }
        if (watch.header_due) {
            const w = writeSome(feed, header[header_off..]) catch |err| switch (err) {
                error.Again => continue,
                else => linux.exit_group(1),
            };
            header_off += w;
            if (header_off >= header.len) {
                watch.header_due = false;
                watch.primed = true;
                header_off = 0;
            }
            continue;
        }
        if (fds[1].revents & linux.POLL.IN != 0) {
            const n = linux.read(packet, &frame, frame.len);
            if (linux.errno(n) == .INTR or linux.errno(n) == .AGAIN) continue;
            if (linux.errno(n) != .SUCCESS) linux.exit_group(1);
            if (n == 0 or watch.readers == 0 or rec_off < rec_len) continue;
            rec_len = record(&rec, frame[0..n]);
            rec_off = 0;
        }
        if (rec_off < rec_len) {
            const w = writeSome(feed, rec[rec_off..rec_len]) catch |err| switch (err) {
                error.Again => continue,
                else => linux.exit_group(1),
            };
            rec_off += w;
        }
    }
}

fn takeNotes(notes: i32, watch: *Watch, feed: i32, scratch: []u8) bool {
    var buf: [4096]u8 = undefined;
    const n = linux.read(notes, &buf, buf.len);
    if (linux.errno(n) == .AGAIN or linux.errno(n) == .INTR) return false;
    if (linux.errno(n) != .SUCCESS) linux.exit_group(1);
    var drained = false;
    var off: usize = 0;
    while (off + 16 <= n) {
        const mask = std.mem.readInt(u32, buf[off + 4 ..][0..4], .little);
        const len = std.mem.readInt(u32, buf[off + 12 ..][0..4], .little);
        if (len > n - off - 16) break;
        if (watch.saw(mask)) {
            discard(feed, scratch);
            drained = true;
        }
        off += 16 + len;
    }
    return drained;
}

fn discard(feed: i32, scratch: []u8) void {
    while (true) {
        const n = linux.read(feed, scratch.ptr, scratch.len);
        if (linux.errno(n) == .INTR) continue;
        if (linux.errno(n) != .SUCCESS or n == 0) return;
    }
}

fn record(buf: *[16 + 65535]u8, pkt: []const u8) usize {
    var ts: linux.timespec = undefined;
    if (linux.errno(linux.clock_gettime(.REALTIME, &ts)) != .SUCCESS) linux.exit_group(1);
    const got: u32 = @intCast(pkt.len);
    const incl = if (got > snaplen) snaplen else got;
    std.mem.writeInt(u32, buf[0..4], @intCast(ts.sec), .little);
    std.mem.writeInt(u32, buf[4..8], @intCast(@divTrunc(ts.nsec, 1000)), .little);
    std.mem.writeInt(u32, buf[8..12], incl, .little);
    std.mem.writeInt(u32, buf[12..16], got, .little);
    @memcpy(buf[16..][0..incl], pkt[0..incl]);
    return 16 + incl;
}

fn pcapHeader() [24]u8 {
    var buf: [24]u8 = @splat(0);
    std.mem.writeInt(u32, buf[0..4], 0xa1b2c3d4, .little);
    std.mem.writeInt(u16, buf[4..6], 2, .little);
    std.mem.writeInt(u16, buf[6..8], 4, .little);
    std.mem.writeInt(u32, buf[16..20], snaplen, .little);
    std.mem.writeInt(u32, buf[20..24], 1, .little);
    return buf;
}

fn writeAll(fd: i32, buf: []const u8) !void {
    var off: usize = 0;
    while (off < buf.len) {
        const n = writeSome(fd, buf[off..]) catch |err| switch (err) {
            // The pipe has room: the header is written before any reader,
            // and a full pipe is not a reason to fail that first write.
            error.Again => continue,
            else => |e| return e,
        };
        off += n;
    }
}

fn writeSome(fd: i32, buf: []const u8) !usize {
    const rc = linux.write(fd, buf.ptr, buf.len);
    if (linux.errno(rc) == .AGAIN) return error.Again;
    if (linux.errno(rc) == .INTR) return 0;
    if (linux.errno(rc) != .SUCCESS or rc == 0) return error.Write;
    return @intCast(rc);
}

const Account = struct { uid: u32, gid: u32 };

fn account(io: Io, gpa: Allocator, name: []const u8) !Account {
    const text = try readFile(io, gpa, "/etc/passwd", 1 << 20);
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var f = std.mem.splitScalar(u8, line, ':');
        const who = f.next() orelse continue;
        if (!std.mem.eql(u8, who, name)) continue;
        _ = f.next();
        const uid = f.next() orelse return error.NoSuchUser;
        const gid = f.next() orelse return error.NoSuchUser;
        return .{
            .uid = std.fmt.parseInt(u32, uid, 10) catch return error.NoSuchUser,
            .gid = std.fmt.parseInt(u32, gid, 10) catch return error.NoSuchUser,
        };
    }
    return error.NoSuchUser;
}

/// parse reads pcap-feed's two lines. Anything else, including a third word or a
/// feed that is not absolute, is refused: the file is in the image, and a
/// surprise there is a bug, not a setting.
fn parse(text: []const u8) !Config {
    var feed: ?[]const u8 = null;
    var user: ?[]const u8 = null;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        var w = std.mem.tokenizeScalar(u8, line, ' ');
        const key = w.next() orelse return error.BadConfig;
        const value = w.next() orelse return error.BadConfig;
        if (w.next() != null) return error.BadConfig;
        if (std.mem.eql(u8, key, "feed")) {
            if (feed != null or !std.mem.startsWith(u8, value, "/") or value.len > 128)
                return error.BadConfig;
            feed = value;
        } else if (std.mem.eql(u8, key, "user")) {
            if (user != null or !plainName(value)) return error.BadConfig;
            user = value;
        } else return error.BadConfig;
    }
    return .{ .feed = feed orelse return error.BadConfig, .user = user orelse return error.BadConfig };
}

fn plainName(s: []const u8) bool {
    if (s.len == 0 or s.len > 32) return false;
    for (s) |c| if (!((c >= 'a' and c <= 'z') or (c >= '0' and c <= '9') or c == '_' or c == '-'))
        return false;
    return true;
}

fn readFile(io: Io, gpa: Allocator, path: []const u8, limit: usize) ![]const u8 {
    return Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(limit));
}

fn z(s: []const u8, buf: []u8) ![*:0]u8 {
    if (s.len + 1 > buf.len) return error.BadConfig;
    @memcpy(buf[0..s.len], s);
    buf[s.len] = 0;
    return buf[0..s.len :0];
}

fn htons(v: u16) u16 {
    return std.mem.nativeToBig(u16, v);
}

fn say(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const line = std.mem.print(&buf, "pcap-feed: " ++ fmt ++ "\n", args) catch return;
    Io.File.stdout().writeStreamingAll(io, line) catch {};
}

const testing = std.testing;

test "parse takes the feed and the reader" {
    const cfg = try parse("feed /run/svc/suricata/feed\nuser suricata\n");
    try testing.expectEqualStrings("/run/svc/suricata/feed", cfg.feed);
    try testing.expectEqualStrings("suricata", cfg.user);
    try testing.expectEqualStrings("/tmp/feed", (try parse("# c\nfeed /tmp/feed\nuser _oci-zeek\n")).feed);
}

test "a new reader after a close needs a header" {
    var w: Watch = .{};
    try testing.expect(!w.saw(linux.IN.OPEN));
    try testing.expect(!w.header_due);
    try testing.expect(w.saw(linux.IN.CLOSE_NOWRITE));
    try testing.expect(!w.primed);
    try testing.expect(!w.saw(linux.IN.OPEN));
    try testing.expect(w.header_due);
    try testing.expectEqual(@as(u32, 1), w.readers);
}

test "two opens share one header" {
    var w: Watch = .{ .primed = false };
    try testing.expect(!w.saw(linux.IN.OPEN));
    try testing.expect(w.header_due);
    w.header_due = false;
    w.primed = true;
    try testing.expect(!w.saw(linux.IN.OPEN));
    try testing.expect(!w.header_due);
    try testing.expect(!w.saw(linux.IN.CLOSE_NOWRITE));
    try testing.expectEqual(@as(u32, 1), w.readers);
}

test "parse refuses a surprise" {
    for ([_][]const u8{
        "",
        "feed /tmp/x\n",
        "user suricata\n",
        "feed relative\nuser suricata\n",
        "feed /tmp/x extra\nuser suricata\n",
        "mode live\nfeed /tmp/x\nuser suricata\n",
        "feed /tmp/x\nuser ../suricata\n",
    }) |bad| try testing.expectError(error.BadConfig, parse(bad));
}
