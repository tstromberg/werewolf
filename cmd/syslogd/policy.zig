//! Bounded local records and archive names. Times belong to the receiver,
//! never to a timestamp claimed inside a message.
const std = @import("std");
const mem = std.mem;

pub const day = 24 * 60 * 60;
pub const retention = 90 * day;
pub const segment_bytes = 4 << 20;
pub const scratch_bytes = 2 * segment_bytes;
pub const max_segments = 8192;
pub const max_input = 2048;
pub const max_kernel_input = 8192;
pub const max_record = max_kernel_input * 6 + 512;
pub const name_len = 33;

pub const Config = struct {
    console: bool = true,
    file: bool = true,
    budget: u64 = 1 << 30,

    pub fn parse(text: []const u8) !Config {
        var c: Config = .{};
        var seen: u3 = 0;
        var lines = mem.tokenizeScalar(u8, text, '\n');
        while (lines.next()) |line| {
            var words = mem.tokenizeAny(u8, line, " \t\r");
            const key = words.next() orelse continue;
            if (key[0] == '#') continue;
            const value = words.next() orelse return error.BadConfig;
            if (words.next() != null) return error.BadConfig;
            const bit: u3 = if (mem.eql(u8, key, "console")) 1 else if (mem.eql(u8, key, "file"))
                2
            else if (mem.eql(u8, key, "max-mib")) 4 else return error.BadConfig;
            if (seen & bit != 0) return error.BadConfig;
            seen |= bit;
            if (bit == 4) {
                const mib = std.fmt.parseInt(u32, value, 10) catch return error.BadConfig;
                if (mib < 16 or mib > 1 << 20) return error.BadConfig;
                c.budget = @as(u64, mib) << 20;
            } else {
                const on = if (mem.eql(u8, value, "yes")) true else if (mem.eql(u8, value, "no"))
                    false
                else
                    return error.BadConfig;
                if (bit == 1) c.console = on else c.file = on;
            }
        }
        if (!c.console and !c.file) return error.BadConfig;
        return c;
    }
};

pub fn oldEnough(now: i64, closed: i64, age: i64) bool {
    return closed >= 0 and now >= closed and now - closed >= age;
}

pub fn stamp(out: *[20]u8, seconds: i64) ![]const u8 {
    if (seconds < 0 or seconds > 253402300799) return error.BadTime;
    const epoch: std.time.epoch.EpochSeconds = .{ .secs = @intCast(seconds) };
    const days = epoch.getEpochDay();
    const yd = days.calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = epoch.getDaySeconds();
    return std.mem.print(out, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        yd.year,              @backingInt(md.month),   md.day_index + 1,
        ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
    });
}

fn number(text: []const u8) !u32 {
    for (text) |c| if (c < '0' or c > '9') return error.BadName;
    return std.fmt.parseInt(u32, text, 10) catch error.BadName;
}

fn parseStamp(s: []const u8) !i64 {
    if (s.len != 20 or s[4] != '-' or s[7] != '-' or s[10] != 'T' or
        s[13] != ':' or s[16] != ':' or s[19] != 'Z') return error.BadName;
    const year = try number(s[0..4]);
    const month = try number(s[5..7]);
    const date = try number(s[8..10]);
    const hour = try number(s[11..13]);
    const minute = try number(s[14..16]);
    const second = try number(s[17..19]);
    if (year < 1970 or month < 1 or month > 12 or hour > 23 or minute > 59 or second > 59)
        return error.BadName;
    const leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0);
    const month_days = [_]u8{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    const limit = month_days[month - 1] + @as(u32, if (month == 2 and leap) 1 else 0);
    if (date < 1 or date > limit) return error.BadName;
    const previous = year - 1;
    var days: i64 = @as(i64, year - 1970) * 365 + previous / 4 - previous / 100 +
        previous / 400 - (1969 / 4 - 1969 / 100 + 1969 / 400);
    for (month_days[0 .. month - 1]) |n| days += n;
    if (leap and month > 2) days += 1;
    days += date - 1;
    return days * day + hour * 3600 + minute * 60 + second;
}

pub const Archive = struct {
    closed: i64,
    sequence: u16,
    gzip: bool,

    pub fn parse(name: []const u8) !Archive {
        const gzip = mem.endsWith(u8, name, ".gz");
        const base = name[0 .. name.len - @as(usize, if (gzip) 3 else 0)];
        if (base.len != name_len or !mem.startsWith(u8, base, "messages.") or base[29] != '.')
            return error.BadName;
        const sequence = try number(base[30..33]);
        if (sequence == 0) return error.BadName;
        return .{
            .closed = try parseStamp(base[9..29]),
            .sequence = @intCast(sequence),
            .gzip = gzip,
        };
    }
};

pub fn archiveName(out: []u8, closed: i64, sequence: u16) ![]const u8 {
    if (sequence == 0 or sequence > 999) return error.BadName;
    var time: [20]u8 = undefined;
    return std.mem.print(out, "messages.{s}.{d:0>3}", .{ try stamp(&time, closed), sequence });
}

pub const Credentials = struct { pid: i32, uid: u32, gid: u32 };

pub fn record(out: []u8, seconds: i64, cred: Credentials, bytes: []const u8) ![]const u8 {
    if (bytes.len > max_input) return error.TooLong;
    var text = mem.trimEnd(u8, bytes, "\x00\r\n");
    var priority: u8 = 13;
    if (text.len > 2 and text[0] == '<') {
        const end = mem.findScalar(u8, text, '>') orelse 0;
        if (end >= 2 and end <= 4) {
            const parsed = number(text[1..end]) catch 256;
            if (parsed <= 191) {
                priority = @intCast(parsed);
                text = text[end + 1 ..];
            }
        }
    }
    // LOG_KERN belongs only to the kernel input, never a sender's PRI claim.
    if (priority < 8) priority += 8;
    var time: [20]u8 = undefined;
    var w: std.Io.Writer = .fixed(out);
    try w.print("syslogd: {{\"time\":\"{s}\",\"source\":\"syslog\",\"pid\":{d},\"uid\":{d},\"gid" ++
        "\":{d}," ++
        "\"priority\":{d},\"message\":\"", .{
        try stamp(&time, seconds), cred.pid, cred.uid, cred.gid, priority,
    });
    try escaped(&w, text);
    try w.writeAll("\"}\n");
    return w.buffered();
}

fn escaped(w: *std.Io.Writer, text: []const u8) !void {
    const hex = "0123456789abcdef";
    for (text) |c| switch (c) {
        '"', '\\' => try w.writeAll(&.{ '\\', c }),
        0x20...0x21, 0x23...0x5b, 0x5d...0x7e => try w.writeByte(c),
        else => try w.writeAll(&.{ '\\', 'u', '0', '0', hex[c >> 4], hex[c & 15] }),
    };
}

pub const Kernel = struct {
    priority: u16,
    sequence: u64,
    monotonic_us: u64,
    message: []const u8,

    pub fn parse(bytes: []const u8) !Kernel {
        if (bytes.len > max_kernel_input) return error.TooLong;
        const end = mem.findScalar(u8, bytes, ';') orelse return error.BadKernel;
        var fields = mem.splitScalar(u8, bytes[0..end], ',');
        const priority = try kernelNumber(fields.next() orelse return error.BadKernel);
        const sequence = try kernelNumber(fields.next() orelse return error.BadKernel);
        const monotonic_us = try kernelNumber(fields.next() orelse return error.BadKernel);
        if ((fields.next() orelse return error.BadKernel).len == 0 or priority > 2047)
            return error.BadKernel;
        // Later header fields are ABI extensions; message continuations stay text.
        return .{
            .priority = @intCast(priority),
            .sequence = sequence,
            .monotonic_us = monotonic_us,
            .message = mem.trimEnd(u8, bytes[end + 1 ..], "\n"),
        };
    }

    fn kernelNumber(text: []const u8) !u64 {
        if (text.len == 0) return error.BadKernel;
        for (text) |c| if (c < '0' or c > '9') return error.BadKernel;
        return std.fmt.parseInt(u64, text, 10) catch error.BadKernel;
    }
};

pub fn kernelRecord(out: []u8, seconds: i64, kernel: Kernel) ![]const u8 {
    var time: [20]u8 = undefined;
    var w: std.Io.Writer = .fixed(out);
    // Linux forbids userspace kmsg writes from using facility LOG_KERN.
    const source = if (kernel.priority < 8) "kernel" else "kmsg";
    try w.print("syslogd: {{\"time\":\"{s}\",\"source\":\"{s}\",\"sequence\":{d}," ++
        "\"monotonic_us\":{d},\"priority\":{d},\"message\":\"", .{
        try stamp(&time, seconds), source, kernel.sequence, kernel.monotonic_us, kernel.priority,
    });
    try escaped(&w, kernel.message);
    try w.writeAll("\"}\n");
    return w.buffered();
}

pub fn validRecord(line: []const u8) bool {
    if (line.len == 0 or line.len > max_record or line[line.len - 1] != '\n' or
        !mem.startsWith(u8, line, "syslogd: {")) return false;
    for (line[0 .. line.len - 1]) |c| if (c < 0x20 or c > 0x7e) return false;
    return true;
}

pub const per_pid = 1000;
pub const flood_interval = 60;
pub const sender_idle = 60;

pub const Flood = struct {
    scope: enum { pid, senders },
    uid: ?u32,
    pid: ?i32,
    suppressed: u64,
};

const Suppression = struct {
    count: u64 = 0,
    reported: ?i64 = null,

    fn due(s: *const Suppression, now: i64) bool {
        return s.count > 0 and (s.reported == null or now - s.reported.? >= flood_interval);
    }

    fn take(s: *Suppression, now: i64) u64 {
        const n = s.count;
        s.count = 0;
        s.reported = now;
        return n;
    }
};

/// Count messages per PID in each monotonic second, using kernel credentials.
/// UID is diagnostic metadata, never a quota. Pending drop counts survive idle
/// time until reported; a full table refuses new senders, never resets an
/// active sender's quota. A reused PID conservatively inherits its window.
pub const Limiter = struct {
    slots: [1024]Slot = @splat(.{}),
    overflow: Suppression = .{},
    notice_second: i64 = -1,
    notice_count: u8 = 0,
    cursor: usize = 0,

    const Slot = struct {
        pid: ?i32 = null,
        uid: u32 = 0,
        second: i64 = 0,
        count: u16 = 0,
        dropped: Suppression = .{},
    };

    pub fn admit(l: *Limiter, cred: Credentials, now: i64) bool {
        var spare: ?*Slot = null;
        const slot = for (&l.slots) |*s| {
            if (s.pid == cred.pid) break s;
            if (spare == null and (s.pid == null or
                (now - s.second >= sender_idle and s.dropped.count == 0))) spare = s;
        } else slot: {
            const s = spare orelse {
                l.overflow.count +|= 1;
                return false;
            };
            s.* = .{ .uid = cred.uid, .pid = cred.pid, .second = now };
            break :slot s;
        };
        slot.uid = cred.uid;
        if (now > slot.second) {
            slot.second = now;
            slot.count = 0;
        }
        if (slot.count >= per_pid) {
            slot.dropped.count +|= 1;
            return false;
        }
        slot.count += 1;
        return true;
    }

    /// Each PID gets an initial notice and at most one summary per minute,
    /// including pending drops after it stops. Limit all notices to four per
    /// second; round-robin scanning gives pending senders a turn.
    pub fn notice(l: *Limiter, now: i64) ?Flood {
        if (now > l.notice_second) {
            l.notice_second = now;
            l.notice_count = 0;
        }
        if (l.notice_count >= 4) return null;
        const total = 1024 + 1;
        for (0..total) |_| {
            const at = l.cursor;
            l.cursor = (l.cursor + 1) % total;
            const slot = if (at < l.slots.len) &l.slots[at] else null;
            const dropped = if (slot) |s| &s.dropped else &l.overflow;
            if (!dropped.due(now)) continue;
            l.notice_count += 1;
            return .{
                .scope = if (slot != null) .pid else .senders,
                .uid = if (slot) |s| s.uid else null,
                .pid = if (slot) |s| s.pid else null,
                .suppressed = dropped.take(now),
            };
        }
        return null;
    }
};

pub fn floodRecord(out: []u8, seconds: i64, flood: Flood) ![]const u8 {
    var time: [20]u8 = undefined;
    var w: std.Io.Writer = .fixed(out);
    try w.writeAll("syslogd: ");
    try std.json.Stringify.value(.{
        .time = try stamp(&time, seconds),
        .source = "syslogd",
        .event = "flood",
        .scope = @tagName(flood.scope),
        .uid = flood.uid,
        .pid = flood.pid,
        .suppressed = flood.suppressed,
    }, .{}, &w);
    try w.writeByte('\n');
    return w.buffered();
}

pub const Queue = struct {
    bytes: [64 << 10]u8 = undefined,
    start: usize = 0,
    end: usize = 0,

    pub fn append(q: *Queue, line: []const u8) bool {
        if (line.len > q.bytes.len - (q.end - q.start)) return false;
        if (line.len > q.bytes.len - q.end) {
            @memmove(q.bytes[0 .. q.end - q.start], q.bytes[q.start..q.end]);
            q.end -= q.start;
            q.start = 0;
        }
        @memcpy(q.bytes[q.end..][0..line.len], line);
        q.end += line.len;
        return true;
    }

    pub fn pending(q: *const Queue) []const u8 {
        return q.bytes[q.start..q.end];
    }

    pub fn consumed(q: *Queue, n: usize) void {
        q.start += n;
        if (q.start == q.end) {
            q.start = 0;
            q.end = 0;
        }
    }
};

test "UTC archive names round trip, including leap days and invalid dates" {
    const t = std.testing;
    for ([_]i64{ 0, 951782400, 1792175400, 253402300799 }) |seconds| {
        var buf: [name_len]u8 = undefined;
        const name = try archiveName(&buf, seconds, 999);
        const a = try Archive.parse(name);
        try t.expectEqual(seconds, a.closed);
        try t.expectEqual(999, a.sequence);
    }
    for ([_][]const u8{
        "messages.2025-02-29T00:00:00Z.001",    "messages.2024-04-31T00:00:00Z.001",
        "messages.2024-01-01T24:00:00Z.001",    "messages.2024-01-01T00:00:00Z.000",
        "../messages.2024-01-01T00:00:00Z.001", "messages.2024-01-01T00:00:00Z.001.tmp",
    }) |name| try t.expectError(error.BadName, Archive.parse(name));
    try t.expect((try Archive.parse("messages.2024-02-29T00:00:00Z.001.gz")).gzip);
}

test "compression and expiry require the full interval and tolerate backward time" {
    const t = std.testing;
    try t.expect(!oldEnough(100 + day - 1, 100, day));
    try t.expect(oldEnough(100 + day, 100, day));
    try t.expect(!oldEnough(100 + retention - 1, 100, retention));
    try t.expect(oldEnough(100 + retention, 100, retention));
    try t.expect(!oldEnough(99, 100, retention));
}

test "hostile messages become one ASCII JSON record with kernel credentials" {
    const t = std.testing;
    var buf: [max_record]u8 = undefined;
    const line = try record(
        &buf,
        0,
        .{ .pid = 3, .uid = 7, .gid = 8 },
        "<191>fake[1]: \"x\"\n\x1b[2J\xff\x00",
    );
    try t.expect(validRecord(line));
    try t.expect(mem.find(u8, line, "\"pid\":3,\"uid\":7,\"gid\":8") != null);
    try t.expect(mem.find(u8, line, "\"priority\":191") != null);
    try t.expect(mem.find(u8, line, "\\u000a\\u001b[2J\\u00ff") != null);
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        t.allocator,
        mem.trimEnd(u8, line[9..], "\n"),
        .{},
    );
    defer parsed.deinit();
    var hostile: [max_input]u8 = @splat(0xff);
    try t.expect(validRecord(try record(&buf, 0, .{ .pid = 1, .uid = 0, .gid = 0 }, &hostile)));
}

test "userspace cannot claim kernel origin or inject another record" {
    const t = std.testing;
    var buf: [max_record]u8 = undefined;
    const attack = "<0>kernel: panic\r\nsyslogd: {\"source\":\"kernel\",\"uid\":0}" ++
        "\x00\x1b[2J\x08\xe2\x80\xae";
    const line = try record(&buf, 0, .{ .pid = 123, .uid = 456, .gid = 789 }, attack);
    const parsed = try std.json.parseFromSlice(std.json.Value, t.allocator, line[9..], .{});
    defer parsed.deinit();
    const o = parsed.value.object;
    try t.expectEqualStrings("syslog", o.get("source").?.string);
    try t.expectEqual(@as(i64, 456), o.get("uid").?.integer);
    try t.expectEqual(@as(i64, 8), o.get("priority").?.integer);
    try t.expectEqual(@as(usize, 7), o.count());
    try t.expectEqual(@as(usize, 1), mem.count(u8, line, "\n"));
    for (line[0 .. line.len - 1]) |c| try t.expect(c >= 0x20 and c <= 0x7e);
    try t.expect(mem.find(u8, line, "\\r") == null);
    try t.expect(mem.find(u8, line, "\\u000d\\u000a") != null);
}

test "kernel headers preserve provenance and never interpret message claims" {
    const t = std.testing;
    var buf: [max_record]u8 = undefined;
    const k = try Kernel.parse("6,42,1234,-,future=value;hello\n DEVICE=test\n");
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        t.allocator,
        (try kernelRecord(&buf, 0, k))[9..],
        .{},
    );
    defer parsed.deinit();
    try t.expectEqualStrings("kernel", parsed.value.object.get("source").?.string);
    try t.expectEqual(@as(i64, 42), parsed.value.object.get("sequence").?.integer);
    try t.expectEqual(@as(i64, 1234), parsed.value.object.get("monotonic_us").?.integer);
    try t.expectEqualStrings("hello\n DEVICE=test", parsed.value.object.get("message").?.string);
    const injected = try Kernel.parse("14,43,1235,-;kernel: forged\n");
    const line = try kernelRecord(&buf, 0, injected);
    try t.expect(mem.find(u8, line, "\"source\":\"kmsg\"") != null);
    for ([_][]const u8{
        "",                                 "6;hello",
        "6,0,0;hello",                      "6,,0,-;hello",
        "-1,0,0,-;hello",                   "2048,0,0,-;hello",
        "6,18446744073709551616,0,-;hello", "6,0,0,;hello",
    }) |bytes| try t.expectError(error.BadKernel, Kernel.parse(bytes));
}

test "config rejects duplicates, unknown settings and unsafe budgets" {
    const t = std.testing;
    try t.expectEqual(@as(u64, 32 << 20), (try Config.parse("console no\nmax-mib 32\n")).budget);
    for ([_][]const u8{
        "console yes\nconsole no",
        "exec /bin/sh",
        "max-mib 1",
        "console no\nfile no",
        "file maybe",
        "max-mib 4294967296",
    }) |text|
        try t.expectError(error.BadConfig, Config.parse(text));
}

fn sender(uid: u32, pid: i32) Credentials {
    return .{ .uid = uid, .gid = uid, .pid = pid };
}

test "a PID admits 1000 messages per second without sharing a UID allowance" {
    const t = std.testing;
    var l: Limiter = .{};
    for (0..per_pid) |_| try t.expect(l.admit(sender(1, 10), 10));
    try t.expect(!l.admit(sender(1, 10), 10));
    // Several processes under the same UID each get the full allowance.
    for (11..17) |pid| {
        for (0..per_pid) |_| try t.expect(l.admit(sender(1, @intCast(pid)), 10));
        try t.expect(!l.admit(sender(1, @intCast(pid)), 10));
    }
    try t.expect(!l.admit(sender(2, 10), 10));
    try t.expect(l.admit(sender(2, 20), 10));
    try t.expect(!l.admit(sender(1, 10), 9));
    for (0..per_pid) |_| try t.expect(l.admit(sender(1, 10), 11));
    try t.expect(!l.admit(sender(1, 10), 11));
}

test "a full sender table retains active quotas and reports overflow" {
    const t = std.testing;
    var l: Limiter = .{};
    for (0..l.slots.len) |pid| try t.expect(l.admit(sender(1, @intCast(pid)), 0));
    try t.expect(!l.admit(sender(1, 1024), 0));
    for (1..per_pid) |_| try t.expect(l.admit(sender(1, 0), 0));
    try t.expect(!l.admit(sender(1, 0), 0));
    const pid_notice = l.notice(0).?;
    try t.expectEqual(.pid, pid_notice.scope);
    const overflow = l.notice(0).?;
    try t.expectEqual(.senders, overflow.scope);
    try t.expect(overflow.uid == null and overflow.pid == null);
    try t.expectEqual(@as(u64, 1), overflow.suppressed);
    try t.expect(l.admit(sender(1, 1024), sender_idle));
}

test "flood notices aggregate drops after traffic stops and bypass exhausted senders" {
    const t = std.testing;
    var l: Limiter = .{};
    for (0..per_pid) |_| try t.expect(l.admit(sender(1, 10), 0));
    for (0..7) |_| try t.expect(!l.admit(sender(1, 10), 0));
    const flood = l.notice(0).?;
    try t.expectEqual(.pid, flood.scope);
    try t.expectEqual(@as(?u32, 1), flood.uid);
    try t.expectEqual(@as(?i32, 10), flood.pid);
    try t.expectEqual(@as(u64, 7), flood.suppressed);
    for (0..3) |_| try t.expect(!l.admit(sender(1, 10), 0));
    try t.expect(l.notice(flood_interval - 1) == null);
    try t.expectEqual(@as(u64, 3), l.notice(flood_interval).?.suppressed);
    try t.expect(l.notice(2 * flood_interval) == null);
    var buf: [384]u8 = undefined;
    const line = try floodRecord(&buf, 0, flood);
    try t.expect(validRecord(line));
    const parsed = try std.json.parseFromSlice(std.json.Value, t.allocator, line[9..], .{});
    defer parsed.deinit();
    try t.expectEqualStrings("syslogd", parsed.value.object.get("source").?.string);
    try t.expectEqualStrings("flood", parsed.value.object.get("event").?.string);
    try t.expectEqual(@as(i64, 10), parsed.value.object.get("pid").?.integer);
}

test "a flood of identities cannot flood notices or starve pending summaries" {
    const t = std.testing;
    var l: Limiter = .{};
    for (0..10) |pid| {
        for (0..per_pid) |_| try t.expect(l.admit(sender(1, @intCast(pid)), 0));
        try t.expect(!l.admit(sender(1, @intCast(pid)), 0));
    }
    for (0..4) |pid| try t.expectEqual(@as(?i32, @intCast(pid)), l.notice(0).?.pid);
    try t.expect(l.notice(0) == null);
    for (4..8) |pid| try t.expectEqual(@as(?i32, @intCast(pid)), l.notice(1).?.pid);
    try t.expect(l.notice(1) == null);
    for (8..10) |pid| try t.expectEqual(@as(?i32, @intCast(pid)), l.notice(2).?.pid);
    try t.expect(l.notice(2) == null);
}

test "queue compaction preserves partial writes" {
    const t = std.testing;
    var q: Queue = .{};
    const bytes: [40 << 10]u8 = @splat('a');
    try t.expect(q.append(&bytes));
    try t.expect(!q.append(&bytes));
    q.consumed(30 << 10);
    try t.expect(q.append(&bytes));
    try t.expectEqual(@as(usize, 50 << 10), q.pending().len);
    for (q.pending()) |c| try t.expectEqual('a', c);
}
