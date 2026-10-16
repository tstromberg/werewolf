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
pub const max_record = max_input * 6 + 256;
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
    var time: [20]u8 = undefined;
    var w: std.Io.Writer = .fixed(out);
    try w.print("syslogd: {{\"time\":\"{s}\",\"pid\":{d},\"uid\":{d},\"gid\":{d}," ++
        "\"priority\":{d},\"message\":\"", .{
        try stamp(&time, seconds), cred.pid, cred.uid, cred.gid, priority,
    });
    const hex = "0123456789abcdef";
    for (text) |c| switch (c) {
        '"', '\\' => try w.writeAll(&.{ '\\', c }),
        0x20...0x21, 0x23...0x5b, 0x5d...0x7e => try w.writeByte(c),
        else => try w.writeAll(&.{ '\\', 'u', '0', '0', hex[c >> 4], hex[c & 15] }),
    };
    try w.writeAll("\"}\n");
    return w.buffered();
}

pub fn validRecord(line: []const u8) bool {
    if (line.len == 0 or line.len > max_record or line[line.len - 1] != '\n' or
        !mem.startsWith(u8, line, "syslogd: {")) return false;
    for (line[0 .. line.len - 1]) |c| if (c < 0x20 or c > 0x7e) return false;
    return true;
}

pub const Limiter = struct {
    slots: [256]Slot = @splat(.{}),
    const Slot = struct { uid: ?u32 = null, second: i64 = 0, count: u16 = 0 };

    pub fn admit(l: *Limiter, uid: u32, second: i64) bool {
        var empty: ?*Slot = null;
        for (&l.slots) |*s| {
            if (s.uid == uid) {
                if (s.second != second) s.* = .{ .uid = uid, .second = second };
                if (s.count >= 100) return false;
                s.count += 1;
                return true;
            }
            if (empty == null and (s.uid == null or s.second != second)) empty = s;
        }
        const s = empty orelse return false;
        s.* = .{ .uid = uid, .second = second, .count = 1 };
        return true;
    }
};

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

test "rate limits are per UID and queue compaction preserves partial writes" {
    const t = std.testing;
    var l: Limiter = .{};
    for (0..100) |_| try t.expect(l.admit(1, 10));
    try t.expect(!l.admit(1, 10));
    try t.expect(l.admit(2, 10));
    try t.expect(l.admit(1, 11));
    var q: Queue = .{};
    const bytes: [40 << 10]u8 = @splat('a');
    try t.expect(q.append(&bytes));
    try t.expect(!q.append(&bytes));
    q.consumed(30 << 10);
    try t.expect(q.append(&bytes));
    try t.expectEqual(@as(usize, 50 << 10), q.pending().len);
    for (q.pending()) |c| try t.expectEqual('a', c);
}
