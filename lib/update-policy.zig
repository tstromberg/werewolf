//! update-policy: when a staged update boots, and why
//! (docs/design/update-policy.md). slot-update decides with it; howl
//! checks an operator's update-policy.json with the same apply.
//!
//! Each fix has a tier. Urgent and High boot within a time of when this
//! machine first saw them; Medium and Low wait at least a time, then boot
//! in the maintenance window. Where in its time or window a machine boots
//! is its place: the same for the same machine and build, different across
//! a fleet. A form and then an operator may change the times and the
//! window, never past the limits, and never Urgent's.
//!
//! Everything here is pure: times are seconds since the epoch, UTC, passed
//! in, so all of it is tested without a clock. Times are written in two
//! forms alone, each read and written here: RFC 3339 (Time), in logs,
//! reports, state files and expiries, and a serial (Serial), the same
//! without dashes or colons, which a git tag can carry, for a release's and
//! a feed's serial and a loader entry's version.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Writer = std.Io.Writer;
const json = std.json;

pub const minute = 60;
pub const hour = 60 * minute;
pub const day = 24 * hour;

/// Urgent fixes, and anything a machine's first check stages, boot within
/// these; update reboots are at least reboot_gap apart.
const urgent_time = 15 * minute;
const first_boot_time = 2 * minute;
const reboot_gap = hour;

/// In order of urgency.
pub const Tier = enum(u2) {
    low,
    medium,
    high,
    urgent,

    fn title(t: Tier) []const u8 {
        return switch (t) {
            .low => "Low",
            .medium => "Medium",
            .high => "High",
            .urgent => "Urgent",
        };
    }
};

/// Who set a setting.
pub const Source = enum { werewolf, form, operator };

/// When Medium and Low fixes boot: on the days in days (bit 0 Sunday, as
/// the epoch's weekdays count), from start to end, seconds into the day in
/// UTC. An end before its start wraps past midnight.
pub const Window = struct {
    days: u7 = 0x7f,
    start: u32 = 2 * hour,
    end: u32 = 5 * hour,

    pub fn len(w: Window) u32 {
        return if (w.end > w.start) w.end - w.start else w.end + day - w.start;
    }

    pub fn format(w: Window, out: *Writer) Writer.Error!void {
        if (w.days == 0x7f) {
            try out.writeAll("daily");
        } else {
            var first = true;
            for (day_names, 0..) |name, i| {
                if (w.days & (@as(u7, 1) << @intCast(i)) == 0) continue;
                if (!first) try out.writeByte(',');
                try out.writeAll(name);
                first = false;
            }
        }
        try out.print(" {d:0>2}:{d:0>2}-{d:0>2}:{d:0>2}", .{
            w.start / hour, w.start % hour / minute, w.end / hour, w.end % hour / minute,
        });
    }
};

const day_names = [7][]const u8{ "sun", "mon", "tue", "wed", "thu", "fri", "sat" };

/// High's time, Medium's and Low's waits, each at most its limit.
pub const Times = struct { high: u32, medium: u32, low: u32 };

pub const Settings = struct {
    window: Window = .{},
    time: Times = .{ .high = 4 * hour, .medium = 7 * day, .low = 28 * day },
    limit: Times = .{ .high = 24 * hour, .medium = 28 * day, .low = 90 * day },
    source: struct {
        window: Source = .werewolf,
        high: Source = .werewolf,
        medium: Source = .werewolf,
        low: Source = .werewolf,
    } = .{},
};

/// The most an update-policy.json may hold.
pub const max_input = 32 << 10;

/// Why a file was refused, and the key it is about ("" for the whole).
pub const Refusal = struct { key: []const u8, why: []const u8 };

/// Apply input, a form's /etc/werewolf/update-policy.json or an operator's
/// update-policy.json from the config tar, to s: all of it, or none of it
/// and the reason. A missing file changes nothing. One JSON object:
///
///   "window"  "daily 02:00-05:00" or "sun,wed 03:00-05:00": UTC, an hour at
///             least
///   "high", "medium", "low"
///             "30m", "4h", "7d": each at most its limit
///   "limits"  a form's only: {"high": ..., "medium": ..., "low": ...},
///             each only lower than werewolf's; a limit below its time
///             brings the time down with it
///
/// An unknown key, one given twice, or a value of the wrong type refuses
/// the file, as does anything over max_input.
pub fn apply(
    gpa: Allocator,
    s: *Settings,
    source: Source,
    input: []const u8,
) error{OutOfMemory}!?Refusal {
    if (input.len > max_input) return .{ .key = "", .why = "over 32 KiB" };
    const doc = json.parseFromSliceLeaky(
        json.Value,
        gpa,
        input,
        .{},
    ) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.DuplicateField => .{ .key = "", .why = "a key is given twice" },
        else => .{ .key = "", .why = "not JSON" },
    };
    if (doc != .object) return .{ .key = "", .why = "not a JSON object" };
    var next = s.*;
    // Limits first, so the times are held to them whatever the order.
    if (doc.object.get("limits")) |v| {
        if (source != .form) return .{ .key = "limits", .why = "only a form may set limits" };
        if (v != .object) return .{ .key = "limits", .why = "not an object" };
        var it = v.object.iterator();
        while (it.next()) |e| {
            const limit = timeOf(&next.limit, e.key_ptr.*) orelse
                return .{ .key = e.key_ptr.*, .why = "not a limit: high, medium or low" };
            const value = duration(e.value_ptr.*) orelse
                return .{
                    .key = e.key_ptr.*,
                    .why = "a time is a string such as \"4h\" or \"7d\"",
                };
            if (value > limit.*) return .{
                .key = e.key_ptr.*,
                .why = "a form may only lower a limit",
            };
            limit.* = value;
            const time = timeOf(&next.time, e.key_ptr.*).?;
            if (value < time.*) {
                // The form's limit set it now, not werewolf's default.
                time.* = value;
                sourceOf(&next, e.key_ptr.*).* = .form;
            }
        }
    }
    var it = doc.object.iterator();
    while (it.next()) |e| {
        const key = e.key_ptr.*;
        const v = e.value_ptr.*;
        if (std.mem.eql(u8, key, "limits")) continue;
        if (std.mem.eql(u8, key, "window")) {
            if (v != .string) return .{ .key = key, .why = "not a string" };
            next.window = parseWindow(v.string) orelse
                return .{
                    .key = key,
                    .why = "days and UTC hours, such as \"daily 02:00-05:00\", an hour at least",
                };
            next.source.window = source;
            continue;
        }
        const time = timeOf(&next.time, key) orelse
            return .{ .key = key, .why = "unknown setting" };
        const value = duration(v) orelse
            return .{ .key = key, .why = "a time is a string such as \"4h\" or \"7d\"" };
        if (value > timeOf(&next.limit, key).?.*) return .{ .key = key, .why = "above its limit" };
        time.* = value;
        sourceOf(&next, key).* = source;
    }
    s.* = next;
    return null;
}

/// The tiers whose times a setting names: Times' fields, and Settings'
/// sources'.
const Timed = enum { high, medium, low };

fn timeOf(t: *Times, key: []const u8) ?*u32 {
    return switch (std.meta.stringToEnum(Timed, key) orelse return null) {
        inline else => |k| &@field(t, @tagName(k)),
    };
}

fn sourceOf(s: *Settings, key: []const u8) *Source {
    return switch (std.meta.stringToEnum(Timed, key).?) {
        inline else => |k| &@field(s.source, @tagName(k)),
    };
}

fn duration(v: json.Value) ?u32 {
    return if (v == .string) parseDuration(v.string) else null;
}

fn parseWindow(s: []const u8) ?Window {
    var words = std.mem.tokenizeScalar(u8, s, ' ');
    const days = parseDays(words.next() orelse return null) orelse return null;
    const range = words.next() orelse return null;
    if (words.next() != null or range.len != 11 or range[5] != '-') return null;
    const w: Window = .{
        .days = days,
        .start = parseClock(range[0..5]) orelse return null,
        .end = parseClock(range[6..11]) orelse return null,
    };
    if (w.start == w.end or w.len() < hour) return null;
    return w;
}

fn parseDuration(s: []const u8) ?u32 {
    if (s.len < 2 or s.len > 5) return null;
    const n = std.fmt.parseUnsigned(u32, s[0 .. s.len - 1], 10) catch return null;
    const unit: u32 = switch (s[s.len - 1]) {
        'm' => minute,
        'h' => hour,
        'd' => day,
        else => return null,
    };
    return std.math.mul(u32, n, unit) catch null;
}

fn parseDays(s: []const u8) ?u7 {
    if (std.mem.eql(u8, s, "daily")) return 0x7f;
    var days: u7 = 0;
    var names = std.mem.splitScalar(u8, s, ',');
    while (names.next()) |n| {
        const i = for (day_names, 0..) |d, i| {
            if (std.mem.eql(u8, n, d)) break i;
        } else return null;
        days |= @as(u7, 1) << @intCast(i);
    }
    return days;
}

fn parseClock(s: []const u8) ?u32 {
    if (s[2] != ':') return null;
    const h = std.fmt.parseUnsigned(u32, s[0..2], 10) catch return null;
    const m = std.fmt.parseUnsigned(u32, s[3..5], 10) catch return null;
    if (h > 23 or m > 59) return null;
    return h * hour + m * minute;
}

/// A machine's seed for a build: the first 8 bytes of SHA-256(machine ‖
/// build). A machine's place in any span is its seed modulo the span.
pub fn seed(machine: []const u8, build: []const u8) u64 {
    var h: std.crypto.hash.sha2.Sha256 = .init(.{});
    h.update(machine);
    h.update(build);
    return std.mem.readInt(u64, h.finalResult()[0..8], .big);
}

fn place(sd: u64, span: u32) u32 {
    return if (span == 0) 0 else @intCast(sd % span);
}

/// When a fix of tier, first seen at seen, boots on a machine of seed sd.
pub fn due(s: *const Settings, tier: Tier, seen: i64, sd: u64) i64 {
    return switch (tier) {
        .urgent => seen + place(sd, urgent_time),
        .high => seen + place(sd, s.time.high),
        .medium => inWindow(s.window, seen + s.time.medium, sd),
        .low => inWindow(s.window, seen + s.time.low, sd),
    };
}

/// The first of this machine's places in a window at or after earliest. A
/// window that began the day before may still hold it, so the search
/// starts there.
fn inWindow(w: Window, earliest: i64, sd: u64) i64 {
    std.debug.assert(w.days != 0);
    const offset = place(sd, w.len());
    var d = @divFloor(earliest, day) - 1;
    while (true) : (d += 1) {
        // The epoch began on a Thursday.
        const weekday: u3 = @intCast(@mod(d + 4, 7));
        if (w.days & (@as(u7, 1) << weekday) == 0) continue;
        const t = d * day + w.start + offset;
        if (t >= earliest) return t;
    }
}

/// When a fix boots by its rule alone: due, or on a machine's first check,
/// within first_boot_time of when it was seen.
fn byRule(s: *const Settings, tier: Tier, seen: i64, sd: u64, first_boot: bool) i64 {
    return if (first_boot) seen + place(sd, first_boot_time) else due(s, tier, seen, sd);
}

/// When the tiers seen first were seen; null for a tier not seen. A tier,
/// once seen, stays until the slot boots, so a fix whose tier rises never
/// boots later than it would have.
pub const Seen = std.enums.EnumArray(Tier, ?i64);

pub fn see(seen: *Seen, tier: Tier, now: i64) void {
    const t = seen.getPtr(tier);
    if (t.* == null) t.* = now;
}

pub const Due = struct { at: i64, tier: Tier };

/// When the staged slot boots, and the tier that makes it then: the
/// earliest of each seen tier's time; on a machine's first check, within
/// first_boot_time of the first fix seen. Null when nothing is seen.
pub fn when(s: *const Settings, seen: Seen, sd: u64, first_boot: bool) ?Due {
    var best: ?Due = null;
    for (std.enums.values(Tier)) |tier| {
        const at = seen.get(tier) orelse continue;
        const d: Due = .{ .at = byRule(s, tier, at, sd, first_boot), .tier = tier };
        if (best == null or d.at < best.?.at or (d.at == best.?.at and
            @backingInt(d.tier) > @backingInt(best.?.tier)))
            best = d;
    }
    return best;
}

/// at, held until reboot_gap after the last update reboot.
pub fn spaced(at: i64, last_reboot: ?i64) i64 {
    const last = last_reboot orelse return at;
    return @max(at, last + reboot_gap);
}

/// A fix, as the log names it: "CVE-2026-1111 in busybox", "no score yet".
pub const Fix = struct { subject: []const u8, evidence: []const u8 };

/// One sentence from evidence to rule to time, for the log's why:
///
///   Medium: CVE-2026-1111 in busybox, no score yet, first seen
///   2026-10-07T14:02:11Z. The operator's medium wait is 14d, then the
///   window, daily 02:00-05:00 UTC, where this machine's place is 1h 41m 7s
///   in. Due 2026-10-22T03:41:07Z, in 14d 13h 38m.
pub fn why(
    out: *Writer,
    s: *const Settings,
    tier: Tier,
    fix: Fix,
    seen: i64,
    sd: u64,
    first_boot: bool,
    at: i64,
    now: i64,
) Writer.Error!void {
    try out.print("{s}: {s}, {s}, first seen {f}. ", .{
        tier.title(), fix.subject, fix.evidence, Time{ .secs = seen },
    });
    // The rule, then this machine's place in the span it boots within.
    const span: u32 = if (first_boot) first_boot_time else switch (tier) {
        .urgent => urgent_time,
        .high => s.time.high,
        .medium, .low => s.window.len(),
    };
    if (first_boot) {
        try out.print("It is this machine's first check, so it boots within {f}", .{
            Duration{ .secs = first_boot_time },
        });
    } else switch (tier) {
        .urgent => try out.print(
            "Urgent fixes boot within {f}",
            .{Duration{ .secs = urgent_time }},
        ),
        .high => try out.print("{s} high time is {f}", .{
            whose(s.source.high), Setting{ .secs = s.time.high },
        }),
        .medium => try out.print("{s} medium wait is {f}, then the window, {f} UTC", .{
            whose(s.source.medium), Setting{ .secs = s.time.medium }, s.window,
        }),
        .low => try out.print("{s} low wait is {f}, then the window, {f} UTC", .{
            whose(s.source.low), Setting{ .secs = s.time.low }, s.window,
        }),
    }
    try out.print(
        ", where this machine's place is {f} in.",
        .{Duration{ .secs = place(sd, span) }},
    );
    if (at > byRule(s, tier, seen, sd, first_boot)) try out.print(
        " An update reboot waits until {f} after boot.",
        .{Duration{ .secs = reboot_gap }},
    );
    try out.print(" Due {f}, ", .{Time{ .secs = at }});
    if (at <= now)
        try out.writeAll("now.")
    else
        try out.print("in {f}.", .{Duration{ .secs = @intCast(at - now) }});
}

fn whose(src: Source) []const u8 {
    return switch (src) {
        .werewolf => "werewolf's default",
        .form => "The form's",
        .operator => "The operator's",
    };
}

/// RFC 3339 in UTC: 2026-10-07T14:02:11Z.
pub const Time = struct {
    secs: i64,

    pub fn format(t: Time, out: *Writer) Writer.Error!void {
        const y, const mo, const d, const h, const mi, const s = civil(t.secs);
        try out.print(
            "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z",
            .{ y, mo, d, h, mi, s },
        );
    }
};

/// A serial: RFC 3339 in UTC without its dashes and colons,
/// 20261007T140211Z, which a git tag can carry and a string compare orders.
pub const Serial = struct {
    secs: i64,

    pub fn format(t: Serial, out: *Writer) Writer.Error!void {
        const y, const mo, const d, const h, const mi, const s = civil(t.secs);
        try out.print("{d:0>4}{d:0>2}{d:0>2}T{d:0>2}{d:0>2}{d:0>2}Z", .{ y, mo, d, h, mi, s });
    }
};

/// secs as year, month, day, hour, minute and second.
fn civil(secs: i64) [6]u32 {
    const es: std.time.epoch.EpochSeconds = .{ .secs = @intCast(secs) };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    return .{
        yd.year,              md.month.numeric(),      md.day_index + 1,
        ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
    };
}

/// RFC 3339 in UTC, as Time writes it, as seconds since the epoch.
pub fn parseTime(s: []const u8) error{BadTime}!i64 {
    if (s.len != 20 or s[4] != '-' or s[7] != '-' or s[10] != 'T' or s[13] != ':' or
        s[16] != ':' or s[19] != 'Z') return error.BadTime;
    return secsOf(.{ s[0..4], s[5..7], s[8..10], s[11..13], s[14..16], s[17..19] });
}

/// A serial, as Serial writes it, as seconds since the epoch.
pub fn parseSerial(s: []const u8) error{BadTime}!i64 {
    if (s.len != 16 or s[8] != 'T' or s[15] != 'Z') return error.BadTime;
    return secsOf(.{ s[0..4], s[4..6], s[6..8], s[9..11], s[11..13], s[13..15] });
}

/// Year, month, day, hour, minute and second, each in digits alone, as
/// seconds since the epoch; a date that is not one, Feb 31, is refused.
fn secsOf(fields: [6][]const u8) error{BadTime}!i64 {
    var n: [6]u32 = undefined;
    for (fields, &n) |digits, *v| {
        for (digits) |c| if (!std.ascii.isDigit(c)) return error.BadTime;
        v.* = std.fmt.parseUnsigned(u32, digits, 10) catch return error.BadTime;
    }
    const year, const month, const d, const h, const mi, const s = n;
    if (year < 1970 or month < 1 or month > 12 or d < 1 or h > 23 or mi > 59 or s > 59)
        return error.BadTime;
    const leap = std.time.epoch.isLeapYear(@intCast(year));
    const days_in = [12]u32{ 31, if (leap) 29 else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    if (d > days_in[month - 1]) return error.BadTime;
    var days: i64 = 0;
    var y: u32 = 1970;
    while (y < year) : (y += 1) days += std.time.epoch.getDaysInYear(@intCast(y));
    for (days_in[0 .. month - 1]) |m| days += m;
    days += d - 1;
    return days * day + @as(i64, h) * hour + @as(i64, mi) * minute + s;
}

/// A span for people: at most its three largest units, "14d 13h 38m",
/// "2h 45m 42s", "15m", "0s".
pub const Duration = struct {
    secs: u64,

    pub fn format(d: Duration, out: *Writer) Writer.Error!void {
        const units = [_]struct { n: u64, c: u8 }{
            .{ .n = day, .c = 'd' },
            .{ .n = hour, .c = 'h' },
            .{ .n = minute, .c = 'm' },
            .{ .n = 1, .c = 's' },
        };
        var left = d.secs;
        var shown: usize = 0;
        for (units) |u| {
            const n = left / u.n;
            left %= u.n;
            if (n == 0 and shown == 0) continue;
            if (shown == 3) break;
            if (n != 0) {
                if (shown > 0) try out.writeByte(' ');
                try out.print("{d}{c}", .{ n, u.c });
            }
            shown += 1;
        }
        if (shown == 0) try out.writeAll("0s");
    }
};

/// A setting as it is written: in its largest whole unit, "4h", "14d".
pub const Setting = struct {
    secs: u32,

    pub fn format(v: Setting, out: *Writer) Writer.Error!void {
        if (v.secs != 0 and v.secs % day == 0) return out.print("{d}d", .{v.secs / day});
        if (v.secs % hour == 0) return out.print("{d}h", .{v.secs / hour});
        try out.print("{d}m", .{v.secs / minute});
    }
};

/// The log's chain: prev for the line after line, as written with its
/// newline, the first 16 hex digits of its SHA-256.
pub fn chain(line: []const u8) [16]u8 {
    var sum: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(line, &sum, .{});
    return std.fmt.bytesToHex(sum[0..8].*, .lower);
}

// --- tests ---------------------------------------------------------------------

const t0 = 1791381731; // 2026-10-07T14:02:11Z, a Wednesday

fn expectText(want: []const u8, value: anytype) !void {
    var buf: [256]u8 = undefined;
    var w: Writer = .fixed(&buf);
    try w.print("{f}", .{value});
    try std.testing.expectEqualStrings(want, w.buffered());
}

fn expectRefused(source: Source, input: []const u8, key: []const u8, reason: []const u8) !void {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    var s: Settings = .{};
    const before = s;
    const r = (try apply(arena.allocator(), &s, source, input)) orelse return error.NotRefused;
    try std.testing.expectEqualStrings(key, r.key);
    try std.testing.expectEqualStrings(reason, r.why);
    try std.testing.expectEqual(before, s);
}

test "settings: an operator's" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    var s: Settings = .{};
    try std.testing.expectEqual(@as(?Refusal, null), try apply(arena.allocator(), &s, .operator,
        \\{"window": "sun,wed 23:00-02:00", "medium": "14d", "low": "0d"}
    ));
    try expectText("sun,wed 23:00-02:00", s.window);
    try std.testing.expectEqual(3 * hour, s.window.len());
    try std.testing.expectEqual(14 * day, s.time.medium);
    try std.testing.expectEqual(Source.operator, s.source.medium);
    try std.testing.expectEqual(0, s.time.low);
    try std.testing.expectEqual(4 * hour, s.time.high);
    try std.testing.expectEqual(Source.werewolf, s.source.high);
}

test "settings: refused whole, naming the key" {
    try expectRefused(
        .operator,
        "{\"medium\": \"14d\", \"high\": \"25h\"}",
        "high",
        "above its limit",
    );
    try expectRefused(
        .operator,
        "{\"limits\": {\"low\": \"1d\"}}",
        "limits",
        "only a form may set limits",
    );
    try expectRefused(.operator, "{\"tier\": \"1h\"}", "tier", "unknown setting");
    try expectRefused(
        .operator,
        "{\"high\": 4}",
        "high",
        "a time is a string such as \"4h\" or \"7d\"",
    );
    try expectRefused(
        .operator,
        "{\"high\": \"2x\"}",
        "high",
        "a time is a string such as \"4h\" or \"7d\"",
    );
    try expectRefused(
        .operator,
        "{\"high\": \"1h\", \"high\": \"2h\"}",
        "",
        "a key is given twice",
    );
    try expectRefused(
        .operator,
        "{\"window\": \"daily 03:00-03:30\"}",
        "window",
        "days and UTC hours, such as \"daily 02:00-05:00\", an hour at least",
    );
    try expectRefused(
        .operator,
        "{\"window\": \"weekdays 01:00-04:00\"}",
        "window",
        "days and UTC hours, such as \"daily 02:00-05:00\", an hour at least",
    );
    try expectRefused(.operator, "[]", "", "not a JSON object");
    try expectRefused(.operator, "high 4h", "", "not JSON");
    try expectRefused(
        .form,
        "{\"limits\": {\"high\": \"48h\"}}",
        "high",
        "a form may only lower a limit",
    );
    try expectRefused(
        .form,
        "{\"limits\": {\"urgent\": \"1h\"}}",
        "urgent",
        "not a limit: high, medium or low",
    );
    const big: [max_input + 1]u8 = @splat(' ');
    try expectRefused(.operator, &big, "", "over 32 KiB");
}

test "settings: a form lowers a limit, and the operator stays under it" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var s: Settings = .{};
    // The order of keys does not matter: limits apply first.
    try std.testing.expectEqual(@as(?Refusal, null), try apply(gpa, &s, .form,
        \\{"medium": "2d", "limits": {"medium": "3d"}}
    ));
    try std.testing.expectEqual(3 * day, s.limit.medium);
    try std.testing.expectEqual(2 * day, s.time.medium);
    try std.testing.expectEqual(Source.form, s.source.medium);
    var t: Settings = .{};
    _ = try apply(gpa, &t, .form, "{\"limits\": {\"medium\": \"3d\"}}");
    try std.testing.expectEqual(3 * day, t.time.medium);
    try std.testing.expectEqual(Source.form, t.source.medium);
    const r = (try apply(gpa, &t, .operator, "{\"medium\": \"4d\"}")).?;
    try std.testing.expectEqualStrings("above its limit", r.why);
    try std.testing.expectEqual(
        @as(?Refusal, null),
        try apply(gpa, &t, .operator, "{\"medium\": \"1d\"}"),
    );
    try std.testing.expectEqual(day, t.time.medium);
}

test "due: Urgent and High within their times" {
    const s: Settings = .{};
    for ([_]u64{ 0, 1, 899, 900, 12345678901 }) |sd| {
        const u = due(&s, .urgent, t0, sd);
        try std.testing.expect(u >= t0 and u < t0 + 15 * minute);
        const h = due(&s, .high, t0, sd);
        try std.testing.expect(h >= t0 and h < t0 + 4 * hour);
    }
    var none: Settings = .{};
    none.time.high = 0;
    try std.testing.expectEqual(@as(i64, t0), due(&none, .high, t0, 77));
}

test "due: Medium waits, then the window" {
    var s: Settings = .{};
    s.time.medium = 14 * day;
    // The design's example: 1h 41m 7s into the default window.
    const sd: u64 = 6067;
    try expectText("2026-10-22T03:41:07Z", Time{ .secs = due(&s, .medium, t0, sd) });
    // A wait that ends inside the window, before this machine's place: the
    // same day. After it: the next day's window.
    s.time.medium = 12 * hour; // ends 2026-10-08T02:02:11Z
    try expectText("2026-10-08T03:41:07Z", Time{ .secs = due(&s, .medium, t0, sd) });
    s.time.medium = 13 * hour + 40 * minute; // ends 03:42:11
    try expectText("2026-10-09T03:41:07Z", Time{ .secs = due(&s, .medium, t0, sd) });
    // A wait of nothing is the next window.
    s.time.medium = 0;
    try expectText("2026-10-08T03:41:07Z", Time{ .secs = due(&s, .medium, t0, sd) });
}

test "due: windows on some days, and past midnight" {
    var s: Settings = .{};
    s.time.low = 0;
    // Sundays only: the Wednesday's next Sunday is 2026-10-11.
    s.window = .{ .days = 1, .start = 2 * hour, .end = 5 * hour };
    try expectText("2026-10-11T02:00:00Z", Time{ .secs = due(&s, .low, t0, 0) });
    // 23:00-02:00 on Wednesdays: Wednesday's window runs into Thursday.
    s.window = .{ .days = 1 << 3, .start = 23 * hour, .end = 2 * hour };
    try expectText("2026-10-08T01:00:00Z", Time{ .secs = due(&s, .low, t0, 2 * hour) });
    // Seen inside that window, after this machine's place: next week's.
    try expectText(
        "2026-10-14T23:30:00Z",
        Time{ .secs = due(&s, .low, t0 + 10 * hour, 30 * minute) },
    );
}

test "when: the earliest tier, kept as tiers rise" {
    const s: Settings = .{};
    var seen: Seen = .initFill(null);
    try std.testing.expectEqual(@as(?Due, null), when(&s, seen, 0, false));
    see(&seen, .low, t0);
    see(&seen, .medium, t0);
    const before = when(&s, seen, 0, false).?;
    try std.testing.expectEqual(Tier.medium, before.tier);
    // A later sighting does not move the first.
    see(&seen, .medium, t0 + day);
    try std.testing.expectEqual(before, when(&s, seen, 0, false).?);
    // A fix that rises to High a week later: High's time is sooner.
    see(&seen, .high, t0 + 6 * day);
    const after = when(&s, seen, 0, false).?;
    try std.testing.expectEqual(Tier.high, after.tier);
    try std.testing.expect(after.at < before.at);
    // On a first check, everything boots within two minutes.
    const first = when(&s, seen, 61, true).?;
    try std.testing.expectEqual(@as(i64, t0 + 61), first.at);
}

test "spaced: an hour between update reboots" {
    try std.testing.expectEqual(@as(i64, 100), spaced(100, null));
    try std.testing.expectEqual(@as(i64, 10 + hour), spaced(100, 10));
    try std.testing.expectEqual(@as(i64, 9000), spaced(9000, 10));
}

test "why" {
    var s: Settings = .{};
    s.time.medium = 14 * day;
    s.source.medium = .operator;
    var buf: [512]u8 = undefined;
    var w: Writer = .fixed(&buf);
    try why(
        &w,
        &s,
        .medium,
        .{ .subject = "CVE-2026-1111 in busybox", .evidence = "no score yet" },
        t0,
        6067,
        false,
        due(&s, .medium, t0, 6067),
        t0,
    );
    try std.testing.expectEqualStrings(
        "Medium: CVE-2026-1111 in busybox, no score yet, first seen 2026-10-07T14:02:11Z. " ++
            "The operator's medium wait is 14d, then the window, daily 02:00-05:00 UTC, " ++
            "where this machine's place is 1h 41m 7s in. Due 2026-10-22T03:41:07Z, in 14d 13h 38m.",
        w.buffered(),
    );
    w = .fixed(&buf);
    try why(
        &w,
        &s,
        .high,
        .{ .subject = "CVE-2026-1111 in busybox", .evidence = "CVSS 8.1 from NVD" },
        t0,
        9942,
        false,
        due(&s, .high, t0, 9942),
        t0 + 4 * hour,
    );
    try std.testing.expectEqualStrings(
        "High: CVE-2026-1111 in busybox, CVSS 8.1 from NVD, first seen 2026-10-07T14:02:11Z. " ++
            "werewolf's default high time is 4h, where this machine's place is 2h 45m 42s in. " ++
            "Due 2026-10-07T16:47:53Z, now.",
        w.buffered(),
    );
}

test "why: Urgent, Low and a first check" {
    var s: Settings = .{};
    s.source.low = .form;
    var buf: [512]u8 = undefined;
    var w: Writer = .fixed(&buf);
    const fix: Fix = .{ .subject = "CVE-2026-2222 in curl", .evidence = "in KEV since 2026-10-06" };
    try why(&w, &s, .urgent, fix, t0, 61, false, t0 + 61, t0);
    try std.testing.expectEqualStrings(
        "Urgent: CVE-2026-2222 in curl, in KEV since 2026-10-06, first seen " ++
            "2026-10-07T14:02:11Z. " ++
            "Urgent fixes boot within 15m, where this machine's place is 1m 1s in. " ++
            "Due 2026-10-07T14:03:12Z, in 1m 1s.",
        w.buffered(),
    );
    w = .fixed(&buf);
    const no_cve: Fix = .{ .subject = "an update", .evidence = "no CVE" };
    try why(&w, &s, .low, no_cve, t0, 0, false, due(&s, .low, t0, 0), t0);
    try std.testing.expectEqualStrings(
        "Low: an update, no CVE, first seen 2026-10-07T14:02:11Z. The form's low wait is 28d, " ++
            "then the window, daily 02:00-05:00 UTC, where this machine's place is 0s in. " ++
            "Due 2026-11-05T02:00:00Z, in 28d 11h 57m.",
        w.buffered(),
    );
    w = .fixed(&buf);
    try why(&w, &s, .low, no_cve, t0, 30, true, t0 + 30, t0);
    try std.testing.expectEqualStrings(
        "Low: an update, no CVE, first seen 2026-10-07T14:02:11Z. It is this machine's first " ++
            "check, so it boots within 2m, where this machine's place is 30s in. " ++
            "Due 2026-10-07T14:02:41Z, in 30s.",
        w.buffered(),
    );
    // Held for the hour after boot: the sentence says so.
    w = .fixed(&buf);
    try why(&w, &s, .urgent, fix, t0, 61, false, t0 + hour, t0);
    try std.testing.expectEqualStrings(
        "Urgent: CVE-2026-2222 in curl, in KEV since 2026-10-06, first seen " ++
            "2026-10-07T14:02:11Z. " ++
            "Urgent fixes boot within 15m, where this machine's place is 1m 1s in. " ++
            "An update reboot waits until 1h after boot. Due 2026-10-07T15:02:11Z, in 1h.",
        w.buffered(),
    );
}

test "durations and settings as text" {
    try expectText("0s", Duration{ .secs = 0 });
    try expectText("15m", Duration{ .secs = 15 * minute });
    try expectText("2h 45m 42s", Duration{ .secs = 9942 });
    try expectText("14d 13h 38m", Duration{ .secs = 1258736 });
    try expectText("1d", Duration{ .secs = day + 5 });
    try expectText("4h", Setting{ .secs = 4 * hour });
    try expectText("14d", Setting{ .secs = 14 * day });
    try expectText("0h", Setting{ .secs = 0 });
    try expectText("90m", Setting{ .secs = 90 * minute });
    try std.testing.expectEqual(@as(?u32, null), parseDuration("100000d"));
}

test "times, written and read" {
    try expectText("2026-10-07T14:02:11Z", Time{ .secs = t0 });
    try expectText("20261007T140211Z", Serial{ .secs = t0 });
    try expectText("20280229T235959Z", Serial{ .secs = 1835481599 });
    try std.testing.expectEqual(t0, try parseTime("2026-10-07T14:02:11Z"));
    try std.testing.expectEqual(t0, try parseSerial("20261007T140211Z"));
    try std.testing.expectEqual(0, try parseTime("1970-01-01T00:00:00Z"));
    try std.testing.expectEqual(951782400, try parseTime("2000-02-29T00:00:00Z"));
    for ([_]i64{ 0, t0, 1835481599, 4102444799 }) |secs| {
        var buf: [32]u8 = undefined;
        try std.testing.expectEqual(secs, try parseSerial(
            try std.mem.print(&buf, "{f}", .{Serial{ .secs = secs }}),
        ));
        try std.testing.expectEqual(secs, try parseTime(
            try std.mem.print(&buf, "{f}", .{Time{ .secs = secs }}),
        ));
    }
    // release/sign's "expires", which updaters from before 2026-10-08
    // check: it must read as later than any now.
    try std.testing.expect(try parseTime("9999-12-31T23:59:59Z") > t0 + 100 * 365 * day);
    for ([_][]const u8{
        "2026-02-29T00:00:00Z",
        "2026-02-31T00:00:00Z",
        "2026-13-01T00:00:00Z",
        "2026-10-13 15:10:16Z",
        "2026-10-13T15:10:16",
        "+026-10-13T15:10:16Z",
        "1969-12-31T23:59:59Z",
    }) |bad| try std.testing.expectError(error.BadTime, parseTime(bad));
    for ([_][]const u8{
        "20260231T000000Z",
        "20261006T120000",
        "20261006T1200+0Z",
        "2026-10-06T12:00",
        "~",
    }) |bad| try std.testing.expectError(error.BadTime, parseSerial(bad));
}

test "seed and chain" {
    try std.testing.expectEqual(seed("m", "b"), seed("m", "b"));
    try std.testing.expect(seed("a", "b") != seed("a", "c"));
    try std.testing.expectEqualStrings("5891b5b522d5df08", &chain("hello\n"));
}
