//! Offline domain-age evidence parsing. No network or policy decision lives
//! here. The age worker will use this to validate bounded evidence before
//! writing SQLite; unwound must not authorize from unverified evidence.
const std = @import("std");
const mem = std.mem;

pub const Boundary = union(enum) {
    unknown,
    tenant,
    registered: []const u8,
};

const Section = enum { none, icann, private };
const Rule = enum { exact, wildcard, exception };

/// boundary applies the PSL's longest-rule algorithm to an ASCII DNS name.
/// A PRIVATE tenant cannot inherit its provider's RDAP age. The PSL must be
/// normalized to A-labels by the updater before calling this function.
pub fn boundary(name: []const u8, psl: []const u8) Boundary {
    if (!dnsName(name, true)) return .unknown;
    var section: Section = .none;
    var best_len: usize = 0;
    var best_rule: Rule = .exact;
    var best_section: Section = .none;
    var lines = mem.splitScalar(u8, psl, '\n');
    while (lines.next()) |raw| {
        const line = mem.trim(u8, raw, " \t\r");
        if (mem.eql(u8, line, "// ===BEGIN ICANN DOMAINS===")) {
            section = .icann;
            continue;
        }
        if (mem.eql(u8, line, "// ===END ICANN DOMAINS===")) {
            section = .none;
            continue;
        }
        if (mem.eql(u8, line, "// ===BEGIN PRIVATE DOMAINS===")) {
            section = .private;
            continue;
        }
        if (mem.eql(u8, line, "// ===END PRIVATE DOMAINS===")) {
            section = .none;
            continue;
        }
        if (section == .none or line.len == 0 or mem.startsWith(u8, line, "//")) continue;
        const rule: Rule = if (mem.startsWith(u8, line, "!"))
            .exception
        else if (mem.startsWith(u8, line, "*."))
            .wildcard
        else
            .exact;
        const value = line[if (rule == .exact)
            @as(usize, 0)
        else if (rule == .wildcard)
            @as(usize, 2)
        else
            @as(usize, 1)..];
        if (!dnsName(value, false) or !suffixMatch(name, value)) continue;
        if (section == .private and mem.eql(u8, name, value)) continue;
        const n = labels(value) + @intFromBool(rule == .wildcard);
        if (labels(name) < n) continue;
        if (n < best_len or (n == best_len and rule != .exception)) continue;
        best_len = n;
        best_rule = rule;
        best_section = section;
    }
    if (best_len == 0) return .unknown;
    const suffix_labels = best_len - @intFromBool(best_rule == .exception);
    if (labels(name) <= suffix_labels) return .unknown;
    if (best_section == .private) return .tenant;
    return .{ .registered = suffix(name, suffix_labels + 1) };
}

fn dnsName(name: []const u8, allow_service: bool) bool {
    if (name.len == 0 or name.len > 253 or name[0] == '.' or
        name[name.len - 1] == '.') return false;
    var parts = mem.splitScalar(u8, name, '.');
    while (parts.next()) |part| {
        if (part.len == 0 or part.len > 63) return false;
        for (part) |c| if (!std.ascii.isLower(c) and !std.ascii.isDigit(c) and
            c != '-' and !(allow_service and c == '_')) return false;
    }
    return true;
}

fn suffixMatch(name: []const u8, part: []const u8) bool {
    return mem.eql(u8, name, part) or (name.len > part.len and
        mem.endsWith(u8, name, part) and name[name.len - part.len - 1] == '.');
}

fn labels(name: []const u8) usize {
    var count: usize = 1;
    for (name) |c| if (c == '.') {
        count += 1;
    };
    return count;
}

fn suffix(name: []const u8, count: usize) []const u8 {
    var left = name.len;
    var n: usize = 0;
    while (left > 0) {
        left = mem.findScalarLast(u8, name[0..left], '.') orelse return name;
        n += 1;
        if (n == count) return name[left + 1 ..];
    }
    return name;
}

pub const Evidence = struct {
    registered: []const u8,
    created: i64,
    effective: i64,
};

pub const Verdict = enum { unknown, young, mature, stale };
pub const threshold_s: i64 = 90 * 86400;
pub const fresh_s: i64 = 86400;
pub const stale_s: i64 = 7 * 86400;
pub const ct_fresh_s: i64 = 86400;

/// classify never lets evidence fetched before its 90-day boundary mature
/// merely because the clock advanced. That boundary needs a fresh RDAP read.
pub fn classify(e: Evidence, fetched: i64, now: i64) Verdict {
    if (now < fetched or fetched < e.effective or e.effective < e.created) return .unknown;
    if (now - e.effective < threshold_s) return .young;
    if (fetched - e.effective < threshold_s) return .unknown;
    if (now - fetched <= fresh_s) return .mature;
    if (now - fetched <= stale_s) return .stale;
    return .unknown;
}

/// rdap accepts one bounded RDAP domain object, matching the registered name.
/// Ambiguous or missing registration events return null, never an old date.
pub fn rdap(gpa: mem.Allocator, name: []const u8, body: []const u8, fetched: i64) ?Evidence {
    if (body.len > 64 << 10 or body.len == 0 or !dnsName(name, false)) return null;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const Event = struct { eventAction: []const u8, eventDate: []const u8 };
    const Domain = struct {
        objectClassName: []const u8,
        ldhName: []const u8,
        events: []const Event,
    };
    const data = std.json.parseFromSliceLeaky(
        Domain,
        arena.allocator(),
        body,
        .{ .ignore_unknown_fields = true },
    ) catch return null;
    if (!mem.eql(u8, data.objectClassName, "domain") or
        !std.ascii.eqlIgnoreCase(data.ldhName, name) or data.events.len > 64) return null;
    var created: ?i64 = null;
    var effective: ?i64 = null;
    var earliest_reset: ?i64 = null;
    for (data.events) |event| {
        const original = mem.eql(u8, event.eventAction, "registration");
        const reset = mem.eql(u8, event.eventAction, "reregistration") or
            mem.eql(u8, event.eventAction, "reinstantiation");
        if (!original and !reset) continue;
        const when = timestamp(event.eventDate) orelse return null;
        if (when > fetched) return null;
        if (original) {
            if (created != null and created.? != when) return null;
            created = when;
        }
        if (reset) earliest_reset = @min(earliest_reset orelse when, when);
        effective = @max(effective orelse when, when);
    }
    const first = created orelse return null;
    const last = effective orelse return null;
    if (earliest_reset != null and earliest_reset.? < first) return null;
    if (last < first) return null;
    return .{ .registered = name, .created = first, .effective = last };
}

/// CT history proves a matching certificate was logged, not that the domain
/// has remained registered. Only an RDAP availability failure may use this
/// weaker evidence as a provisional result.
pub const CtHistory = struct {
    registered: []const u8,
    first_seen: i64,
};

/// crtsh reads a bounded crt.sh JSON result. For a timestamp without an
/// offset, this parser treats the service's value as UTC.
/// Any malformed entry makes the whole response unknown.
pub fn crtsh(gpa: mem.Allocator, name: []const u8, body: []const u8, fetched: i64) ?CtHistory {
    if (body.len == 0 or body.len > 256 << 10 or !dnsName(name, false)) return null;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const Entry = struct { name_value: []const u8, min_entry_timestamp: []const u8 };
    const data = std.json.parseFromSliceLeaky(
        []const Entry,
        arena.allocator(),
        body,
        .{ .ignore_unknown_fields = true },
    ) catch return null;
    if (data.len > 512) return null;
    var earliest: ?i64 = null;
    for (data) |entry| {
        if (entry.name_value.len > 4096) return null;
        var names = mem.splitScalar(u8, entry.name_value, '\n');
        var matches = false;
        while (names.next()) |raw| {
            const n = mem.trim(u8, raw, " \t\r");
            const host = if (mem.startsWith(u8, n, "*.")) n[2..] else n;
            var lower: [253]u8 = undefined;
            if (host.len == 0 or host.len > lower.len) continue;
            for (host, 0..) |c, i| lower[i] = std.ascii.toLower(c);
            if (dnsName(lower[0..host.len], false) and (std.ascii.eqlIgnoreCase(host, name) or
                (host.len > name.len and host[host.len - name.len - 1] == '.' and
                    std.ascii.eqlIgnoreCase(host[host.len - name.len ..], name)))) matches = true;
        }
        if (!matches) continue;
        const when = ctTimestamp(entry.min_entry_timestamp) orelse return null;
        if (when > fetched) return null;
        earliest = @min(earliest orelse when, when);
    }
    return .{ .registered = name, .first_seen = earliest orelse return null };
}

pub fn classifyCt(history: CtHistory, fetched: i64, now: i64) Verdict {
    if (now < fetched or fetched < history.first_seen or now - fetched > ct_fresh_s)
        return .unknown;
    if (fetched - history.first_seen < threshold_s) return .young;
    return .mature;
}

fn ctTimestamp(value: []const u8) ?i64 {
    if (value.len < 19 or value.len + 1 > 48) return null;
    if (value[value.len - 1] == 'Z') return timestamp(value);
    var buf: [48]u8 = undefined;
    @memcpy(buf[0..value.len], value);
    buf[value.len] = 'Z';
    return timestamp(buf[0 .. value.len + 1]);
}

/// timestamp parses RFC 3339 whole seconds, optional fractions and offsets.
fn timestamp(text: []const u8) ?i64 {
    if (text.len < 20 or text[4] != '-' or text[7] != '-' or text[10] != 'T' or
        text[13] != ':' or text[16] != ':') return null;
    const year = decimal(text[0..4]) orelse return null;
    const month = decimal(text[5..7]) orelse return null;
    const day = decimal(text[8..10]) orelse return null;
    const hour = decimal(text[11..13]) orelse return null;
    const minute = decimal(text[14..16]) orelse return null;
    const second = decimal(text[17..19]) orelse return null;
    if (year < 1970 or year > 9999 or month < 1 or month > 12 or
        day < 1 or day > monthDays(year, month) or hour > 23 or minute > 59 or
        second > 59) return null;
    var at: usize = 19;
    if (at < text.len and text[at] == '.') {
        at += 1;
        const start = at;
        while (at < text.len and std.ascii.isDigit(text[at])) : (at += 1) {}
        if (at == start) return null;
    }
    var offset: i64 = 0;
    if (at + 1 == text.len and text[at] == 'Z') {
        // UTC.
    } else if (at + 6 == text.len and (text[at] == '+' or text[at] == '-') and
        text[at + 3] == ':')
    {
        const oh = decimal(text[at + 1 .. at + 3]) orelse return null;
        const om = decimal(text[at + 4 .. at + 6]) orelse return null;
        if (oh > 23 or om > 59) return null;
        offset = @as(i64, @intCast(oh * 60 + om)) * 60;
        if (text[at] == '-') offset = -offset;
    } else return null;
    return daysFromCivil(@intCast(year), @intCast(month), @intCast(day)) * 86400 +
        @as(i64, @intCast(hour * 3600 + minute * 60 + second)) - offset;
}

fn decimal(text: []const u8) ?u32 {
    var n: u32 = 0;
    for (text) |c| {
        if (!std.ascii.isDigit(c)) return null;
        n = n * 10 + c - '0';
    }
    return n;
}

fn leap(year: u32) bool {
    return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0);
}

fn monthDays(year: u32, month: u32) u32 {
    return switch (month) {
        2 => if (leap(year)) 29 else 28,
        4, 6, 9, 11 => 30,
        else => 31,
    };
}

fn daysFromCivil(year: i64, month: i64, day: i64) i64 {
    const y = year - @intFromBool(month <= 2);
    const era = @divFloor(y, 400);
    const yoe = y - era * 400;
    const mp = month + (if (month > 2) @as(i64, -3) else 9);
    const doy = @divFloor(153 * mp + 2, 5) + day - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    return era * 146097 + doe - 719468;
}

const fixture_psl =
    "// ===BEGIN ICANN DOMAINS===\n" ++
    "com\nio\nuk\nco.uk\nck\n*.ck\n!www.ck\n" ++
    "// ===END ICANN DOMAINS===\n" ++
    "// ===BEGIN PRIVATE DOMAINS===\n" ++
    "github.io\nblogspot.com\n" ++
    "// ===END PRIVATE DOMAINS===\n";

test "PSL boundaries keep private tenants separate from registered owners" {
    const t = std.testing;
    try t.expectEqualStrings("example.co.uk", boundary("a.example.co.uk", fixture_psl).registered);
    try t.expectEqualStrings(
        "example.co.uk",
        boundary("_25._tcp.mail.example.co.uk", fixture_psl).registered,
    );
    try t.expectEqualStrings("github.io", boundary("github.io", fixture_psl).registered);
    try t.expect(boundary("alice.github.io", fixture_psl) == .tenant);
    try t.expect(boundary("b.blogspot.com", fixture_psl) == .tenant);
    try t.expectEqualStrings("www.ck", boundary("a.www.ck", fixture_psl).registered);
    try t.expectEqualStrings("foo.bar.ck", boundary("foo.bar.ck", fixture_psl).registered);
    try t.expect(boundary("example.unknown", fixture_psl) == .unknown);
    try t.expect(boundary("co.uk", fixture_psl) == .unknown);
}

test "RDAP age takes registration resets and refuses ambiguous evidence" {
    const t = std.testing;
    const base =
        "{\"objectClassName\":\"domain\",\"ldhName\":\"EXAMPLE.COM\",\"events\":[" ++
        "{\"eventAction\":\"registration\",\"eventDate\":\"2020-01-01T00:00:00Z\"}," ++
        "{\"eventAction\":\"reregistration\",\"eventDate\":\"2026-10-01T12:00:00Z\"}," ++
        "{\"eventAction\":\"last changed\",\"eventDate\":\"2026-10-23T00:00:00Z\"}]}";
    const found = rdap(t.allocator, "example.com", base, timestamp("2026-10-23T00:00:00Z").?).?;
    try t.expectEqual(timestamp("2020-01-01T00:00:00Z").?, found.created);
    try t.expectEqual(timestamp("2026-10-01T12:00:00Z").?, found.effective);
    try t.expect(rdap(t.allocator, "other.com", base, found.effective) == null);
    try t.expect(rdap(t.allocator, "example.com", base, found.effective - 1) == null);
    try t.expect(rdap(t.allocator, "example.com", "{}", found.effective) == null);
    const conflict =
        "{\"objectClassName\":\"domain\",\"ldhName\":\"example.com\",\"events\":[" ++
        "{\"eventAction\":\"registration\",\"eventDate\":\"2020-01-01T00:00:00Z\"}," ++
        "{\"eventAction\":\"registration\",\"eventDate\":\"2021-01-01T00:00:00Z\"}]}";
    try t.expect(rdap(t.allocator, "example.com", conflict, found.effective) == null);
    try t.expectEqual(@as(i64, 0), timestamp("1970-01-01T00:00:00Z").?);
    try t.expectEqual(
        timestamp("2026-10-01T12:00:00Z").?,
        timestamp("2026-10-01T08:00:00-04:00").?,
    );
    try t.expectEqual(
        timestamp("2026-10-01T12:00:00Z").?,
        timestamp("2026-10-01T12:00:00.123+00:00").?,
    );
    try t.expect(timestamp("2026-02-29T00:00:00Z") == null);
}

test "age at the threshold needs a fresh fetch; mature evidence expires" {
    const t = std.testing;
    try t.expectEqual(@as(i64, 90 * 86400), threshold_s);
    const e: Evidence = .{ .registered = "example.com", .created = 1, .effective = 1000 };
    try t.expectEqual(Verdict.young, classify(e, 1000, 1000 + threshold_s - 1));
    try t.expectEqual(Verdict.unknown, classify(e, 1000, 1000 + threshold_s));
    const fetched = 1000 + threshold_s;
    try t.expectEqual(Verdict.mature, classify(e, fetched, fetched + fresh_s));
    try t.expectEqual(Verdict.stale, classify(e, fetched, fetched + fresh_s + 1));
    try t.expectEqual(Verdict.unknown, classify(e, fetched, fetched + stale_s + 1));
    try t.expectEqual(Verdict.unknown, classify(e, fetched, fetched - 1));
}

test "crt.sh fallback uses matching log-entry time and expires in one day" {
    const t = std.testing;
    const fetched = timestamp("2026-10-23T00:00:00Z").?;
    const body =
        "[{\"name_value\":\"foo.example.com.evil.org\",\"min_entry_timestamp\":\"2010-01-01T00:0" ++
        "0:00\"}," ++
        "{\"name_value\":\"*.EXAMPLE.COM\",\"min_entry_timestamp\":\"2026-01-01T00:00:00.123\"}]";
    const found = crtsh(t.allocator, "example.com", body, fetched).?;
    try t.expectEqual(timestamp("2026-01-01T00:00:00Z").?, found.first_seen);
    try t.expectEqual(Verdict.mature, classifyCt(found, fetched, fetched + ct_fresh_s));
    try t.expectEqual(Verdict.unknown, classifyCt(found, fetched, fetched + ct_fresh_s + 1));
    try t.expect(crtsh(t.allocator, "other.com", body, fetched) == null);
    const future =
        "[{\"name_value\":\"example.com\",\"min_entry_timestamp\":\"2026-10-24T00:00:00\"}]";
    try t.expect(crtsh(t.allocator, "example.com", future, fetched) == null);
    const young =
        "[{\"name_value\":\"example.com\",\"min_entry_timestamp\":\"2026-10-01T00:00:00\"}]";
    try t.expectEqual(
        Verdict.young,
        classifyCt(crtsh(t.allocator, "example.com", young, fetched).?, fetched, fetched),
    );
}
