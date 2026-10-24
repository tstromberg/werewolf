//! Offline domain-age evidence parsing. No network or policy decision lives
//! here. The age worker will use this to validate bounded evidence before
//! writing SQLite; unwound must not authorize from unverified evidence.
const std = @import("std");
const mem = std.mem;

/// psl is the image-pinned Public Suffix List, normalized to A-labels.
pub const psl = @embedFile("data/public_suffix_list.ascii.dat");

pub const Boundary = union(enum) {
    unknown,
    tenant,
    registered: []const u8,
};

const Section = enum { none, icann, private };
const Rule = enum { exact, wildcard, exception };

/// Rules reads a PSL's ICANN and PRIVATE rules, skipping malformed ones.
const Rules = struct {
    lines: mem.SplitIterator(u8, .scalar),
    section: Section = .none,

    const Entry = struct { section: Section, rule: Rule, value: []const u8 };

    fn init(list: []const u8) Rules {
        return .{ .lines = mem.splitScalar(u8, list, '\n') };
    }

    fn next(r: *Rules) ?Entry {
        while (r.lines.next()) |raw| {
            const line = mem.trim(u8, raw, " \t\r");
            if (mem.eql(u8, line, "// ===BEGIN ICANN DOMAINS===")) {
                r.section = .icann;
                continue;
            }
            if (mem.eql(u8, line, "// ===END ICANN DOMAINS===")) {
                r.section = .none;
                continue;
            }
            if (mem.eql(u8, line, "// ===BEGIN PRIVATE DOMAINS===")) {
                r.section = .private;
                continue;
            }
            if (mem.eql(u8, line, "// ===END PRIVATE DOMAINS===")) {
                r.section = .none;
                continue;
            }
            if (r.section == .none or line.len == 0 or mem.startsWith(u8, line, "//")) continue;
            const rule: Rule = if (mem.startsWith(u8, line, "!"))
                .exception
            else if (mem.startsWith(u8, line, "*."))
                .wildcard
            else
                .exact;
            const value = switch (rule) {
                .exact => line,
                .wildcard => line[2..],
                .exception => line[1..],
            };
            if (!dnsName(value, false)) continue;
            return .{ .section = r.section, .rule = rule, .value = value };
        }
        return null;
    }
};

/// boundary applies the PSL's longest-rule algorithm to an ASCII DNS name.
/// A PRIVATE tenant cannot inherit its provider's RDAP age. The PSL must be
/// normalized to A-labels by the updater before calling this function.
pub fn boundary(name: []const u8, list: []const u8) Boundary {
    if (!dnsName(name, true)) return .unknown;
    var best_len: usize = 0;
    var best_rule: Rule = .exact;
    var best_section: Section = .none;
    var rules: Rules = .init(list);
    while (rules.next()) |r| {
        if (!suffixMatch(name, r.value)) continue;
        if (r.section == .private and mem.eql(u8, name, r.value)) continue;
        const n = labels(r.value) + @intFromBool(r.rule == .wildcard);
        if (labels(name) < n) continue;
        if (n < best_len or (n == best_len and r.rule != .exception)) continue;
        best_len = n;
        best_rule = r.rule;
        best_section = r.section;
    }
    if (best_len == 0) return .unknown;
    const suffix_labels = best_len - @intFromBool(best_rule == .exception);
    if (labels(name) <= suffix_labels) return .unknown;
    if (best_section == .private) return .tenant;
    return .{ .registered = suffix(name, suffix_labels + 1) };
}

/// exemptable reports whether an assigned system domain may open the names
/// below it to every DNS-enabled service without an age check. No public
/// suffix may lie at or below it, since anyone may register or claim names
/// there: it must sit inside one registered domain, or under a TLD the list
/// does not name at all, such as .internal or .test.
pub fn exemptable(domain: []const u8, list: []const u8) bool {
    if (!dnsName(domain, false)) return false;
    const tld = domain[(mem.findScalarLast(u8, domain, '.') orelse return false) + 1 ..];
    var listed = false;
    var rules: Rules = .init(list);
    while (rules.next()) |r| {
        if (r.rule != .exception and suffixMatch(r.value, domain)) return false;
        if (suffixMatch(r.value, tld)) listed = true;
    }
    return !listed or boundary(domain, list) == .registered;
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

/// suffixMatch reports whether name is part or a name below it.
pub fn suffixMatch(name: []const u8, part: []const u8) bool {
    return mem.eql(u8, name, part) or (name.len > part.len and
        mem.endsWith(u8, name, part) and name[name.len - part.len - 1] == '.');
}

pub fn labels(name: []const u8) usize {
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

/// Verdict and Source values are also their age IPC wire encoding.
pub const Verdict = enum(u8) { unknown = 0, young = 1, mature = 2 };
pub const Source = enum(u8) { none = 0, rdap = 1, crtsh = 2 };
pub const Status = enum { valid, history, unknown, @"error" };
pub const threshold_s: i64 = 30 * 86400;
pub const rdap_cache_s: i64 = 7 * 86400;
pub const ct_fresh_s: i64 = 86400;

/// classify never lets evidence fetched before its 30-day boundary mature
/// merely because the clock advanced. That boundary needs a fresh RDAP read.
pub fn classify(e: Evidence, fetched: i64, now: i64) Verdict {
    if (now < fetched or fetched < e.effective or e.effective < e.created) return .unknown;
    if (now - fetched > rdap_cache_s) return .unknown;
    if (now - e.effective < threshold_s) return .young;
    if (fetched - e.effective < threshold_s) return .unknown;
    return .mature;
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
/// has remained registered, and anyone on the path can make RDAP unavailable.
/// Only an RDAP availability failure consults it, and only to refuse.
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
            var buf: [253]u8 = undefined;
            if (host.len == 0 or host.len > buf.len) continue;
            const lower = std.ascii.lowerString(&buf, host);
            if (dnsName(lower, false) and suffixMatch(lower, name)) matches = true;
        }
        if (!matches) continue;
        const when = ctTimestamp(entry.min_entry_timestamp) orelse return null;
        if (when > fetched) return null;
        earliest = @min(earliest orelse when, when);
    }
    return .{ .registered = name, .first_seen = earliest orelse return null };
}

/// classifyCt lets CT history make a decision stricter, never looser: a
/// recent first certificate is young, and anything else stays unknown.
pub fn classifyCt(history: CtHistory, fetched: i64, now: i64) Verdict {
    if (now < fetched or fetched < history.first_seen or now - fetched > ct_fresh_s)
        return .unknown;
    if (fetched - history.first_seen < threshold_s) return .young;
    return .unknown;
}

pub const Lookup = union(enum) {
    /// Transport failure, timeout, rate limit or server failure.
    unavailable,
    /// A registry response, including a semantically invalid one.
    body: []const u8,
};

pub const Decision = struct {
    source: Source,
    verdict: Verdict,
};

/// decide allows CT fallback only when the RDAP service was unavailable.
/// A registry response with young or ambiguous events is never replaced.
pub fn decide(
    gpa: mem.Allocator,
    name: []const u8,
    lookup: Lookup,
    rdap_fetched: i64,
    ct_body: ?[]const u8,
    ct_fetched: i64,
    now: i64,
) Decision {
    switch (lookup) {
        .body => |body| {
            const evidence = rdap(gpa, name, body, rdap_fetched) orelse
                return .{ .source = .rdap, .verdict = .unknown };
            return .{ .source = .rdap, .verdict = classify(evidence, rdap_fetched, now) };
        },
        .unavailable => {
            const body = ct_body orelse return .{ .source = .none, .verdict = .unknown };
            const history = crtsh(gpa, name, body, ct_fetched) orelse
                return .{ .source = .crtsh, .verdict = .unknown };
            return .{ .source = .crtsh, .verdict = classifyCt(history, ct_fetched, now) };
        },
    }
}

/// Cached is the typed form of one domain_age row. The worker must parse the
/// SQLite row into this shape before using it; no persisted verdict is trusted.
pub const Cached = struct {
    domain: []const u8,
    source: Source,
    status: Status,
    registered_at: ?i64 = null,
    effective_at: ?i64 = null,
    ct_first_seen_at: ?i64 = null,
    fetched_at: i64,
};

/// cachedVerdict recomputes a verdict from dated evidence at every use. A
/// previous mature result is never durable authority by itself. RDAP is
/// usable for seven days; CT history can mark a domain young for one day.
pub fn cachedVerdict(
    row: Cached,
    domain: []const u8,
    now: i64,
) Verdict {
    if (!dnsName(domain, false) or !mem.eql(u8, row.domain, domain) or
        row.fetched_at < 0 or now < row.fetched_at) return .unknown;
    switch (row.source) {
        .rdap => {
            if (row.status != .valid or row.ct_first_seen_at != null) return .unknown;
            const evidence: Evidence = .{
                .registered = row.domain,
                .created = row.registered_at orelse return .unknown,
                .effective = row.effective_at orelse return .unknown,
            };
            return classify(evidence, row.fetched_at, now);
        },
        .crtsh => {
            if (row.status != .history or
                row.registered_at != null or row.effective_at != null) return .unknown;
            return classifyCt(.{
                .registered = row.domain,
                .first_seen = row.ct_first_seen_at orelse return .unknown,
            }, row.fetched_at, now);
        },
        .none => return .unknown,
    }
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

test "pinned PSL handles ICANN, PRIVATE, wildcard and Unicode A-label rules" {
    const t = std.testing;
    try t.expectEqualStrings("example.co.uk", boundary("a.example.co.uk", psl).registered);
    try t.expectEqualStrings("github.io", boundary("github.io", psl).registered);
    try t.expect(boundary("alice.github.io", psl) == .tenant);
    try t.expectEqualStrings("www.ck", boundary("a.www.ck", psl).registered);
    try t.expectEqualStrings(
        "x.xn--aroport-bya.ci",
        boundary("x.xn--aroport-bya.ci", psl).registered,
    );
}

test "a system domain may not exempt a public suffix or its tenants" {
    const t = std.testing;
    for ([_][]const u8{
        "corp.example.com",
        "example.co.uk",
        "c.project.internal",
        "assigned.test",
        "corp.example.test",
    }) |good| try t.expect(exemptable(good, psl));
    for ([_][]const u8{
        "com",
        "co.uk",
        "uk",
        "github.io",
        "alice.github.io",
        "blogspot.com",
        "foo.ck",
        "amazonaws.com",
        "",
        "Example.COM",
    }) |bad| try t.expect(!exemptable(bad, psl));
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

test "age at the threshold needs a fresh fetch; RDAP expires after seven days" {
    const t = std.testing;
    try t.expectEqual(@as(i64, 30 * 86400), threshold_s);
    const e: Evidence = .{ .registered = "example.com", .created = 1, .effective = 1000 };
    try t.expectEqual(Verdict.young, classify(e, 1000, 1000 + rdap_cache_s));
    try t.expectEqual(Verdict.unknown, classify(e, 1000, 1000 + rdap_cache_s + 1));
    try t.expectEqual(Verdict.unknown, classify(e, 1000 + threshold_s - 1, 1000 + threshold_s));
    const fetched = 1000 + threshold_s;
    try t.expectEqual(Verdict.mature, classify(e, fetched, fetched + rdap_cache_s));
    try t.expectEqual(Verdict.unknown, classify(e, fetched, fetched + rdap_cache_s + 1));
    try t.expectEqual(Verdict.unknown, classify(e, fetched, fetched - 1));
}

test "crt.sh history uses matching log-entry time and can only refuse" {
    const t = std.testing;
    const fetched = timestamp("2026-10-23T00:00:00Z").?;
    const body =
        "[{\"name_value\":\"foo.example.com.evil.org\",\"min_entry_timestamp\":\"2010-01-01T00:0" ++
        "0:00\"}," ++
        "{\"name_value\":\"*.EXAMPLE.COM\",\"min_entry_timestamp\":\"2026-01-01T00:00:00.123\"}]";
    const found = crtsh(t.allocator, "example.com", body, fetched).?;
    try t.expectEqual(timestamp("2026-01-01T00:00:00Z").?, found.first_seen);
    try t.expectEqual(Verdict.unknown, classifyCt(found, fetched, fetched));
    try t.expect(crtsh(t.allocator, "other.com", body, fetched) == null);
    const future =
        "[{\"name_value\":\"example.com\",\"min_entry_timestamp\":\"2026-10-24T00:00:00\"}]";
    try t.expect(crtsh(t.allocator, "example.com", future, fetched) == null);
    const young =
        "[{\"name_value\":\"example.com\",\"min_entry_timestamp\":\"2026-10-01T00:00:00\"}]";
    const recent = crtsh(t.allocator, "example.com", young, fetched).?;
    try t.expectEqual(Verdict.young, classifyCt(recent, fetched, fetched + ct_fresh_s));
    try t.expectEqual(Verdict.unknown, classifyCt(recent, fetched, fetched + ct_fresh_s + 1));
}

test "CT never overrides a young or malformed RDAP response" {
    const t = std.testing;
    const fetched = timestamp("2026-10-23T00:00:00Z").?;
    const ct =
        "[{\"name_value\":\"example.com\",\"min_entry_timestamp\":\"2020-01-01T00:00:00\"}]";
    const young =
        "{\"objectClassName\":\"domain\",\"ldhName\":\"example.com\",\"events\":[" ++
        "{\"eventAction\":\"registration\",\"eventDate\":\"2026-10-01T00:00:00Z\"}]}";
    try t.expectEqual(
        Verdict.young,
        decide(
            t.allocator,
            "example.com",
            .{ .body = young },
            fetched,
            ct,
            fetched,
            fetched,
        ).verdict,
    );
    const ambiguous = decide(
        t.allocator,
        "example.com",
        .{ .body = "{}" },
        fetched,
        ct,
        fetched,
        fetched,
    );
    try t.expectEqual(.rdap, ambiguous.source);
    try t.expectEqual(Verdict.unknown, ambiguous.verdict);
    const fallback = decide(
        t.allocator,
        "example.com",
        .unavailable,
        fetched,
        ct,
        fetched,
        fetched,
    );
    try t.expectEqual(.crtsh, fallback.source);
    try t.expectEqual(Verdict.unknown, fallback.verdict);
}

test "cached evidence uses one RDAP lifetime and one CT lifetime" {
    const t = std.testing;
    const fetched = timestamp("2026-10-23T00:00:00Z").?;
    const created = timestamp("2020-01-01T00:00:00Z").?;
    var row: Cached = .{
        .domain = "example.com",
        .source = .rdap,
        .status = .valid,
        .registered_at = created,
        .effective_at = created,
        .fetched_at = fetched,
    };
    const check = struct {
        fn at(value: Cached, now: i64) Verdict {
            return cachedVerdict(value, "example.com", now);
        }
    }.at;
    try t.expectEqual(Verdict.mature, check(row, fetched + rdap_cache_s));
    try t.expectEqual(Verdict.unknown, check(row, fetched + rdap_cache_s + 1));
    try t.expectEqual(Verdict.unknown, check(row, fetched - 1));
    try t.expectEqual(Verdict.unknown, cachedVerdict(row, "other.com", fetched));

    row.source = .crtsh;
    row.status = .history;
    row.registered_at = null;
    row.effective_at = null;
    row.ct_first_seen_at = created;
    try t.expectEqual(Verdict.unknown, check(row, fetched));
    row.ct_first_seen_at = fetched - threshold_s + 1;
    try t.expectEqual(Verdict.young, check(row, fetched + ct_fresh_s));
    try t.expectEqual(Verdict.unknown, check(row, fetched + ct_fresh_s + 1));
    row.status = .unknown;
    try t.expectEqual(Verdict.unknown, check(row, fetched));
}
