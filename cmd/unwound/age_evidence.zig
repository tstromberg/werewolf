//! Turn bounded provider replies into dated SQLite evidence. A fetch child
//! parses what providers said into Found, a few dates; the writer checks
//! those dates again before it records anything.
const std = @import("std");
const age = @import("age.zig");
const age_db = @import("age_db.zig");

const retry_s: i64 = 3600;

/// Found is what a fetch learned: dates only, no text. The writer trusts
/// none of it until decode has checked every field.
pub const Found = struct {
    rdap: union(enum) {
        unavailable,
        /// A registry answered, but not with usable registration events.
        invalid,
        valid: struct { created: i64, effective: i64 },
    },
    /// CT is consulted only when RDAP was unavailable.
    ct: union(enum) { none, invalid, history: i64 } = .none,
};

pub const found_len = 26;

/// found parses one RDAP lookup and, after an RDAP outage, crt.sh history.
pub fn found(
    allocator: std.mem.Allocator,
    domain: []const u8,
    lookup: age.Lookup,
    ct_body: ?[]const u8,
    now: i64,
) Found {
    switch (lookup) {
        .body => |body| {
            const e = age.rdap(allocator, domain, body, now) orelse return .{ .rdap = .invalid };
            return .{ .rdap = .{ .valid = .{ .created = e.created, .effective = e.effective } } };
        },
        .unavailable => {
            const body = ct_body orelse return .{ .rdap = .unavailable };
            const history = age.crtsh(allocator, domain, body, now) orelse
                return .{ .rdap = .unavailable, .ct = .invalid };
            return .{ .rdap = .unavailable, .ct = .{ .history = history.first_seen } };
        },
    }
}

pub fn encode(out: *[found_len]u8, f: Found) void {
    @memset(out, 0);
    out[0] = @backingInt(std.meta.activeTag(f.rdap));
    out[1] = @backingInt(std.meta.activeTag(f.ct));
    if (f.rdap == .valid) {
        std.mem.writeInt(i64, out[2..10], f.rdap.valid.created, .big);
        std.mem.writeInt(i64, out[10..18], f.rdap.valid.effective, .big);
    }
    if (f.ct == .history) std.mem.writeInt(i64, out[18..26], f.ct.history, .big);
}

/// decode accepts only the one encoding of a consistent result: dates in
/// order and not after now, unused fields zero, and CT only after an outage.
pub fn decode(b: []const u8, now: i64) ?Found {
    if (b.len != found_len) return null;
    const created = std.mem.readInt(i64, b[2..10], .big);
    const effective = std.mem.readInt(i64, b[10..18], .big);
    const seen = std.mem.readInt(i64, b[18..26], .big);
    var f: Found = .{ .rdap = switch (b[0]) {
        0 => .unavailable,
        1 => .invalid,
        2 => .{ .valid = .{ .created = created, .effective = effective } },
        else => return null,
    } };
    if (f.rdap == .valid) {
        if (created < 0 or created > effective or effective > now) return null;
    } else if (created != 0 or effective != 0) return null;
    f.ct = switch (b[1]) {
        0 => .none,
        1 => .invalid,
        2 => .{ .history = seen },
        else => return null,
    };
    if (f.ct == .history) {
        if (seen < 0 or seen > now) return null;
    } else if (seen != 0) return null;
    if (f.ct != .none and f.rdap != .unavailable) return null;
    return f;
}

/// record turns checked dates into the row the writer stores. An outage is
/// retried within the hour: CT history alone never authorizes a name, so
/// only a fresh RDAP answer can.
pub fn record(
    domain: []const u8,
    f: Found,
    rdap_url: ?[]const u8,
    now: i64,
    psl_generation: []const u8,
    bootstrap_generation: []const u8,
) age_db.Result {
    var out: age_db.Result = .{
        .domain = domain,
        .finished_at = now,
        .rdap_result = .unknown,
        .source = .none,
        .status = .unknown,
        .fetched_at = now,
        .retry_after = now + retry_s,
        .psl_generation = psl_generation,
        .bootstrap_generation = bootstrap_generation,
    };
    switch (f.rdap) {
        .invalid => {
            out.source = .rdap;
            out.evidence_uri = rdap_url;
        },
        .valid => |e| {
            out.source = .rdap;
            out.evidence_uri = rdap_url;
            out.rdap_result = .valid;
            out.status = .valid;
            out.registered_at = e.created;
            out.effective_at = e.effective;
            out.retry_after = now + age.rdap_cache_s;
            const evidence: age.Evidence = .{
                .registered = domain,
                .created = e.created,
                .effective = e.effective,
            };
            if (age.classify(evidence, now, now) == .young)
                out.retry_after = @min(out.retry_after, e.effective + age.threshold_s);
        },
        .unavailable => {
            out.rdap_result = .@"error";
            out.status = .@"error";
            switch (f.ct) {
                .none => {},
                .invalid => out.crtsh_result = .@"error",
                .history => |seen| {
                    out.crtsh_result = .history;
                    out.source = .crtsh;
                    out.status = .history;
                    out.ct_first_seen_at = seen;
                    out.evidence_uri = "https://crt.sh/";
                },
            }
        },
    }
    return out;
}

test "writer preserves RDAP dates, including a reset that makes a domain young" {
    const t = std.testing;
    const body =
        "{\"objectClassName\":\"domain\",\"ldhName\":\"example.com\",\"events\":[" ++
        "{\"eventAction\":\"registration\",\"eventDate\":\"2020-01-01T00:00:00Z\"}," ++
        "{\"eventAction\":\"reregistration\",\"eventDate\":\"2026-09-28T00:00:00Z\"}]}";
    const now: i64 = 1_792_716_800; // 2026-10-23, after the reset but under 30 days.
    const r = record(
        "example.com",
        found(t.allocator, "example.com", .{ .body = body }, null, now),
        "https://rdap.example/domain/example.com",
        now,
        "psl",
        "iana",
    );
    try t.expect(r.rdap_result == .valid);
    try t.expect(r.source == .rdap);
    try t.expect(r.registered_at.? < r.effective_at.?);
    try t.expectEqual(r.effective_at.? + age.threshold_s, r.retry_after);
}

test "malformed RDAP cannot be replaced by old CT history" {
    const t = std.testing;
    const ct = "[{\"name_value\":\"example.com\",\"min_entry_timestamp\":\"2020-01-01T00:00:00\"}]";
    const now: i64 = 1_792_716_800;
    const r = record(
        "example.com",
        found(t.allocator, "example.com", .{ .body = "{}" }, ct, now),
        null,
        now,
        "psl",
        "iana",
    );
    try t.expect(r.source == .rdap);
    try t.expect(r.status == .unknown);
    try t.expectEqual(@as(?i64, null), r.ct_first_seen_at);
}

test "an RDAP outage records dated CT history and retries within the hour" {
    const t = std.testing;
    const body = "[{\"name_value\":\"*.example.com\",\"min_entry_timestamp\":\"2020-01-01T00:00:" ++
        "00\"}]";
    const now: i64 = 1_792_716_800;
    const f = found(t.allocator, "example.com", .unavailable, body, now);
    const r = record("example.com", f, null, now, "psl", "iana");
    try t.expect(r.rdap_result == .@"error");
    try t.expect(r.source == .crtsh);
    try t.expect(r.status == .history);
    try t.expectEqual(now + 3600, r.retry_after);
}

test "fetch results round trip, and anything inconsistent is refused" {
    const t = std.testing;
    const now: i64 = 1_792_716_800;
    var buf: [found_len]u8 = undefined;
    for ([_]Found{
        .{ .rdap = .unavailable },
        .{ .rdap = .invalid },
        .{ .rdap = .{ .valid = .{ .created = 1, .effective = now } } },
        .{ .rdap = .unavailable, .ct = .invalid },
        .{ .rdap = .unavailable, .ct = .{ .history = 0 } },
    }) |f| {
        encode(&buf, f);
        try t.expectEqualDeep(f, decode(&buf, now).?);
    }
    try t.expect(decode(buf[0 .. found_len - 1], now) == null);
    for ([_]Found{
        .{ .rdap = .{ .valid = .{ .created = 2, .effective = 1 } } },
        .{ .rdap = .{ .valid = .{ .created = -1, .effective = 1 } } },
        .{ .rdap = .{ .valid = .{ .created = 1, .effective = now + 1 } } },
        .{ .rdap = .unavailable, .ct = .{ .history = now + 1 } },
        .{ .rdap = .invalid, .ct = .invalid },
        .{ .rdap = .{ .valid = .{ .created = 1, .effective = 1 } }, .ct = .{ .history = 1 } },
    }) |f| {
        encode(&buf, f);
        try t.expect(decode(&buf, now) == null);
    }
    encode(&buf, .{ .rdap = .unavailable });
    buf[0] = 3;
    try t.expect(decode(&buf, now) == null);
    encode(&buf, .{ .rdap = .invalid });
    buf[5] = 1;
    try t.expect(decode(&buf, now) == null);
}
