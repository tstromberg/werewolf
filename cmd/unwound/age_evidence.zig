//! Turn bounded provider replies into dated SQLite evidence. The age
//! authority validates identity and dates before storing any evidence.
const std = @import("std");
const age = @import("age.zig");
const age_db = @import("age_db.zig");

const retry_s: i64 = 3600;

pub fn result(
    allocator: std.mem.Allocator,
    domain: []const u8,
    lookup: age.Lookup,
    rdap_url: ?[]const u8,
    ct_body: ?[]const u8,
    now: i64,
    psl_generation: []const u8,
    bootstrap_generation: []const u8,
) age_db.Result {
    const base: age_db.Result = .{
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
    switch (lookup) {
        .body => |body| {
            var out = base;
            out.source = .rdap;
            out.evidence_uri = rdap_url;
            const evidence = age.rdap(allocator, domain, body, now) orelse return out;
            out.rdap_result = .valid;
            out.status = .valid;
            out.registered_at = evidence.created;
            out.effective_at = evidence.effective;
            out.retry_after = now + age.rdap_cache_s;
            if (age.classify(evidence, now, now) == .young)
                out.retry_after = @min(out.retry_after, evidence.effective + age.threshold_s);
            return out;
        },
        .unavailable => {
            var out = base;
            out.rdap_result = .@"error";
            out.status = .@"error";
            const body = ct_body orelse return out;
            out.crtsh_result = .@"error";
            const history = age.crtsh(allocator, domain, body, now) orelse return out;
            out.crtsh_result = .history;
            out.source = .crtsh;
            out.status = .history;
            out.ct_first_seen_at = history.first_seen;
            out.evidence_uri = "https://crt.sh/";
            out.retry_after = now + age.ct_fresh_s;
            if (age.classifyCt(history, now, now) == .young)
                out.retry_after = @min(out.retry_after, history.first_seen + age.threshold_s);
            return out;
        },
    }
}

test "writer preserves RDAP dates, including a reset that makes a domain young" {
    const t = std.testing;
    const body =
        "{\"objectClassName\":\"domain\",\"ldhName\":\"example.com\",\"events\":[" ++
        "{\"eventAction\":\"registration\",\"eventDate\":\"2020-01-01T00:00:00Z\"}," ++
        "{\"eventAction\":\"reregistration\",\"eventDate\":\"2026-07-30T00:00:00Z\"}]}";
    const now: i64 = 1_792_716_800; // 2026-10-23, after the reset but under 90 days.
    const r = result(
        t.allocator,
        "example.com",
        .{ .body = body },
        "https://rdap.example/domain/example.com",
        null,
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
    const r = result(
        t.allocator,
        "example.com",
        .{ .body = "{}" },
        null,
        "[{\"name_value\":\"example.com\",\"min_entry_timestamp\":\"2020-01-01T00:00:00\"}]",
        1_792_716_800,
        "psl",
        "iana",
    );
    try t.expect(r.source == .rdap);
    try t.expect(r.status == .unknown);
    try t.expectEqual(@as(?i64, null), r.ct_first_seen_at);
}

test "an RDAP outage may use dated CT history" {
    const t = std.testing;
    const body = "[{\"name_value\":\"*.example.com\",\"min_entry_timestamp\":\"2020-01-01T00:00:" ++
        "00\"}]";
    const now: i64 = 1_792_716_800;
    const r = result(t.allocator, "example.com", .unavailable, null, body, now, "psl", "iana");
    try t.expect(r.rdap_result == .@"error");
    try t.expect(r.source == .crtsh);
    try t.expect(r.status == .history);
    try t.expectEqual(now + age.ct_fresh_s, r.retry_after);
}
