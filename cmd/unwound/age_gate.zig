//! Validate one age-worker answer before it can release a waiting DNS query.
//! The frontend independently derives the PSL boundary; an answer naming a
//! different domain cannot authorize the query, even if the worker errs.
const std = @import("std");
const age = @import("age.zig");
const ipc = @import("age_ipc.zig");

pub const Outcome = enum { ignore, refuse_young, refuse_unknown, allow };

/// An alias in the answer may stay inside the age-checked registered domain.
/// An alias elsewhere must be looked up separately and pass its own age gate.
pub fn sameRegistered(a: []const u8, b: []const u8, psl: []const u8) bool {
    const left = switch (age.boundary(a, psl)) {
        .registered => |domain| domain,
        else => return false,
    };
    const right = switch (age.boundary(b, psl)) {
        .registered => |domain| domain,
        else => return false,
    };
    return std.mem.eql(u8, left, right);
}

pub fn decide(request: *const ipc.Request, reply: *const ipc.Response, psl: []const u8) Outcome {
    if (reply.request_id != request.request_id) return .ignore;
    const domain = switch (age.boundary(request.name.text(), psl)) {
        .registered => |name| name,
        else => return .refuse_unknown,
    };
    const supplied = if (reply.domain) |name| name.text() else return .refuse_unknown;
    if (!std.mem.eql(u8, domain, supplied)) return .refuse_unknown;
    return switch (reply.verdict) {
        .mature => if (reply.source == .none) .refuse_unknown else .allow,
        .young => .refuse_young,
        .unknown => .refuse_unknown,
    };
}

test "only mature evidence for the request's registered domain releases DNS" {
    const t = std.testing;
    const wire = @import("wire.zig");
    const psl =
        "// ===BEGIN ICANN DOMAINS===\ncom\n// ===END ICANN DOMAINS===\n" ++
        "// ===BEGIN PRIVATE DOMAINS===\ngithub.io\n// ===END PRIVATE DOMAINS===\n";
    const request: ipc.Request = .{
        .request_id = 19,
        .dns_id = 7,
        .qtype = .a,
        .service = 1,
        .line = 8,
        .policy_generation = 9,
        .transport = .udp,
        .name = try wire.Name.fromText("a.example.com"),
    };
    var reply: ipc.Response = .{
        .request_id = 19,
        .verdict = .mature,
        .source = .rdap,
        .domain = try wire.Name.fromText("example.com"),
    };
    try t.expectEqual(Outcome.allow, decide(&request, &reply, psl));
    reply.domain = try wire.Name.fromText("other.com");
    try t.expectEqual(Outcome.refuse_unknown, decide(&request, &reply, psl));
    reply.request_id = 18;
    try t.expectEqual(Outcome.ignore, decide(&request, &reply, psl));
    reply.request_id = 19;
    reply.domain = try wire.Name.fromText("example.com");
    reply.verdict = .young;
    try t.expectEqual(Outcome.refuse_young, decide(&request, &reply, psl));
    reply.verdict = .unknown;
    try t.expectEqual(Outcome.refuse_unknown, decide(&request, &reply, psl));
    var tenant = request;
    tenant.name = try wire.Name.fromText("alice.github.io");
    reply.verdict = .mature;
    reply.domain = try wire.Name.fromText("github.io");
    try t.expectEqual(Outcome.refuse_unknown, decide(&tenant, &reply, psl));
    try t.expect(sameRegistered("a.example.com", "edge.example.com", psl));
    try t.expect(!sameRegistered("a.example.com", "edge.other.com", psl));
    try t.expect(!sameRegistered("a.example.com", "alice.github.io", psl));
}
