//! Exact release authorization carried by a signed TPM NV-extend record.
const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;
pub const Digest = [32]u8;
pub const tag = "werewolf.boot/2\x00";
pub const size = tag.len + 5 * 32;

pub fn releaseId(
    arch: []const u8,
    root: Digest,
    kernel: Digest,
    stage0: Digest,
    context: Digest,
) Digest {
    var hash = Sha256.init(.{});
    hash.update("werewolf.release/2\x00");
    hash.update(arch);
    hash.update(&.{0});
    for ([4]Digest{ root, kernel, stage0, context }) |part| hash.update(&part);
    return hash.finalResult();
}

pub const Record = struct {
    machine: Digest,
    previous: Digest,
    retained: Digest,
    candidate: Digest,
    pcr: Digest,

    pub fn encode(s: Record) [size]u8 {
        var out: [size]u8 = undefined;
        @memcpy(out[0..tag.len], tag);
        inline for (.{ "machine", "previous", "retained", "candidate", "pcr" }, 0..) |field, i|
            @memcpy(out[tag.len + i * 32 ..][0..32], &@field(s, field));
        return out;
    }

    pub fn decode(raw: []const u8) !Record {
        if (raw.len != size or !std.mem.eql(u8, raw[0..tag.len], tag))
            return error.BadBootState;
        var s: Record = undefined;
        inline for (.{ "machine", "previous", "retained", "candidate", "pcr" }, 0..) |field, i|
            @memcpy(&@field(s, field), raw[tag.len + i * 32 ..][0..32]);
        const zero: Digest = @splat(0);
        inline for (.{ "machine", "retained", "candidate", "pcr" }) |field|
            if (std.mem.eql(u8, &@field(s, field), &zero)) return error.BadBootState;
        if (std.mem.eql(u8, &s.previous, &zero) and
            !std.mem.eql(u8, &s.retained, &s.candidate)) return error.BadBootState;
        return s;
    }

    pub fn digest(s: Record) Digest {
        var result: Digest = undefined;
        Sha256.hash(&s.encode(), &result, .{});
        return result;
    }

    pub fn anchor(s: Record) Digest {
        var hash = Sha256.init(.{});
        hash.update(&s.previous);
        hash.update(&s.digest());
        return hash.finalResult();
    }

    /// Membership is useful only after signature and TPM-anchor verification.
    pub fn allows(s: Record, release: Digest) bool {
        return std.mem.eql(u8, &release, &s.retained) or
            std.mem.eql(u8, &release, &s.candidate);
    }

    /// The signing host validates this relation before issuing a transition.
    pub fn transition(s: Record, next: Record, running: Digest, pcr: Digest) !void {
        _ = try decode(&s.encode());
        _ = try decode(&next.encode());
        if (!std.mem.eql(u8, &s.machine, &next.machine) or
            !std.mem.eql(u8, &s.anchor(), &next.previous)) return error.StaleBootState;
        if (!s.allows(running) or !std.mem.eql(u8, &next.retained, &running) or
            !std.mem.eql(u8, &next.pcr, &pcr) or
            std.mem.eql(u8, &next.retained, &next.candidate)) return error.UnsafeRetirement;
    }
};

test "release identity distinguishes boot contexts even with identical executable payloads" {
    const t = std.testing;
    const first = releaseId("x86_64", @splat(1), @splat(2), @splat(3), @splat(4));
    const changed = releaseId("x86_64", @splat(1), @splat(2), @splat(3), @splat(5));
    try t.expect(!std.mem.eql(u8, &first, &changed));
}

test "exact pairs preserve operator rollback without relying on serial order" {
    const t = std.testing;
    const a: Digest = @splat(1);
    const b: Digest = @splat(2);
    const c: Digest = @splat(3);
    const initial: Record = .{
        .machine = @splat(4),
        .previous = @splat(0),
        .retained = a,
        .candidate = a,
        .pcr = @splat(5),
    };
    const ab: Record = .{
        .machine = initial.machine,
        .previous = initial.anchor(),
        .retained = a,
        .candidate = b,
        .pcr = initial.pcr,
    };
    try initial.transition(ab, a, initial.pcr);
    try t.expect(ab.allows(a) and ab.allows(b) and !ab.allows(c));
    const ac: Record = .{
        .machine = ab.machine,
        .previous = ab.anchor(),
        .retained = a,
        .candidate = c,
        .pcr = initial.pcr,
    };
    try ab.transition(ac, a, initial.pcr);
    try t.expect(ac.allows(a) and ac.allows(c) and !ac.allows(b));
    try t.expectError(error.UnsafeRetirement, ab.transition(ac, b, initial.pcr));
    try t.expectError(error.StaleBootState, initial.transition(ac, a, initial.pcr));
    var foreign = ac;
    foreign.machine[0] ^= 1;
    try t.expectError(error.StaleBootState, ab.transition(foreign, a, initial.pcr));
    try t.expectError(error.UnsafeRetirement, ab.transition(ac, a, @splat(9)));
}

test "boot records reject truncation, suffixes, wrong domains and missing identities" {
    const t = std.testing;
    const s: Record = .{
        .machine = @splat(1),
        .previous = @splat(0),
        .retained = @splat(2),
        .candidate = @splat(2),
        .pcr = @splat(3),
    };
    var raw = s.encode();
    try t.expectEqualDeep(s, try Record.decode(&raw));
    for (0..raw.len) |n| try t.expectError(error.BadBootState, Record.decode(raw[0..n]));
    try t.expectError(error.BadBootState, Record.decode(&(raw ++ .{0})));
    raw[0] ^= 1;
    try t.expectError(error.BadBootState, Record.decode(&raw));
    inline for (.{ "machine", "retained", "candidate", "pcr" }) |field| {
        var bad = s;
        @field(bad, field) = @splat(0);
        try t.expectError(error.BadBootState, Record.decode(&bad.encode()));
    }
    var bad = s;
    bad.candidate = @splat(4);
    try t.expectError(error.BadBootState, Record.decode(&bad.encode()));
}
