//! Framing between the SQLite age writer and the stateless HTTPS fetcher.
//! Only a registered domain crosses this boundary. Responses carry bounded
//! raw evidence so the writer, rather than the fetcher, validates its dates.
const std = @import("std");

pub const request_header_len = 10;
pub const request_max = request_header_len + 253;
pub const response_header_len = 14;
pub const rdap_max = 64 << 10;
pub const crtsh_max = 256 << 10;

pub const Kind = enum(u8) { rdap = 1, crtsh = 2, unavailable = 3, invalid = 4 };

pub const Request = struct { id: u64, domain: []const u8 };
pub const Response = struct { id: u64, kind: Kind, body_len: u32 };

pub fn encodeRequest(out: *[request_max]u8, request: Request) ?[]const u8 {
    if (!validDomain(request.domain)) return null;
    out[0] = 1;
    out[1] = @intCast(request.domain.len);
    std.mem.writeInt(u64, out[2..10], request.id, .big);
    @memcpy(out[request_header_len..][0..request.domain.len], request.domain);
    return out[0 .. request_header_len + request.domain.len];
}

pub fn decodeRequest(packet: []const u8) ?Request {
    if (packet.len < request_header_len or packet.len > request_max or packet[0] != 1 or
        packet.len != request_header_len + @as(usize, packet[1])) return null;
    const domain = packet[request_header_len..];
    if (!validDomain(domain)) return null;
    return .{ .id = std.mem.readInt(u64, packet[2..10], .big), .domain = domain };
}

pub fn encodeResponse(out: *[response_header_len]u8, response: Response) ?[]const u8 {
    if (!validResponse(response)) return null;
    out[0] = 1;
    out[1] = @backingInt(response.kind);
    std.mem.writeInt(u32, out[2..6], response.body_len, .big);
    std.mem.writeInt(u64, out[6..14], response.id, .big);
    return out;
}

pub fn decodeResponse(packet: []const u8) ?Response {
    if (packet.len != response_header_len or packet[0] != 1) return null;
    const kind = std.enums.fromInt(Kind, packet[1]) orelse return null;
    const response: Response = .{
        .id = std.mem.readInt(u64, packet[6..14], .big),
        .kind = kind,
        .body_len = std.mem.readInt(u32, packet[2..6], .big),
    };
    return if (validResponse(response)) response else null;
}

fn validResponse(response: Response) bool {
    return switch (response.kind) {
        .rdap => response.body_len > 0 and response.body_len <= rdap_max,
        .crtsh => response.body_len > 0 and response.body_len <= crtsh_max,
        .unavailable, .invalid => response.body_len == 0,
    };
}

fn validDomain(domain: []const u8) bool {
    if (domain.len == 0 or domain.len > 253 or domain[0] == '.' or
        domain[domain.len - 1] == '.') return false;
    var parts = std.mem.splitScalar(u8, domain, '.');
    while (parts.next()) |part| {
        if (part.len == 0 or part.len > 63 or part[0] == '-' or
            part[part.len - 1] == '-') return false;
        for (part) |c| if (!std.ascii.isLower(c) and !std.ascii.isDigit(c) and c != '-')
            return false;
    }
    return true;
}

test "fetch request carries only a canonical registered domain" {
    const t = std.testing;
    var buf: [request_max]u8 = undefined;
    const wire = encodeRequest(&buf, .{ .id = 42, .domain = "example.com" }).?;
    const parsed = decodeRequest(wire).?;
    try t.expectEqual(@as(u64, 42), parsed.id);
    try t.expectEqualStrings("example.com", parsed.domain);
    try t.expect(decodeRequest(wire[0 .. wire.len - 1]) == null);
    try t.expect(encodeRequest(&buf, .{ .id = 1, .domain = "foo/bar.com" }) == null);
    try t.expect(encodeRequest(&buf, .{ .id = 1, .domain = "EXAMPLE.COM" }) == null);
}

test "fetch response bounds RDAP and CT bodies before allocation" {
    const t = std.testing;
    var buf: [response_header_len]u8 = undefined;
    const wire = encodeResponse(&buf, .{ .id = 7, .kind = .crtsh, .body_len = crtsh_max }).?;
    try t.expectEqual(@as(u64, 7), decodeResponse(wire).?.id);
    try t.expect(encodeResponse(
        &buf,
        .{ .id = 7, .kind = .rdap, .body_len = rdap_max + 1 },
    ) == null);
    try t.expect(encodeResponse(&buf, .{ .id = 7, .kind = .invalid, .body_len = 1 }) == null);
    buf[1] = 255;
    try t.expect(decodeResponse(&buf) == null);
}
