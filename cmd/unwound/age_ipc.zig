//! Versioned, bounded request from the DNS frontend to the age worker.
//! The worker derives UID and source label from the service index and the
//! compiled policy it inherited at fork. PID is never inferred from DNS.
const std = @import("std");
const wire = @import("wire.zig");

pub const header_len = 23;
pub const max_len = header_len + 253;
pub const Transport = enum(u8) { udp = 0, tcp = 1 };

pub const Request = struct {
    request_id: u64,
    dns_id: u16,
    qtype: wire.Type,
    service: u8,
    line: u16,
    policy_generation: u32,
    transport: Transport,
    name: wire.Name,
};

pub fn encode(out: *[max_len]u8, request: *const Request) []const u8 {
    out[0] = 1;
    out[1] = @backingInt(request.transport);
    out[2] = request.service;
    out[3] = 0;
    std.mem.writeInt(u64, out[4..12], request.request_id, .big);
    std.mem.writeInt(u16, out[12..14], request.dns_id, .big);
    std.mem.writeInt(u16, out[14..16], @backingInt(request.qtype), .big);
    std.mem.writeInt(u16, out[16..18], request.line, .big);
    std.mem.writeInt(u32, out[18..22], request.policy_generation, .big);
    out[22] = request.name.len;
    @memcpy(out[header_len..][0..request.name.len], request.name.text());
    return out[0 .. header_len + request.name.len];
}

pub fn decode(packet: []const u8) ?Request {
    if (packet.len < header_len or packet.len > max_len or packet[0] != 1 or
        packet[3] != 0 or packet[22] == 0 or
        packet.len != header_len + @as(usize, packet[22])) return null;
    const transport: Transport = switch (packet[1]) {
        0 => .udp,
        1 => .tcp,
        else => return null,
    };
    const qtype = wire.Type.from(std.mem.readInt(u16, packet[14..16], .big)) orelse return null;
    const name = wire.Name.fromText(packet[header_len..]) catch return null;
    return .{
        .request_id = std.mem.readInt(u64, packet[4..12], .big),
        .dns_id = std.mem.readInt(u16, packet[12..14], .big),
        .qtype = qtype,
        .service = packet[2],
        .line = std.mem.readInt(u16, packet[16..18], .big),
        .policy_generation = std.mem.readInt(u32, packet[18..22], .big),
        .transport = transport,
        .name = name,
    };
}

test "age request round trip preserves exact DNS trigger" {
    const t = std.testing;
    const request: Request = .{
        .request_id = 0x123456789abcdef0,
        .dns_id = 0xabcd,
        .qtype = .tlsa,
        .service = 7,
        .line = 123,
        .policy_generation = 0xdeadbeef,
        .transport = .tcp,
        .name = try wire.Name.fromText("_25._tcp.mail.example.com"),
    };
    var buf: [max_len]u8 = undefined;
    const packet = encode(&buf, &request);
    const found = decode(packet).?;
    try t.expectEqual(request.request_id, found.request_id);
    try t.expectEqual(request.dns_id, found.dns_id);
    try t.expectEqual(request.qtype, found.qtype);
    try t.expectEqual(request.service, found.service);
    try t.expectEqual(request.line, found.line);
    try t.expectEqual(request.policy_generation, found.policy_generation);
    try t.expectEqual(request.transport, found.transport);
    try t.expectEqualStrings(request.name.text(), found.name.text());
    try t.expect(decode(packet[0 .. packet.len - 1]) == null);
    buf[packet.len] = 0;
    try t.expect(decode(buf[0 .. packet.len + 1]) == null);
}

test "age request rejects forged versions, types and names" {
    const t = std.testing;
    var buf: [max_len]u8 = undefined;
    const request: Request = .{
        .request_id = 1,
        .dns_id = 2,
        .qtype = .a,
        .service = 0,
        .line = 3,
        .policy_generation = 4,
        .transport = .udp,
        .name = try wire.Name.fromText("example.com"),
    };
    const len = encode(&buf, &request).len;
    buf[0] = 2;
    try t.expect(decode(buf[0..len]) == null);
    buf[0] = 1;
    buf[1] = 2;
    try t.expect(decode(buf[0..len]) == null);
    buf[1] = 0;
    buf[14] = 0;
    buf[15] = 255;
    try t.expect(decode(buf[0..len]) == null);
    buf[15] = 1;
    buf[header_len] = 'A';
    try t.expect(decode(buf[0..len]) == null);
}
