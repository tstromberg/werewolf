//! Network-only side of a domain-age check. The caller confines this process
//! to DNS and public HTTPS. Raw replies cross to the SQLite writer, which
//! checks the domain identity and dates before storing any evidence.
const std = @import("std");
const linux = std.os.linux;
const age_http = @import("age_http.zig");
const ipc = @import("age_fetch_ipc.zig");

pub const Reply = struct {
    kind: ipc.Kind,
    body: []const u8,
};

pub fn fetch(
    client: *std.http.Client,
    domain: []const u8,
    url: *[512]u8,
    rdap_body: *[ipc.rdap_max]u8,
    ct_body: *[ipc.crtsh_max]u8,
) Reply {
    const rdap = age_http.rdap(client, domain, url, rdap_body);
    switch (rdap.lookup) {
        .body => |body| return .{
            .kind = if (body.len > 0) .rdap else .invalid,
            .body = body,
        },
        .unavailable => {
            const history = age_http.crtsh(client, domain, ct_body) orelse
                return .{ .kind = .unavailable, .body = &.{} };
            if (history.len == 0) return .{ .kind = .unavailable, .body = &.{} };
            return .{ .kind = .crtsh, .body = history };
        },
    }
}

/// Serve one blocking stream socket inherited from the age writer. Each
/// request is a small frame; a response has a fixed header then at most
/// 256 KiB of raw evidence. The writer supervises this child with a deadline.
pub fn serve(channel: i32, client: *std.http.Client) noreturn {
    var request: [ipc.request_max]u8 = undefined;
    var response: [ipc.response_header_len]u8 = undefined;
    var url: [512]u8 = undefined;
    var rdap_body: [ipc.rdap_max]u8 = undefined;
    var ct_body: [ipc.crtsh_max]u8 = undefined;
    while (true) {
        if (!readFull(channel, request[0..ipc.request_header_len])) linux.exit_group(0);
        const domain_len: usize = request[1];
        if (domain_len == 0 or domain_len > 253 or
            !readFull(channel, request[ipc.request_header_len..][0..domain_len]))
            linux.exit_group(1);
        const ask = ipc.decodeRequest(request[0 .. ipc.request_header_len + domain_len]) orelse
            linux.exit_group(1);
        const answer = fetch(client, ask.domain, &url, &rdap_body, &ct_body);
        const header = ipc.encodeResponse(&response, .{
            .id = ask.id,
            .kind = answer.kind,
            .body_len = @intCast(answer.body.len),
        }) orelse linux.exit_group(1);
        if (!writeFull(channel, header) or !writeFull(channel, answer.body))
            linux.exit_group(1);
    }
}

fn readFull(fd: i32, buffer: []u8) bool {
    var off: usize = 0;
    while (off < buffer.len) {
        const rc = linux.read(fd, buffer[off..].ptr, buffer.len - off);
        if (linux.errno(rc) == .INTR) continue;
        if (linux.errno(rc) != .SUCCESS or rc == 0) return false;
        off += rc;
    }
    return true;
}

fn writeFull(fd: i32, buffer: []const u8) bool {
    var off: usize = 0;
    while (off < buffer.len) {
        const rc = linux.sendto(
            fd,
            buffer[off..].ptr,
            buffer.len - off,
            linux.MSG.NOSIGNAL,
            null,
            0,
        );
        if (linux.errno(rc) == .INTR) continue;
        if (linux.errno(rc) != .SUCCESS or rc == 0) return false;
        off += rc;
    }
    return true;
}

test "invalid registered domains cannot initiate an HTTPS check" {
    const t = std.testing;
    var client: std.http.Client = undefined;
    var url: [512]u8 = undefined;
    var rdap_body: [ipc.rdap_max]u8 = undefined;
    var ct_body: [ipc.crtsh_max]u8 = undefined;
    const got = fetch(&client, "bad/host.com", &url, &rdap_body, &ct_body);
    try t.expectEqual(ipc.Kind.invalid, got.kind);
    try t.expectEqual(@as(usize, 0), got.body.len);
}
