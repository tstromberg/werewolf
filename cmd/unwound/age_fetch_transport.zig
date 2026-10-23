//! Writer side of the private HTTPS fetcher stream. One check is outstanding
//! at a time. A deadline covers the entire header and body so a slow fetcher
//! cannot hold the age worker indefinitely.
const std = @import("std");
const linux = std.os.linux;
const ipc = @import("age_fetch_ipc.zig");

pub const timeout_ms: i64 = 10_000;

pub const Reply = struct {
    kind: ipc.Kind,
    body: []const u8,
};

pub fn exchange(
    channel: i32,
    id: u64,
    domain: []const u8,
    rdap_body: *[ipc.rdap_max]u8,
    ct_body: *[ipc.crtsh_max]u8,
) !Reply {
    var request: [ipc.request_max]u8 = undefined;
    const wire = ipc.encodeRequest(&request, .{ .id = id, .domain = domain }) orelse
        return error.BadDomain;
    var off: usize = 0;
    while (off < wire.len) {
        const rc = linux.sendto(
            channel,
            wire[off..].ptr,
            wire.len - off,
            linux.MSG.NOSIGNAL,
            null,
            0,
        );
        if (linux.errno(rc) == .INTR) continue;
        if (linux.errno(rc) != .SUCCESS or rc == 0) return error.FetcherClosed;
        off += rc;
    }
    const deadline = monotonic() + timeout_ms;
    var header: [ipc.response_header_len]u8 = undefined;
    try readFull(channel, &header, deadline);
    const response = ipc.decodeResponse(&header) orelse return error.BadFetcherResponse;
    if (response.id != id) return error.BadFetcherResponse;
    const body = switch (response.kind) {
        .rdap => rdap_body[0..response.body_len],
        .crtsh => ct_body[0..response.body_len],
        .unavailable, .invalid => return .{ .kind = response.kind, .body = &.{} },
    };
    try readFull(channel, body, deadline);
    return .{ .kind = response.kind, .body = body };
}

fn monotonic() i64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return ts.sec * std.time.ms_per_s + @divFloor(ts.nsec, std.time.ns_per_ms);
}

fn readFull(fd: i32, buffer: []u8, deadline: i64) !void {
    var off: usize = 0;
    while (off < buffer.len) {
        const remaining = deadline - monotonic();
        if (remaining <= 0) return error.FetchTimeout;
        var ready: [1]linux.pollfd = .{.{
            .fd = fd,
            .events = linux.POLL.IN,
            .revents = 0,
        }};
        const polled = linux.poll(&ready, 1, @intCast(remaining));
        if (linux.errno(polled) == .INTR) continue;
        if (linux.errno(polled) != .SUCCESS) return error.FetcherClosed;
        if (polled == 0) return error.FetchTimeout;
        if (ready[0].revents & linux.POLL.IN == 0) return error.FetcherClosed;
        const rc = linux.read(fd, buffer[off..].ptr, buffer.len - off);
        if (linux.errno(rc) == .INTR or linux.errno(rc) == .AGAIN) continue;
        if (linux.errno(rc) != .SUCCESS or rc == 0) return error.FetcherClosed;
        off += rc;
    }
}

test "fetcher stream keeps frame boundaries across short reads" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    const t = std.testing;
    var pair: [2]i32 = undefined;
    try t.expect(linux.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &pair)) ==
        .SUCCESS);
    const pid = linux.fork();
    try t.expect(linux.errno(pid) == .SUCCESS);
    if (pid == 0) {
        _ = linux.close(pair[0]);
        var request: [ipc.request_max]u8 = undefined;
        if (!childRead(pair[1], request[0..ipc.request_header_len])) linux.exit_group(2);
        const length: usize = request[1];
        if (!childRead(pair[1], request[ipc.request_header_len..][0..length])) linux.exit_group(3);
        const parsed = ipc.decodeRequest(request[0 .. ipc.request_header_len + length]) orelse
            linux.exit_group(4);
        if (parsed.id != 99 or !std.mem.eql(u8, parsed.domain, "example.com"))
            linux.exit_group(5);
        var header: [ipc.response_header_len]u8 = undefined;
        const frame = ipc.encodeResponse(&header, .{
            .id = 99,
            .kind = .rdap,
            .body_len = 4,
        }) orelse linux.exit_group(6);
        for (frame, 0..) |_, i| if (linux.write(pair[1], frame[i..].ptr, 1) != 1) {
            linux.exit_group(7);
        };
        if (linux.write(pair[1], "date", 4) != 4) linux.exit_group(8);
        linux.exit_group(0);
    }
    _ = linux.close(pair[1]);
    defer _ = linux.close(pair[0]);
    var rdap: [ipc.rdap_max]u8 = undefined;
    var ct: [ipc.crtsh_max]u8 = undefined;
    const got = try exchange(pair[0], 99, "example.com", &rdap, &ct);
    try t.expectEqual(ipc.Kind.rdap, got.kind);
    try t.expectEqualStrings("date", got.body);
    var status: i32 = 0;
    try t.expect(linux.errno(linux.waitpid(@intCast(pid), &status, 0)) == .SUCCESS);
    try t.expectEqual(@as(i32, 0), status);
}

fn childRead(fd: i32, buffer: []u8) bool {
    var off: usize = 0;
    while (off < buffer.len) {
        const rc = linux.read(fd, buffer[off..].ptr, buffer.len - off);
        if (linux.errno(rc) != .SUCCESS or rc == 0) return false;
        off += rc;
    }
    return true;
}
