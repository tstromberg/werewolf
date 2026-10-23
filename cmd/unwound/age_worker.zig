//! Observe-only PSL boundary worker when the age marker is absent.
const std = @import("std");
const linux = std.os.linux;
const sandbox = @import("sandbox");
const dns = @import("dns");
const age = @import("age.zig");
const ipc = @import("age_ipc.zig");
const Policy = @import("policy.zig").Policy;
const unwound = @import("unwound.zig");

pub fn run(channel: i32, log: i32, policy: *const Policy) noreturn {
    unwound.log_fd = log;
    unwound.side = "age";
    setup(channel, log) catch @panic("age worker setup");
    const psl = @embedFile("data/public_suffix_list.ascii.dat");
    var packet: [ipc.max_len + 1]u8 = undefined;
    while (true) {
        var ready: [1]linux.pollfd = .{.{ .fd = channel, .events = linux.POLL.IN, .revents = 0 }};
        const polled = linux.poll(&ready, 1, -1);
        if (linux.errno(polled) == .INTR) continue;
        if (linux.errno(polled) != .SUCCESS or ready[0].revents & linux.POLL.IN == 0)
            @panic("age worker channel");
        const got = linux.recvfrom(channel, &packet, packet.len, linux.MSG.TRUNC, null, null);
        if (linux.errno(got) == .AGAIN) continue;
        if (linux.errno(got) != .SUCCESS or got == 0 or got > ipc.max_len)
            @panic("age worker packet");
        const request = ipc.decode(packet[0..got]) orelse continue;
        if (request.policy_generation != policy.generation or request.service >= policy.users.len)
            continue;
        const uid = policy.uid(request.service);
        const boundary = age.boundary(request.name.text(), psl);
        const kind: []const u8 = switch (boundary) {
            .unknown => "unknown",
            .tenant => "tenant",
            .registered => "registered",
        };
        const domain: ?[]const u8 = switch (boundary) {
            .registered => |value| value,
            else => null,
        };
        const label = dns.label(request.service);
        var line: [768]u8 = undefined;
        const record = std.mem.print(
            &line,
            "unwound: {{\"event\":\"age_observe\",\"request\":{d},\"dns_id\":{d}," ++
                "\"uid\":{d},\"source\":\"{d}.{d}.{d}.{d}\",\"qname\":{f}," ++
                "\"qtype\":{d},\"transport\":\"{s}\",\"rule\":{d}," ++
                "\"generation\":\"{x:0>8}\",\"boundary\":\"{s}\",\"domain\":{f}}}\n",
            .{
                request.request_id,
                request.dns_id,
                uid,
                label[0],
                label[1],
                label[2],
                label[3],
                std.json.fmt(request.name.text(), .{}),
                @backingInt(request.qtype),
                @tagName(request.transport),
                request.line,
                request.policy_generation,
                kind,
                std.json.fmt(domain, .{}),
            },
        ) catch continue;
        _ = linux.write(log, record.ptr, record.len);
    }
}

fn setup(channel: i32, log: i32) !void {
    try sandbox.limit(.NOFILE, 16);
    try sandbox.dropTo(55, "/var/empty");
    _ = try sandbox.sys(linux.prctl(@backingInt(linux.PR.SET_DUMPABLE), 0, 0, 0, 0), "dumpable");
    try sandbox.landlock(&.{}, &.{});
    var filter: sandbox.Filter = .{};
    filter.allowArg("recvfrom", 0, @intCast(channel));
    filter.allowArg("write", 0, @intCast(log));
    inline for (.{
        "poll",
        "ppoll",
        "rt_sigreturn",
        "restart_syscall",
        "exit",
        "exit_group",
    }) |call|
        filter.allow(call);
    try filter.install();
}
