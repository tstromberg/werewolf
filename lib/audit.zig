//! audit talks to the kernel's audit subsystem over netlink. init uses it
//! to log every refused exec and lock the configuration; posture checks
//! that the lock holds. See lib/README.md.

const std = @import("std");
const seal = @import("seal");
const linux = std.os.linux;

/// Message types from linux/audit.h.
const msg_get = 1000;
const msg_set = 1001;
const msg_add_rule = 1011;

/// Rule lists: filter_exit matches as a system call returns; filter_exclude
/// names record types to drop as they are written.
const filter_exit = 4;
const filter_exclude = 5;
const always = 2;

/// Rule fields, each compared with equal.
const field_arch = 11;
const field_msgtype = 12;
const field_success = 104;
const equal = 0x40000000;

/// left_out drops the CWD, EXECVE, EOE and PROCTITLE records, so a refused
/// exec is two lines on the console (SYSCALL and PATH), not six.
const left_out = [_]u32{ 1307, 1309, 1320, 1327 };

/// Status is struct audit_status; mask says which fields AUDIT_SET changes.
const Status = extern struct {
    mask: u32,
    enabled: u32 = 0,
    failure: u32 = 0,
    pid: u32 = 0,
    rate_limit: u32 = 0,
    backlog_limit: u32 = 0,
    lost: u32 = 0,
    backlog: u32 = 0,
    feature_bitmap: u32 = 0,
    backlog_wait_time: u32 = 0,
    backlog_wait_time_actual: u32 = 0,
};
const status_enabled = 0x0001;
const status_backlog_wait_time = 0x0040;

/// locked is the enabled value for on and locked until reboot (0 is off, 1 on).
pub const locked = 2;

/// Rule is struct audit_rule_data without the string buffer, since every
/// field used here is a number.
const Rule = extern struct {
    flags: u32,
    action: u32 = always,
    field_count: u32 = 0,
    mask: [64]u32 = @splat(0),
    fields: [64]u32 = @splat(0),
    values: [64]u32 = @splat(0),
    fieldflags: [64]u32 = @splat(0),
    buflen: u32 = 0,

    fn field(r: *Rule, f: u32, v: u32) void {
        r.fields[r.field_count] = f;
        r.values[r.field_count] = v;
        r.fieldflags[r.field_count] = equal;
        r.field_count += 1;
    }

    fn syscall(r: *Rule, sys: linux.SYS) void {
        const nr: u32 = @intCast(@backingInt(sys));
        r.mask[nr / 32] |= @as(u32, 1) << @intCast(nr % 32);
    }
};

pub const Error = error{
    /// NoAudit means the kernel has no audit, or this is not the first PID namespace.
    NoAudit,
    /// Refused means no CAP_AUDIT_CONTROL, or the configuration is locked.
    Refused,
    /// Failed is any other answer from the kernel.
    Failed,
};

/// enable turns audit on with one rule, which logs every refused exec, and
/// locks the configuration until reboot. backlog_wait_time is 0, so a full
/// queue loses and counts records rather than block a process.
pub fn enable() Error!void {
    const sock = try open();
    defer _ = linux.close(sock);
    const on: Status = .{
        .mask = status_enabled | status_backlog_wait_time,
        .enabled = 1,
        .backlog_wait_time = 0,
    };
    try send(sock, msg_set, std.mem.asBytes(&on));
    var refused_exec: Rule = .{ .flags = filter_exit };
    refused_exec.syscall(.execve);
    refused_exec.syscall(.execveat);
    // Match native calls only; the seal kills 32-bit ones anyway.
    refused_exec.field(field_arch, seal.native_arch);
    refused_exec.field(field_success, 0);
    try send(sock, msg_add_rule, std.mem.asBytes(&refused_exec));
    for (left_out) |t| {
        var out: Rule = .{ .flags = filter_exclude };
        out.field(field_msgtype, t);
        try send(sock, msg_add_rule, std.mem.asBytes(&out));
    }
    const lock: Status = .{ .mask = status_enabled, .enabled = locked };
    try send(sock, msg_set, std.mem.asBytes(&lock));
}

/// setEnabled asks the kernel to set enabled, as an attacker stopping the
/// log would. On a sealed machine it returns error.Refused: PID 1 dropped
/// CAP_AUDIT_CONTROL, and the configuration is locked as well.
pub fn setEnabled(enabled: u32) Error!void {
    const sock = try open();
    defer _ = linux.close(sock);
    const s: Status = .{ .mask = status_enabled, .enabled = enabled };
    try send(sock, msg_set, std.mem.asBytes(&s));
}

/// enabledNow returns the kernel's enabled value: 0, 1 or locked. Reading
/// it needs CAP_AUDIT_CONTROL; without it the error is error.Refused.
pub fn enabledNow() Error!u32 {
    const sock = try open();
    defer _ = linux.close(sock);
    const header = @sizeOf(linux.nlmsghdr);
    const req: linux.nlmsghdr = .{
        .len = header,
        .type = @fromBackingInt(msg_get),
        .flags = linux.NLM_F_REQUEST,
        .seq = 1,
        .pid = 0,
    };
    const kernel: linux.sockaddr.nl = .{ .pid = 0, .groups = 0 };
    const sent = linux.sendto(
        sock,
        std.mem.asBytes(&req),
        header,
        0,
        @ptrCast(&kernel),
        @sizeOf(linux.sockaddr.nl),
    );
    if (linux.errno(sent) != .SUCCESS) return switch (linux.errno(sent)) {
        .PERM, .ACCES => error.Refused,
        .CONNREFUSED => error.NoAudit,
        else => error.Failed,
    };
    // The reply is the status, or an error message if refused.
    var reply: [header + @sizeOf(Status)]u8 align(4) = undefined;
    const n = linux.recvfrom(sock, &reply, reply.len, 0, null, null);
    if (linux.errno(n) != .SUCCESS or n < header + 8) return error.Failed;
    const rh: *const linux.nlmsghdr = @ptrCast(&reply);
    if (rh.type == .ERROR) {
        const code = std.mem.readInt(i32, reply[header..][0..4], .little);
        return if (code == -@as(i32, @backingInt(linux.E.PERM))) error.Refused else error.Failed;
    }
    if (@backingInt(rh.type) != msg_get) return error.Failed;
    return std.mem.readInt(u32, reply[header + @offsetOf(Status, "enabled") ..][0..4], .little);
}

fn open() Error!i32 {
    const rc = linux.socket(
        linux.AF.NETLINK,
        linux.SOCK.RAW | linux.SOCK.CLOEXEC,
        linux.NETLINK.AUDIT,
    );
    return switch (linux.errno(rc)) {
        .SUCCESS => @intCast(rc),
        .PERM, .ACCES => error.Refused,
        else => error.NoAudit,
    };
}

/// send sends one request and waits for the kernel's acknowledgment, an
/// error message whose code is 0 on success.
fn send(sock: i32, msg_type: u16, payload: []const u8) Error!void {
    const header = @sizeOf(linux.nlmsghdr);
    var buf: [header + @sizeOf(Rule)]u8 align(4) = undefined;
    const hdr: *linux.nlmsghdr = @ptrCast(&buf);
    hdr.* = .{
        .len = @intCast(header + payload.len),
        .type = @fromBackingInt(@intCast(msg_type)),
        .flags = linux.NLM_F_REQUEST | linux.NLM_F_ACK,
        .seq = 1,
        .pid = 0,
    };
    @memcpy(buf[header..][0..payload.len], payload);
    const kernel: linux.sockaddr.nl = .{ .pid = 0, .groups = 0 };
    const sent = linux.sendto(
        sock,
        &buf,
        hdr.len,
        0,
        @ptrCast(&kernel),
        @sizeOf(linux.sockaddr.nl),
    );
    if (linux.errno(sent) != .SUCCESS) return switch (linux.errno(sent)) {
        .PERM, .ACCES => error.Refused,
        .CONNREFUSED => error.NoAudit,
        else => error.Failed,
    };
    var reply: [256]u8 align(4) = undefined;
    const n = linux.recvfrom(sock, &reply, reply.len, 0, null, null);
    if (linux.errno(n) != .SUCCESS or n < header + 4) return error.Failed;
    const rh: *const linux.nlmsghdr = @ptrCast(&reply);
    if (rh.type != .ERROR) return error.Failed;
    const code = std.mem.readInt(i32, reply[header..][0..4], .little);
    return switch (code) {
        0 => {},
        -@as(i32, @backingInt(linux.E.PERM)) => error.Refused,
        else => error.Failed,
    };
}

const testing = std.testing;

test Rule {
    try testing.expectEqual(1040, @sizeOf(Rule));
    try testing.expectEqual(44, @sizeOf(Status));
    var r: Rule = .{ .flags = filter_exit };
    r.syscall(.execve);
    r.field(field_success, 0);
    const nr: u32 = @intCast(@backingInt(linux.SYS.execve));
    try testing.expect(r.mask[nr / 32] & (@as(u32, 1) << @intCast(nr % 32)) != 0);
    try testing.expectEqual(1, r.field_count);
    try testing.expectEqual(field_success, r.fields[0]);
    try testing.expectEqual(equal, r.fieldflags[0]);
}
