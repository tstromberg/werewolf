//! TPM 2.0 release floor: one NV counter per release channel, which boot
//! reads, the mount broker raises, and nothing lowers. A release boots only
//! if its index is at least the floor (docs/design/implemented/independent-updates.md).
//!
//! stage0 enrolls a fresh TPM on first boot: it defines the counter, disables
//! clear and sets random owner and lockout authorization that nothing keeps.
//! The counter has empty authorization and no policy, so anyone holding the
//! device may increment it, which only retires releases, and nobody may
//! define, undefine, lock, clear or lower it.
const std = @import("std");
const posix = std.posix;
const Sha256 = std.crypto.hash.sha2.Sha256;
/// firmware parses the boot certificate howl enrolls (boot-authority.zig).
pub const firmware = @import("boot-authority.zig");

/// metadata holds protocol, which marks a root whose boot requires the floor.
pub const metadata = "/usr/share/werewolf/tpm";
pub const protocol = "3\n";
pub const device = "/dev/tpmrm0";

const owner: u32 = 0x40000001;
const lockout: u32 = 0x4000000a;
const endorsement: u32 = 0x4000000b;
const platform: u32 = 0x4000000c;
const password: u32 = 0x40000009;

/// counter_attributes are AUTHWRITE, TPM_NT_COUNTER, AUTHREAD and NO_DA:
/// no owner or platform write, no write or read lock, no policy delete.
pub const counter_attributes: u32 = 0x02040014;
const written: u32 = 1 << 29;

// TPM_PT_PERMANENT and TPM_PT_STARTUP_CLEAR, and the bits read from them.
const permanent: u32 = 0x200;
const startup_clear: u32 = 0x201;
const owner_auth_set: u32 = 1 << 0;
const lockout_auth_set: u32 = 1 << 2;
const disable_clear: u32 = 1 << 8;
const ph_enable: u32 = 1 << 0;
const sh_enable: u32 = 1 << 1;

/// handle is the NV index of channel's counter. Publishers refuse a channel
/// whose handle another of theirs already has.
pub fn handle(channel: [32]u8) u32 {
    return 0x01500000 | @as(u32, channel[0]) << 8 | channel[1];
}

const Bytes = struct {
    data: [512]u8 = undefined,
    len: usize = 0,
    fn bytes(b: *Bytes, input: []const u8) void {
        if (input.len > b.data.len - b.len) unreachable;
        @memcpy(b.data[b.len..][0..input.len], input);
        b.len += input.len;
    }
    fn int(b: *Bytes, comptime T: type, input: T) void {
        var raw: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &raw, input, .big);
        b.bytes(&raw);
    }
    fn sized(b: *Bytes, input: []const u8) void {
        b.int(u16, @intCast(input.len));
        b.bytes(input);
    }
    fn slice(b: *const Bytes) []const u8 {
        return b.data[0..b.len];
    }
};

const Read = struct {
    data: []const u8,
    at: usize = 0,
    fn bytes(r: *Read, n: usize) ![]const u8 {
        if (n > r.data.len - r.at) return error.BadTpmResponse;
        defer r.at += n;
        return r.data[r.at..][0..n];
    }
    fn int(r: *Read, comptime T: type) !T {
        return std.mem.readInt(T, (try r.bytes(@sizeOf(T)))[0..@sizeOf(T)], .big);
    }
    fn sized(r: *Read) ![]const u8 {
        return r.bytes(try r.int(u16));
    }
};

/// command starts a TPM command; with auth, one empty-password session.
fn command(code: u32, handles: []const u32, auth: ?u32) Bytes {
    var b: Bytes = .{};
    b.int(u16, if (auth != null) 0x8002 else 0x8001);
    b.int(u32, 0);
    b.int(u32, code);
    for (handles) |h| b.int(u32, h);
    if (auth) |session| {
        b.int(u32, 9);
        b.int(u32, session);
        b.int(u16, 0);
        b.int(u8, 0);
        b.int(u16, 0);
    }
    return b;
}

/// counterPublic is the exact TPMS_NV_PUBLIC of the counter at h.
fn counterPublic(h: u32, attributes: u32) Bytes {
    var b: Bytes = .{};
    b.int(u32, h);
    b.int(u16, 0xb); // SHA-256 names
    b.int(u32, attributes);
    b.sized(""); // no policy
    b.int(u16, 8);
    return b;
}

fn name(public: []const u8) [34]u8 {
    var out: [34]u8 = undefined;
    std.mem.writeInt(u16, out[0..2], 0xb, .big);
    Sha256.hash(public, out[2..34], .{});
    return out;
}

/// checkHierarchyPolicies reads TPM_CAP_AUTH_POLICIES. Owner and lockout
/// must have none, and so must the platform when listed: a policy would be
/// a second way to their authority. The endorsement hierarchy reaches no
/// owner index, so its policy is the provider's business. GCP omits a
/// disabled platform hierarchy; an enabled one must be listed.
pub fn checkHierarchyPolicies(raw: []const u8, platform_enabled: bool) !void {
    var r: Read = .{ .data = raw };
    if (try r.int(u8) != 0 or try r.int(u32) != 9) return error.UnprotectedTpmHierarchy;
    const count = try r.int(u32);
    if (count > 4) return error.BadTpmResponse;
    var guarded: u2 = 0;
    var listed_platform = false;
    for (0..count) |_| {
        const h = try r.int(u32);
        const algorithm = try r.int(u16);
        _ = try r.bytes(switch (algorithm) {
            0x10 => 0,
            0x04 => 20,
            0x0b => 32,
            0x0c => 48,
            0x0d => 64,
            else => return error.BadTpmResponse,
        });
        switch (h) {
            owner, lockout => {
                if (algorithm != 0x10) return error.UnprotectedTpmHierarchy;
                guarded += 1;
            },
            platform => {
                if (algorithm != 0x10) return error.UnprotectedTpmHierarchy;
                listed_platform = true;
            },
            endorsement => {},
            else => return error.BadTpmResponse,
        }
    }
    if (r.at != r.data.len) return error.BadTpmResponse;
    if (guarded != 2 or (platform_enabled and !listed_platform))
        return error.UnprotectedTpmHierarchy;
}

pub const Device = struct {
    fd: posix.fd_t,
    response: [4096]u8 = undefined,
    last_error: u32 = 0,

    pub fn open() !Device {
        return .{ .fd = try posix.openat(posix.AT.FDCWD, device, .{
            .ACCMODE = .RDWR,
            .CLOEXEC = true,
            .NOFOLLOW = true,
        }, 0) };
    }

    pub fn close(d: *Device) void {
        std.crypto.secureZero(u8, &d.response);
        _ = posix.system.close(d.fd);
    }

    fn send(d: *Device, bytes: []const u8) !void {
        var at: usize = 0;
        while (at < bytes.len) {
            const rc = posix.system.write(d.fd, bytes[at..].ptr, bytes.len - at);
            switch (posix.errno(rc)) {
                .SUCCESS => at += @intCast(rc),
                .INTR => {},
                else => return error.TpmWrite,
            }
        }
    }

    fn receive(d: *Device, end: usize, got: usize) !usize {
        const n = try posix.read(d.fd, d.response[got..end]);
        if (n == 0) return error.BadTpmResponse;
        return got + n;
    }

    /// call sends b and returns the response's parameters. It retries the
    /// TPM's warnings (busy, self-test, NV rate) for up to ten seconds.
    fn call(d: *Device, b: *Bytes) !Read {
        defer std.crypto.secureZero(u8, &b.data);
        std.mem.writeInt(u32, b.data[2..6], @intCast(b.len), .big);
        var tries: u32 = 0;
        while (true) : (tries += 1) {
            try d.send(b.slice());
            var got = try d.receive(d.response.len, 0);
            while (got < 10) got = try d.receive(d.response.len, got);
            const size = std.mem.readInt(u32, d.response[2..6], .big);
            if (size < 10 or size > d.response.len or got > size) return error.BadTpmResponse;
            while (got < size) got = try d.receive(size, got);
            d.last_error = std.mem.readInt(u32, d.response[6..10], .big);
            switch (d.last_error) {
                0 => {},
                0x908, 0x90a, 0x920, 0x922, 0x923 => {
                    if (tries == 100) return error.TpmBusy;
                    const pause: posix.timespec = .{ .sec = 0, .nsec = 100_000_000 };
                    _ = posix.system.nanosleep(&pause, null);
                    continue;
                },
                else => return error.TpmRefused,
            }
            var r: Read = .{ .data = d.response[10..size] };
            const tag = std.mem.readInt(u16, d.response[0..2], .big);
            if (tag == 0x8002) return .{ .data = try r.bytes(try r.int(u32)) };
            if (tag != 0x8001) return error.BadTpmResponse;
            return r;
        }
    }

    fn property(d: *Device, id: u32) !u32 {
        var b = command(0x17a, &.{}, null); // GetCapability
        b.int(u32, 6); // TPM_CAP_TPM_PROPERTIES
        b.int(u32, id);
        b.int(u32, 1);
        var r = try d.call(&b);
        _ = try r.int(u8);
        if (try r.int(u32) != 6 or try r.int(u32) != 1 or
            try r.int(u32) != id) return error.BadTpmResponse;
        return r.int(u32);
    }

    fn authRefused(d: *Device) bool {
        return d.last_error == 0x9a2 or d.last_error == 0x98e;
    }

    fn noHierarchyPolicies(d: *Device) !void {
        const platform_enabled = try d.property(startup_clear) & ph_enable != 0;
        var b = command(0x17a, &.{}, null);
        b.int(u32, 9); // TPM_CAP_AUTH_POLICIES
        b.int(u32, owner);
        b.int(u32, 4);
        const r = try d.call(&b);
        try checkHierarchyPolicies(r.data, platform_enabled);
    }

    /// disablePlatform closes the platform hierarchy until the next reset,
    /// so nothing after boot can re-enable clear. Firmware that keeps it
    /// behind a random password of its own has closed it already.
    pub fn disablePlatform(d: *Device) !void {
        if (try d.property(startup_clear) & ph_enable == 0) return;
        var b = command(0x121, &.{platform}, password); // HierarchyControl
        b.int(u32, platform);
        b.int(u8, 0);
        _ = d.call(&b) catch |err| {
            if (err == error.TpmRefused and d.authRefused()) return d.noHierarchyPolicies();
            return err;
        };
        if (try d.property(startup_clear) & ph_enable != 0) return error.TpmPlatformEnabled;
    }

    /// hierarchyProtected requires what enrollment leaves: owner and lockout
    /// authorization set, clear disabled, no hierarchy policy, and the
    /// platform hierarchy closed or behind firmware's own password.
    fn hierarchyProtected(d: *Device) !void {
        const flags = owner_auth_set | lockout_auth_set | disable_clear;
        if (try d.property(permanent) & flags != flags) return error.UnprotectedTpmHierarchy;
        try d.noHierarchyPolicies();
        if (try d.property(startup_clear) & ph_enable == 0) return;
        var b = command(0x121, &.{platform}, password);
        b.int(u32, platform);
        b.int(u8, 1);
        _ = d.call(&b) catch |err| {
            if (err == error.TpmRefused and d.authRefused()) return;
            return err;
        };
        return error.UnprotectedTpmHierarchy;
    }

    pub const Counter = enum { absent, unwritten, written };

    /// counter reports whether h holds this protocol's counter, by its
    /// exact public area; anything else at h is refused.
    pub fn counter(d: *Device, h: u32) !Counter {
        var b = command(0x17a, &.{}, null);
        b.int(u32, 1); // TPM_CAP_HANDLES
        b.int(u32, h);
        b.int(u32, 1);
        var r = try d.call(&b);
        _ = try r.int(u8);
        if (try r.int(u32) != 1) return error.BadTpmResponse;
        const count = try r.int(u32);
        if (count > 1) return error.BadTpmResponse;
        const found = count == 1 and try r.int(u32) == h;
        if (r.at != r.data.len) return error.BadTpmResponse;
        if (!found) return .absent;
        b = command(0x169, &.{h}, null); // NV_ReadPublic
        r = try d.call(&b);
        const actual = try r.sized();
        const nv_name = try r.sized();
        if (r.at != r.data.len) return error.BadTpmResponse;
        for ([_]Counter{ .unwritten, .written }) |state| {
            const attributes = if (state == .written)
                counter_attributes | written
            else
                counter_attributes;
            const expected = counterPublic(h, attributes);
            if (std.mem.eql(u8, actual, expected.slice())) {
                if (!std.mem.eql(u8, nv_name, &name(actual))) return error.BadTpmResponse;
                return state;
            }
        }
        return error.WrongTpmCounter;
    }

    /// read returns the written counter at h.
    pub fn read(d: *Device, h: u32) !u64 {
        var b = command(0x14e, &.{ h, h }, password); // NV_Read
        b.int(u16, 8);
        b.int(u16, 0);
        var r = try d.call(&b);
        const data = try r.sized();
        if (data.len != 8) return error.BadTpmResponse;
        return std.mem.readInt(u64, data[0..8], .big);
    }

    /// raise increments the counter at h until it holds at least target,
    /// and returns its value. A counter's first increment starts it from
    /// the highest value any counter on the TPM has held, which may already
    /// pass target. A lost reply is settled by reading, never by counting.
    pub fn raise(d: *Device, h: u32, target: u64) !u64 {
        var value: u64 = switch (try d.counter(h)) {
            .absent => return error.ForeignTpm,
            .unwritten => 0,
            .written => try d.read(h),
        };
        var budget = (target -| value) +| 8;
        while (value < target) : (budget -= 1) {
            if (budget == 0) return error.TpmCounterStuck;
            var b = command(0x134, &.{ h, h }, password); // NV_Increment
            _ = d.call(&b) catch |err| if (err == error.TpmRefused) return err;
            value = try d.read(h);
        }
        return value;
    }

    /// enroll makes a fresh TPM the machine's: the channel's counter at
    /// least index, clear disabled, then random lockout and owner passwords
    /// that nothing keeps. Each step is checked first and owner comes last,
    /// so a cut leaves a state the next boot completes.
    fn enroll(d: *Device, io: std.Io, h: u32, index: u64) !void {
        if (try d.property(startup_clear) & sh_enable == 0) return error.TpmOwnerDisabled;
        try d.noHierarchyPolicies();
        const flags = try d.property(permanent);
        // Enrollment disables clear before it sets lockout's password.
        if (flags & lockout_auth_set != 0 and flags & disable_clear == 0) return error.ForeignTpm;
        if (try d.counter(h) == .absent) {
            var b = command(0x12a, &.{owner}, password); // NV_DefineSpace
            b.sized("");
            b.sized(counterPublic(h, counter_attributes).slice());
            _ = try d.call(&b);
        }
        _ = try d.raise(h, index);
        if (flags & disable_clear == 0) {
            var b = command(0x127, &.{lockout}, password); // ClearControl
            b.int(u8, 1);
            _ = try d.call(&b);
        }
        var secret: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &secret);
        for ([_]u32{ lockout, owner }) |hierarchy| {
            if (hierarchy == lockout and flags & lockout_auth_set != 0) continue;
            try io.randomSecure(&secret);
            var b = command(0x129, &.{hierarchy}, password); // HierarchyChangeAuth
            b.sized(&secret);
            _ = try d.call(&b);
        }
    }

    /// boot closes the platform's reset path, enrolls a TPM nobody owns
    /// yet, verifies the enrolled state and returns channel's floor. The
    /// caller refuses an index below it.
    pub fn boot(d: *Device, io: std.Io, channel: [32]u8, index: u64) !u64 {
        if (index == 0) return error.BadReleaseIndex;
        const h = handle(channel);
        try d.disablePlatform();
        const flags = try d.property(permanent);
        if (flags & owner_auth_set == 0) {
            try d.enroll(io, h, index);
        } else if (flags & (lockout_auth_set | disable_clear) != lockout_auth_set | disable_clear) {
            // Enrollment sets owner's password last: this one is another's.
            return error.ForeignTpm;
        }
        try d.hierarchyProtected();
        // An owned TPM without this channel's counter is another's.
        if (try d.counter(h) != .written) return error.ForeignTpm;
        return d.read(h);
    }
};

/// Marker is what stage0 found before handover, as init records it in
/// marker_path for posture: the channel's counter, its floor, and this
/// release's index, which was at least the floor.
pub const Marker = struct {
    handle: u32,
    floor: u64,
    index: u64,

    pub const path = "/run/werewolf/rollback-checked";
    /// max is the longest format writes: two 20-digit numbers and a handle.
    pub const max = "floor= index= handle=0x".len + 2 * 20 + 8;

    pub fn format(m: Marker, buf: []u8) ![]const u8 {
        return std.mem.print(buf, "floor={d} index={d} handle=0x{x:0>8}", .{
            m.floor, m.index, m.handle,
        });
    }

    /// parse reads exactly what format writes, and refuses anything else,
    /// including an index below the floor.
    pub fn parse(text: []const u8) ?Marker {
        var it = std.mem.splitScalar(u8, std.mem.trimEnd(u8, text, "\n"), ' ');
        const floor = number(it.next() orelse return null, "floor=") orelse return null;
        const index = number(it.next() orelse return null, "index=") orelse return null;
        const h = std.mem.cutPrefix(u8, it.next() orelse return null, "handle=0x") orelse
            return null;
        if (it.next() != null or h.len != 8) return null;
        const value = std.fmt.parseUnsigned(u32, h, 16) catch return null;
        if (value >> 16 != 0x0150 or index < floor or floor == 0) return null;
        return .{ .handle = value, .floor = floor, .index = index };
    }

    fn number(word: []const u8, comptime key: []const u8) ?u64 {
        const digits = std.mem.cutPrefix(u8, word, key) orelse return null;
        if (digits.len == 0 or digits.len > 20 or digits[0] == '0') return null;
        for (digits) |c| if (!std.ascii.isDigit(c)) return null;
        return std.fmt.parseUnsigned(u64, digits, 10) catch null;
    }
};

const testing = std.testing;

test "channel handles stay in werewolf's NV range and differ by the channel's first bytes" {
    var channel: [32]u8 = @splat(0xff);
    channel[0] = 0xab;
    channel[1] = 0xcd;
    try testing.expectEqual(@as(u32, 0x0150abcd), handle(channel));
    channel[2] = 0;
    try testing.expectEqual(@as(u32, 0x0150abcd), handle(channel));
    try testing.expectEqual(@as(u32, 0x01500000), handle(@splat(0)));
}

test "the counter's public area has no policy, no lock and no owner write" {
    const public = counterPublic(0x0150abcd, counter_attributes);
    const expected = [_]u8{
        0x01, 0x50, 0xab, 0xcd, // handle
        0x00, 0x0b, // SHA-256
        0x02, 0x04, 0x00, 0x14, // NO_DA | AUTHREAD | TPM_NT_COUNTER | AUTHWRITE
        0x00, 0x00, // empty policy
        0x00, 0x08, // eight bytes
    };
    try testing.expectEqualSlices(u8, &expected, public.slice());
    // TPMA_NV: PPWRITE 0, OWNERWRITE 1, POLICYWRITE 3, POLICY_DELETE 10,
    // WRITELOCKED 11, WRITEALL 12, WRITEDEFINE 13, WRITE_STCLEAR 14,
    // GLOBALLOCK 15, PPREAD 16, OWNERREAD 17, POLICYREAD 19, ORDERLY 26,
    // CLEAR_STCLEAR 27, READLOCKED 28, PLATFORMCREATE 30, READ_STCLEAR 31.
    for ([_]u5{ 0, 1, 3, 10, 11, 12, 13, 14, 15, 16, 17, 19, 26, 27, 28, 30, 31 }) |bit|
        try testing.expect(counter_attributes & (@as(u32, 1) << bit) == 0);
    try testing.expectEqual(@as(u32, 1), counter_attributes >> 4 & 0xf); // TPM_NT_COUNTER
}

test "commands carry one empty-password session" {
    const b = command(0x134, &.{ 0x0150abcd, 0x0150abcd }, password);
    try testing.expectEqualSlices(u8, &.{ 0x80, 0x02 }, b.slice()[0..2]);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0x01, 0x34 }, b.slice()[6..10]);
    try testing.expectEqualSlices(
        u8,
        &.{ 0, 0, 0, 9, 0x40, 0, 0, 9, 0, 0, 0, 0, 0 },
        b.slice()[18..],
    );
    try testing.expectEqual(@as(usize, 10), command(0x17a, &.{}, null).len);
}

test "hierarchy policies: owner and lockout none, platform none while listed" {
    // Actual GCP AUTH_POLICIES response, excluding the TPM response header.
    const google = [_]u8{
        0,    0, 0,    0,    9, 0,    0,    0, 3,
        0x40, 0, 0,    1,    0, 0x10, 0x40, 0, 0,
        0xa,  0, 0x10, 0x40, 0, 0,    0xb,  0, 0x10,
    };
    try checkHierarchyPolicies(&google, false);
    try testing.expectError(error.UnprotectedTpmHierarchy, checkHierarchyPolicies(&google, true));
    var all = google ++ [_]u8{ 0x40, 0, 0, 0xc, 0, 0x10 };
    all[8] = 4;
    try checkHierarchyPolicies(&all, true);
    for (0..google.len) |length| {
        if (checkHierarchyPolicies(google[0..length], false)) |_|
            return error.TruncatedPoliciesAccepted
        else |_| {}
    }
    try testing.expectError(
        error.BadTpmResponse,
        checkHierarchyPolicies(&(google ++ [_]u8{0}), false),
    );
    // An endorsement policy is allowed; an owner, lockout or platform one is not.
    const policy = [_]u8{ 0, 0x0b } ++ @as([32]u8, @splat(7));
    try checkHierarchyPolicies(google[0..21] ++ [_]u8{ 0x40, 0, 0, 0xb } ++ policy, false);
    const owned = google[0..9] ++ [_]u8{ 0x40, 0, 0, 1 } ++ policy ++ google[15..];
    try testing.expectError(error.UnprotectedTpmHierarchy, checkHierarchyPolicies(owned, false));
    const platformed = all[0..27] ++ [_]u8{ 0x40, 0, 0, 0xc } ++ policy;
    try testing.expectError(
        error.UnprotectedTpmHierarchy,
        checkHierarchyPolicies(platformed, true),
    );
    // Owner or lockout missing from the list is never assumed safe.
    const missing = [_]u8{ 0, 0, 0, 0, 9, 0, 0, 0, 1, 0x40, 0, 0, 1, 0, 0x10 };
    try testing.expectError(
        error.UnprotectedTpmHierarchy,
        checkHierarchyPolicies(&missing, false),
    );
}

test "the boot marker round-trips and refuses anything else" {
    var buf: [Marker.max]u8 = undefined;
    const largest: Marker = .{
        .handle = 0x0150ffff,
        .floor = std.math.maxInt(u64),
        .index = std.math.maxInt(u64),
    };
    try testing.expectEqualDeep(largest, Marker.parse(try largest.format(&buf)).?);
    const m: Marker = .{ .handle = 0x0150abcd, .floor = 3, .index = 7 };
    const text = try m.format(&buf);
    try testing.expectEqualStrings("floor=3 index=7 handle=0x0150abcd", text);
    try testing.expectEqualDeep(m, Marker.parse(text).?);
    try testing.expectEqualDeep(m, Marker.parse("floor=3 index=7 handle=0x0150abcd\n").?);
    for ([_][]const u8{
        "",                                   "checked",
        "floor=3 index=2 handle=0x0150abcd",  "floor=0 index=2 handle=0x0150abcd",
        "floor=03 index=7 handle=0x0150abcd", "floor=3 index=7 handle=0x0160abcd",
        "floor=3 index=7 handle=0x150abcd",   "floor=3 index=7 handle=0x0150abcd x",
        "index=7 floor=3 handle=0x0150abcd",  "floor=3  index=7 handle=0x0150abcd",
    }) |bad| try testing.expectEqual(null, Marker.parse(bad));
}
