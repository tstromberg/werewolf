//! broker is the client for cmd/mount-broker. fence's Landlock domain stops
//! root's programs from mounting, so they ask the broker over inherited
//! socketpairs. See lib/README.md.

const std = @import("std");
const linux = std.os.linux;

/// Role names the three inherited socketpair channels between init, the
/// supervised slot services, stage 3, and mount-broker.
pub const Role = enum(u2) {
    updater = 0,
    keeper = 1,
    stage = 2,
};

/// serverFd returns mount-broker's inherited socketpair descriptor for role.
pub fn serverFd(role: Role) i32 {
    return 3 + @as(i32, @backingInt(role));
}

/// clientFd returns the inherited client socketpair descriptor for role.
pub fn clientFd(role: Role) i32 {
    return 60 + @as(i32, @backingInt(role));
}

/// keepOnlyClient closes every descriptor above stderr except keep, marks
/// keep close-on-exec, and clears dumpable when a descriptor is retained.
pub fn keepOnlyClient(keep: ?Role) void {
    const flags: linux.CLOSE_RANGE = .{ .UNSHARE = false, .CLOEXEC = false };
    if (keep) |r| {
        const fd = clientFd(r);
        _ = linux.close_range(3, fd - 1, flags);
        _ = linux.close_range(fd + 1, std.math.maxInt(linux.fd_t), flags);
        _ = linux.fcntl(fd, linux.F.SETFD, linux.FD_CLOEXEC);
        _ = linux.prctl(@backingInt(linux.PR.SET_DUMPABLE), 0, 0, 0, 0);
    } else {
        _ = linux.close_range(3, std.math.maxInt(linux.fd_t), flags);
    }
}

/// Word requests shutdown. Neither the EFI partition nor the boot partition
/// is lent as a mount (see the ESP and slot operations below).
pub const Word = enum {
    shutdown,
};

/// refusal holds the broker's answer after error.Refused.
pub var refusal_buf: [128]u8 = undefined;
pub var refusal: []const u8 = "";

/// ask sends word to the broker over the stage channel.
pub fn ask(word: Word) !void {
    try callOk(.stage, @tagName(word));
}

// --- the EFI and boot partitions ---------------------------------------------
//
// Neither the ESP nor /boot is lent as a mount. The broker mounts each
// detached, does one of these fixed operations itself, and closes it. Only
// the process holding the role's inherited socketpair descriptor can ask.

/// EspStatus is the state of this boot's loader entry on the ESP.
pub const EspStatus = enum { already, tried, none };

/// EspArtifact names staged bytes by size and lowercase SHA-256 hex.
pub const EspArtifact = struct { size: u64, sha256: []const u8 };

/// EspFile is an artifact the broker found on the ESP.
pub const EspFile = struct { size: u64, sha256: [64]u8 };

/// EspFiles is what esp-inspect found for the other slot.
pub const EspFiles = struct {
    vmlinuz: ?EspFile = null,
    stage0: ?EspFile = null,
    uki: ?EspFile = null,
};

/// EspInstall is a parsed esp-install request. The command line is an
/// artifact like the files: the broker seals it into the loader entry,
/// so it must be digest-bound or confined root, which can write the
/// staging directory, could choose the trial boot's boot context.
pub const EspInstall = struct {
    vmlinuz: EspArtifact,
    stage0: EspArtifact,
    uki: ?EspArtifact,
    cmdline: EspArtifact,
};

fn noteRefusal(answer: []const u8) void {
    const n = @min(answer.len, refusal_buf.len);
    @memcpy(refusal_buf[0..n], answer[0..n]);
    refusal = refusal_buf[0..n];
}

/// call sends one request packet on role's socketpair and returns the
/// broker's one-line answer in out. An answer of `no ...` is error.Refused.
fn call(role: Role, request: []const u8, out: []u8) ![]const u8 {
    const fd = clientFd(role);
    const sent = linux.sendto(fd, request.ptr, request.len, linux.MSG.NOSIGNAL, null, 0);
    if (linux.errno(sent) != .SUCCESS or sent != request.len) return error.NoBroker;
    const n = while (true) {
        const rc = linux.recvfrom(fd, out.ptr, out.len, linux.MSG.TRUNC, null, null);
        if (linux.errno(rc) == .INTR) continue;
        if (linux.errno(rc) != .SUCCESS or rc == 0) return error.NoBroker;
        if (rc > out.len) return error.BadAnswer;
        break rc;
    };
    const answer = std.mem.trimEnd(u8, out[0..n], "\n");
    if (std.mem.startsWith(u8, answer, "no")) {
        noteRefusal(answer);
        return error.Refused;
    }
    if (!std.mem.startsWith(u8, answer, "ok")) return error.BadAnswer;
    return answer;
}

fn callOk(role: Role, request: []const u8) !void {
    var out: [256]u8 = undefined;
    const answer = try call(role, request, &out);
    if (!std.mem.eql(u8, answer, "ok")) return error.BadAnswer;
}

fn espCall(request: []const u8, out: []u8) ![]const u8 {
    return call(.updater, request, out);
}

fn espOk(request: []const u8) !void {
    try callOk(.updater, request);
}

/// installerRuntime exposes immutable /usr read-only at the fixed apk chroot.
pub fn installerRuntime() !void {
    try callOk(.updater, "installer-runtime");
}

/// espStatus reports whether this boot's entry is already good, still
/// counting tries, or absent.
pub fn espStatus() !EspStatus {
    var out: [256]u8 = undefined;
    const answer = try call(.keeper, "esp-status", &out);
    if (std.mem.eql(u8, answer, "ok already")) return .already;
    if (std.mem.eql(u8, answer, "ok tried")) return .tried;
    if (std.mem.eql(u8, answer, "ok none")) return .none;
    return error.BadAnswer;
}

/// espCommit keeps this boot's loader entry and publishes the committed marker.
pub fn espCommit() !void {
    try callOk(.keeper, "esp-commit");
}

/// espDisarm removes the other slot's loader entries, so nothing boots it
/// while its files change.
pub fn espDisarm() !void {
    try espOk("esp-disarm");
}

/// espArm writes one counting entry for the other slot as it stands.
pub fn espArm() !void {
    try espOk("esp-arm");
}

/// espInspect returns the size and SHA-256 of the other slot's boot files
/// on the ESP, or null for each that is absent.
pub fn espInspect() !EspFiles {
    var out: [1024]u8 = undefined;
    return parseEspFiles(try espCall("esp-inspect", &out));
}

/// espInstall has the broker copy the staged vmlinuz, stage0 and optional
/// UKI of the other slot to the ESP, checking each against its digest, and
/// arm one try of it. The staged files are the ones in slot-update's work
/// directory; the broker reads only those fixed names.
pub fn espInstall(
    vmlinuz: EspArtifact,
    stage0: EspArtifact,
    uki: ?EspArtifact,
    cmdline: EspArtifact,
) !void {
    var buf: [768]u8 = undefined;
    try espOk(try formatEspInstall(&buf, vmlinuz, stage0, uki, cmdline));
}

/// slotRoot has the broker copy the staged root.erofs of the other slot
/// slotRoot has the broker copy the staged root.erofs of the other slot
/// onto the boot filesystem, checking it against its digest.
pub fn slotRoot(root: EspArtifact) !void {
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try w.print("slot-root k={d}:{s}", .{ root.size, root.sha256 });
    try espOk(w.buffered());
}

/// slotDecl records the local-build declarations of the current and other
/// slots (64 lowercase hex characters each, or null to leave one alone).
pub fn slotDecl(current: ?[]const u8, next: ?[]const u8) !void {
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try w.print("slot-decl c={s} n={s}", .{ current orelse "-", next orelse "-" });
    try espOk(w.buffered());
}

/// slotMeta copies the staged signed image's manifest, signature and slot
/// command line onto the boot filesystem, each digest-checked.
pub fn slotMeta(manifest: EspArtifact, signature: EspArtifact, cmdline_file: EspArtifact) !void {
    var buf: [768]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try w.print("slot-meta a={d}:{s} b={d}:{s} c={d}:{s}", .{
        manifest.size,     manifest.sha256,     signature.size, signature.sha256,
        cmdline_file.size, cmdline_file.sha256,
    });
    try espOk(w.buffered());
}

/// slotState copies the staged boot.permit into /state/{position} on the
/// boot filesystem, checking it against its digest.
pub fn slotState(position: u1, permit: EspArtifact) !void {
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try w.print("slot-state p={d} k={d}:{s}", .{ position, permit.size, permit.sha256 });
    try espOk(w.buffered());
}

/// SlotJournal is a parsed slot-state request.
pub const SlotJournal = struct { position: u1, permit: EspArtifact };

/// parseSlotState parses a slot-state request line.
pub fn parseSlotState(line: []const u8) !SlotJournal {
    var it = std.mem.tokenizeScalar(u8, line, ' ');
    if (!std.mem.eql(u8, it.next() orelse return error.BadRequest, "slot-state"))
        return error.BadRequest;
    const p_tok = it.next() orelse return error.BadRequest;
    const k_tok = it.next() orelse return error.BadRequest;
    if (it.next() != null or p_tok.len != 3 or !std.mem.startsWith(u8, p_tok, "p=") or
        !std.mem.startsWith(u8, k_tok, "k=")) return error.BadRequest;
    const position: u1 = switch (p_tok[2]) {
        '0' => 0,
        '1' => 1,
        else => return error.BadRequest,
    };
    return .{ .position = position, .permit = try parseArtifact(k_tok[2..]) };
}

/// parseSlotRoot parses a slot-root request line.
pub fn parseSlotRoot(line: []const u8) !EspArtifact {
    var it = std.mem.tokenizeScalar(u8, line, ' ');
    if (!std.mem.eql(u8, it.next() orelse return error.BadRequest, "slot-root"))
        return error.BadRequest;
    const tok = it.next() orelse return error.BadRequest;
    if (it.next() != null or !std.mem.startsWith(u8, tok, "k=")) return error.BadRequest;
    return parseArtifact(tok[2..]);
}

/// SlotDecl is a parsed slot-decl request.
pub const SlotDecl = struct { current: ?[]const u8, next: ?[]const u8 };

/// parseSlotDecl parses a slot-decl request line.
pub fn parseSlotDecl(line: []const u8) !SlotDecl {
    var it = std.mem.tokenizeScalar(u8, line, ' ');
    if (!std.mem.eql(u8, it.next() orelse return error.BadRequest, "slot-decl"))
        return error.BadRequest;
    var out: SlotDecl = .{ .current = null, .next = null };
    var seen: u2 = 0;
    while (it.next()) |tok| {
        if (tok.len < 3 or tok[1] != '=') return error.BadRequest;
        const value = tok[2..];
        const slot: *?[]const u8, const bit: u2 = switch (tok[0]) {
            'c' => .{ &out.current, 1 },
            'n' => .{ &out.next, 2 },
            else => return error.BadRequest,
        };
        if (seen & bit != 0) return error.BadRequest;
        seen |= bit;
        if (std.mem.eql(u8, value, "-")) continue;
        if (!isHex64(value)) return error.BadRequest;
        slot.* = value;
    }
    if (seen != 0b11) return error.BadRequest;
    return out;
}

/// SlotMeta is a parsed slot-meta request.
pub const SlotMeta = struct {
    manifest: EspArtifact,
    signature: EspArtifact,
    cmdline_file: EspArtifact,
};

/// parseSlotMeta parses a slot-meta request line.
pub fn parseSlotMeta(line: []const u8) !SlotMeta {
    var it = std.mem.tokenizeScalar(u8, line, ' ');
    if (!std.mem.eql(u8, it.next() orelse return error.BadRequest, "slot-meta"))
        return error.BadRequest;
    var got: [3]?EspArtifact = .{ null, null, null };
    while (it.next()) |tok| {
        if (tok.len < 3 or tok[1] != '=') return error.BadRequest;
        const i: usize = switch (tok[0]) {
            'a' => 0,
            'b' => 1,
            'c' => 2,
            else => return error.BadRequest,
        };
        if (got[i] != null) return error.BadRequest;
        got[i] = try parseArtifact(tok[2..]);
    }
    return .{
        .manifest = got[0] orelse return error.BadRequest,
        .signature = got[1] orelse return error.BadRequest,
        .cmdline_file = got[2] orelse return error.BadRequest,
    };
}

/// formatEspInstall formats an esp-install request line in buf.
pub fn formatEspInstall(
    buf: []u8,
    vmlinuz: EspArtifact,
    stage0: EspArtifact,
    uki: ?EspArtifact,
    cmdline: EspArtifact,
) ![]const u8 {
    if (!validArtifact(vmlinuz) or !validArtifact(stage0) or !validArtifact(cmdline))
        return error.BadArtifact;
    if (uki) |u| if (!validArtifact(u)) return error.BadArtifact;
    var w: std.Io.Writer = .fixed(buf);
    try w.print(
        "esp-install k={d}:{s} s={d}:{s} u=",
        .{ vmlinuz.size, vmlinuz.sha256, stage0.size, stage0.sha256 },
    );
    if (uki) |u| try w.print("{d}:{s}", .{ u.size, u.sha256 }) else try w.writeAll("-");
    try w.print(" c={d}:{s}", .{ cmdline.size, cmdline.sha256 });
    return w.buffered();
}

/// parseEspInstall parses an esp-install request line. The artifacts'
/// digests are slices of line.
pub fn parseEspInstall(line: []const u8) !EspInstall {
    var it = std.mem.tokenizeScalar(u8, line, ' ');
    if (!std.mem.eql(u8, it.next() orelse return error.BadRequest, "esp-install"))
        return error.BadRequest;
    var got: EspInstall = .{
        .vmlinuz = .{ .size = 0, .sha256 = "" },
        .stage0 = .{ .size = 0, .sha256 = "" },
        .uki = null,
        .cmdline = .{ .size = 0, .sha256 = "" },
    };
    var seen: u4 = 0;
    while (it.next()) |tok| {
        const eq = std.mem.findScalar(u8, tok, '=') orelse return error.BadRequest;
        const value = tok[eq + 1 ..];
        switch (tok[0]) {
            'k', 's', 'u', 'c' => {},
            else => return error.BadRequest,
        }
        if (tok[0..eq].len != 1) return error.BadRequest;
        const bit: u4 = switch (tok[0]) {
            'k' => 1,
            's' => 2,
            'u' => 4,
            else => 8,
        };
        if (seen & bit != 0) return error.BadRequest;
        seen |= bit;
        if (std.mem.eql(u8, value, "-")) {
            if (tok[0] != 'u') return error.BadRequest;
            continue;
        }
        const art = try parseArtifact(value);
        switch (tok[0]) {
            'k' => got.vmlinuz = art,
            's' => got.stage0 = art,
            'u' => got.uki = art,
            else => got.cmdline = art,
        }
    }
    if (seen != 0b1111 or got.vmlinuz.sha256.len == 0 or got.stage0.sha256.len == 0 or
        got.cmdline.sha256.len == 0)
        return error.BadRequest;
    return got;
}

/// parseEspFiles parses an esp-inspect answer line.
pub fn parseEspFiles(line: []const u8) !EspFiles {
    if (!std.mem.startsWith(u8, line, "ok ")) return error.BadAnswer;
    var files: EspFiles = .{};
    var it = std.mem.tokenizeScalar(u8, line[3..], ' ');
    var seen: u3 = 0;
    while (it.next()) |tok| {
        const eq = std.mem.findScalar(u8, tok, '=') orelse return error.BadAnswer;
        if (eq != 1) return error.BadAnswer;
        const bit: u3 = switch (tok[0]) {
            'k' => 1,
            's' => 2,
            'u' => 4,
            else => return error.BadAnswer,
        };
        if (seen & bit != 0) return error.BadAnswer;
        seen |= bit;
        if (std.mem.eql(u8, tok[eq + 1 ..], "-")) continue;
        const art = try parseArtifact(tok[eq + 1 ..]);
        var file: EspFile = .{ .size = art.size, .sha256 = @splat(0) };
        @memcpy(&file.sha256, art.sha256);
        switch (tok[0]) {
            'k' => files.vmlinuz = file,
            's' => files.stage0 = file,
            else => files.uki = file,
        }
    }
    if (seen != 0b111) return error.BadAnswer;
    return files;
}

fn parseArtifact(value: []const u8) !EspArtifact {
    const colon = std.mem.findScalar(u8, value, ':') orelse return error.BadArtifact;
    const size = std.fmt.parseInt(u64, value[0..colon], 10) catch return error.BadArtifact;
    const sha256 = value[colon + 1 ..];
    if (size == 0 or !isHex64(sha256)) return error.BadArtifact;
    return .{ .size = size, .sha256 = sha256 };
}

fn validArtifact(a: EspArtifact) bool {
    return a.size > 0 and isHex64(a.sha256);
}

fn isHex64(s: []const u8) bool {
    if (s.len != 64) return false;
    for (s) |c| if (!(c >= '0' and c <= '9') and !(c >= 'a' and c <= 'f')) return false;
    return true;
}

const testing = std.testing;

test "neither esp nor boot is a mount word" {
    try testing.expect(std.meta.stringToEnum(Word, "esp") == null);
    try testing.expect(std.meta.stringToEnum(Word, "boot") == null);
    try testing.expect(std.meta.stringToEnum(Word, "shutdown") != null);
}

test "esp install requests and inspect answers round-trip" {
    const hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    var buf: [768]u8 = undefined;
    const line = try formatEspInstall(
        &buf,
        .{ .size = 10, .sha256 = hex },
        .{ .size = 20, .sha256 = hex },
        null,
        .{ .size = 30, .sha256 = hex },
    );
    const req = try parseEspInstall(line);
    try testing.expectEqual(10, req.vmlinuz.size);
    try testing.expectEqualStrings(hex, req.vmlinuz.sha256);
    try testing.expectEqual(20, req.stage0.size);
    try testing.expectEqual(null, req.uki);
    try testing.expectEqual(30, req.cmdline.size);
    // A request that does not name the command line's digest is refused:
    // the broker must never seal unbound options into a loader entry.
    try testing.expectError(error.BadRequest, parseEspInstall(try std.mem.print(
        &buf,
        "esp-install k=10:{s} s=20:{s} u=-",
        .{ hex, hex },
    )));
    try testing.expectError(error.BadArtifact, parseEspInstall("esp-install k=1:aa s=2:bb u=-"));
    try testing.expectError(error.BadArtifact, formatEspInstall(
        &buf,
        .{ .size = 0, .sha256 = hex },
        .{ .size = 20, .sha256 = hex },
        null,
        .{ .size = 30, .sha256 = hex },
    ));

    const files = try parseEspFiles(try std.mem.print(
        &buf,
        "ok k=10:{s} s=- u=30:{s}",
        .{ hex, hex },
    ));
    try testing.expectEqual(10, files.vmlinuz.?.size);
    try testing.expectEqualStrings(hex, &files.vmlinuz.?.sha256);
    try testing.expectEqual(null, files.stage0);
    try testing.expectEqual(30, files.uki.?.size);
    try testing.expectError(error.BadArtifact, parseEspFiles("ok k=1:aa s=- u=-"));
}

test "slot requests carry only digests and declarations" {
    const hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    var buf: [768]u8 = undefined;
    const root = try parseSlotRoot(try std.mem.print(&buf, "slot-root k=99:{s}", .{hex}));
    try testing.expectEqual(99, root.size);
    try testing.expectError(error.BadArtifact, parseSlotRoot("slot-root k=99:zz"));

    const decl = try parseSlotDecl(try std.mem.print(&buf, "slot-decl c={s} n=-", .{hex}));
    try testing.expectEqualStrings(hex, decl.current.?);
    try testing.expectEqual(null, decl.next);
    try testing.expectError(error.BadRequest, parseSlotDecl("slot-decl c=short n=-"));

    const meta = try parseSlotMeta(try std.mem.print(
        &buf,
        "slot-meta a=1:{s} b=2:{s} c=3:{s}",
        .{ hex, hex, hex },
    ));
    try testing.expectEqual(2, meta.signature.size);
    try testing.expectError(error.BadRequest, parseSlotMeta("slot-meta a=1:" ++ hex));

    const st = try parseSlotState(try std.mem.print(&buf, "slot-state p=1 k=42:{s}", .{hex}));
    try testing.expectEqual(@as(u1, 1), st.position);
    try testing.expectEqual(42, st.permit.size);
    try testing.expectError(error.BadRequest, parseSlotState("slot-state p=2 k=42:" ++ hex));
}

/// Request a clean update reboot through the fixed runit flags.
pub fn reboot() !void {
    try callOk(.updater, "reboot");
}

/// Publish the root-owned readiness flag after coordinator setup succeeds.
pub fn updaterReady() !void {
    try callOk(.updater, "updater-ready");
}

/// A host-private owner port is optional. Only the existing supervised updater
/// socketpair can receive its descriptor; no path or device is selected by a peer.
pub fn ownerChannel() !?i32 {
    const fd = clientFd(.updater);
    const word = "owner-channel";
    const sent = linux.sendto(fd, word, word.len, linux.MSG.NOSIGNAL, null, 0);
    if (linux.errno(sent) != .SUCCESS) return null;
    return receiveOwnerChannel(fd);
}

fn receiveOwnerChannel(fd: i32) !?i32 {
    var bytes: [128]u8 = undefined;
    var ancillary: [1040]u8 align(8) = undefined;
    var iov = [_]std.posix.iovec{.{ .base = &bytes, .len = bytes.len }};
    var msg: linux.msghdr = .{
        .name = null,
        .namelen = 0,
        .iov = &iov,
        .iovlen = 1,
        .control = &ancillary,
        .controllen = ancillary.len,
        .flags = 0,
    };
    const n = linux.recvmsg(fd, &msg, linux.MSG.CMSG_CLOEXEC);
    if (linux.errno(n) != .SUCCESS) return error.OwnerChannelReceive;
    var received: ?i32 = null;
    var valid = n > 0 and n <= bytes.len and msg.flags & (linux.MSG.TRUNC | linux.MSG.CTRUNC) == 0;
    var at: usize = 0;
    while (at + @sizeOf(linux.cmsghdr) <= msg.controllen) {
        const header: *align(1) const linux.cmsghdr = @ptrCast(&ancillary[at]);
        if (header.len < 16 or header.len > msg.controllen - at) {
            valid = false;
            break;
        }
        if (header.level != linux.SOL.SOCKET or header.type != linux.SCM.RIGHTS or
            (header.len - 16) % 4 != 0)
        {
            valid = false;
        } else {
            var pos = at + 16;
            while (pos < at + header.len) : (pos += 4) {
                const value = std.mem.readInt(
                    i32,
                    ancillary[pos..][0..4],
                    @import("builtin").cpu.arch.endian(),
                );
                if (received == null) received = value else {
                    _ = linux.close(value);
                    valid = false;
                }
            }
        }
        at += std.mem.alignForward(usize, header.len, 8);
    }
    errdefer if (received) |value| {
        _ = linux.close(value);
    };
    if (!valid) return error.BadOwnerChannelPacket;
    if (std.mem.eql(u8, bytes[0..n], "ok\n") and received != null) return received;
    if (received != null) return error.BadOwnerChannelPacket;
    // Mixed-version package updates remain functional with a previous broker.
    if (std.mem.eql(u8, bytes[0..n], "ok none\n") or
        std.mem.eql(u8, bytes[0..n], "no UnknownEspOperation\n")) return null;
    return error.OwnerChannelRefused;
}

pub fn sendOwnerChannel(socket: i32, fd: ?i32) !void {
    if (fd == null) {
        const text = "ok none\n";
        if (linux.sendto(socket, text, text.len, linux.MSG.NOSIGNAL | linux.MSG.DONTWAIT, null, 0) != text.len)
            return error.OwnerChannelSend;
        return;
    }
    var ancillary: [24]u8 align(8) = @splat(0);
    const endian = @import("builtin").cpu.arch.endian();
    std.mem.writeInt(usize, ancillary[0..8], 20, endian);
    std.mem.writeInt(i32, ancillary[8..12], linux.SOL.SOCKET, endian);
    std.mem.writeInt(i32, ancillary[12..16], linux.SCM.RIGHTS, endian);
    std.mem.writeInt(i32, ancillary[16..20], fd.?, endian);
    const text = "ok\n";
    const iov = [_]std.posix.iovec_const{.{ .base = text, .len = text.len }};
    const message: linux.msghdr_const = .{
        .name = null,
        .namelen = 0,
        .iov = &iov,
        .iovlen = 1,
        .control = &ancillary,
        .controllen = ancillary.len,
        .flags = 0,
    };
    if (linux.sendmsg(
        socket,
        &message,
        linux.MSG.NOSIGNAL | linux.MSG.DONTWAIT,
    ) != text.len) return error.OwnerChannelSend;
}

/// Called by the broker before it confines itself; kernel sysfs chooses the
/// device, one uniquely named virtio port. No guest path is accepted as input.
pub fn openOwnerPort(io: std.Io, gpa: std.mem.Allocator) !?i32 {
    var dir = std.Io.Dir.cwd().openDir(
        io,
        "/sys/class/virtio-ports",
        .{ .iterate = true },
    ) catch |err|
        return if (err == error.FileNotFound) null else err;
    defer dir.close(io);
    var entries = dir.iterate();
    var found: ?i32 = null;
    errdefer if (found) |fd| {
        _ = linux.close(fd);
    };
    var count: usize = 0;
    while (try entries.next(io)) |entry| {
        count += 1;
        if (count > 16) return error.TooManyOwnerPorts;
        if (!validOwnerDevice(entry.name)) return error.BadOwnerPort;
        const attr = try gpa.print("/sys/class/virtio-ports/{s}/name", .{entry.name});
        var file = std.Io.Dir.cwd().openFile(io, attr, .{}) catch |err|
            if (err == error.FileNotFound) continue else return err;
        defer file.close(io);
        var buffer: [65]u8 = undefined;
        const length = try file.readPositionalAll(io, &buffer, 0);
        if (length == buffer.len) return error.BadOwnerPort;
        if (!std.mem.eql(u8, std.mem.trim(u8, buffer[0..length], "\n"), "werewolf.owner")) continue;
        if (found != null) return error.AmbiguousOwnerPort;
        const path = try gpa.printSentinel("/dev/{s}", .{entry.name}, 0);
        const raw = linux.open(
            path,
            .{ .ACCMODE = .RDWR, .NONBLOCK = true, .NOFOLLOW = true, .CLOEXEC = true },
            0,
        );
        if (linux.errno(raw) != .SUCCESS) return error.OpenOwnerPort;
        const fd: i32 = @intCast(raw);
        found = fd;
        var st: linux.Statx = undefined;
        if (linux.errno(linux.statx(
            fd,
            "",
            linux.AT.EMPTY_PATH,
            .{ .TYPE = true },
            &st,
        )) != .SUCCESS or
            st.mode & linux.S.IFMT != linux.S.IFCHR) return error.BadOwnerPort;
        if (linux.errno(linux.fchown(fd, 0, 0)) != .SUCCESS or
            linux.errno(linux.fchmod(fd, 0o600)) != .SUCCESS)
            return error.UnsafeOwnerPort;
    }
    return found;
}

fn validOwnerDevice(name: []const u8) bool {
    if (!std.mem.startsWith(u8, name, "vport") or name.len > 32) return false;
    var parts = std.mem.splitScalar(u8, name[5..], 'p');
    const controller = parts.next().?;
    const port = parts.next() orelse return false;
    if (controller.len == 0 or port.len == 0 or parts.next() != null) return false;
    for (controller) |c| if (c < '0' or c > '9') return false;
    for (port) |c| if (c < '0' or c > '9') return false;
    return true;
}

test "owner port names cannot select arbitrary device paths" {
    try testing.expect(validOwnerDevice("vport0p0"));
    try testing.expect(validOwnerDevice("vport12p34"));
    for ([_][]const u8{ "vport", "vport../vda", "vport0/0", "vda", "vport0p1p2", "vportp1" }) |name|
        try testing.expect(!validOwnerDevice(name));
}

test "coordinator owner channel carries only one close-on-exec descriptor" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    var sockets: [2]i32 = undefined;
    try testing.expectEqual(
        linux.E.SUCCESS,
        linux.errno(linux.socketpair(
            linux.AF.UNIX,
            linux.SOCK.SEQPACKET | linux.SOCK.CLOEXEC,
            0,
            &sockets,
        )),
    );
    defer for (sockets) |fd| {
        _ = linux.close(fd);
    };
    var pipe: [2]i32 = undefined;
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.pipe2(&pipe, .{ .CLOEXEC = true })));
    defer for (pipe) |fd| {
        _ = linux.close(fd);
    };
    try sendOwnerChannel(sockets[0], pipe[0]);
    const received = (try receiveOwnerChannel(sockets[1])).?;
    defer _ = linux.close(received);
    try testing.expect(linux.fcntl(received, linux.F.GETFD, 0) & linux.FD_CLOEXEC != 0);
    try testing.expectEqual(@as(usize, 1), linux.write(pipe[1], "x", 1));
    var byte: [1]u8 = undefined;
    try testing.expectEqual(@as(usize, 1), linux.read(received, &byte, 1));
    try testing.expectEqual(@as(u8, 'x'), byte[0]);
    try sendOwnerChannel(sockets[0], null);
    try testing.expectEqual(null, try receiveOwnerChannel(sockets[1]));
    const malformed = "ok\n";
    _ = linux.sendto(sockets[0], malformed, malformed.len, linux.MSG.NOSIGNAL, null, 0);
    try testing.expectError(error.OwnerChannelRefused, receiveOwnerChannel(sockets[1]));
}
