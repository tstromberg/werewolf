//! broker is the client for cmd/mount-broker. fence's Landlock domain stops
//! root's programs from mounting, so they ask the broker. See lib/README.md.

const std = @import("std");

/// Private metadata-only reader protocol; it never accepts a file path.
pub const LinkKind = enum(u8) { exe, cwd };
pub const link_request_size = 12;
pub const link_limit = 256;
pub const LinkRequest = struct { pid: u32, kind: LinkKind };

pub fn linkRequest(pid: u32, kind: LinkKind) ![link_request_size]u8 {
    if (pid == 0 or pid > std.math.maxInt(i32)) return error.BadLinkRequest;
    var raw: [link_request_size]u8 = @splat(0);
    @memcpy(raw[0..4], "WLP1");
    std.mem.writeInt(u32, raw[4..8], pid, .little);
    raw[8] = @backingInt(kind);
    return raw;
}

pub fn parseLinkRequest(raw: []const u8) !LinkRequest {
    if (raw.len != link_request_size or !std.mem.eql(u8, raw[0..4], "WLP1") or
        !std.mem.eql(u8, raw[9..12], &@as([3]u8, @splat(0)))) return error.BadLinkRequest;
    const pid = std.mem.readInt(u32, raw[4..8], .little);
    if (pid == 0 or pid > std.math.maxInt(i32)) return error.BadLinkRequest;
    return .{ .pid = pid, .kind = std.enums.fromInt(LinkKind, raw[8]) orelse
        return error.BadLinkRequest };
}

test "private process link requests accept only a bounded PID and metadata selector" {
    const t = std.testing;
    const valid = try linkRequest(42, .exe);
    try t.expectEqual(LinkRequest{ .pid = 42, .kind = .exe }, try parseLinkRequest(&valid));
    try t.expectError(error.BadLinkRequest, linkRequest(0, .cwd));
    try t.expectError(error.BadLinkRequest, linkRequest(0x80000000, .cwd));
    for (0..valid.len) |n| try t.expectError(error.BadLinkRequest, parseLinkRequest(valid[0..n]));
    for ([_]usize{ 0, 8, 9, 10, 11 }) |at| {
        var changed = valid;
        changed[at] = 255;
        try t.expectError(error.BadLinkRequest, parseLinkRequest(&changed));
    }
}
const linux = std.os.linux;

pub const socket_path = "/run/werewolf/mount-broker.sock";

/// mnt_dir is where the broker mounts what it is asked for.
pub const mnt_dir = "/run/werewolf/mnt";

/// Word is a request: one of two filesystems, or shutdown. The EFI
/// partition is not a word: no asker gets it as a mount (see the ESP
/// operations below).
pub const Word = enum {
    grub,
    victim,
    shutdown,

    /// place returns where w's filesystem is mounted. It is fixed so the
    /// asker never takes a path from the answer: root inside fence's domain
    /// could put its own listener at the socket in /run.
    pub fn place(w: Word) [:0]const u8 {
        return switch (w) {
            .grub => mnt_dir ++ "/grub",
            .victim => mnt_dir ++ "/victim",
            .shutdown => unreachable,
        };
    }
};

/// Held is a filesystem the broker has mounted for us. It stays mounted
/// while fd, the connection, is open.
pub const Held = struct {
    fd: i32,
    word: Word,

    pub fn path(h: *const Held) []const u8 {
        return h.word.place();
    }

    /// release closes the connection, and the broker unmounts.
    pub fn release(h: Held) void {
        _ = linux.close(h.fd);
    }
};

/// refusal holds the broker's answer after error.Refused.
pub var refusal_buf: [128]u8 = undefined;
pub var refusal: []const u8 = "";

/// ask sends word to the broker. For a filesystem, the mount lasts until
/// release or until this process exits.
pub fn ask(word: Word) !Held {
    const rc = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return error.NoSocket;
    const fd: i32 = @intCast(rc);
    errdefer _ = linux.close(fd);
    var addr: linux.sockaddr.un = .{ .family = linux.AF.UNIX, .path = @splat(0) };
    @memcpy(addr.path[0..socket_path.len], socket_path);
    if (linux.errno(linux.connect(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.un))) != .SUCCESS)
        return error.NoBroker;
    var line: [16]u8 = undefined;
    const request = std.mem.print(&line, "{s}\n", .{@tagName(word)}) catch unreachable;
    const sent = linux.sendto(fd, request.ptr, request.len, linux.MSG.NOSIGNAL, null, 0);
    if (linux.errno(sent) != .SUCCESS) return error.NoBroker;

    var buf: [128]u8 = undefined;
    var got: usize = 0;
    const answer = while (true) {
        if (std.mem.findScalar(u8, buf[0..got], '\n')) |end| break buf[0..end];
        if (got == buf.len) return error.BadAnswer;
        const n = linux.read(fd, buf[got..].ptr, buf.len - got);
        if (linux.errno(n) == .INTR) continue;
        if (linux.errno(n) != .SUCCESS or n == 0) return error.NoBroker;
        got += n;
    };
    const h: Held = .{ .fd = fd, .word = word };
    // The answer must name the word's fixed place. Otherwise a fake
    // listener at the socket could send the asker's writes anywhere.
    if (word == .shutdown) {
        if (std.mem.eql(u8, answer, "ok")) return h;
    } else if (std.mem.startsWith(u8, answer, "ok ") and
        std.mem.eql(u8, answer[3..], word.place()))
    {
        return h;
    }
    const n = @min(answer.len, refusal_buf.len);
    @memcpy(refusal_buf[0..n], answer[0..n]);
    refusal = refusal_buf[0..n];
    return error.Refused;
}

// --- the EFI partition -------------------------------------------------------
//
// The ESP is never lent as a mount. The broker mounts it detached, does
// one of these fixed operations itself, and closes it. Only the supervised
// slot-keep and slot-update services may ask (cmd/mount-broker checks the
// asking process's identity); every other root process is refused.

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

/// espCall sends one ESP request line and returns the broker's one-line
/// answer, in out. An answer of `no ...` is error.Refused.
fn espCall(request: []const u8, out: []u8) ![]const u8 {
    const rc = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return error.NoSocket;
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    var addr: linux.sockaddr.un = .{ .family = linux.AF.UNIX, .path = @splat(0) };
    @memcpy(addr.path[0..socket_path.len], socket_path);
    if (linux.errno(linux.connect(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.un))) != .SUCCESS)
        return error.NoBroker;
    for ([_][]const u8{ request, "\n" }) |part| {
        const sent = linux.sendto(fd, part.ptr, part.len, linux.MSG.NOSIGNAL, null, 0);
        if (linux.errno(sent) != .SUCCESS) return error.NoBroker;
    }
    var got: usize = 0;
    while (true) {
        if (std.mem.findScalar(u8, out[0..got], '\n')) |end| {
            const answer = out[0..end];
            if (std.mem.startsWith(u8, answer, "no")) {
                noteRefusal(answer);
                return error.Refused;
            }
            if (!std.mem.startsWith(u8, answer, "ok")) return error.BadAnswer;
            return answer;
        }
        if (got == out.len) return error.BadAnswer;
        const n = linux.read(fd, out[got..].ptr, out.len - got);
        if (linux.errno(n) == .INTR) continue;
        if (linux.errno(n) != .SUCCESS or n == 0) return error.NoBroker;
        got += n;
    }
}

fn espOk(request: []const u8) !void {
    var out: [256]u8 = undefined;
    const answer = try espCall(request, &out);
    if (!std.mem.eql(u8, answer, "ok")) return error.BadAnswer;
}

/// espStatus reports whether this boot's entry is already good, still
/// counting tries, or absent.
pub fn espStatus() !EspStatus {
    var out: [256]u8 = undefined;
    const answer = try espCall("esp-status", &out);
    if (std.mem.eql(u8, answer, "ok already")) return .already;
    if (std.mem.eql(u8, answer, "ok tried")) return .tried;
    if (std.mem.eql(u8, answer, "ok none")) return .none;
    return error.BadAnswer;
}

/// espCommit renames this boot's counting entry to its good name.
pub fn espCommit() !void {
    try espOk("esp-commit");
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
/// onto the victim filesystem, checking it against its digest. On native
/// boots that filesystem is never lent as a mount either.
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
/// command line onto the victim filesystem, each digest-checked.
pub fn slotMeta(manifest: EspArtifact, signature: EspArtifact, cmdline_file: EspArtifact) !void {
    var buf: [768]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try w.print("slot-meta a={d}:{s} b={d}:{s} c={d}:{s}", .{
        manifest.size,     manifest.sha256,     signature.size, signature.sha256,
        cmdline_file.size, cmdline_file.sha256,
    });
    try espOk(w.buffered());
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

test "esp is not a mount word" {
    try testing.expect(std.meta.stringToEnum(Word, "esp") == null);
    try testing.expect(std.meta.stringToEnum(Word, "victim") != null);
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
}
