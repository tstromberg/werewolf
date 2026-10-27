//! boot holds posture's boot-chain checks: what the firmware, the
//! kernel's own build, and the update machinery vouch for before PID 1
//! runs (docs/design/implemented/verified-boot.md).

const std = @import("std");
const linux = std.os.linux;
const testing = std.testing;
const ipe = @import("ipe");
const tpm = @import("tpm");
const cmdline = @import("cmdline");

const posture = @import("posture.zig");
const Posture = posture.Posture;
const exists = posture.exists;
const trim = posture.trim;

/// The EFI variable every firmware keeps the Secure Boot state in, with
/// its vendor GUID: the global variable GUID.
const secure_boot_var =
    "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c";
const setup_mode_var =
    "/sys/firmware/efi/efivars/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c";

/// parseSecureBoot reads the SecureBoot variable's bytes: four attribute
/// bytes, then the value. null says the bytes are not a variable to judge.
fn parseSecureBoot(data: []const u8) ?bool {
    if (data.len != 5) return null;
    return switch (data[4]) {
        0 => false,
        1 => true,
        else => null,
    };
}

fn secureBoot(enabled: ?bool, setup: ?bool) ?bool {
    const on = enabled orelse return null;
    return on and setup != null and !setup.?;
}

test "Secure Boot posture requires enforcement outside setup mode" {
    const t = std.testing;
    try t.expect(secureBoot(true, false).?);
    try t.expect(!secureBoot(false, false).?);
    try t.expect(!secureBoot(true, true).?);
    try t.expect(!secureBoot(true, null).?);
    try t.expect(secureBoot(null, false) == null);
}

test "generic Linux boot checks omit image policy and TPM release authorization" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var p: Posture = .{ .io = testing.io, .gpa = arena.allocator(), .root = false };
    try check(&p);
    try testing.expectEqual(@as(usize, 2), p.checks.items.len);
    try testing.expectEqualStrings("boot-secure-boot", p.checks.items[0].id);
    try testing.expectEqualStrings("boot-sig-enforced", p.checks.items[1].id);
}

/// parseSwitch reads a kernel module parameter that holds Y or N.
fn parseSwitch(text: []const u8) ?bool {
    const t = trim(text);
    if (std.mem.eql(u8, t, "Y")) return true;
    if (std.mem.eql(u8, t, "N")) return false;
    return null;
}

/// readBytes reads at most buf.len bytes of path, raw: efivar files hold
/// NULs, which a text read stops at.
fn readBytes(path: []const u8, buf: []u8) ?[]const u8 {
    if (path.len >= 256) return null;
    var z: [256]u8 = undefined;
    @memcpy(z[0..path.len], path);
    z[path.len] = 0;
    const rc = linux.open(z[0..path.len :0], .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(rc) != .SUCCESS) return null;
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    var len: usize = 0;
    while (len < buf.len) {
        const n = linux.read(fd, buf[len..].ptr, buf.len - len);
        const err = linux.errno(n);
        if (err == .SUCCESS) {
            if (n == 0) break;
            len += @intCast(n);
            continue;
        }
        if (err == .INTR) continue;
        return null;
    }
    return buf[0..len];
}

pub fn check(p: *Posture) !void {
    if (p.werewolf) try imagePolicy(p);
    var buf: [64]u8 = undefined;
    const sb_value = parseSecureBoot(readBytes(secure_boot_var, &buf) orelse "");
    const setup_value = parseSecureBoot(readBytes(setup_mode_var, &buf) orelse "");
    const sb = secureBoot(sb_value, setup_value);
    try p.add(.{
        .id = "boot-secure-boot",
        .area = "boot",
        .name = "Secure Boot on",
        .why = "Whoever reaches the console or the disk can boot another kernel, or another " ++
            "stage0 with its own root hash. Firmware that verifies signatures boots only what " ++
            "was signed.",
        .how = "SecureBoot is on and SetupMode is off",
        .expected = "SecureBoot byte 4 = 1; SetupMode byte 4 = 0",
        .observed = try p.gpa.print(
            "SecureBoot={s}; SetupMode={s}",
            .{
                if (sb_value) |on| if (on) "1" else "0" else "unavailable/invalid",
                if (setup_value) |on| if (on) "1" else "0" else "unavailable/invalid",
            },
        ),
        .result = if (sb) |on| (if (on) .pass else .fail) else .skip,
        .detail = if (sb == null)
            "no EFI variables to read: no EFI firmware, or a kernel without them"
        else
            "",
    });
    const sig_value = trim(p.read("/sys/module/module/parameters/sig_enforce"));
    const sig = parseSwitch(sig_value);
    // werewolf's kernel has no module loader at all, which no signature
    // switch can match; a kernel with one must enforce signatures.
    const no_loader = sig == null and !exists(p.io, "/proc/modules");
    try p.add(.{
        .id = "boot-sig-enforced",
        .area = "boot",
        .name = "No unsigned kernel modules",
        .why = "The kernel's own build is all that decides what it runs: one with no module " ++
            "loader, or built to refuse unsigned modules, cannot be told to take them.",
        .how = "the kernel has no module loader, or /sys/module/module/parameters/sig_enforce is Y",
        .expected = "no loader, or Y",
        .observed = if (no_loader)
            "no module loader"
        else if (sig_value.len > 0)
            sig_value
        else
            "unavailable (missing, unreadable or empty)",
        .result = if (no_loader) .pass else if (sig) |on| (if (on) .pass else .fail) else .skip,
        .detail = if (no_loader)
            "built without modules"
        else if (sig == null)
            "this kernel has no module signature switch"
        else
            "",
    });
    if (p.werewolf) try rollback(p);
}

fn imagePolicy(p: *Posture) !void {
    const ipe_on = ipe.enforced(
        p.read(ipe.policy_path),
        p.read(ipe.active),
        p.read(ipe.base ++ "/enforce"),
    );
    const bounded = posture.capBit(p.read("/proc/1/status"), "CapBnd", 33);
    try p.add(.{
        .id = "boot-ipe-enforced",
        .area = "boot",
        .name = "Only this image's native code executes",
        .why = "A trusted loader must not map untrusted native code, and root must not " ++
            "disable the integrity policy. IPE judges executable files and mappings globally.",
        .how = "the single-root default-deny policy is active and enforcing, and PID 1 " ++
            "cannot regain CAP_MAC_ADMIN",
        .result = if (ipe_on and bounded != null and !bounded.?) .pass else .fail,
        .detail = if (!ipe_on)
            if (p.disabled.contains(.ipe))
                "no enforcing release IPE policy: --disable gave it up (werewolf.disable)"
            else
                "no enforcing release IPE policy"
        else
            "",
    });
}

fn rollback(p: *Posture) !void {
    const has_tpm = exists(p.io, tpm.device);
    var rb: posture.Check = .{
        .id = "boot-rollback-protected",
        .area = "boot",
        .name = "Rollback protected",
        .why = "Retired signed images must be refused while the retained A/B release remains " ++
            "bootable.",
        .how = "stage0 admitted this release at or above its channel's TPM floor before " ++
            "handover, as " ++ tpm.Marker.path ++ " records",
        .result = .fail,
    };
    const text = p.read(tpm.Marker.path);
    // A root SSH session may not read init's records (forms/sshd's Landlock layer).
    if (text.len == 0 and exists(p.io, tpm.Marker.path)) {
        rb.detail = "this process may not read stage0's record, as an SSH session may not";
        rb.result = .skip;
        return p.fromBoot(rb);
    }
    var bad: cmdline.Failure = .{};
    const found = tpm.Marker.parse(text);
    if (found) |m| p.tpm = .{ .handle = m.handle, .floor = m.floor, .index = m.index };
    const release = cmdline.parse(p.read("/proc/cmdline"), &bad);
    rb.result = if (has_tpm and found != null and release != null and
        floorMatches(release.?, found.?)) .pass else .fail;
    rb.detail = if (!has_tpm)
        "no TPM device: no release floor"
    else if (found == null)
        "stage0 recorded no TPM floor for this boot"
    else if (rb.result == .fail)
        "the recorded floor is not this boot's release"
    else
        "";
    try p.add(rb);
}

/// floorMatches reports whether stage0's record is of this boot's release.
fn floorMatches(release: cmdline.Cmdline, m: tpm.Marker) bool {
    const channel = release.channel orelse return false;
    return tpm.handle(channel) == m.handle and release.index.? == m.index;
}

test floorMatches {
    var f: cmdline.Failure = .{};
    const line = "werewolf.native=1 werewolf.secure=1 " ++
        "werewolf.slots=57e1f000-77e2-4b0f-8a3c-0000000000a0 werewolf.esp=57E1-F000 " ++
        "werewolf.channel=abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd" ++
        " werewolf.index=7";
    const release = cmdline.parse(line, &f).?;
    try testing.expect(floorMatches(release, .{ .handle = 0x0150abcd, .floor = 3, .index = 7 }));
    try testing.expect(!floorMatches(release, .{ .handle = 0x0150abcd, .floor = 3, .index = 8 }));
    try testing.expect(!floorMatches(release, .{ .handle = 0x0150abce, .floor = 3, .index = 7 }));
}

test parseSecureBoot {
    try testing.expectEqual(true, parseSecureBoot(&.{ 0, 0, 0, 0, 1 }));
    try testing.expectEqual(false, parseSecureBoot(&.{ 0, 0, 0, 0, 0 }));
    try testing.expectEqual(null, parseSecureBoot(&.{ 0, 0, 0, 0, 2 }));
    try testing.expectEqual(null, parseSecureBoot(&.{ 0, 0, 0, 0 }));
    try testing.expectEqual(null, parseSecureBoot(""));
}

test parseSwitch {
    try testing.expectEqual(true, parseSwitch("Y\n"));
    try testing.expectEqual(false, parseSwitch("N\n"));
    try testing.expectEqual(null, parseSwitch(""));
    try testing.expectEqual(null, parseSwitch("y\n"));
    try testing.expectEqual(null, parseSwitch("YN"));
}
