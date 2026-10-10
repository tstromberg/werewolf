//! boot holds posture's boot-chain checks: what the firmware, the
//! kernel's own build, and the update machinery vouch for before PID 1
//! runs (docs/design/verified-boot.md).

const std = @import("std");
const linux = std.os.linux;
const testing = std.testing;

const posture = @import("posture.zig");
const Posture = posture.Posture;
const exists = posture.exists;
const trim = posture.trim;

/// The EFI variable every firmware keeps the Secure Boot state in, with
/// its vendor GUID: the global variable GUID.
const secure_boot_var =
    "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c";

/// Stage0 writes this once a TPM counter at least the running slot's
/// serial has held (phase 5). Nothing does yet, so the check fails and
/// every image excuses it (test/posture-known).
const rollback_marker = "/run/werewolf/rollback-checked";

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
    var buf: [64]u8 = undefined;
    const sb = parseSecureBoot(readBytes(secure_boot_var, &buf) orelse "");
    try p.add(.{
        .id = "boot-secure-boot",
        .area = "boot",
        .name = "Secure Boot on",
        .why = "Whoever reaches the console or the disk can boot another kernel, or another stage0 with its own root hash. Firmware that verifies signatures boots only what was signed.",
        .how = "the firmware's SecureBoot variable is on",
        .result = if (sb) |on| (if (on) .pass else .fail) else .skip,
        .detail = if (sb == null) "no EFI variables to read: no EFI firmware, or a kernel without them" else "",
    });
    const sig = parseSwitch(p.read("/sys/module/module/parameters/sig_enforce"));
    try p.add(.{
        .id = "boot-sig-enforced",
        .area = "boot",
        .name = "Module signatures enforced",
        .why = "Until init closes the module loader, the kernel's own build is all that decides what it runs: one built to refuse unsigned modules cannot be told to take them.",
        .how = "/sys/module/module/parameters/sig_enforce is Y",
        .result = if (sig) |on| (if (on) .pass else .fail) else .skip,
        .detail = if (sig == null) "this kernel has no module signature switch" else "",
    });
    try p.add(.{
        .id = "boot-rollback-protected",
        .area = "boot",
        .name = "Rollback protected",
        .why = "An older image, still signed, is an easier target than a new one; the boot must refuse to go back to it.",
        .how = "a TPM counter at least the running slot's serial, checked before handover, marked in " ++ rollback_marker,
        .result = if (exists(p.io, "/dev/tpmrm0") and exists(p.io, rollback_marker)) .pass else .fail,
        .detail = if (!exists(p.io, "/dev/tpmrm0"))
            "no TPM device: no counter to guard the slot serial"
        else
            "a TPM is here, but no counter checked this boot",
    });
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
