//! IPE's release policy and the checks shared by stage0, init and posture.
const std = @import("std");
const mem = std.mem;
const linux = std.os.linux;

pub const marker = "/usr/share/werewolf/ipe";
pub const base = "/sys/kernel/security/ipe";
pub const active = base ++ "/policies/werewolf/active";
pub const policy_path = base ++ "/policies/werewolf/policy";
pub const prefix = "policy_name=werewolf policy_version=1.0.0\n" ++
    "DEFAULT action=DENY\nop=EXECUTE dmverity_roothash=sha256:";
pub const suffix = " action=ALLOW\n";
pub const max_policy = 64 << 10;
/// boot_policy is the TPM bootstrap image's: its initramfs alone may execute.
/// The kernel has no policy of its own; tpm-enroll activates this one, signed
/// with the image key, before anything else runs.
pub const boot_policy = "policy_name=werewolf_boot policy_version=0.0.0\n" ++
    "DEFAULT action=DENY\nop=EXECUTE boot_verified=TRUE action=ALLOW\n";

/// Enrollment trusts only the signed initramfs and never enables a workload root.
pub fn bootstrapEnforced(text: []const u8, is_active: []const u8, enforce: []const u8) bool {
    return mem.eql(u8, text, boot_policy) and mem.eql(u8, mem.trim(u8, is_active, "\n"), "1") and
        mem.eql(u8, mem.trim(u8, enforce, "\n"), "1");
}

test "bootstrap IPE trust refuses permissive policies and disabled enforcement" {
    const t = std.testing;
    try t.expect(bootstrapEnforced(boot_policy, "1\n", "1\n"));
    try t.expect(!bootstrapEnforced(boot_policy, "0", "1"));
    try t.expect(!bootstrapEnforced(boot_policy, "1", "0"));
    try t.expect(!bootstrapEnforced("DEFAULT action=ALLOW\n", "1", "1"));
    try t.expect(!bootstrapEnforced(boot_policy ++ "op=EXECUTE action=ALLOW\n", "1", "1"));
}

/// policy writes the single-root policy; no initramfs or other volume is trusted.
pub fn policy(w: *std.Io.Writer, root: [32]u8) std.Io.Writer.Error!void {
    try w.print(prefix ++ "{s}" ++ suffix, .{std.fmt.bytesToHex(root, .lower)});
}

/// policyRoot accepts only our canonical, single-root, default-deny policy.
pub fn policyRoot(text: []const u8) ?[32]u8 {
    if (!mem.startsWith(u8, text, prefix) or !mem.endsWith(u8, text, suffix) or
        text.len != prefix.len + 64 + suffix.len) return null;
    var root: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&root, text[prefix.len..][0..64]) catch return null;
    return root;
}

pub fn enforced(text: []const u8, is_active: []const u8, enforce: []const u8) bool {
    return policyRoot(text) != null and
        mem.eql(u8, mem.trim(u8, is_active, "\n"), "1") and
        mem.eql(u8, mem.trim(u8, enforce, "\n"), "1");
}

/// checkConfig rejects a kernel that cannot hold the IPE boundary: IPE and
/// forced lockdown built in, no module loader, and no policy of its own, so
/// an image without a signed release policy boots unenforced, never refused.
pub fn checkConfig(text: []const u8) !void {
    for ([_][]const u8{
        "SECURITY_IPE",
        "IPE_PROP_DM_VERITY",
        "SECURITYFS",
        "AUDIT",
        "AUDITSYSCALL",
        "LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY",
    }) |opt| {
        if (!mem.eql(u8, configValue(text, opt), "y")) return error.IpeKernelConfig;
    }
    var lsms = mem.tokenizeAny(u8, configValue(text, "LSM"), "\", ");
    var found = false;
    while (lsms.next()) |lsm| if (mem.eql(u8, lsm, "ipe")) {
        found = true;
    };
    if (!found or configValue(text, "IPE_BOOT_POLICY").len > 2 or
        configValue(text, "SYSTEM_TRUSTED_KEYS").len <= 2) return error.IpeKernelConfig;
    for ([_][]const u8{
        "MODULES",
        "KEXEC",
        "KEXEC_FILE",
        "KEXEC_CORE",
        "IPE_POLICY_SIG_SECONDARY_KEYRING",
        "IPE_POLICY_SIG_PLATFORM_KEYRING",
    }) |opt| {
        if (mem.eql(u8, configValue(text, opt), "y")) return error.IpeKernelConfig;
    }
}

fn configValue(text: []const u8, name: []const u8) []const u8 {
    var lines = mem.tokenizeScalar(u8, text, '\n');
    while (lines.next()) |line| {
        const rest = mem.cutPrefix(u8, line, "CONFIG_") orelse continue;
        if (rest.len > name.len and mem.startsWith(u8, rest, name) and rest[name.len] == '=')
            return rest[name.len + 1 ..];
    }
    return "";
}

/// lockAdmin removes IPE administration from every capability set before fork.
/// Dropping the bounding set alone would leave stage0's effective capability.
pub fn lockAdmin() !void {
    const mac_admin = 33;
    if (linux.errno(linux.prctl(24, mac_admin, 0, 0, 0)) != .SUCCESS)
        return error.IpeCapability;
    const Header = extern struct { version: u32 = 0x20080522, pid: i32 = 0 };
    const Sets = extern struct { effective: u32, permitted: u32, inheritable: u32 };
    var header: Header = .{};
    var sets: [2]Sets = undefined;
    if (linux.errno(linux.syscall2(.capget, @intFromPtr(&header), @intFromPtr(&sets))) != .SUCCESS)
        return error.IpeCapability;
    const mask: u32 = ~@as(u32, 1 << (mac_admin - 32));
    sets[1].effective &= mask;
    sets[1].permitted &= mask;
    sets[1].inheritable &= mask;
    if (linux.errno(linux.syscall2(.capset, @intFromPtr(&header), @intFromPtr(&sets))) != .SUCCESS)
        return error.IpeCapability;
}

test "release policy accepts exactly one trusted root" {
    const t = std.testing;
    var w: std.Io.Writer.Allocating = .init(t.allocator);
    defer w.deinit();
    const root: [32]u8 = @splat(0xab);
    try policy(&w.writer, root);
    try t.expectEqual(root, policyRoot(w.written()).?);
    try t.expect(enforced(w.written(), "1\n", "1"));
    try t.expect(!enforced(w.written(), "0", "1"));
    try t.expect(!enforced(w.written(), "1", "0"));
    try t.expect(!enforced(w.written(), "", "1"));
    try t.expect(!enforced(w.written(), "1", ""));
    try t.expect(policyRoot(prefix ++ "bad" ++ suffix) == null);
    const invalid = try t.allocator.dupe(u8, w.written());
    defer t.allocator.free(invalid);
    invalid[prefix.len] = 'z';
    try t.expect(policyRoot(invalid) == null);
    try t.expect(policyRoot("DEFAULT action=ALLOW\n") == null);
    try w.writer.writeAll("op=EXECUTE boot_verified=TRUE action=ALLOW\n");
    try t.expect(policyRoot(w.written()) == null);
}

test "IPE cannot silently disappear from the kernel" {
    const t = std.testing;
    const config = "CONFIG_SECURITY_IPE=y\nCONFIG_IPE_PROP_DM_VERITY=y\n" ++
        "CONFIG_SECURITYFS=y\nCONFIG_AUDIT=y\n" ++
        "CONFIG_AUDITSYSCALL=y\nCONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY=y\n" ++
        "CONFIG_LSM=\"landlock,lockdown,yama,ipe\"\nCONFIG_IPE_BOOT_POLICY=\"\"\n" ++
        "CONFIG_SYSTEM_TRUSTED_KEYS=\"image.crt\"\n# CONFIG_MODULES is not set\n";
    try checkConfig(config);
    try t.expectError(error.IpeKernelConfig, checkConfig(config["CONFIG_SECURITY_IPE=y\n".len..]));
    try t.expectError(error.IpeKernelConfig, checkConfig("CONFIG_LSM=\"landlock\"\n" ++ config));
    try t.expectError(error.IpeKernelConfig, checkConfig(config ++ "CONFIG_KEXEC=y\n"));
    try t.expectError(error.IpeKernelConfig, checkConfig(config ++ "CONFIG_MODULES=y\n"));
    // A policy of the kernel's own would refuse every image signed for no root.
    try t.expectError(
        error.IpeKernelConfig,
        checkConfig("CONFIG_IPE_BOOT_POLICY=\"boot.policy\"\n" ++ config),
    );
    try t.expectError(
        error.IpeKernelConfig,
        checkConfig(config ++ "CONFIG_IPE_POLICY_SIG_SECONDARY_KEYRING=y\n"),
    );
}
