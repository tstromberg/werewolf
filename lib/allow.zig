//! allow lists the allowances a form may use to take back one of werewolf's
//! defaults, and the capabilities werewolf takes from root. Only the image
//! decides allowances. See lib/README.md and docs/design/lockdown.md.

const std = @import("std");
const linux = std.os.linux;

pub const Allowance = enum {
    /// kvm lets the machine run virtual machines. KVM is built in on aarch64
    /// and loaded from the form's modules on x86_64; nesting stays off.
    kvm,
    /// nested-kvm lets guests run virtual machines too. It needs kvm.
    @"nested-kvm",
    /// netadmin keeps CAP_NET_ADMIN after fence, to change addresses, routes
    /// and fence's rules. DHCP does not need it: init starts the client
    /// before fence.
    netadmin,
    /// packet keeps CAP_NET_RAW after fence. Packet sockets bypass fence's rules.
    packet,
    /// ipv6 boots the kernel with IPv6. Otherwise ipv6.disable=1 removes the
    /// family and the code behind it (CVE-2026-53362;
    /// docs/cve-mitigation-survey.md).
    ipv6,
    /// pty lets init mount devpts, for ssh logins. Without it /dev/ptmx
    /// fails even for root, and the TTY layer's pty code is out of reach
    /// (CVE-2014-0196).
    pty,
    /// jit leaves Memory-Deny-Write-Execute off, for runtimes that compile
    /// code (a JVM, V8, .NET, PCRE2's JIT, LLVM). Without it no process can
    /// make written memory executable, so code an exploit writes never runs.
    jit,
    /// sh lets every leashed service run the sh shim (cmd/sh-shim), which
    /// starts only what the service's `run` lines name. The grant is the
    /// shim's file, so it covers /bin/sh only where /bin/sh is the shim,
    /// never a package's shell.
    sh,
};

/// dir holds one empty file per allowance the form grants.
pub const dir = "/etc/werewolf/allow";

/// has reports whether the machine's form grants a.
pub fn has(a: Allowance) bool {
    switch (a) {
        inline else => |t| return linux.errno(
            linux.access(dir ++ "/" ++ @tagName(t), linux.F_OK),
        ) == .SUCCESS,
    }
}

/// Cap lists the capabilities werewolf takes from root, numbered as in
/// linux/capability.h. init drops most from the bounding set, fence drops
/// the network ones and CAP_SYS_ADMIN, and posture checks they are gone.
pub const Cap = enum(u6) {
    linux_immutable = 9,
    net_admin = 12,
    net_raw = 13,
    sys_module = 16,
    sys_rawio = 17,
    sys_ptrace = 19,
    sys_pacct = 20,
    sys_admin = 21,
    sys_boot = 22,
    sys_time = 25,
    mknod = 27,
    audit_control = 30,
    mac_override = 32,
    mac_admin = 33,
    wake_alarm = 35,
    block_suspend = 36,
    perfmon = 38,
    bpf = 39,
    checkpoint_restore = 40,

    /// allowance returns the allowance that keeps c, if any.
    pub fn allowance(c: Cap) ?Allowance {
        return switch (c) {
            .net_admin => .netadmin,
            .net_raw => .packet,
            else => null,
        };
    }

    /// name returns CAP_NAME, as the kernel headers spell it.
    pub fn name(c: Cap) []const u8 {
        switch (c) {
            inline else => |t| return comptime upper("CAP_" ++ @tagName(t)),
        }
    }
};

fn upper(comptime s: []const u8) []const u8 {
    var out: [s.len]u8 = undefined;
    for (s, &out) |c, *o| o.* = std.ascii.toUpper(c);
    const done = out;
    return &done;
}

test "Cap.name" {
    try std.testing.expectEqualStrings("CAP_NET_ADMIN", Cap.net_admin.name());
    try std.testing.expectEqualStrings("CAP_CHECKPOINT_RESTORE", Cap.checkpoint_restore.name());
    inline for (@typeInfo(Cap).@"enum".field_names) |n|
        try std.testing.expectEqual(
            @field(linux.CAP, upper(n)),
            @backingInt(@field(Cap, n)),
        );
}
