//! allow: what a form may take back of werewolf's defaults, and the
//! capabilities werewolf takes from root, with the allowance that keeps
//! each, if any. A form names its allowances in form.yaml's `allow`, added
//! to along its chain, so no form drops what one it is built on was given
//! (lib/form.zig checks each name against Allowance). The build writes
//! them into the image, an empty file each in /etc/werewolf/allow, and
//! turns them into its kernel arguments and module parameters (Makefile,
//! allowances). Nothing on the machine reads an allowance from its command
//! line, config or metadata, which root can rewrite: the image is what
//! decides (docs/design/lockdown.md, Allowances).

const std = @import("std");
const linux = std.os.linux;

pub const Allowance = enum {
    /// Run virtual machines: KVM starts, built in (aarch64) or from the
    /// form's modules (x86_64), with nested virtualization off.
    kvm,
    /// And let their guests run virtual machines too; needs kvm.
    @"nested-kvm",
    /// CAP_NET_ADMIN after boot, which fence otherwise drops: to change
    /// addresses, routes and fence's rules. DHCP needs none: init starts
    /// its renewal before fence.
    netadmin,
    /// CAP_NET_RAW after boot: packet sockets, which pass below fence's
    /// rules.
    packet,
    /// IPv6, which the kernel is otherwise booted without (ipv6.disable=1):
    /// no address family, and none of the code behind it
    /// (docs/cve-mitigation-survey.md, CVE-2026-53362).
    ipv6,
    /// Pseudo-terminals, for ssh logins: init mounts devpts. Without it
    /// /dev/ptmx opens nothing, for root too, and the TTY layer's
    /// pseudo-terminal code is out of reach (CVE-2014-0196).
    pty,
    /// Memory written and then run, for a runtime that compiles code as it
    /// runs (a JVM, V8, .NET, PCRE2's JIT, LLVM): init leaves
    /// Memory-Deny-Write-Execute off. Without it no process can make memory
    /// both writable and executable, or executable once written, so code an
    /// exploit writes never runs.
    jit,
};

/// Where the image holds its form's allowances, an empty file each.
pub const dir = "/etc/werewolf/allow";

/// Whether the machine's form allows a.
pub fn has(a: Allowance) bool {
    switch (a) {
        inline else => |t| return linux.errno(
            linux.access(dir ++ "/" ++ @tagName(t), linux.F_OK),
        ) == .SUCCESS,
    }
}

/// The capabilities werewolf takes from root, by their numbers in
/// linux/capability.h: init drops most from the bounding set for good,
/// fence the network's and CAP_SYS_ADMIN, and posture checks they are
/// gone.
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

    /// The allowance that keeps it, if any.
    pub fn allowance(c: Cap) ?Allowance {
        return switch (c) {
            .net_admin => .netadmin,
            .net_raw => .packet,
            else => null,
        };
    }

    /// CAP_NAME, as the kernel's headers spell it.
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
