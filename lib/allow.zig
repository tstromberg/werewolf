//! allow lists the allowances a form may use to take back one of werewolf's
//! defaults, and the capabilities werewolf takes from root. Only the image
//! decides allowances. See lib/README.md and docs/design/implemented/lockdown.md.

const std = @import("std");
const linux = std.os.linux;

pub const Allowance = enum {
    /// kvm lets the machine run virtual machines. KVM is built into the
    /// kernel and kept from starting without it; nesting stays off.
    kvm,
    /// nested-kvm lets guests run virtual machines too. It needs kvm.
    @"nested-kvm",
    /// netadmin keeps CAP_NET_ADMIN after fence, to change addresses, routes
    /// and fence's rules. DHCP does not need it: init starts the client
    /// before fence.
    netadmin,
    /// packet keeps CAP_NET_RAW after fence. Packet sockets bypass fence's rules.
    packet,
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

/// dir holds one empty file per general allowance the form grants, read at
/// runtime by werewolf itself (has, below). Runtime allowances live apart, in
/// runtime_dir.
pub const dir = "/etc/werewolf/allow";

/// runtime_dir is the portable tree the hardened interpreters read, the same
/// on werewolf and on any distro shipping the packages. A runtime allowance is
/// an empty file at runtime_dir/<ns>/RUNTIME/NAME: NS the service it is for, or
/// runtime_blanket for every service. The interpreter reads it off the
/// read-only root, never from argv or the environment, which a process that
/// re-runs its runtime controls; NS is the service's cgroup leaf, which the
/// supervisor sets and the process cannot change. See
/// docs/design/implemented/hardened-interpreters.md.
pub const runtime_dir = "/etc/runtime-hardening/allow";

/// runtime_blanket names the namespace an image-wide runtime allowance uses.
/// A form's top-level allow list writes here; services.NAME.allow writes to
/// that service's cgroup namespace instead.
pub const runtime_blanket = "all";

/// RuntimeAllowance is PACKAGE:NAME, a capability granted to a hardened package.
/// Packages define their own capability names; forms validate only the shape.
pub const RuntimeAllowance = struct {
    runtime: []const u8,
    name: []const u8,

    /// parse requires exactly one colon between two nonempty names made of
    /// a-z, 0-9 and dash, safe as single components of the allowance path.
    pub fn parse(word: []const u8) ?RuntimeAllowance {
        const colon = std.mem.findScalar(u8, word, ':') orelse return null;
        const runtime = word[0..colon];
        const name = word[colon + 1 ..];
        if (!isName(runtime) or !isName(name)) return null;
        return .{ .runtime = runtime, .name = name };
    }

    pub fn isName(name: []const u8) bool {
        if (name.len == 0) return false;
        for (name) |c| if (!std.ascii.isLower(c) and !std.ascii.isDigit(c) and c != '-')
            return false;
        return true;
    }
};

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

test "RuntimeAllowance.parse" {
    const t = std.testing;
    for ([_][2][]const u8{
        .{ "php", "exec" },
        .{ "php", "upload-progress" },
        .{ "glibc", "dlopen" },
        .{ "glibc", "ifunc" },
        .{ "future-package2", "feature-3" },
        .{ "0123456789", "abcdefghijklmnopqrstuvwxyz-" },
    }) |parts| {
        const word = try t.allocator.print("{s}:{s}", .{ parts[0], parts[1] });
        defer t.allocator.free(word);
        const grant = RuntimeAllowance.parse(word).?;
        try t.expectEqualStrings(parts[0], grant.runtime);
        try t.expectEqualStrings(parts[1], grant.name);
    }
    for ([_][]const u8{
        "",              "php",            "jit",            ":",
        "php:",          ":exec",          "php:exec:x",     "php::exec",
        "php:../exec",   "../php:exec",    "php:.",          ".:exec",
        "php:/exec",     "php/other:exec", "php:exec/other", "php:exec\\other",
        "PHP:exec",      "php:Exec",       "php_name:exec",  "php:proc_open",
        "php.name:exec", "php:exec.name",  " php:exec",      "php:exec ",
        "php:ex ec",     "php:exec\n",     "php:exec\x00",
        "phé:exec",
        "php:éxec",
    }) |w| try t.expectEqual(null, RuntimeAllowance.parse(w));
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
