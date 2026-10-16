//! allow lists the allowances a form may use to take back one of werewolf's
//! defaults, and the capabilities werewolf takes from root. Only the image
//! decides allowances. See lib/README.md and docs/design/lockdown.md.

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

/// dir holds one empty file per allowance the form grants, and a directory per
/// runtime holding one empty file per runtime allowance (Runtime).
pub const dir = "/etc/werewolf/allow";

/// Runtime is a language runtime werewolf rebuilds with its protections
/// compiled in (docs/design/hardened-interpreters.md). A form takes one back
/// as RUNTIME:NAME, and the image holds it as dir/RUNTIME/NAME, an empty file
/// on the read-only root: the runtime reads it there, never from argv or the
/// environment, which a process that re-runs its runtime controls.
pub const Runtime = enum {
    java,
    python,
    php,

    /// names lists what a form may take back from the runtime's build.
    pub fn names(r: Runtime) []const []const u8 {
        return switch (r) {
            // Deserializing objects (jdk.serialFilter is `!*`); sun.misc.Unsafe
            // memory access; native access a jar's manifest does not grant.
            .java => &.{ "deserialize", "native-access", "unsafe" },
            // ctypes, with which Python code writes its own memory.
            .python => &.{"ctypes"},
            // The functions of the disable_functions floor; unserialize making
            // objects; the phar:// stream wrapper.
            .php => &.{
                "dl",    "exec",      "passthru",   "pcntl_exec", "phar",
                "popen", "proc_open", "shell_exec", "system",     "unserialize",
            },
        };
    }
};

/// RuntimeAllowance is RUNTIME:NAME, one thing a form takes back from a runtime.
pub const RuntimeAllowance = struct {
    runtime: Runtime,
    name: []const u8,

    /// parse returns word as a runtime allowance, or null unless it is
    /// RUNTIME:NAME with a NAME that runtime defines.
    pub fn parse(word: []const u8) ?RuntimeAllowance {
        const colon = std.mem.findScalar(u8, word, ':') orelse return null;
        const runtime = std.meta.stringToEnum(Runtime, word[0..colon]) orelse return null;
        const name = word[colon + 1 ..];
        for (runtime.names()) |n| if (std.mem.eql(u8, n, name))
            return .{ .runtime = runtime, .name = n };
        return null;
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
    const a = RuntimeAllowance.parse("php:proc_open").?;
    try t.expectEqual(Runtime.php, a.runtime);
    try t.expectEqualStrings("proc_open", a.name);
    try t.expectEqual(Runtime.java, RuntimeAllowance.parse("java:deserialize").?.runtime);
    for ([_][]const u8{
        "php",         "php:",     ":exec", "php:fpassthru", "perl:exec", "jit", "php:exec:x",
        "php:../exec", "PHP:exec",
    }) |w| try t.expectEqual(null, RuntimeAllowance.parse(w));
}

test "runtime allowance names are plain file names, listed once" {
    for (std.enums.values(Runtime)) |r| for (r.names(), 0..) |n, i| {
        try std.testing.expect(n.len > 0);
        for (n) |c| try std.testing.expect(std.ascii.isLower(c) or c == '_' or c == '-');
        for (r.names()[i + 1 ..]) |m| try std.testing.expect(!std.mem.eql(u8, n, m));
    };
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
