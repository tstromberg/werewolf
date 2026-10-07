//! kernel-config-check CONFIG: fails the build if Alpine's kernel config,
//! the boot/config-* in its linux-virt package, has changed under werewolf
//! in a way that reopens a bug exploited in the wild
//! (docs/cve-mitigation-survey.md). Some of werewolf's protection is code
//! Alpine leaves out, or builds as a module the machine never loads; on a
//! running machine nothing can read the config (/proc/config.gz is itself a
//! module), so the build checks it, once, as it unpacks the kernel.
//!
//! Each rule says what the option must be, and why. Silent when every rule
//! holds; otherwise one line for each that does not, and exit 1.

const std = @import("std");
const Io = std.Io;

/// What an option may be.
const Want = enum {
    /// Built in: werewolf relies on it.
    yes,
    /// Not built in: a module, which the machine never loads and cannot
    /// load once modload closes the loader, or left out. Built in, it
    /// would be there without the loader.
    not_built_in,
    /// Left out altogether.
    off,
};

/// An option, what it must be, and why.
const Rule = struct { []const u8, Want, []const u8 };

const rules = [_]Rule{
    .{ "CONFIG_CRYPTO_USER_API", .not_built_in, "AF_ALG: CVE-2025-39964, CVE-2026-31431" },
    .{ "CONFIG_CRYPTO_USER_API_AEAD", .not_built_in, "AF_ALG: CVE-2026-31431" },
    .{ "CONFIG_CRYPTO_USER_API_SKCIPHER", .not_built_in, "AF_ALG" },
    .{ "CONFIG_CRYPTO_USER_API_HASH", .not_built_in, "AF_ALG" },
    .{ "CONFIG_CRYPTO_USER_API_RNG", .not_built_in, "AF_ALG" },
    .{ "CONFIG_TLS", .not_built_in, "kernel TLS: CVE-2025-39682" },
    .{ "CONFIG_BRIDGE_NF_EBTABLES", .not_built_in, "ebtables: CVE-2026-53266" },
    .{ "CONFIG_NF_TABLES", .not_built_in, "nf_tables: CVE-2022-2586, CVE-2024-1086" },
    .{ "CONFIG_NETFILTER_XTABLES", .not_built_in, "x_tables: CVE-2021-22555" },
    .{ "CONFIG_OVERLAY_FS", .not_built_in, "overlayfs: CVE-2023-0386" },
    .{ "CONFIG_HID", .not_built_in, "HID: CVE-2024-50302" },
    .{ "CONFIG_USB", .not_built_in, "USB: CVE-2024-53150, CVE-2024-53197, CVE-2024-53104" },
    .{ "CONFIG_WATCH_QUEUE", .off, "watch queues: CVE-2022-0995" },
    .{ "CONFIG_SND_USB_AUDIO", .off, "USB audio: CVE-2024-53150, CVE-2024-53197" },
    .{ "CONFIG_USB_VIDEO_CLASS", .off, "USB video: CVE-2024-53104" },
    .{ "CONFIG_POSIX_CPU_TIMERS_TASK_WORK", .yes, "closes CVE-2025-38352's race" },
};

pub fn main(init: std.process.Init) !void {
    const gpa = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(gpa);
    if (args.len != 2) {
        std.log.err("usage: kernel-config-check CONFIG", .{});
        std.process.exit(2);
    }
    const text = try Io.Dir.cwd().readFileAlloc(io, args[1], gpa, .limited(4 << 20));
    var failed = false;
    for (rules) |r| {
        const name, const want, const why = r;
        const v = value(text, name);
        if (holds(want, v)) continue;
        failed = true;
        std.debug.print("kernel-config-check: {s} is {s}, werewolf needs it {s} ({s})\n", .{
            name, if (v.len == 0) "off" else v, wantText(want), why,
        });
    }
    if (failed) std.process.exit(1);
}

/// The option's value in a kernel config: "y", "m", a string or number,
/// or "" for "# CONFIG_X is not set" and for an option not there at all.
fn value(text: []const u8, name: []const u8) []const u8 {
    var it = std.mem.tokenizeScalar(u8, text, '\n');
    while (it.next()) |line| {
        if (line.len > name.len and std.mem.startsWith(u8, line, name) and line[name.len] == '=')
            return line[name.len + 1 ..];
    }
    return "";
}

fn holds(want: Want, v: []const u8) bool {
    return switch (want) {
        .yes => std.mem.eql(u8, v, "y"),
        .not_built_in => !std.mem.eql(u8, v, "y"),
        .off => v.len == 0,
    };
}

fn wantText(want: Want) []const u8 {
    return switch (want) {
        .yes => "built in",
        .not_built_in => "a module or off",
        .off => "off",
    };
}

const testing = std.testing;

test value {
    const config =
        \\CONFIG_TLS=m
        \\# CONFIG_WATCH_QUEUE is not set
        \\CONFIG_TLS_DEVICE=y
        \\CONFIG_POSIX_CPU_TIMERS_TASK_WORK=y
        \\CONFIG_LSM="landlock,lockdown"
    ;
    try testing.expectEqualStrings("m", value(config, "CONFIG_TLS"));
    try testing.expectEqualStrings("", value(config, "CONFIG_WATCH_QUEUE"));
    try testing.expectEqualStrings("", value(config, "CONFIG_OVERLAY_FS"));
    try testing.expectEqualStrings("y", value(config, "CONFIG_POSIX_CPU_TIMERS_TASK_WORK"));
    try testing.expectEqualStrings("\"landlock,lockdown\"", value(config, "CONFIG_LSM"));
}

test holds {
    try testing.expect(holds(.not_built_in, "m"));
    try testing.expect(holds(.not_built_in, ""));
    try testing.expect(!holds(.not_built_in, "y"));
    try testing.expect(holds(.off, ""));
    try testing.expect(!holds(.off, "m"));
    try testing.expect(holds(.yes, "y"));
    try testing.expect(!holds(.yes, "m"));
}
