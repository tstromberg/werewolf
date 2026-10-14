//! init's seal phase: it starts seal-watch, drops capabilities for good,
//! and installs the machine-wide seccomp seal (lib/seal.zig).

const std = @import("std");
const seal_lib = @import("seal");
const allow = @import("allow");
const Allocator = std.mem.Allocator;
const linux = std.os.linux;
const testing = std.testing;
const init = @import("init.zig");
const Machine = init.Machine;
const executable = init.executable;
const exists = init.exists;
const mkdir = init.mkdir;
const say = init.say;
const writeErrno = init.writeErrno;

/// policyText returns the text of seal_lib.policy_path: the mode and the
/// promises the seal allows.
fn policyText(gpa: Allocator, learn: bool, promises: seal_lib.Set) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.print(gpa, "mode {s}\npromises", .{if (learn) "learn" else "enforce"});
    var it = promises.iterator();
    while (it.next()) |p| try out.print(gpa, " {s}", .{@tagName(p)});
    try out.append(gpa, '\n');
    return out.items;
}

/// dropped_caps leave the bounding set, so not even root gets them back
/// before a reboot. They reach into the kernel (SYS_MODULE, BPF, PERFMON),
/// hardware (SYS_RAWIO), other processes (SYS_PTRACE) and device files
/// (MKNOD), or nothing here uses them. fence drops NET_ADMIN and NET_RAW
/// unless the form allows them. SYSLOG stays, for dmesg.
const dropped_caps = [_]allow.Cap{
    .linux_immutable, .sys_module,    .sys_rawio,     .sys_ptrace,   .sys_pacct,
    .sys_time,        .mknod,         .audit_control, .mac_override, .mac_admin,
    .wake_alarm,      .block_suspend, .perfmon,       .bpf,          .checkpoint_restore,
};

/// helper_caps bounds a usermode helper, a program the kernel starts from
/// kthreadd, outside the seal. Root could name one (core_pattern `|PROG`,
/// kernel.modprobe, kernel.hotplug) to run with every capability. Only
/// CAP_SYS_BOOT stays, for orderly poweroff. Lowering this needs
/// CAP_SYS_MODULE, which the seal then drops, and it can never be raised.
const helper_caps: u64 = 1 << @backingInt(allow.Cap.sys_boot);

/// capWords formats set as "LOW HIGH", as kernel.usermodehelper.bset reads it.
fn capWords(buf: []u8, set: u64) []const u8 {
    return std.mem.print(
        buf,
        "{d} {d}",
        .{ @as(u32, @truncate(set)), @as(u32, @truncate(set >> 32)) },
    ) catch unreachable;
}

/// startWatch starts seal-watch before the seal, so it is not under it,
/// with one end of a socket pair as its stdin. It returns the other end,
/// for sending the listener, or null. Only raw calls run between fork and
/// exec, since this process may have threads.
fn startWatch() ?i32 {
    const path = "/usr/lib/werewolf/seal-watch";
    if (!executable(path)) return null;
    var sv: [2]i32 = undefined;
    if (linux.errno(linux.socketpair(
        linux.AF.UNIX,
        linux.SOCK.SEQPACKET | linux.SOCK.CLOEXEC,
        0,
        &sv,
    )) != .SUCCESS) return null;
    const argv: [*:null]const ?[*:0]const u8 = &[_:null]?[*:0]const u8{path};
    const envp: [*:null]const ?[*:0]const u8 = &[_:null]?[*:0]const u8{};
    const pid = linux.fork();
    if (linux.errno(pid) != .SUCCESS) return null;
    if (pid == 0) {
        _ = linux.dup2(sv[1], 0);
        _ = linux.execve(path, argv, envp);
        linux.exit_group(127);
    }
    _ = linux.close(sv[1]);
    return sv[0];
}

/// seal installs a default-deny seccomp filter on PID 1, which every process
/// inherits and none can remove before a reboot (docs/design/lockdown.md).
/// It allows the calls of werewolf's base promises and of every promise in
/// the services' `pledge` lines (/usr/share/werewolf/pledge,
/// docs/design/pledge.md); leash then narrows each service to its own.
/// Other calls go to seal-watch, which refuses them with ENOSYS and logs
/// each once, or allows and records them under werewolf.seal=learn on a
/// DEV=1 build. A leashed service's own filter refuses first; the kernel
/// audits those refusals (SECCOMP_FILTER_FLAG_LOG).
///
/// The order is the helpers' bounding set, PID 1's, then the filter. PID 1
/// holds CAP_SYS_ADMIN, so it needs no no_new_privs, which would bind every
/// later program. Any failed step is an error, except a capability the
/// kernel does not know (EINVAL), which it cannot grant anyway.
pub fn seal(m: *Machine) !void {
    // In learn mode seal-watch allows and records each unpromised call with
    // the promise that would allow it, so an author learns what a pledge
    // lacks. Only DEV=1 builds, which are never released, honor it.
    const learn = m.cmd.seal == .learn and exists("/usr/share/werewolf/dev");
    if (m.cmd.seal == .learn and !learn)
        say("werewolf.seal=learn ignored: only a DEV=1 build learns", .{});
    var bad: []const u8 = "";
    const pledged = seal_lib.parse(m.read("/usr/share/werewolf/pledge"), &bad) catch |err| {
        say("/usr/share/werewolf/pledge: {s}: {s}", .{ bad, @errorName(err) });
        return err;
    };
    const promises = seal_lib.base.unionWith(pledged);
    var buf: [32]u8 = undefined;
    // On a real machine init has just mounted /proc, so a failure here is
    // real and fatal. In a container /proc/sys is read-only (EROFS) and the
    // helpers are the host's. Tolerate EROFS alone, so no other error can
    // skip the limit on a real boot.
    for ([_][:0]const u8{
        "/proc/sys/kernel/usermodehelper/bset",
        "/proc/sys/kernel/usermodehelper/inheritable",
    }, [_]u64{ helper_caps, 0 }) |path, set| {
        switch (writeErrno(path, capWords(&buf, set))) {
            .SUCCESS => {},
            .ROFS => {
                say(
                    "usermodehelper caps left to the host: /proc/sys is read-only (a container)",
                    .{},
                );
                break;
            },
            else => |e| {
                say("usermodehelper caps: {t}", .{e});
                return error.UsermodeHelperCaps;
            },
        }
    }
    mkdir("/run/werewolf/seal", 0o755);
    const watch = startWatch();
    if (watch == null) say("no seal-watch: unlisted calls are refused unsaid", .{});
    const PR_CAPBSET_DROP = 24;
    var caps: usize = 0;
    for (dropped_caps) |c| {
        const rc = linux.prctl(PR_CAPBSET_DROP, @backingInt(c), 0, 0, 0);
        switch (linux.errno(rc)) {
            .SUCCESS => caps += 1,
            .INVAL => {},
            else => |e| {
                say("cap_{t} not dropped: {t}", .{ c, e });
                return error.BoundingSet;
            },
        }
    }
    var filter_buf: [seal_lib.max_filter]seal_lib.Filter = undefined;
    const filter = seal_lib.buildFilter(&filter_buf, promises, false);
    const listener = seal_lib.install(filter, true) catch |err| {
        say("seccomp: {s}", .{@errorName(err)});
        return err;
    };
    // Only seal-watch keeps the listener. If no one holds it, the kernel
    // refuses every unpromised call itself.
    if (watch) |sock| {
        if (!seal_lib.sendListener(sock, listener, if (learn) "l" else "e"))
            say("seal-watch did not take the listener: unlisted calls are refused unsaid", .{});
        _ = linux.close(sock);
    }
    _ = linux.close(listener);
    m.write(seal_lib.policy_path, policyText(m.gpa, learn, promises) catch "", 0o644);
    say(
        "sealed: {d} promises; every other call {s}; {d} capabilities dropped; " ++
            "other architectures' calls fatal",
        .{ promises.count(), if (learn) "allowed and recorded" else "refused", caps },
    );
}

test policyText {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const text = try policyText(arena.allocator(), false, .initMany(&.{ .stdio, .inet }));
    try testing.expectEqualStrings("mode enforce\npromises stdio inet\n", text);
}

test capWords {
    var buf: [32]u8 = undefined;
    try testing.expectEqualStrings("4194304 0", capWords(&buf, helper_caps));
    try testing.expectEqualStrings("0 0", capWords(&buf, 0));
    try testing.expectEqualStrings("4294967295 511", capWords(&buf, (1 << 41) - 1));
}
