//! init's last step: the machine seal (lib/seal.zig), the capabilities
//! dropped for good, and seal-watch started to answer what is refused.

const std = @import("std");
const seal_lib = @import("seal");
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

/// The seal (docs/design/lockdown.md) denies by default, in promises
/// (docs/design/pledge.md, System calls: promises): every process the
/// machine will run may make the calls of the promises werewolf's own
/// programs make (seal_lib.base) and of every promise the image's services
/// make, which the build gathers from their service files' `pledge` lines
/// into /usr/share/werewolf/pledge. leash then holds each service to its
/// own. The rest go to seal-watch (cmd/seal-watch), which refuses them as
/// if the kernel had no such call and says so once each, with the promise
/// that would allow it; or, on a DEV=1 build booted with
/// werewolf.seal=learn, allows and records them. What no promise brings
/// goes to seal-watch too, so an attempt by a program the machine's
/// promises alone bind is seen; a leashed service's own filter refuses it
/// first, and the kernel takes that ENOSYS over the listener, unseen.
pub const never = seal_lib.never;

/// What policy_path says: the mode, and the promises the seal allows.
fn policyText(gpa: Allocator, learn: bool, promises: seal_lib.Set) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.print(gpa, "mode {s}\npromises", .{if (learn) "learn" else "enforce"});
    var it = promises.iterator();
    while (it.next()) |p| try out.print(gpa, " {s}", .{@tagName(p)});
    try out.append(gpa, '\n');
    return out.items;
}

/// Capabilities no process needs once init hands over, dropped from the
/// bounding set, so not even root gets them back before a reboot: code in
/// the kernel (SYS_MODULE, BPF, PERFMON), hardware and ports (SYS_RAWIO),
/// other processes (SYS_PTRACE), device files (MKNOD), and what nothing here
/// uses. fence drops NET_ADMIN and NET_RAW after it sets the network
/// policy, unless the form allows them. SYSLOG stays, for dmesg.
const dropped_caps = [_]struct { name: []const u8, n: u6 }{
    .{ .name = "linux_immutable", .n = 9 },
    .{ .name = "sys_module", .n = 16 },
    .{ .name = "sys_rawio", .n = 17 },
    .{ .name = "sys_ptrace", .n = 19 },
    .{ .name = "sys_pacct", .n = 20 },
    .{ .name = "sys_time", .n = 25 },
    .{ .name = "mknod", .n = 27 },
    .{ .name = "audit_control", .n = 30 },
    .{ .name = "mac_override", .n = 32 },
    .{ .name = "mac_admin", .n = 33 },
    .{ .name = "wake_alarm", .n = 35 },
    .{ .name = "block_suspend", .n = 36 },
    .{ .name = "perfmon", .n = 38 },
    .{ .name = "bpf", .n = 39 },
    .{ .name = "checkpoint_restore", .n = 40 },
};

/// The capabilities a program the kernel starts itself may have: a
/// usermode helper, which kthreadd starts, not PID 1, so neither the seal's
/// filter nor its bounding set reach it. Root could name one (a core
/// pattern of `|PROGRAM`, kernel.modprobe, kernel.hotplug) and have it run
/// with every capability, outside the seal. Only CAP_SYS_BOOT is left, for
/// the kernel's own orderly poweroff. The kernel lets these only fall, and
/// only for a holder of CAP_SYS_MODULE, which the seal then takes.
const helper_caps: u64 = 1 << 22; // CAP_SYS_BOOT

/// "LOW HIGH": a capability set as kernel.usermodehelper.bset reads it.
fn capWords(buf: []u8, set: u64) []const u8 {
    return std.mem.print(
        buf,
        "{d} {d}",
        .{ @as(u32, @truncate(set)), @as(u32, @truncate(set >> 32)) },
    ) catch unreachable;
}

/// seal-watch, started before the seal so it is not under it, with one end
/// of a socket as its stdin, over which it is sent the seal's listener; the
/// other end, or null if it cannot be started. Raw calls only between fork
/// and exec: this process may have threads.
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

/// Install the seal on PID 1, which every process inherits and none, root
/// included, can remove until the machine reboots: the helpers' bounding
/// set, PID 1's, then the filter. PID 1 holds CAP_SYS_ADMIN, so it needs no
/// no_new_privs, which would bind every program after it. Any step that
/// fails is an error; a capability the kernel does not know (EINVAL) is
/// one it cannot grant.
pub fn seal(m: *Machine) !void {
    // Learning: what the promises do not allow, seal-watch allows and
    // records, with the promise that would, so a service's author learns
    // what its pledge lacks. Only on a DEV=1 build, never released;
    // anywhere else the word is ignored.
    const learn = std.mem.eql(u8, m.cmd.seal, "learn") and exists("/usr/share/werewolf/dev");
    if (m.cmd.seal.len > 0 and
        !learn) say("werewolf.seal={s} ignored: only a DEV=1 build learns", .{m.cmd.seal});
    var bad: []const u8 = "";
    const pledged = seal_lib.parse(m.read("/usr/share/werewolf/pledge"), &bad) catch |err| {
        say("/usr/share/werewolf/pledge: {s}: {s}", .{ bad, @errorName(err) });
        return err;
    };
    const promises = seal_lib.base.unionWith(pledged);
    var buf: [32]u8 = undefined;
    // The bounding set for the programs the kernel starts itself, which the
    // seccomp filter does not reach. On real hardware /proc/sys is writable --
    // init has just mounted /proc -- so a failure here is real and fatal. In a
    // container /proc/sys is read-only (EROFS) and these are the host's to set,
    // not ours, and the kernel's helpers never run in the container's
    // namespaces anyway; tolerate that one case, and that one alone, so the
    // read-only mount cannot be forged into skipping the limit on a real boot.
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
        const rc = linux.prctl(PR_CAPBSET_DROP, c.n, 0, 0, 0);
        switch (linux.errno(rc)) {
            .SUCCESS => caps += 1,
            .INVAL => {},
            else => |e| {
                say("cap_{s} not dropped: {t}", .{ c.name, e });
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
    // The listener goes to seal-watch alone. Once no one holds it, the
    // kernel refuses every call the promises do not allow, itself.
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
