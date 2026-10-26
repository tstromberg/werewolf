//! dhcp-client as cmd/dhcp-client/dhcp-client.zig splits it: a packet engine
//! that reads the network as _dhcp, chrooted to the empty /var/empty, with no
//! capabilities, under seccomp; and a parent as _netcfg (uid 73) that keeps
//! CAP_NET_ADMIN alone. The engine must give up its raw socket when the
//! parent dies, which only the first boot tries: it ends the renewal.
const std = @import("std");
const driver = @import("test-driver");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const mem = std.mem;

/// netcfg is the parent's uid, fixed by lib/baselayout.zig.
const netcfg = 73;
/// net_admin is CAP_NET_ADMIN's bit in a capability mask.
const net_admin = "0000000000001000";

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 4 or !mem.eql(u8, args[2], "client")) return error.Usage;
    const ctx = try driver.Run.load(io, a, args[3]);
    const suite = args[1];
    const parent = try findParent(io, a) orelse return error.NoDhcpParent;
    const engine = try findChild(io, a, parent) orelse return error.NoDhcpEngine;
    try ctx.result(io, suite, "engine-jailed", try jailed(io, a, engine));
    try ctx.result(io, suite, "parent-narrowed", try narrowed(io, a, parent));
    if (mem.eql(u8, ctx.phase, "seed"))
        try ctx.result(io, suite, "engine-parent-loss", try endsWithParent(io, a, parent, engine));
}

/// field is the first word after key in a /proc/PID/status text.
fn field(text: []const u8, key: []const u8) []const u8 {
    var lines = mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| if (mem.startsWith(u8, line, key)) {
        var words = mem.tokenizeAny(u8, line[key.len..], " \t");
        return words.next() orelse "";
    };
    return "";
}

fn statusOf(io: Io, a: Allocator, pid: u32) ![]const u8 {
    return driver.readKernel(io, a, try a.print("/proc/{d}/status", .{pid}));
}

fn findParent(io: Io, a: Allocator) !?u32 {
    var proc = try Io.Dir.cwd().openDir(io, "/proc", .{ .iterate = true });
    defer proc.close(io);
    var it = proc.iterate();
    while (try it.next(io)) |e| {
        const pid = std.fmt.parseInt(u32, e.name, 10) catch continue;
        const s = statusOf(io, a, pid) catch continue;
        if (mem.eql(u8, field(s, "Name:"), "dhcp-client") and
            mem.eql(u8, field(s, "Uid:"), std.fmt.comptimePrint("{d}", .{netcfg}))) return pid;
    }
    return null;
}

fn findChild(io: Io, a: Allocator, parent: u32) !?u32 {
    var proc = try Io.Dir.cwd().openDir(io, "/proc", .{ .iterate = true });
    defer proc.close(io);
    var it = proc.iterate();
    const want = try a.print("{d}", .{parent});
    while (try it.next(io)) |e| {
        const pid = std.fmt.parseInt(u32, e.name, 10) catch continue;
        const s = statusOf(io, a, pid) catch continue;
        if (mem.eql(u8, field(s, "PPid:"), want)) return pid;
    }
    return null;
}

/// jailed is the engine as _dhcp, with no capability, under seccomp, its root
/// unreadable and no mount reachable from it.
fn jailed(io: Io, a: Allocator, engine: u32) !bool {
    const s = try statusOf(io, a, engine);
    const dhcp = try driver.system.account(io, a, "_dhcp");
    var root: [64]u8 = undefined;
    const link = Io.Dir.cwd().readLink(io, try a.print("/proc/{d}/root", .{engine}), &root);
    const mounts = driver.readKernel(io, a, try a.print("/proc/{d}/mountinfo", .{engine}));
    const no_mounts = if (mounts) |m| m.len == 0 else |err| err == error.EmptyKernelFile;
    return std.meta.isError(link) and no_mounts and
        mem.eql(u8, field(s, "Uid:"), try a.print("{d}", .{dhcp})) and
        mem.eql(u8, field(s, "CapEff:"), "0000000000000000") and
        mem.eql(u8, field(s, "Seccomp:"), "2") and mem.eql(u8, field(s, "NoNewPrivs:"), "1");
}

/// narrowed is the parent as _netcfg in every uid, with CAP_NET_ADMIN
/// alone, effective and bounding, nothing to inherit, under seccomp.
fn narrowed(io: Io, a: Allocator, parent: u32) !bool {
    const s = try statusOf(io, a, parent);
    var uids = mem.tokenizeAny(
        u8,
        s[(mem.find(u8, s, "Uid:") orelse return false) + 4 ..],
        " \t\n",
    );
    for (0..4) |_| if (!mem.eql(u8, uids.next() orelse "", "73")) return false;
    return mem.eql(u8, field(s, "CapEff:"), net_admin) and
        mem.eql(u8, field(s, "CapBnd:"), net_admin) and
        mem.eql(u8, field(s, "CapInh:"), "0000000000000000") and
        mem.eql(u8, field(s, "CapAmb:"), "0000000000000000") and
        mem.eql(u8, field(s, "NoNewPrivs:"), "1") and mem.eql(u8, field(s, "Seccomp:"), "2");
}

/// endsWithParent kills the parent alone, in a cgroup of its own, and
/// waits up to 30 s for the engine to end with it.
fn endsWithParent(io: Io, a: Allocator, parent: u32, engine: u32) !bool {
    const group = "/run/cgroup/dhcp-parent-loss";
    try Io.Dir.cwd().createDirPath(io, group);
    try Io.Dir.cwd().writeFile(
        io,
        .{ .sub_path = group ++ "/cgroup.procs", .data = try a.print("{d}", .{parent}) },
    );
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = group ++ "/cgroup.kill", .data = "1" });
    const path = try a.print("/proc/{d}", .{engine});
    for (0..30) |_| {
        Io.Dir.cwd().access(io, path, .{}) catch return true;
        try io.sleep(.fromSeconds(1), .awake);
    }
    return false;
}

test "status fields are the words after their keys" {
    const s = "Name:\tdhcp-client\nUid:\t73\t73\t73\t73\nCapEff:\t0000000000001000\n";
    try std.testing.expectEqualStrings("dhcp-client", field(s, "Name:"));
    try std.testing.expectEqualStrings("73", field(s, "Uid:"));
    try std.testing.expectEqualStrings("", field(s, "Seccomp:"));
}
