//! init's network: the command line's address, or the config tar's, or
//! DHCP's, and router advertisements limited to what they must give.

const std = @import("std");
const network_file = @import("network");
const linux = std.os.linux;
const init = @import("init.zig");
const Machine = init.Machine;
const executable = init.executable;
const exists = init.exists;
const mkdir = init.mkdir;
const orNone = init.orNone;
const say = init.say;
const trim = init.trim;
const writeFile = init.writeFile;

/// One address: the command line's, or else the config tar's network
/// file's, or else, in forms built on dhcp, the network's DHCP server's.
/// A static address is for machines whose provider gives none by DHCP,
/// or which bite took over and so keep the victim's; werewolf's net
/// (cmd/iface-up/iface-up.zig) applies it. DHCP is werewolf's
/// own client (cmd/dhcp-client/dhcp-client.zig), which applies the lease, logs it, and
/// keeps the resolvers in its own directory; its renewal starts before fence.
pub fn network(m: *Machine) void {
    _ = m.run(&.{ "/usr/lib/werewolf/iface-up", "lo" });
    const nic = m.pickNic();
    m.routerAdvertisements(nic);
    var from: []const u8 = "";
    const c = m.staticNetwork(&from);
    if (nic.len == 0) {
        if (m.cmd.mac.len > 0)
            say("no network: no NIC with address {s}", .{m.cmd.mac})
        else
            say("no network: no NIC", .{});
    } else if (c.ip.len > 0) {
        const ok = if (c.gw.len > 0)
            m.run(&.{ "/usr/lib/werewolf/iface-up", nic, c.ip, c.gw })
        else
            m.run(&.{ "/usr/lib/werewolf/iface-up", nic, c.ip });
        if (!ok) {
            if (c.gw.len > 0)
                say("network: {s} {s} via {s} refused", .{ nic, c.ip, c.gw })
            else
                say("network: {s} {s} refused", .{ nic, c.ip });
        }
        // Where /etc/resolv.conf leads, and DHCP's client writes when there
        // is no static address: a file, since no link under /run is
        // followed (nosymfollow).
        if (c.dns.len > 0) {
            mkdir("/run/werewolf/network", 0o755);
            m.write(
                "/run/werewolf/network/resolv.conf",
                m.fmt("nameserver {s}\n", .{c.dns}),
                0o644,
            );
        }
        say(
            "{s} {s} via {s} dns {s}, from {s}",
            .{ nic, c.ip, orNone(c.gw), orNone(c.dns), from },
        );
    } else if (executable("/usr/lib/werewolf/dhcp-client")) {
        m.dhcp = true;
        if (!m.run(&.{
            "/usr/lib/werewolf/dhcp-client",
            "up",
            nic,
        })) say("no network: no DHCP lease for {s}; its renewal keeps asking", .{nic});
    } else {
        say(
            "no network: no werewolf.ip, no network file in the config tar, and this form " ++
                "has no DHCP client",
            .{},
        );
    }
}

/// The static address, and where it came from: the command line's
/// werewolf.ip, or else the config tar's network file, checked as
/// howl pack checks it (lib/network.zig). The command line wins,
/// since whoever set it holds the boot; a file refused is said and
/// left, as if absent.
pub fn staticNetwork(m: *Machine, from: *[]const u8) network_file.Network {
    const has_file = exists("/run/config/network");
    if (m.cmd.ip.len > 0) {
        if (has_file) say(
            "network: the command line's, not the config tar's network file",
            .{},
        );
        from.* = "the command line";
        return .{ .ip = m.cmd.ip, .gw = m.cmd.gw, .dns = m.cmd.dns };
    }
    if (!has_file) return .{};
    var why: []const u8 = "";
    const n = network_file.parse(m.read("/run/config/network"), &why) orelse {
        say("network: the config tar's network file refused: {s}", .{why});
        return .{};
    };
    from.* = "the config tar";
    return n;
}

/// The NIC: the one werewolf.mac names, or else the first but lo.
/// IPv6 is on, and router advertisements are how most networks give it a
/// route, so they are taken, but on the machine's NIC alone, before it
/// is up, and only for what they must give: a rogue router on the same
/// network cannot rank itself above the real one, add a more specific
/// route to steal one destination's traffic, or flood the NIC with
/// addresses. Interfaces made later (default) take none.
pub fn routerAdvertisements(m: *Machine, nic: []const u8) void {
    var all = true;
    for (m.list("/proc/sys/net/ipv6/conf")) |c| {
        const d = m.fmt("/proc/sys/net/ipv6/conf/{s}", .{c});
        for ([_][2][]const u8{
            .{ "accept_ra_rtr_pref", "0" },
            .{ "accept_ra_rt_info_max_plen", "0" },
            .{ "max_addresses", "4" },
        }) |kv| {
            if (!writeFile(m.fmtZ("{s}/{s}", .{ d, kv[0] }), kv[1])) all = false;
        }
        // all's accept_ra governs no interface; each has its own.
        if (!std.mem.eql(u8, c, nic) and !std.mem.eql(u8, c, "all") and
            !writeFile(m.fmtZ("{s}/accept_ra", .{d}), "0")) all = false;
    }
    if (!all) say("some IPv6 router advertisement limits were not applied", .{});
}

pub fn pickNic(m: *Machine) []const u8 {
    for (m.list("/sys/class/net")) |n| {
        if (std.mem.eql(u8, n, "lo")) continue;
        if (m.cmd.mac.len == 0) return n;
        const addr = trim(m.read(m.fmt("/sys/class/net/{s}/address", .{n})));
        if (std.ascii.eqlIgnoreCase(addr, m.cmd.mac)) return n;
    }
    return "";
}
