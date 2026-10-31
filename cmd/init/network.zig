//! init's network phase: a static address from the command line or the
//! config tar, else DHCP, with IPv6 router advertisements limited.

const std = @import("std");
const network_file = @import("network");
const dns = @import("dns");
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

/// network brings up lo and one NIC. iface-up applies a static address,
/// from the command line or else the config tar's network file; it is for
/// providers without DHCP. Otherwise, if
/// the form has it, dhcp-client gets a lease; init starts its renewal later.
pub fn network(m: *Machine) void {
    const local_validator = exists(dns.local_validator_path);
    // Keep the directory present even when DHCP has not acquired a lease.
    // Every program asks unwound; only it, fence and DHCP read upstream,
    // which DHCP atomically replaces (docs/design/implemented/unwound.md).
    mkdir("/run/werewolf/network", 0o755);
    m.write(dns.resolv_path, dns.resolv_text, 0o644);
    m.write(dns.service_address_path, "", 0o644);
    m.write(dns.dhcp_domain_path, "", 0o644);
    m.write(dns.config_domain_path, "", 0o644);
    m.write(dns.upstream_path, if (local_validator) dns.local_validator_text else "", 0o644);
    _ = m.run(&.{ "/usr/lib/werewolf/iface-up", "lo" });
    const nic = pickNic(m);
    m.write("/run/werewolf/network/nic", nic, 0o644);
    routerAdvertisements(m, nic);
    var from: []const u8 = "";
    const c = staticNetwork(m, &from);
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
        } else {
            const slash = std.mem.findScalar(u8, c.ip, '/') orelse c.ip.len;
            m.write(dns.service_address_path, c.ip[0..slash], 0o644);
        }
        // upstream must be a file, since /run is nosymfollow. Check the
        // resolver here because nothing checked the command line's
        // (lib/network.zig checked the config tar's).
        const dns_ok = if (network_file.ip4(c.dns)) |d| network_file.usable(d) else |_| false;
        if (!local_validator and c.dns.len > 0 and !dns_ok) {
            say("network: dns {s} refused: not a usable IPv4 address", .{c.dns});
        } else if (!local_validator and c.dns.len > 0) {
            mkdir("/run/werewolf/network", 0o755);
            m.write(dns.upstream_path, m.fmt("nameserver {s}\n", .{c.dns}), 0o644);
        }
        say(
            "{s} {s} via {s} dns {s}, from {s}",
            .{ nic, c.ip, orNone(c.gw), orNone(c.dns), from },
        );
    } else if (executable("/usr/lib/werewolf/dhcp-client")) {
        m.dhcp = true;
        if (!m.run(&.{ "/usr/lib/werewolf/dhcp-client", "up", nic }))
            say("no network: no DHCP lease for {s}; its renewal keeps asking", .{nic});
    } else {
        say(
            "no network: no werewolf.ip, no network file in the config tar, and this form " ++
                "has no DHCP client",
            .{},
        );
    }
}

/// staticNetwork returns the static address and sets from to its source:
/// werewolf.ip, or else the config tar's network file (checked by
/// lib/network.zig). The command line wins, since whoever set it controls
/// the boot. A refused file is logged and treated as absent.
fn staticNetwork(m: *Machine, from: *[]const u8) network_file.Network {
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

/// routerAdvertisements accepts IPv6 router advertisements only on nic, set
/// before it is up, and ignores their router preference and route options.
/// A rogue router then cannot rank itself above the real one, add a more
/// specific route to steal traffic, or flood the NIC with addresses.
fn routerAdvertisements(m: *Machine, nic: []const u8) void {
    var all = true;
    for (m.list("/proc/sys/net/ipv6/conf")) |c| {
        const d = m.fmt("/proc/sys/net/ipv6/conf/{s}", .{c});
        for ([_][2][]const u8{
            .{ "accept_ra_rtr_pref", "0" },
            .{ "accept_ra_rt_info_max_plen", "0" },
            .{ "accept_ra_mtu", "0" },
            .{ "max_addresses", "4" },
        }) |kv| {
            if (!writeFile(m.fmtZ("{s}/{s}", .{ d, kv[0] }), kv[1])) all = false;
        }
        // "all"'s accept_ra governs no interface; each has its own.
        if (!std.mem.eql(u8, c, nic) and !std.mem.eql(u8, c, "all")) {
            for ([_][]const u8{ "accept_ra", "accept_ra_pinfo", "autoconf" }) |k| {
                if (!writeFile(m.fmtZ("{s}/{s}", .{ d, k }), "0")) all = false;
            }
        }
    }
    if (!all) say("some IPv6 router advertisement limits were not applied", .{});
}

/// pickNic returns the NIC werewolf.mac names, or else the first that is not
/// lo, or "".
fn pickNic(m: *Machine) []const u8 {
    for (m.list("/sys/class/net")) |n| {
        if (std.mem.eql(u8, n, "lo")) continue;
        if (m.cmd.mac.len == 0) return n;
        const addr = trim(m.read(m.fmt("/sys/class/net/{s}/address", .{n})));
        if (std.ascii.eqlIgnoreCase(addr, m.cmd.mac)) return n;
    }
    return "";
}
