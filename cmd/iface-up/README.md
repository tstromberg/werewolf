# iface-up

## Summary

iface-up brings a network interface up, optionally with an address and a
default route: `iface-up NIC [ADDR/PREFIX [GATEWAY]]`. It replaces
net-tools' `ifconfig` and `route` with one small program that refuses
anything odd.

## Background

init brings up `lo` with it, then the machine's NIC when there is a static
address: from the kernel command line (`werewolf.ip`, `werewolf.gw`), or
else the config tar's `network` file. That is how a machine on a network
without DHCP, or one bite took over and that keeps the distro's static
address, gets online. Otherwise dhcp-client applies its own leases.

## Goals

- One address, one prefix, one default route, from arguments alone.
- A gateway outside the subnet, as GCP gives with a /32, reachable anyway.
- Nothing it is told that is odd ever reaches the kernel.
- When it fails, it says which request failed and why.

## Non-Goals

- More than one address or route, IPv6, MTU: a static machine needs only
  these, and IPv6 comes from router advertisements.
- Removing what is there: it runs once, at boot, on a NIC with nothing.

## Detailed design

- **Parsing** is strict, since the arguments come from the kernel command
  line: an interface name of 1 to 15 letters, digits, `_`, `-` and `.`,
  not `.` or `..`; a dotted quad with no leading zeros; a prefix of 1 to 32.
  The address may not be zero, broadcast, loopback or multicast, nor, below
  a /31, the subnet's own or broadcast address. The gateway may be none of
  those, nor the address itself. The rules are `lib/network.zig`'s, which
  also check the config tar's `network` file and `howl pack`, so all agree.
- **Pledge** before any request (`lib/sandbox.zig`): after opening its one
  socket it keeps only CAP_NET_ADMIN, dropped from the bounding set too and
  with securebits locked so root's uid brings none back, and installs a
  seccomp filter allowing write, close, exit, and ioctl only for its five
  requests. Any other call, or another architecture's, kills it.
- **Requests**: set the address (SIOCSIFADDR) and netmask (SIOCSIFNETMASK),
  set the interface up (SIOCGIFFLAGS, SIOCSIFFLAGS), and add routes
  (SIOCADDRT). A gateway outside the subnet first gets a host route through
  the NIC, so the default route through it can be added. A route that is
  already there, gateway and all, counts as done.
- **Output**: nothing on success; one line on failure, naming the request
  and the kernel's reason. It reads no environment and no files.

## Drawbacks

- The ioctl interface is the old one; netlink would say more on failure.
- One address, one route: a richer static setup would need more.

## Alternatives Considered

### busybox's ifconfig and route
A shell-free image has no busybox, and those parse looser input with far
more code than two ioctls need.

### netlink (RTM_NEWADDR, RTM_NEWROUTE)
More code to build and parse messages for the same effect. The ioctls do
what a single static address needs, and the filter can name each one.

### Privilege separation
It reads nothing from the network, and what it is told comes from whoever
booted the machine, so there is no untrusted input for a second process to
hold apart.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| Odd input from the command line | Parsed strictly and refused before any request: names, quads, prefixes, and unusable addresses or gateways. |
| A bug that turns a request into something else | seccomp allows only its five ioctls by number; anything else kills it. |
| Its privileges outliving the work | It keeps CAP_NET_ADMIN alone, cannot regain others, and exits once done. |
| Whoever sets the command line | Chooses the address, by design: root, through GRUB's environment on a bitten machine. |

## Reliability Considerations

- **Idempotent for routes:** the same route already there is success, so a
  rerun does not fail.
- **A refused argument** leaves the NIC untouched, and init says the network
  was refused.
- **Tested:** every `make check` boot but `lease` comes up through it, with
  `werewolf.ip` and a gateway.
