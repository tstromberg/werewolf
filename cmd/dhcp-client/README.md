# dhcp-client

## Summary

dhcp-client is werewolf's DHCP client. It gets an IPv4 address, routes, MTU
and resolvers from the network's DHCP server and keeps them for as long as
the machine runs. `dhcp up NIC` gets a lease within 30 seconds or exits 1;
`dhcp keep` renews it, or gets a new one.

## Background

Clouds hand out addresses over DHCP. At boot, init runs `dhcp up` when the
kernel command line has no `werewolf.ip`, then starts `dhcp keep` itself,
before it becomes fence. keep is started that early so it has
CAP_NET_ADMIN to apply leases and its open packet socket; fence then takes
both powers from every later process, root's included.

## Goals

- An address on every cloud, and on Lima, with no configuration.
- The process that parses the wire can do nothing else.
- No process started after fence, root's included, holds CAP_NET_ADMIN or
  CAP_NET_RAW.

## Non-Goals

- IPv6 (router advertisements cover it), unrequested options, ARP probes.

## Detailed design

The program is two processes, like OpenBSD's dhclient. Both are set up as
root before the fork, and the packet socket is opened, filtered and locked
before either touches the network.

- **The engine** speaks DHCP and is the only process that parses the wire.
  It runs as `_dhcp` (uid 67), chrooted to the empty `/var/empty`, with no
  capabilities, and dies with its parent. seccomp allows only its packet
  socket, writes to a socket pair to the parent, polling, the clock and
  random numbers. The socket's kernel filter, locked before bind, passes
  only unfragmented UDP from port 67 to 68. For each lease it sends the
  parent a fixed-size message.
- **The parent** applies leases. It keeps only CAP_NET_ADMIN and seccomp
  allows four ioctls (address, netmask, MTU, add route). Landlock limits
  its writes to `/run/werewolf/network` (`lease.json`, and `resolv.conf`,
  which `/etc/resolv.conf` links to). It never sees a packet. It checks
  every field of the engine's message again and treats a bad one as a
  compromised engine, ending both. It writes every log line, as JSON.
- **Replies are hostile.** They are read with strict bounds and must match
  our random transaction ID and our MAC. The ACK must come from the server
  that offered, for the address offered; renewals must come from the
  server that gave the lease. Addresses must be unicast, routes masked, and
  lease times are at least a minute. Only these options are used: message
  type, server, subnet mask, router, classless static routes (RFC 3442,
  which GCP sends with a /32 address), DNS servers, MTU and lease times.
- **Retries are fast at first.** The first broadcasts of a boot often go
  unheard (Lima's vzNAT, Azure), so they repeat every 0.25 s for 5 s, then
  back off to 8 s, with RFC 2131 jitter. Up to 2 s waits for carrier
  before the first DISCOVER, since a NIC drops frames until then.
- **Changes are applied cleanly.** A lease with a different address, mask
  or routes first takes the old address off, which makes the kernel flush
  its routes. Routes on the link go in before routes through a gateway. A
  NAK takes the address off. A lease that expires with no server answering
  is kept until a new one comes: a cloud's address does not change, and a
  server that is briefly down should not take the machine offline.

## Drawbacks

- runit does not restart `keep`. If it exits, renewals stop, and a host
  that tracks leases, such as Lima's vzNAT, loses the machine when the
  lease runs out. keep treats failed sends and receives (a brief link drop)
  as unanswered rounds, so it rarely exits.
- An expired lease's address stays, against RFC 2131.
- Renewals are broadcast, and nothing probes for a duplicate address.

## Alternatives Considered

### keep as a runit service
It would need CAP_NET_ADMIN after fence, so every root process would keep
it, and with it the power to delete fence's rules.

### udhcpc or dhclient
Their scripts need a shell, and dhclient parses far more of the wire, as
root.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| A hostile reply | Parsed only by the engine; the parent validates again; a fuzz test covers the parser. |
| A compromised engine | It can send any frame on the link (Linux has no write filter for packet sockets), but it can open nothing and change nothing. |
| A rogue DHCP server | Inherent to DHCP. On a cloud the hypervisor answers; elsewhere, use `werewolf.ip`. |
| Root rewrites the network | Every process after fence loses CAP_NET_ADMIN and CAP_NET_RAW; only keep, started before fence, holds CAP_NET_ADMIN. |

## Reliability Considerations

- **A brief link drop** costs a round, not the program.
- **A DHCP server down past the lease** does not take the machine off the
  network: the address is kept.
- **A refused MTU or route** is logged and skipped, so keep stays up.
- **Tested:** `make check-lease`, and `howl create` on Lima.
