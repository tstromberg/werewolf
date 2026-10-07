# dhcp-client

## Summary

werewolf's own DHCP client: an IPv4 address, routes, MTU and resolvers from
the network's DHCP server, kept for as long as the machine runs. `dhcp up
NIC` gets a lease within 30 seconds or exits 1; `dhcp keep` renews it.

## Background

A cloud gives its address over DHCP. At boot, init runs `dhcp up` when the
command line names no `werewolf.ip`, then starts `dhcp keep` itself, before
it becomes fence.

## Goals

- An address on every cloud, and on Lima, with no configuration.
- The process that parses the wire can do nothing else.
- No process after fence, root's included, holds CAP_NET_ADMIN or CAP_NET_RAW.

## Non-Goals

- IPv6 (router advertisements give it), options beyond nine, ARP probes.

## Detailed design

- **The engine** speaks DHCP and alone parses the wire, as `_dhcp` (uid 67),
  chrooted to `/var/empty`, with no capabilities, dying with its parent.
  seccomp allows its packet socket, a pipe to the parent, polling, the clock
  and random numbers. The socket's kernel filter, locked before it hears
  anything, passes only unfragmented UDP from port 67 to 68.
- **The parent** applies leases with CAP_NET_ADMIN alone and four ioctls
  (address, netmask, MTU, add a route), writing only in
  `/run/werewolf/dhcp`. It checks every field of the engine's fixed-size
  message again, and ends both on one it does not like.
- **Replies are hostile.** Strict bounds; our random transaction ID and MAC;
  the ACK from the server that offered, for the address offered; renewals
  from the server that gave the lease; addresses unicast, routes masked;
  lease times at least a minute.
- **Changes are applied clean.** A lease that differs in address, mask or
  routes takes the old address off first, which flushes its routes; routes
  on the link go in first. A NAK takes the address off. A lease that runs
  out unanswered is kept.

## Drawbacks

- runit does not restart `keep`: if it ends, renewals stop, and a host that
  tracks leases, as Lima's vzNAT does, loses the machine after the lease.
- An expired lease's address stays, against RFC 2131.
- Renewals are broadcast, and nothing probes for a duplicate address.

## Alternatives Considered

### keep as a runit service
It would need CAP_NET_ADMIN after fence, so every root process would keep
it, and with it the power to delete fence's rules.

### udhcpc or dhclient
Scripts need a shell; dhclient parses far more of the wire, as root.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| A hostile reply | Parsed only by the engine; the parent validates again; a fuzz test covers the parser. |
| A compromised engine | It can send any frame on the link: Linux has no write filter for packet sockets. It can open nothing and change nothing. |
| A rogue DHCP server | Inherent to DHCP. On a cloud the hypervisor answers; elsewhere, use `werewolf.ip`. |
| Root rewrites the network | CAP_NET_ADMIN and CAP_NET_RAW leave every process after fence; only `keep` holds them. |

## Reliability Considerations

- **A link that drops for a moment** costs a round, not the program.
- **A DHCP server down past the lease** does not take the machine off the
  network: the address is kept, as a cloud's does not change.
- **Tested:** `make check-lease`, and `werewolf create` on Lima.
