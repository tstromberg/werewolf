# fence

## Summary

fence sets the machine's network and file policy once at boot, from the
image, then execs runit. Every process descends from it, and none, not even
root, can loosen the policy before a reboot.

## Background

A machine should send only what its form declares and receive only what it
serves or asked for, with no firewall to configure. init's last step is
`exec fence runit`. Before that, init installs the seal and starts the
programs that stay outside fence's domain: the mount broker, DHCP's renewal
(which keeps its CAP_NET_ADMIN and packet socket) and stage0's deadman.
fence reads only `/usr/share/werewolf/net`, compiled from form.yaml's `net`
lines: one entry per line, numbers only, `all` for every user.

    listen tcp 22
    listen tcp 5432 loopback
    connect 0 tcp 443
    connect all udp 53
    connect 207 tcp 443 public
    metadata 68

## Goals

- Default deny, both ways, for every user, from the image alone.
- No process after fence can change the rules, or send below them.
- Files are written only where a machine must write, and run only from `/usr`.

## Non-Goals

- Connection state, which policy-routing rules lack, and policy between
  local services, which leash's Landlock rules handle.

## Detailed design

1. **Policy-routing rules** for IPv4, and for IPv6 if the kernel has it
   (werewolf boots with `ipv6.disable=1` unless the form allows IPv6). Sent
   traffic passes only if its user declared the protocol and port
   (`connect`), as a reply from a served port (`listen`), as ICMPv6, or to
   the metadata server's TCP 80 for a user named in `metadata`. Anything
   else fails with EACCES. A `public` connect is also refused to private,
   loopback, link-local, shared, multicast and reserved addresses, so a
   service that fetches URLs strangers name cannot reach the local network
   or the metadata server. Azure's wire server is closed to everyone.
   Arriving traffic passes to a served port, from a port the machine
   connects to, or as ICMP. TCP, UDP, the other transports, tunnels and
   IPsec are dropped unanswered; other protocols get "unreachable". Local
   and loopback traffic always pass. A `loopback` listen has no rule, so
   only this machine reaches it. Allowed traffic with no route fails as
   "network unreachable", not EACCES, so clients try the next address.
2. **Landlock**, for every process: TCP binds only to the policy's ports
   or 0, and connects only to declared, served, loopback and metadata
   ports. Files are readable anywhere but `/dev`; programs run only from
   `/usr` and `/oci`; writes go only to `/run`, `/tmp`, `/var/tmp`,
   `/dev/shm`, `/data` and binds under image roots; sockets and FIFOs only
   in `/run` and those roots' `/run` and `/tmp`. `/dev` is closed, even to
   reads, but for null, zero, full, random, urandom, kmsg, terminals, input
   devices, ptys if allowed, and a PL061 GPIO chip. No process may mount.
   Every refusal is audited, after exec too.
3. **The bounding set** loses CAP_NET_ADMIN and CAP_NET_RAW, unless a form
   allows them (`lib/allow.zig`: `netadmin`, `packet`; none does), and
   always CAP_SYS_ADMIN, which only Landlock needed. Root then cannot
   mount or configure a filesystem (fsconfig, CVE-2022-0185).
4. **exec** PROGRAM, under its base name.

## Drawbacks

- Stateless: any packet from TCP 443 or UDP 53 passes as a reply, to any socket.
- Fragmented UDP replies are lost: later fragments carry no ports.

## Alternatives Considered

### netfilter or BPF
More to configure and more kernel to reach. Policy routing, Landlock and
the bounding set are built in, and nothing sets them again.

### A rule that drops every protocol arriving
ARP asks whether an address is local with a lookup that has no protocol.
Dropping that would leave the machine unreachable.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| Root removes the rules | That needs CAP_NET_ADMIN, gone after fence. No one can lift Landlock. |
| Raw or packet sockets below the rules | That needs CAP_NET_RAW, gone after fence. DHCP's engine holds the one packet socket, locked to DHCP replies. |
| A reply forged by its source port | **Open, by design:** it reaches any socket, including one listening on a port the kernel picked (`listen()` without `bind()`, unseen by Landlock). It needs code already running here, and leash refuses `listen` to services that did not promise it. |
| Root signals the mount broker or DHCP | Landlock ABI 6 scoping blocks signals and abstract sockets out of the domain. |
| Root drives GPIO lines | Only a PL061 (`arm,pl061`) gets ioctls: the chip a VM wires its power button to. |

## Reliability Considerations

- **Fails closed:** any failed step exits 1; PID 1 dies, the kernel
  panics, and the machine comes back on the slot that last worked.
- **A malformed policy** is an error, never a guess; a rule two forms
  share is accepted (EEXIST), not fatal.
- **Tested:** posture checks each protection on every `make check` boot.
