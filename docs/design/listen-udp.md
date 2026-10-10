# UDP listeners

Built, 2026-10-10, with both decisions as recommended (lib/form.zig,
lib/compose.zig, lib/service.zig, cmd/leash, cmd/fence); posture's UDP
probes are not. Proposed 2026-10-10, for `unbound`, `chrony`, `wireguard`
([service-forms.md](service-forms.md)), the ad-blockers and Syncthing
([self-hosting.md](self-hosting.md)), and Caddy's HTTP/3.

## Summary

A service may declare `listen: [udp/53]`, as it declares TCP. fence then
delivers datagrams arriving at that port, and lets only that service's
user send from it. Nothing can hold the bind itself, as Landlock does
for TCP, so a stranger's process that takes a free declared port hears
what arrives but cannot answer.

## Background

fence ([fence.md](fence.md)) holds TCP twice. Landlock lets a process
bind and connect only to declared ports. Routing rules, by user,
protocol and port, refuse what leaves undeclared and drop what arrives at
no served port. UDP has the routing rules alone: Landlock's network rules
(ABI 4 to 7) name TCP only, and seccomp cannot read bind()'s address.

So today the build refuses `listen udp/...` (lib/compose.zig), and rule
399 drops all arriving UDP but replies to declared connects (DNS). Rule
200, which lets a served port answer anyone, is TCP's and keyed by port
alone: Landlock already keeps the port its service's.

Waiting on this: unbound (udp/53 beside tcp/53), chrony (NTP on udp/123;
NTS-KE on tcp/4460), wireguard (udp/51820, a socket the kernel owns),
and HTTP/3 for Caddy (udp/443).

## Goals

- `listen: [udp/PORT]` on a service, as `tcp/PORT`; a form's `net:` may
  not declare one for a service's user, as for TCP.
- A datagram arriving at a declared UDP port is delivered; a datagram
  from that port leaves only if its sender is the declaring user.
- posture's `network-bind` and `network-inbound` probe UDP too, and each
  form's check proves that another user cannot send from its port.

## Non-Goals

- Holding the UDP bind: that needs Landlock to name UDP, in the kernel.
- Fragmented UDP, which fence still drops: unbound answers within 1232
  bytes (its `edns-buffer-size`), so a DNS answer is never fragmented.

## Detailed design

1. **The line.** compose writes `listen USER udp PORT` into
   `/usr/share/werewolf/net`. A UDP listen carries its user because,
   unlike TCP's, nothing else ties the port to the service.
2. **fence's rules.** Rule 300 gains `udp dport PORT`: deliver, for any
   socket (an arriving datagram has no user yet). Rule 200 gains
   `udp sport PORT uidrange USER`: route. Another user's datagram from
   that port meets 299 and fails `EACCES`.
3. **The bind.** leash grants a port below 1024 as it does for TCP
   (`CAP_NET_BIND_SERVICE`). The kernel's privileged ports stay at 1024,
   so only a service with a low `listen` can take udp/53 or udp/123 at all.
4. **A kernel socket.** WireGuard's datagrams carry no service's user;
   `wireguard-up` sets the device up as root before fence, so its form
   declares `listen root udp 51820` in `net:`, the one listen for root.
5. **Checks.** test/checks' `listeners` takes the declared UDP ports;
   each UDP form's check binds a second socket on its port as another
   user, where the port is free, and finds its sends refused.

## Drawbacks

- The bind is unguarded. While unbound is down, a broken-into service
  that holds `CAP_NET_BIND_SERVICE` (any low-port server) can bind
  udp/53 and read the queries that arrive; above 1024 any service can.
  It cannot answer them: its datagrams from the port leave only to ports
  its own user may reach anyway (DNS's 53), never to a client's. runit restarts unbound
  within a second, but a squatter would keep the port until a reboot.
- One more pair of rules for each UDP port, read once per route lookup.

## Alternatives Considered

- **BPF cgroup hooks** (`cgroup/bind4`, `bind6`) on each service's
  cgroup: exact, per service. But `bpf()` must be open at boot, which
  the seal shuts (fence.md weighed it for TCP and declined), and the
  verifier is code an attacker would love to reach.
- **leash binds and passes the socket**, as inetd did, with a pledge
  that may not bind: exact, but each daemon must take a socket it is
  given, and these do not all.
- **Wait for Landlock to name UDP.** Then fence and leash hold the bind
  as for TCP, and this design keeps its rules as a second layer.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| A squatter on a free declared port answers clients (DNS or NTP poisoning) | rule 200 sends from the port only as the declaring user |
| A squatter hears what arrives | low ports need `CAP_NET_BIND_SERVICE`; the service restarts at once; reboot heals |
| A served UDP port amplifies (DNS, NTP) | each form's own limits: unbound answers its networks alone, chrony serves NTS |
| A reply rule opens the port outward | `sport` and user both match, so only the service's replies leave |

## Reliability Considerations

- A form whose service is down leaves its port unheld; nothing about
  that changes. test/checks' `listeners` (`netstat -ltun`) already fails
  a UDP socket on an undeclared port.
- Fails closed as fence does: a rule fence cannot add stops the boot,
  and the last slot that worked boots.

## Decisions

1. The per-user reply rule, with the bind unguarded (recommended), or
   BPF cgroup hooks, opening `bpf()` at boot.
2. WireGuard's kernel socket as `listen root udp PORT` in `net:`.
