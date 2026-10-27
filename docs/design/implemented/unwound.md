# unwound: DNS permissions and audit

**Status:** Implemented
[2026-10-22](https://github.com/werewolf-linux/werewolf/commit/a81852da)

This is the original design draft. The [implementation plan](unwound-plan.md)
and [command manual](../../../cmd/unwound/unwound.8.md) describe the shipped local
behavior; deferred ideas below are not implemented.

## Summary

Propose a Linux Zig forwarder using [unwind]'s privilege separation, per-service DNS
allowances and audit. DHCP supplies upstreams; limit DNS command-and-control (C2).

## Background

[Current grants](dns.md) allow arbitrary DNS. Unwind delegates DNS to libunbound.

## Goals

- Enforce service name/type policy before cache access or upstream transmission.
- Audit decisions; pass Linux confinement/spoofing tests before shipping.

## Non-Goals

BSD support, recursion, DNSSEC validation, search expansion and DHCP parsing.
Allowed domains/HTTPS can still carry C2; restrictions reduce, not eliminate, risk.

## Detailed design

All clients read one `nameserver 127.0.0.53`; no per-service file or chroot.
Prototype kernel-enforced source labels: Linux UID rules select a local route
with a service-specific preferred loopback source. Explicit source binds must
match that UID's label or be refused before general loopback rules. The listener
maps labels to immutable service identities; unknown labels fail closed.
Proved on Linux 6.8: the `n`th lookup UID gets label 127.53.n/256.n%256 and table
0x5300+n, holding `local 127.0.0.53 dev lo src LABEL`:

| pref | rule | why |
|---|---|---|
| 1 | `from LABEL to 127.0.0.53 uidrange U lookup T` | U's label, bound |
| 2 | `from 127.0.0.0/8 to 127.0.0.53 prohibit` | other bound sources |
| 3 | `to 127.0.0.53 uidrange U lookup T` | unbound: U's label |
| 4 | `to 127.0.0.53 prohibit` | everyone else, root included |
Service UIDs are unique/immutable; passed sockets share authority. Reject remote
input.

Setup opens listeners/control FDs; frontend and upstream drop root before parsing.
Frontend checks policy. A socket opener runs as the upstream UID and accepts only
approved numeric endpoints from DHCP's network helper over inherited IPC. Passing
FDs preserves socket identity; the helper alone changes routes/firewall rules.
Use seccomp/Landlock; missing confinement stops startup. DNS workers cannot open
new sockets, exec or read secrets; only the opener can create upstream sockets.

Forms declare [lookup allowances](unwound-policy.md); compiled lines have # comments:
```text
lookup 1001 api.example.com A AAAA
lookup 1001 _acme-challenge.example.com TXT
```
No grant means no DNS. Grants union without ordering; no deny rules or service modes.
Forms default omitted types to A AAAA; explicit lists replace that line's default.
Named grants bypass screening; bare `*` requires it unless that line says
`unfiltered`. `all` expands to supported query types. Framing, quotas and audit
always apply. ASCII/A-label names are lowercase with one terminal dot removed; suffix
matching is label-boundary only. Invalid declarations fail the load. IN/QUERY only;
no expansion. No ANY/transfers/UPDATE; migrate `connect: dns` and direct port-53
grants explicitly.

DHCP sends up to three numeric upstreams via bounded, versioned IPC; static uses the
same path. Pause, revoke grants/states, replace FDs, cancel queries, ack, resume.
Expired or empty leases deny forwarding. Only the upstream role reaches UDP/TCP 53.
Priority denies override broad grants for external IPv4/IPv6 TCP/UDP 53/853. Other
ports follow fence; DNS inside allowed HTTPS/tunnels cannot be identified by port.

Parse one question and complete framing; reject unexplained trailing data. Re-encode
canonical names, fresh IDs and controlled flags/options; discard caller EDNS
payloads. Validate response peer, ID, name, class and type; bound TCP framing,
compression traversal, record counts, alias hops, memory, connections and deadlines.
Check alias targets before follow-up/return; a recursive upstream may follow them
before we can check. Response types need separate parsing/serialization rules. Defer
answer caching; DHCP DNS is trusted, upstream AD is not local validation.

Requests emit escaped `unwound:` JSON: time, sequence, service, UID, question,
allow/deny/reason, rule/generation; completion adds rcode/latency. Log malformed
input. Return REFUSED for policy denial, FORMERR for malformed DNS, SERVFAIL for
failures. Optional PID/exe/cgroup path/namespace snapshots describe socket-associated
processes; never authorize with them. Bound entries; cache boot/PID/start time for
<=1s with age. Exec/migration can stale data; unavailable/ambiguous data is unknown.
Observer access needs separate confinement review; no privileged fallback. DNS
logging is best effort through [syslog](syslog.md). No acknowledgement or durability
is required before forwarding; logging failure never changes DNS policy or answers.
Count failed local writes; syslogd reports later suppression and storage drops. An
absent sink at startup falls back to stderr. Logs are private.

## Drawbacks

Alias grants need maintenance; age/entropy filters can reject legitimate names. A new
parser needs justification against existing resolvers; ReleaseSafe is not proof.

## Alternatives Considered

Per-service resolver files require mount setup. BSD adapters are deferred.
A policy frontend to Unbound/Hickory avoids a new resolver implementation.

## Security Considerations

Fuzz framing/compression/serialization/IPC with fixed resource caps and checked math.
Raw/network-admin services are outside the guarantee. Both DNS workers are trusted
for C2 policy; confinement limits compromise impact, not malicious DNS to an
upstream.

## Reliability Considerations

First test binds, IP_PKTINFO, output-interface/DONTROUTE paths, shared/passed
sockets, UID/label reuse, stale routes and remote spoofing on Linux. Then implement
forwarding/audit, then metadata/cache. Test revocation, aliases, framing and crashes.

[unwind]: https://github.com/openbsd/src/tree/master/sbin/unwind
