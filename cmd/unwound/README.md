# unwound

## Summary

unwound answers DNS at 127.0.0.53 with per-service name and type grants. It forwards
allowed queries to DHCP's resolvers, caches and audits answers, and screens `*`
grants for tunnels. See the [design](../../docs/design/unwound.md),
[allowances](../../docs/design/unwound-policy.md) and [plan](../../docs/design/unwound-plan.md).

## Background

Arbitrary DNS can carry data. Fence reserves direct DNS transport for unwound
and `dns-direct: true` DNS servers; ordinary lookups use unwound.

## Goals

- No grant, no DNS; only granted services reach the resolvers.
- Know which service asked from the kernel, never from what a process says.
- Bound memory, work and what a screened grant can carry, per service.

## Non-Goals

Recursion, DNSSEC validation, search lists, DoT, and process metadata.

## Detailed design

The builder compiles each form's `lookup:` allowances into the image's network
policy as `lookup UID PATTERN TYPE... [unfiltered]` lines. Fence gives each UID with
one a loopback label, 127.53.x.y, which the kernel picks as the source of that UID's
queries; no other user can send from it, and root has none unless granted.

Root setup reads policy, binds 127.0.0.53:53 UDP/TCP, opens `/dev/log`, and forks.
The frontend becomes `_unwound` (53) in `/var/empty`: Landlock allows no files;
seccomp permits I/O on held descriptors and `accept4` on its listener. It parses,
decides, screens and audits queries, passing them over a `SOCK_SEQPACKET` pair.
The upstream becomes `_unwoundnet` (54), which alone may reach the assigned
resolvers on port 53. It can make IPv4 sockets and read the upstream file at
`/run/werewolf/network/upstream`. A private channel carries the assigned domain:
every DNS-enabled service can query it and its descendants, subject to screening.
Boot metadata's FQDN precedes DHCP option 15; renewal updates grants live.

Each attempt uses a fresh socket/port, random ID and 0x20 case; answers must echo
the question. Each resolver gets two one-second UDP tries and TCP on truncation;
silence gives SERVFAIL. The frontend keeps aliases and records of the asked type,
checks alias grants, and rebuilds replies with TTLs capped at an hour.

Each service caches 256 answers by positive minimum TTL or negative SOA TTL
(RFC 2308), without failures. Duplicate questions wait; eviction is LRU. Screened
`*` grants refuse data-shaped names, budget new names/sites per service hourly,
hold answers five minutes (early eviction charges the name again), and return
at most four records of public addresses or well-shaped names, without aliases.

Broad `*` grants, including `unfiltered`, refuse callback, request capture,
tunnel and address-to-DNS domains in the [endpoint list](endpoints.zig), including
their descendants. Dotted/dashed IPv4, integer/hex IPv4 and dashed IPv6 prefixes
are refused under any suffix; reverse PTR names remain available. Exact and
`*.domain` grants override these defaults for their service/types; the assigned
system domain does not. Checks precede cache, age and forwarding and cover aliases,
including cached aliases and direct CNAME answers.

Audit records are JSON datagrams to syslogd, `unwound: {"event":"query",...}`,
with the UID, name, type, decision, why, rule line, policy generation, rcode
and latency. A question that gets no answer, or less of one, says why:

| why | detail | answer |
|---|---|---|
| `no_grant`, `unsupported`, `alias` | (the type, or `alias`'s target) | REFUSED |
| `endpoint` | `callback_domain`, `ip_prefix` | REFUSED |
| `tunnel` | `long_name`, `many_labels`, `long_label`, `random_label`, `random_name`, with `bits` | REFUSED |
| `budget` | `new_sites`, `new_names` | REFUSED |
| `busy` | `slots`, `service_slots`, `channel`, `connections` | SERVFAIL |
| `unanswered` | `no_resolvers`, `send_failed`, `timeout`, `tcp_failed`, `busy` | SERVFAIL |
| `timeout` | | SERVFAIL |
| `malformed`, `unsupported` | `short`, `response`, `format`, `tcp_length`, `opcode_or_class` | FORMERR, REFUSED or none |
| `screened` | `dropped_nonpublic`, `dropped_shape`, `dropped_room` | fewer records |

An answer from the cache is marked `cached`; one that waited, `merged`. A
per-minute `stats` record counts queries, cached, merged, refusals, tunnel
signs, failures, busy and lost audit lines.

## Drawbacks

Screening may refuse generated names that need an exact grant. A grant trusts
the name's controller. The endpoint list includes legitimate testing services;
grant them explicitly when required. It cannot identify every callback service
or prevent literal IPs or DNS over allowed HTTPS connections.

## Security Considerations

Neither side can exec after setup. The frontend cannot open files or sockets;
the upstream can open only the preopened network state directory's files.
Both treat IPC as untrusted. Budgets use keyed SipHash. Policy is decided
before cache lookup, and services have separate caches.

## Reliability Considerations

256 questions in flight, 32 per service, 64 TCP clients, 8 per service; past these,
SERVFAIL. TCP pipelines answer one frame at a time. Either side's death restarts
both. `make check-unwound` uses namespaces and a fixture resolver;
`make fuzz-unwound` covers queries, responses, policy and cache.
