# unwound

## Summary

unwound answers every program's DNS at 127.0.0.53 and decides, per service, which
names and types it may look up. It forwards what is allowed to the resolvers DHCP
named, caches and audits it, and screens `*` grants to limit DNS tunnels. See
[the design](../../docs/design/unwound.md), [the
allowances](../../docs/design/unwound-policy.md) and [the
plan](../../docs/design/unwound-plan.md).

## Background

Arbitrary DNS can carry data. Fence reserves direct DNS transport for unwound
and `dns-direct: true` DNS servers; ordinary lookups use unwound.

## Goals

- No grant, no DNS; grants name what each service may look up, and nothing
  else reaches the resolvers.
- Know which service asked from the kernel, never from what a process says.
- Bound memory, work and what a screened grant can carry, per service.

## Non-Goals

Recursion, DNSSEC validation, search lists, DoT, and process metadata.

## Detailed design

The builder compiles each form's `lookup:` allowances into the image's network
policy as `lookup UID PATTERN TYPE... [unfiltered]` lines. Fence gives each UID with
one a loopback label, 127.53.x.y, which the kernel picks as the source of that UID's
queries; no other user can send from it, and root has none unless granted.

Setup, as root, reads the policy, binds 127.0.0.53:53 over UDP and TCP, opens
`/dev/log`, and forks. The frontend becomes `_unwound` (53) in `/var/empty`,
under Landlock with no files and a seccomp filter that permits I/O on what it
holds and `accept4` on its listener. It parses each query strictly, decides it,
screens it, audits it, and passes it over a `SOCK_SEQPACKET` pair. The upstream
side becomes `_unwoundnet` (54), the one user fence lets reach the resolvers on
port 53; it may make IPv4 sockets and read `/run/werewolf/network/upstream`.
It sends the assigned domain to the frontend on a separate private channel.
Every DNS-enabled service can query it and its descendants with supported
types, subject to tunnel screening. Boot metadata's FQDN takes precedence over
DHCP option 15; renewal or removal updates the grant without a restart.

Each upstream attempt uses a fresh socket and source port, a random ID and
0x20 case; an answer must repeat the question exactly. Two tries per resolver
of a second each over UDP, then TCP on truncation. A question no resolver
answers comes back as a bare header and why: SERVFAIL. The frontend keeps
only the alias chain and records of the asked type, checks each alias target
against the grants, and builds the reply from scratch, TTLs capped at an hour.

Each service has its own cache of 256 answers: a positive answer is kept for its least
TTL, a negative one for its SOA's (RFC 2308), failures not at all. A question asked
while the same one is out waits for it; full, the cache lets the answer least recently
given go. Screened `*` grants refuse names shaped like data, budget new names and sites
per service by the hour, hold each answer at least five minutes (one let go early costs
its name the budget again), and keep at most four records of public addresses or
well-shaped names, with no aliases.

All broad `*` grants, including `unfiltered`, refuse shared callback, request
capture, tunnel and address-to-DNS domains from the compiled
[endpoint list](endpoints.zig), at the apex and below it. They also refuse
hostnames beginning with dotted/dashed IPv4, integer/hex IPv4 or dashed IPv6,
regardless of the DNS suffix. Ordinary reverse PTR names remain available.
Exact names and `*.domain` grants override these defaults for that service
and the granted query types. The assigned system domain does not override them.
Refusal precedes cache, age checks and upstream forwarding; alias targets
are checked too, including cached aliases and direct CNAME answers.

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

TCP connections accept pipelined queries, answering one frame at a time.

## Drawbacks

Screening may refuse generated names that need an exact grant. A service
granted a name trusts whoever controls it.
The endpoint list includes legitimate testing and development services; grant
their names explicitly when required. It cannot identify every callback
service or prevent use of literal IPs or DNS over allowed HTTPS connections.

## Security Considerations

Neither side can exec after setup. The frontend cannot open files or sockets;
the upstream can open only the preopened network state directory's files.
Both treat IPC as untrusted. Budgets use keyed SipHash. Policy is decided
before cache lookup, and services have separate caches.

## Reliability Considerations

256 questions in flight, 32 per service, 64 TCP clients, 8 per service; past
those, SERVFAIL. If either side dies, runit restarts both. `make check-unwound`
uses Linux namespaces and a fixture resolver; `make fuzz-unwound` covers
queries, responses, policy and cache.
