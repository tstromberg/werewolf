# unwound

## Summary

unwound answers every program's DNS at 127.0.0.53 and decides, per service, which
names and types it may look up. It forwards what is allowed to the resolvers DHCP
named, caches and audits it, and screens `*` grants to limit DNS tunnels. See
[the design](../../docs/design/unwound.md), [the
allowances](../../docs/design/unwound-policy.md) and [the
plan](../../docs/design/unwound-plan.md).

## Background

A service that may resolve anything can send data to anyone who runs a name server.
Fence keeps port 53 from every user but unwound's; unwound decides what each asks.

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

Audit records are JSON datagrams to syslogd, `unwound: {"event":"query",...}`,
with the UID, name, type, decision, why, rule line, policy generation, rcode
and latency. A question that gets no answer, or less of one, says why:

| why | detail | answer |
|---|---|---|
| `no_grant`, `unsupported`, `alias` | (the type, or `alias`'s target) | REFUSED |
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

TCP connections accept successive or pipelined queries. Unwound answers one
frame at a time and buffers the next frame until the prior answer is ready.

## Drawbacks

Screening refuses some generated names (AWS's, in long regions) that need an
exact grant. A service granted a name trusts whoever controls it.

## Security Considerations

Neither side can exec or open files after setup; the frontend cannot open a socket.
Each side treats the other's messages as untrusted input. Budgets hash names with
SipHash under a key drawn at start. Policy is decided before the cache is looked at,
and no service's cache answers another.

## Reliability Considerations

256 questions in flight, 32 per service, 64 TCP clients, 8 per service; past
those, SERVFAIL, counted. If either side dies, the other exits and runit
restarts both. `make check-unwound` runs the real fence and unwound in Linux
namespaces against a fixture resolver; `make fuzz-unwound` runs the four fuzz
targets: queries, responses, policy and the cache.
