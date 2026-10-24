# unwound

## Summary

unwound answers every program's DNS at 127.0.0.53 and decides, per service, which
names and types it may look up. It forwards what is allowed to the resolvers DHCP
named, caches and audits it, and screens `*` grants to limit DNS tunnels. See
[the design](../../docs/design/unwound.md),
[the policy](../../docs/design/unwound-policy.md) and
[the plan](../../docs/design/unwound-plan.md).

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

Setup reads the policy and binds 127.0.0.53:53, then forks. The frontend runs
as `_unwound` in `/var/empty`, with no file or socket creation; it checks and
audits each query. The `_unwoundnet` child alone reaches DHCP's resolvers and
reads network state. It sends the assigned domain to the frontend. Boot FQDN
wins over DHCP option 15; renewal and removal take effect without a restart.

Each upstream attempt uses a fresh socket and source port, a random ID and
0x20 case; an answer must repeat the question exactly. Two tries per resolver
of a second each over UDP, then TCP on truncation. A question no resolver
answers comes back as a bare header and why: SERVFAIL. The frontend keeps
only the alias chain and records of the asked type, checks each alias target
against the grants, and builds the reply from scratch, TTLs capped at an hour.

Each service caches up to 256 answers. Positive answers use their least TTL;
negative answers use the SOA's TTL (RFC 2308); failures are not cached.
Screened `*` grants bound name shape, new sites and names per hour, and answers.
They hold answers for five minutes and keep at most four public addresses or
well-shaped names, without aliases.

All broad `*` grants exclude the compiled [endpoint list](endpoints.zig) and
hostnames beginning with encoded IPv4 or IPv6 addresses. Exact and
`*.domain` grants override these defaults; the assigned domain does not.
Refusal precedes cache, age checks and forwarding, and includes alias targets.

Audit records are JSON datagrams to syslogd, `unwound: {"event":"query",...}`,
with the UID, name, type, decision, why, rule line, policy generation, rcode
and latency. A question that gets no answer, or less of one, says why:

| why | detail | answer |
|---|---|---|
| `no_grant`, `unsupported`, `alias` | (the type, or `alias`'s target) | REFUSED |
| `endpoint` | `callback_domain`, `ip_prefix` | REFUSED |
| `tunnel` | name shape or entropy, with `bits` | REFUSED |
| `budget` | `new_sites`, `new_names` | REFUSED |
| `busy` | `slots`, `service_slots`, `channel`, `connections` | SERVFAIL |
| `unanswered` | resolver failure, timeout or busy | SERVFAIL |
| `timeout` | | SERVFAIL |
| `malformed`, `unsupported` | framing, format or class | FORMERR or REFUSED |
| `screened` | `dropped_nonpublic`, `dropped_shape`, `dropped_room` | fewer records |

Cached answers say `cached`; waiting ones say `merged`. DNS logging is best effort.
Logger failures never change DNS policy or answers. Stats count local write losses;
syslogd reports later drops. If syslog is absent at startup, logs go to stderr.
TCP connections accept pipelined queries, answering one frame at a time.

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
