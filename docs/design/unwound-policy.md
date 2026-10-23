# unwound: DNS allowances

## Summary

Add name/type allowances to [unwound](unwound.md); deny DNS unless a grant permits it.

## Background

Werewolf's [allowances](../../forms/README.md) relax defaults; grants name resources.

## Goals

- Use service allowances without ordered allow/deny rules, modes or exceptions.
- Screen arbitrary names from bounded local data; never wait for an Internet lookup.

## Non-Goals

Ownership verification, complete C2 detection, BSD support or live CT harvesting.

## Local policy

Implemented form syntax:
```yaml
services:
  app:
    lookup: [api.example.com, "*.example.net", "_acme.example.org TXT"]
  fetcher:
    lookup: "*"                  # arbitrary names, screened A/AAAA
  lab:
    lookup: "* all unfiltered"   # arbitrary names and supported types, unscreened
  resolver:
    user: resolver
    listen: [tcp/53 udp/53 lan]
    dns-direct: true              # DNS server may contact upstream DNS directly
    connect: [udp/53 tcp/53]
    lookup: "*"                   # its ordinary host lookups use unwound
```
`lookup` takes a scalar or list like `connect`: `PATTERN [TYPE...|all] [unfiltered]`.
Omitted types mean A AAAA; explicit lists replace that line's default. Grants union.
`all` expands to the image's supported query types, never DNS ANY, transfers or UPDATE.
Exact names and `*.domain` are deliberate grants without age/endpoint/entropy checks.
The latter covers descendants, not the apex; it grants the entire subtree's authority.
Bare `*` screens names; `unfiltered` removes only that line's screening. Require `*`
with it. Type limits, quotas, parsing, audit and local resolution through unwound
still apply.
Explicit name/type grants work during screening outages and fix false positives.
Canonicalize all names to lowercase ASCII/A-labels without one terminal dot; accept
only exact names, leading `*.` or bare `*`. No regex or substring matching.
Screening uses bounded name shape, entropy, per-service name and site budgets,
answer holding and answer trimming. See the [implementation plan](unwound-plan.md)
for the actual limits. Age and endpoint lists remain deferred.
Apply grants to aliases before follow-up/return; upstreams may already follow them.

Builder adds `lookup` alongside `connect`, derives UID/service identity, and emits
immutable `lookup UID PATTERN TYPE... [unfiltered]` records, expanding defaults/`all`.
It grants local resolver transport automatically; HTTP egress still needs `connect`.
The single directive carries names, types and screening; no `allow` marker is needed.
Unknown types/modifiers fail the build. No process-supplied namespace authorizes DNS.
Allow service-scoped lookup grants for native/OCI services; reject shared service UIDs.
Whole-service replacement replaces DNS grants too; do not merge inherited grants back.
Non-service users use `net: lookup USER PATTERN [TYPE...|all] [unfiltered]`.
Reject legacy bare `dns USER`/`connect: dns` at migration; never silently grant `*`.

`dns-direct: true` is a service-local exception for a DNS server with its own
non-root user and a port 53 or 853 listener. It grants only the upstream DNS
transport explicitly named by that service's `connect` lines, on port 53 or
853. Ordinary application hostname resolution still uses `lookup` and unwound.
The builder derives the user ID; the compiled policy's `dns-direct UID` line
is an internal fence instruction, not form syntax. A top-level `net:` exception
and a shared service user are refused.

## Deferred: age and endpoint evidence

The following is research for a later updater; none of it authorizes current
queries. A reviewed endpoint list may identify known out-of-band DNS endpoints,
but an entry would express risk policy rather than prove maliciousness.

Age defaults to 30 days from the current registry [RDAP] registration event. Match the
domain object; absent/conflicting/future dates mean unknown. Renewal is not creation.
CT's earliest log-entry time supports history, not ownership/registration age; neither
certificate notBefore nor old CT overrides young/unknown RDAP. Use the [PSL] ICANN
boundary for registry queries; PRIVATE tenants cannot borrow provider age. Unknown
age, internal names and PRIVATE tenants need explicit grants; no CT-only fallback.
An isolated updater queries [RDAP bootstrap] HTTPS endpoints, with a fixed bootstrap
DNS policy. Send only registrable domains after local endpoint/entropy checks, never
full QNAMEs. Bound/coalesce misses per service/provider; restrict redirects/referrals,
reject private destinations and cap HTTP/JSON sizes, depth and time. DNS workers read
snapshots only. Persist domain/source/event/fetch/expiry/provenance, shared by services.
Refresh daily with jitter; mature records may remain usable for seven days from fetch
during outages, logged as stale. Cache unknown/errors one hour; honor Retry-After.
Require fresh evidence at the age threshold. Cap records at 100,000/64 MiB; eviction
means unknown. Atomically validate snapshots; signed lists/PSL have expiry and rollback
protection. Expired data or uncertain time cannot authorize screened names.
An updater would add age/source/fetch time and data generations to audit records.
The current local screen uses a 3.5-bit entropy threshold for labels of at least
24 characters and enforces bounded distinct-name rates.

## Drawbacks

Old/compromised domains and low-entropy C2 evade screening; stale age can mask domain
re-registration. Wildcard grants deliberately widen trust. RDAP coverage is incomplete.

## Alternatives Considered

Ordered rules add precedence; CT/passive-DNS history does not establish registry age.

## Security Considerations

Updater queries expose domain interests to registries; cap abuse and isolate its rights.

## Reliability Considerations

Test grant union/replacement, UID/OCI binding, aliases, expiry/restart/clock/rollback,
provider failures, bounded miss floods, tenant boundaries and entropy false positives.

[RDAP]: https://www.rfc-editor.org/rfc/rfc9083.html#section-4.5
[PSL]: https://publicsuffix.org/learn/
[RDAP bootstrap]: https://www.rfc-editor.org/rfc/rfc9224.html
