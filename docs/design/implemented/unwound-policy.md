# unwound: DNS allowances

**Status:** Implemented
[2026-10-22](https://github.com/werewolf-linux/werewolf/commit/a81852da)
## Summary
Add name/type allowances to [unwound](unwound.md); deny DNS unless a grant permits
it.
## Background
Werewolf's [allowances](../../../forms/README.md) relax defaults; grants name
resources.
## Goals
- Use service allowances without ordered allow/deny rules, modes or exceptions.
- Screen arbitrary names with bounded local work and isolated age lookups.

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
`all` expands to the image's supported query types, never DNS ANY, transfers or
UPDATE. Exact names and `*.domain` are deliberate grants without age/endpoint/entropy
checks. The latter covers descendants, not the apex; it grants the entire subtree's
authority. Broad `*` grants refuse the compiled [callback and tunnel domain
list](../../../cmd/unwound/endpoints.zig) and IP-prefixed hostnames. This includes
dotted/dashed IPv4, integer/hex IPv4, and dashed IPv6 prefixes under any DNS suffix;
ordinary reverse PTR names remain available. The block uses whole suffixes and label
boundaries, including the listed apex. It runs before cache access, age checks and
upstream DNS, and applies to alias targets too. A matching exact name or `*.domain`
grant overrides the block for its service and query types, regardless of grant order.
Bare `*` screens names; `unfiltered` removes only that line's screening. Require `*`
with it. The endpoint defaults still require a named grant even with `unfiltered`.
Type limits, quotas, parsing, audit and local resolution through unwound still apply.
The assigned system domain and its descendants are granted to every service with DNS
enabled, including supported types beyond A and AAAA. The automatic grant retains
endpoint and tunnel screening and bypasses the 30-day age gate. The FQDN from boot
metadata takes precedence over DHCP option 15. Canonicalize all names to lowercase
ASCII/A-labels without one terminal dot; accept only exact names, leading `*.` or
bare `*`. No regex or substring matching. Screening uses bounded name shape, entropy,
per-service name and site budgets, answer holding and answer trimming. Screened
wildcards also require domain-age evidence. See the [implementation
plan](unwound-plan.md) for the actual limits. Apply grants to aliases before
follow-up/return; upstreams may already follow them.

Builder adds `lookup` alongside `connect`, derives UID/service identity, and emits
immutable `lookup UID PATTERN TYPE... [unfiltered]` records, expanding
defaults/`all`. It grants local resolver transport automatically; HTTP egress still
needs `connect`. Unknown types/modifiers fail the build. No process-supplied
namespace authorizes DNS. Allow service-scoped lookup grants for native/OCI services;
reject shared service UIDs. Whole-service replacement replaces DNS grants too; do not
merge inherited grants back. Non-service users use `net: lookup USER|:people PATTERN
[TYPE...|all] [unfiltered]`; `:people` is one label for every person's uid range
(lib/people.zig ids). Reject legacy bare `dns USER`/`connect: dns` at migration;
never silently grant `*`.

`dns-direct: true` is a service-local exception for a DNS server with its own
non-root user and a port 53 or 853 listener. It grants only the upstream DNS
transport explicitly named by that service's `connect` lines, on port 53 or
853. Ordinary application hostname resolution still uses `lookup` and unwound.
The builder derives the user ID; the compiled policy's `dns-direct UID` line is an
internal fence instruction, not form syntax. A top-level `net:` exception and a
shared service user are refused.

## Age and endpoint evidence

The [age design](unwound-age.md) describes enforcement. Endpoint lists identify risk
policy, rather than prove maliciousness.

Age defaults to 30 days from the current registry [RDAP] registration event. An RDAP
answer can authorize from cache for seven days; the row can remain stored after that
but needs a new check to authorize again. The [PSL] ICANN boundary identifies the
registered domain; PRIVATE tenants need their own grant. On RDAP availability
failure, crt.sh history can mark a domain young for 24 hours; it never authorizes
maturity or overrides RDAP. One isolated authority uses [RDAP bootstrap] over HTTPS
and SQLite to retain 20,000 domains and their triggering requests. DNS workers
receive bounded verdicts over IPC. Source labels establish UID and service namespace,
including passed sockets; individual process identity is not claimed. The local
screen keeps its 3.5-bit entropy threshold and distinct-name budgets.

## Drawbacks

Old/compromised domains and low-entropy C2 evade screening; stale age can mask domain
re-registration. Wildcard grants deliberately widen trust. RDAP coverage is
incomplete.

## Alternatives Considered

Ordered rules add precedence; CT/passive-DNS history does not establish registry age.

## Security Considerations

Updater queries expose domain interests to registries; cap abuse and isolate its
rights.

## Reliability Considerations

Test grant union/replacement, UID/OCI binding, aliases,
expiry/restart/clock/rollback, provider failures, bounded miss floods, tenant
boundaries and entropy false positives.

[RDAP]: https://www.rfc-editor.org/rfc/rfc9083.html#section-4.5
[PSL]: https://publicsuffix.org/learn/
[RDAP bootstrap]: https://www.rfc-editor.org/rfc/rfc9224.html
