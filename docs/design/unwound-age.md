# Domain age for screened DNS

Status: offline classifier and fixture work, 2026-10-23. No age decision is
active in unwound. This builds on the [allowance policy](unwound-policy.md).

## Decision

Only a screened `lookup: "*"` uses age. Exact and `*.NAME` grants remain the
operator's explicit trust. Age is one more screen after local name shape and
endpoint checks. An effective registration younger than 30 days is refused.
Unknown or stale evidence is refused once age enforcement is enabled. The
first release measures coverage without changing answers; enforcement follows
only after its bootstrap and restart paths work in a native image.

The age belongs to the registered domain, never the whole QNAME. Use the
ICANN section of the Public Suffix List (PSL) to find that boundary. A name
below a PRIVATE rule is a tenant: its provider's old registration does not
prove the tenant's age. Such a tenant needs an explicit grant or a verified
tenant-specific source. Local names, unknown suffixes, and a name that is
itself a public suffix have no RDAP registration age.

Use the top-level RDAP `domain` object's events. Its `ldhName` must equal
the requested registered domain. A `registration` event records initial
creation; a later `reregistration` or `reinstantiation` resets the effective
age. Conflicting dates for one event action, a missing creation event, a
future date, and a date after fetch are unknown. `last changed`, transfer,
expiration and entity events do not establish creation. Certificate times
and CT history cannot substitute for registry age.

## Data path

1. The frontend sends only the derived registered domain to a bounded local
   miss queue. It never performs HTTPS and never sends a full QNAME. Repeated
   misses for a domain coalesce across services.
2. A separate `_rdap` worker uses an image-pinned IANA RDAP bootstrap and PSL
   generation. It picks the label-wise longest bootstrap match and only HTTPS
   URLs. Its own lookup grant covers the bootstrap and selected registry
   hosts; its network grant is public TCP 443. It cannot edit DNS policy.
3. The worker validates TLS, response type and size, JSON depth, domain
   identity and event dates. Redirects and referrals remain within vetted
   HTTPS public destinations, at a small hop limit. Retry-After and failures
   produce short-lived unknown results. No HTTP request can be initiated by
   a malformed DNS name or a PRIVATE tenant.
4. It writes a root-mediated atomic snapshot with domain, effective event,
   fetch and expiry times, source URL, bootstrap and PSL generations. The
   frontend reads a validated snapshot at start and on generation change.
   Missing, partial, rolled-back or expired data never authorizes a name.

Bound the worker to 100,000 records or 64 MiB, a daily refresh with jitter,
one-hour negative results, per-service and per-registry miss rates, and no
more than seven days of stale mature evidence during a registry outage.
At the 30-day threshold evidence must be fresh. A clock behind snapshot
creation or bootstrap publication makes the evidence unknown. The current
screen's name and site budgets still apply while the updater is unavailable.

## Rollout and checks

The offline classifier in `cmd/unwound/age.zig` covers PSL exact, wildcard,
exception and PRIVATE rules; RDAP registration and resets; and threshold,
staleness and clock boundaries. It accepts only normalized ASCII PSL input.
The updater must convert Unicode PSL rules to A-labels before using it. Run
the updater with fixture HTTPS servers and inspect audit records without
enforcement. Enable the age gate after native tests prove initial boot,
renewal, restart, outage, rollback, and bounded miss floods. Audit records
name the derived domain, evidence generation and decision, never the RDAP
response body. A domain's age is not evidence that it is safe: compromised
old domains still face the other screens.

[RFC 9083](https://www.rfc-editor.org/rfc/rfc9083.html#section-4.5) defines
RDAP events; [RFC 9224](https://www.rfc-editor.org/rfc/rfc9224.html#section-4)
defines bootstrap matching. The [PSL](https://publicsuffix.org/list/) has
separate ICANN and PRIVATE sections.
