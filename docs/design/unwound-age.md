# Domain age for screened DNS

Status: enforcement is selected by the image marker. See the
[allowance policy](unwound-policy.md) and the native checks below.

## Decision

Only a screened `lookup: "*"` uses age. Exact and `*.NAME` grants remain the
operator's explicit trust. Age is one more screen after local name shape and
endpoint checks. The default cutoff is 90 days after effective registration.
The currently assigned system domain and its descendants are automatically
available to DNS-enabled services and bypass this age gate. They still pass
the existing tunnel screen. Boot metadata's FQDN suffix takes precedence over
DHCP option 15; a domain assignment can change during DHCP renewal.
Unknown evidence is refused. Without the marker, the observer records PSL
boundaries without changing answers.

Aliases from an age-checked name must stay in its checked registered domain.
An exempt name may only alias to another exempt name; other chains are
refused. Cached aliases are checked against the current grants again,
including changes to the assigned system domain.

The age belongs to the registered domain, never the whole QNAME. Use the
ICANN section of the Public Suffix List (PSL) to find that boundary. A name
below a PRIVATE rule is a tenant: its provider's old registration does not
prove the tenant's age. Such a tenant needs an explicit grant or a verified
tenant-specific source. Local names, unknown suffixes and public suffixes
have no RDAP registration age.

Use the top-level RDAP `domain` object's events. Its `ldhName` must equal
the requested registered domain. A `registration` event records initial
creation; a later `reregistration` or `reinstantiation` resets the effective
age. Conflicting dates for one event action, a missing creation event, a
future date and a date after fetch are unknown. `last changed`, transfer,
expiration and entity events do not establish creation.

If RDAP is unavailable, query crt.sh for the same registered domain's CT
history. Use the earliest matching log-entry timestamp, never certificate
`notBefore`. An old certificate does not prove continuous registration: a
domain can expire and be registered again. An RDAP answer saying young or
giving ambiguous dates is not a transport failure and must never be
overridden by CT. During an RDAP outage, old CT history may give a
*provisional* mature decision for at most 24 hours, marked `crtsh` in the
audit, while RDAP retries continue. No CT result, a young CT result or an
invalid/oversized response leaves age unknown.

## Data path

1. The frontend sends the full QNAME and exact triggering request metadata
   over one bounded channel, then waits without blocking other DNS queries.
   The authority derives the registered domain. Repeated misses coalesce;
   the first request is stored with the check.
2. The `_unwoundage` authority owns SQLite in `/data/svc/unwound-age` and
   fetches HTTPS evidence for only that registered domain. Its network grant
   is public TCP 443; DNS goes through unwound. The pinned IANA bootstrap
   chooses a label-wise longest HTTPS endpoint. Redirects are refused.
3. The authority bounds each response, validates TLS, JSON identity and
   dates, and uses crt.sh only when RDAP is unavailable. It writes evidence
   and an `age_check` row, then returns a dated verdict.
   Missing, partial, rolled-back or expired evidence never authorizes a name.

Keep the most recently used 20,000 registered domains. A domain row has no
fixed lifetime: it can remain indefinitely if it stays in the LRU set, but
each verdict is recomputed from dated evidence. Refresh expired evidence
before it authorizes another query. Eviction means unknown, never allow.
Cache unknown/errors for one hour. Bound pending DNS requests per service.
SQLite WAL, `-wal` and `-shm` files all live in the worker's private directory
and have one writer. Keep the check history independent of domain eviction for
a bounded audit period; pin each cached domain's `last_check_id` row while
pruning older audit rows. SQL triggers enforce 20,000 domain and 120,000 check
row limits.

RDAP evidence can authorize for seven days after fetch. Data fetched before
the 90-day boundary cannot become mature merely because time passes; it needs
a new RDAP check at the boundary. crt.sh fallback can authorize for only 24
hours after an RDAP availability failure. Its result remains marked `crtsh`.
A clock behind fetch makes evidence unknown. The current name/site budgets
still apply.

## Request provenance and file authority

The [age evidence authority](unwound-age-authority.md) specifies which
request fields can be trusted and how the SQLite files must be protected.

## Rollout and checks

Without the marker, an `_unwoundage` child logs PSL boundaries for screened
wildcard requests and cannot change DNS answers.

The offline classifier in `cmd/unwound/age.zig` covers PSL exact, wildcard,
exception and PRIVATE rules; RDAP registration and resets; bounded crt.sh
history parsing; and threshold, expiry and clock boundaries with the
90-day default. Cached evidence is reclassified by its fetch date and domain.
PSL and IANA versions are retained for audit, not cache invalidation. It
accepts only normalized ASCII PSL input. `tools/update-unwound-age-data`
converts the official PSL to A-labels with `idna==3.20` and pins it alongside
the IANA RDAP DNS bootstrap in `cmd/unwound/data`. The authority embeds both.
`sources.json` records
source URLs, SHA-256 hashes, versions and generation details. Refresh by
downloading the two official URLs into local files and passing both paths to
the updater; review the data diff before building an image. The updater makes
no network requests.
`cmd/unwound/bootstrap.zig` selects a pinned IANA entry by longest label match
and requires HTTPS. `make check-unwound-age-store`, `check-unwound-age`,
`check-unwound-age-live`, `check-unwound-age-mount` and
`check-unwound-age-authority` cover storage, live DNS decisions, provider
failures and the Linux mount boundary. The shared native image check tries
root writes and remounts on the booted cache, and checks for mount aliases.
The live fixture also checks that expired RDAP and CT evidence cannot
release a positive DNS answer already in the DNS cache.
Old domains still face the other screens.

[RFC 9083](https://www.rfc-editor.org/rfc/rfc9083.html#section-4.5) defines
RDAP events; [RFC 9224](https://www.rfc-editor.org/rfc/rfc9224.html#section-4)
defines bootstrap matching. The [PSL](https://publicsuffix.org/list/) has
separate ICANN and PRIVATE sections. [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162.html)
describes CT log entries, which do not report registration age.
