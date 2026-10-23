# Domain age for screened DNS

Status: offline classifier and SQLite schema, 2026-10-23. No age decision is
active in unwound. This builds on the [allowance policy](unwound-policy.md).

## Decision

Only a screened `lookup: "*"` uses age. Exact and `*.NAME` grants remain the
operator's explicit trust. Age is one more screen after local name shape and
endpoint checks. The default cutoff is 90 days after effective registration.
The currently assigned system domain and its descendants are automatically
available to DNS-enabled services and bypass this age gate. They still pass
the existing tunnel screen. Boot metadata's FQDN suffix takes precedence over
DHCP option 15; a domain assignment can change during DHCP renewal.
Unknown evidence is refused once enforcement is enabled. The first release
measures coverage without changing answers; enforcement follows only after
native boot, restart and integrity checks pass.

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
invalid/oversized response leaves age unknown. Measure provisional decisions
in observe mode before enabling this weaker fallback.

## Data path

1. The frontend sends the derived registered domain and triggering DNS
   request metadata to a bounded local miss queue. It never performs HTTPS.
   The external worker receives only the registered domain, never a full
   QNAME. Repeated misses coalesce. The first triggering request is recorded
   with the external check; other requests retain their normal DNS audit.
2. An isolated `_rdap` fetcher uses an image-pinned IANA RDAP bootstrap and
   PSL generation. It picks the label-wise longest bootstrap match and only
   HTTPS URLs. Its own lookup grant covers bootstrap and registry hosts; its
   network grant is public TCP 443. It cannot edit DNS policy or the database.
3. The fetcher validates TLS, response type and size, JSON depth, domain
   identity and event dates. Redirects and referrals remain within vetted
   HTTPS public destinations, at a small hop limit. RDAP availability
   failures may trigger a separate bounded crt.sh HTTPS query. No HTTP request
   can be initiated by a malformed DNS name or PRIVATE tenant.
4. A dedicated `_unwoundage` worker owns SQLite in `/data/svc/unwound-age`,
   using `cmd/unwound/age.sql`. It writes evidence and one `age_check` row per
   external check in a transaction, then serves validated verdicts over a
   private channel. Neither DNS process opens the database. Missing, partial,
   rolled-back or expired evidence never authorizes a name.

Keep the most recently used 20,000 registered domains. A domain row has no
fixed lifetime: it can remain indefinitely if it stays in the LRU set, but
each verdict is recomputed from dated evidence. Refresh expired evidence
before it authorizes another query. Eviction means unknown, never allow.
Cache unknown/errors for one hour or a longer server Retry-After. Bound miss
rates per service and registry, and database bytes as well as rows.
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

The offline classifier in `cmd/unwound/age.zig` covers PSL exact, wildcard,
exception and PRIVATE rules; RDAP registration and resets; bounded crt.sh
history parsing; and threshold, expiry and clock boundaries with the
90-day default. Cached evidence is reclassified by its fetch date and domain.
PSL and IANA versions are retained for audit, not cache invalidation. It
accepts only normalized ASCII PSL input. The updater must convert Unicode
PSL rules to A-labels before using it. `cmd/unwound/bootstrap.zig` selects a
pinned IANA entry by label-wise longest match and requires HTTPS. Run fetchers
against fixture HTTPS servers and inspect audit records in observe mode.
Enable the gate after native tests cover initial boot, renewal, restart,
outage, rollback, CT fallback, LRU eviction, provenance, file authority and
bounded miss floods. Audit records
name the derived domain, evidence generation and decision, never the RDAP
response body. Old domains still face the other screens.

[RFC 9083](https://www.rfc-editor.org/rfc/rfc9083.html#section-4.5) defines
RDAP events; [RFC 9224](https://www.rfc-editor.org/rfc/rfc9224.html#section-4)
defines bootstrap matching. The [PSL](https://publicsuffix.org/list/) has
separate ICANN and PRIVATE sections. [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162.html)
describes CT log entries, which do not report registration age.
