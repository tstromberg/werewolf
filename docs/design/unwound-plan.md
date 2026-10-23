# unwound: implementation plan

Builds [unwound](unwound.md) and its [allowances](unwound-policy.md) as
`cmd/unwound`, a werewolf program like syslogd. Security first, then
simplicity, then everything else; compatibility last.

`wire`, `policy`, `screen`, and `cache` parse and decide without syscalls;
`unwound` and `upstream` hold the sockets. `fuzz` exercises the pure parts.

Setup (root) reads `/usr/share/werewolf/net`, binds 127.0.0.53 UDP and TCP,
opens `/dev/log` and one `SOCK_SEQPACKET` pair, and forks. The **frontend**
becomes `_unwound` in `/var/empty`: no files, no new sockets; it maps a query's
loopback source to a service, decides, screens, audits, and asks over the pair.
The **upstream** child becomes `_unwoundnet`, the one user fence lets reach the
DHCP resolvers: a fresh socket, port, ID and 0x20 case per attempt, TCP on
truncation, and `resolv.conf` reread when it changes. Either's death ends both.

## Query path

Client → frontend parses (FORMERR beyond one IN question; EDNS dropped) → policy
(REFUSED, audited) → screening for a screened `*` → the service's cache → the
same question already out, to wait for → upstream validates peer, port, ID, echoed
case, class and type, and returns the alias chain and the asked type, or a bare
header and why none answered → frontend checks alias targets against the grants
and builds the reply from scratch. 256 questions in flight, 32 per service; past
that SERVFAIL, counted. Audit lines, JSON datagrams to `/dev/log`, give a `why`
and a `detail` for each question that gets no answer; a lost one is counted.

## Phases

1. **The label mechanism on Linux.** Done, 2026-10-22, Ubuntu 24.04 (6.8):
   the `n`th distinct UID among `lookup` lines gets label 127.53.n/256.n%256
   (lib/dns.zig), and fence's rules, in [the design](unwound.md), let only
   that UID send from it to 127.0.0.53. Others, root included, get EACCES;
   forged loopback over a veth is a martian; passed sockets keep their label.
2. **The forwarder**, with exact, `*.NAME` and `* unfiltered` grants. Done.
3. **Werewolf integration.** Core done: `lookup:` in forms and compose,
   fence labels, `_unwound` and `_unwoundnet` in minimal, resolver at
   127.0.0.53, direct DNS grants refused unless a DNS service declares
   `dns-direct: true`, and `check-unwound`. Existing
   bundled application forms have been migrated; see [rollout](unwound-rollout.md).
4. **Screening `*`**, below. Done, including `check-unwound-tunnels`.
5. **A cache for every grant**, below. Done.
6. **DNS over TCP framing.** Done: one connection may carry successive or
   pipelined queries; unwound buffers the next frame until it answers the
   current one. `check-unwound` sends two frames in one write.

Next: RDAP age. Endpoint lists, process metadata, stale answers and DoT are deferred.

## Cache

Decided 2026-10-22: every grant's answers are kept, per service, so that no
service learns from timing what another asked or pushes out its answers: 256
each, of at most 768 bytes of records; a larger answer passes uncached. A
positive answer is kept for its least TTL, at most an hour; a negative one for
its SOA's TTL and minimum (RFC 2308), which upstream sends on as a root SOA.
Failures, a TTL of 0, and negative answers with no SOA are not kept. A
question asked while the same one is out waits for its answer, audited
`merged`; a hit is audited `cached`. Full, the cache lets the answer least
recently given go, and never fails a question. Policy comes first.

## Tunnels: screening a `*` grant

Decided 2026-10-22: a form that uses DNS but cannot name its hosts gets the
screened `lookup: "*"` (A and AAAA). Screening limits common DNS tunnels
without breaking ordinary lookups. A tunnel needs new names to send data,
changing answers to receive it, and roomy records. Screening bounds each:

- Shape: at most 100 characters and 6 labels, each at most 40. A label, or
  the labels left of the site together, of 24 characters or more at 3.5 bits
  per character or more is refused, audited `tunnel` with its sign and score.
  Dots and hyphens are left out: they neither dilute data nor fake words.
- New names: a site (the last two labels, or three under a two-letter
  country's co, com, net, org, gov, edu or ac) takes at most 32 names the
  service has not asked about within the hour, and a service at most 32 such
  sites. Past either: REFUSED, audited `budget` and which. Names are SipHash
  values under a key drawn at start, so no name can pass for another.
- Changing answers: an answer stands at least five minutes whatever its TTL:
  NXDOMAIN, NODATA and a resolver's SERVFAIL too, since the attacker's server
  chooses those. Only "no resolver answered" is not kept: no resolver chose
  it, and keeping it would break lookups before the first DHCP lease.
- Room: at most 4 A, AAAA, MX, SRV, NS or PTR, 2 TXT, CAA or TLSA, 512 bytes of
  data in all. Addresses fence's `public` refuses (lib/network.zig) are
  dropped, which also stops DNS rebinding; so are records naming a name of
  the wrong shape; the audit record counts each. The alias chain is not
  returned at all: kept records are the question's own, with no aliases.
- Eviction: an answer the cache lets go early charges its name to the budget
  again, so a poller cannot refresh answers faster than it gets new names.

What remains: one site yields about 32 names and 12 answers per name an
hour, a few kilobytes; 32 registered domains, some tens of kilobytes; and the
timing of failures. Exact and `*.NAME` grants skip screening, as their names
are fixed. `* unfiltered` skips it, audited, for what must resolve anything.

Keep the provisional 3.5-bit threshold until real service names show a reason
to change it; site and name exhaustion stay audited as `budget`, separate
from names refused for their shape. Known false refusals: AWS's names in long
(`ec2-203-0-113-255.ap-southeast-2.compute.amazonaws.com`) and load balancers'
score as data; a `*.NAME` grant resolves them. Tune the threshold before relaxing.

`make check-unwound-tunnels` runs local iodine, dns2tcp and shellack servers
in private namespaces. Direct clients first prove the tunnel programs work:
iodine connects, dns2tcp echoes data, and shellack runs a fixed command and
returns its result. Against screened unwound, iodine gets no usable A answer,
dns2tcp's probe gets FORMERR, and shellack's SRV target is removed for its
shape. The test needs those programs in a Linux lab and a local shellack
checkout; it is separate from CI's `check-unwound`.

## Testing and fuzzing

Every parser and screen is a pure function over slices, unit tested and
fuzzed in the same files: malformed messages (trailing data, compression
loops, counts past the buffer, wrong questions), round trips, grant parsing
and label-boundary matching, IPC frames as untrusted, and what screening
keeps, with tunnels' and real services' names. `make check-unwound` runs the
real fence and unwound in namespaces against a fixture resolver: allow, deny,
aliases, TCP fallback, forgeries, resolver change, label forgery, screening (a
poller, a slow tunnel past its budget, data-shaped names, silence not kept),
the cache's TTLs, negative answers, merging and eviction, and upstream death.
`make test` runs the seeds; `make fuzz-unwound` runs each target for longer.
