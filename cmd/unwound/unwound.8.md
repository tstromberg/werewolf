# unwound(8)

<!-- date: October 25, 2026 -->
<!-- os: Werewolf -->

## NAME

unwound — enforce per-service DNS lookup policy

## SYNOPSIS

**unwound**

## DESCRIPTION

The **unwound** daemon answers DNS at 127.0.0.53 and forwards only the names and
record types granted to the requesting service. The image's compiled lookup policy
determines access. fence(8) assigns source labels so the daemon identifies the caller
from kernel network state rather than from a claimed identity.

An unprivileged _unwound frontend validates and audits queries. A separate
_unwoundnet process reaches the resolvers supplied by DHCP and reads network state.
The boot FQDN takes precedence over the DHCP domain. Policy is checked before cache
lookup; services have separate caches.

Replies are rebuilt from the requested records and permitted alias chain. Alias
targets must also satisfy policy. TTLs are capped at one hour. Broad screened grants
restrict name shape, rates and answers to limit DNS tunnels; explicit grants can
admit names those rules reject. Callback endpoints and encoded-address names are
excluded from broad grants.

Each upstream attempt uses a fresh socket, source port, random identifier and
randomized question case. There are two one-second UDP attempts per resolver, with
TCP on truncation. Failure to obtain an answer yields SERVFAIL. Policy refusals
normally yield REFUSED.

Audit records go to syslogd(8) as JSON with the caller, question, decision, reason,
policy generation and latency. Logging failure does not change policy or answers.
Each service caches at most 256 answers. There are at most 256 in-flight questions
and 64 TCP clients, with per-service limits of 32 questions and 8 clients.

## FILES

- `/usr/share/werewolf/net`

  Compiled lookup policy.

- `/run/werewolf/network`

  Upstream resolver and assigned-domain state.

## SEE ALSO

dhcp-client(8), fence(8), syslogd(8), unwound-age(8)

## CAVEATS

This is a policy forwarder, not a recursive or DNSSEC-validating resolver. A grant
trusts the name's controller. Screening cannot prevent literal IP connections or DNS
over an otherwise permitted HTTPS connection.
