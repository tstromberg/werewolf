# unwound: form rollout

The caddy form is the first application pilot. It uses a screened `*` lookup
grant instead of direct port 53 access. Its composed network policy has an
A/AAAA grant for Caddy's UID, while only `_unwoundnet` can reach the DHCP
resolver on port 53. `make check-caddy` boots the service and passes its native
checks. Its test certificate is for `localhost`, so that check makes no
external DNS lookup. An isolated lab run used the composed Caddy policy and
Ubuntu's Caddy 2.6 with `werewolf-linux.org` and Let's Encrypt's staging CA.
Caddy's A and AAAA lookups of `acme-staging-v02.api.letsencrypt.org` were both
allowed by screening. The fixture resolver returned NXDOMAIN, so no ACME
request was made. `test/check-unwound-caddy` reproduces that audit in a Linux
lab with Caddy installed. Other ACME endpoints and later Caddy versions still
need observation before changing the provisional entropy threshold.

Other application forms still declare direct port 53 access and fail the new
builder rule. Migrate them per service and test their actual query types; a
blanket A/AAAA grant is insufficient for Mox's mail lookups. Unbound, Pi-hole,
AdGuard Home and Blocky are DNS servers themselves and need a separate design
for upstream access and binding alongside unwound. Do not mark the form rollout
complete until those cases are resolved.
