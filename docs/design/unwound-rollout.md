# unwound: form rollout

The caddy form is the first application pilot. It uses a screened `*` lookup
grant instead of direct port 53 access. Its composed network policy has an
A/AAAA grant for Caddy's UID, while only `_unwoundnet` can reach the DHCP
resolver on port 53. `make check-caddy` boots the service and passes its native
checks. Its test certificate is for `localhost`, so this does not exercise
real ACME hostnames or provide audit data for tuning the entropy threshold.

Other application forms still declare direct port 53 access and fail the new
builder rule. Migrate them per service and test their actual query types; a
blanket A/AAAA grant is insufficient for Mox's mail lookups. Unbound, Pi-hole,
AdGuard Home and Blocky are DNS servers themselves and need a separate design
for upstream access and binding alongside unwound. Do not mark the form rollout
complete until those cases are resolved.
