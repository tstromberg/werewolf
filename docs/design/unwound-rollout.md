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

Other application forms still need migration per service and testing of their
actual query types; a blanket A/AAAA grant is insufficient for Mox's mail
lookups. Unbound, Pi-hole, AdGuard Home and Blocky are DNS servers: their
service-local `dns-direct: true`
grant lets their declared upstream DNS connections through while their ordinary
`lookup:` calls use unwound. The grant derives its UID from the service user.
Their listeners must avoid unwound's 127.0.0.53 socket. Unbound, AdGuard Home
and Blocky bind loopback and the machine's current IPv4 address; Pi-hole binds
the network interface through dnsmasq. Fence limits their TCP and UDP DNS
listeners to connected subnets. All four DNS server forms pass their native
checks. Address plan changes require a reboot so fence can load the new LAN
prefixes and the DNS services can bind the new address.
