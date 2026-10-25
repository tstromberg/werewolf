# DNS permissions

DNS configuration and network permission are separate. A resolver in
`/etc/resolv.conf` does not grant every process access to it.

The minimal form declares `dns _update`, so its network fetcher (UID 69)
can resolve APK repositories, CVE feeds and signed update endpoints.
Playground also declares `dns root`, so interactive tools resolve names.
Other services opt in with `connect: dns`, alongside their declared TCP
ports and network promises. Services without a DNS declaration remain denied.

## Configuration

Static networks use `werewolf.dns`. DHCP supplies up to three IPv4
resolvers. init or DHCP writes `/run/werewolf/network/resolv.conf`, linked
from `/etc/resolv.conf`. Resolver input is bounded, validated as unicast
IPv4 addresses, and deduplicated; missing resolvers grant nothing.
IPv6 resolver discovery remains unsupported; IPv4 DNS can return AAAA records.

The build compiles `dns USER...` to numeric `dns UID` entries in the
immutable `/usr/share/werewolf/net`. Service declarations compile to that
same policy and grant TCP 53 in the service's Landlock domain.

## Enforcement

fence grants each declared UID UDP and TCP destination port 53 only to
the detected addresses. TCP supports truncated UDP responses and large
answers. DNS rules precede the metadata refusal because GCP uses
169.254.169.254 for both services; the exception matches port 53 alone.
Azure's resolver at 168.63.129.16 works without opening its control ports.

Replies must come from a configured resolver's port 53 to a local
ephemeral port (32768–60999). These rules remain stateless. Explicit
broader `connect` declarations still grant what they say; `dns` does not
subtract those permissions. Loopback keeps fence's existing local policy.
HTTP and HTTPS egress require their own declarations. Successful DNS
resolution alone does not let playground's root download arbitrary URLs.

Editing `resolv.conf` after fence cannot change the kernel grants. Only
the trusted DHCP parent can update them; processes started after fence
lack CAP_NET_ADMIN and cannot signal that parent across Landlock's domain.

## DHCP renewals

The parent reads DNS UIDs from the immutable image before confinement
and opens a routing socket before forking. The unprivileged engine
closes that socket and cannot change policy. Parent seccomp permits
send/receive only on this preopened descriptor, alongside its existing
bounded lease application syscalls; CAP_NET_ADMIN remains its only capability.

After independently validating a lease, the parent revokes old DNS rules,
adds grants for the new resolvers, then atomically replaces `resolv.conf`.
Unchanged resolvers cause no routing operations. Removing resolvers removes
the grants and empties the file. Failure stops application before the new
resolver file is published; no temporary broad port-53 grant is installed.
The DHCP parent remains trusted to apply network configuration.
Services grant reads on the resolver directory so replacements stay readable
under Landlock. New OCI roots bind that directory read-only and link
`/etc/resolv.conf` into it; binding the old file inode would keep stale DNS.
Older OCI roots retain their previous file binding until rebuilt.

## Verification

Unit tests cover declaration compilation, service opt-in, malformed and
bounded input, duplicate grants, unchanged leases, removal, and failure
ordering. `make check-dns` uses the real fence and DHCP binaries in
private Linux namespaces, with local DNS, HTTPS and DHCP fixtures; its
allow/deny cases are [test/dns/cases.yaml](../../test/dns/cases.yaml).
It checks UDP/TCP success for UID 69, root refusal in production, alternate
resolver refusal, HTTPS by hostname, actual sandboxed DHCP renewal, old
resolver revocation, GCP/Azure DNS without metadata HTTP, and playground
root's narrow grant. CI runs the test on x86_64 and aarch64.

Posture measures root DNS to assigned resolvers, root DNS to other servers,
and root HTTPS to other servers. Restricted access passes; allowed access
fails. Playground explicitly expects the assigned-resolver failure, while
qemu-host expects all three for its guests' forwarded traffic. UDP probes
send nothing; nonblocking TCP closes immediately without awaiting a server.
TEST-NET destinations make arbitrary-server probes independent of public
service availability. Missing routes or unsupported networking are skipped,
never passed as proof of restriction. IPv6 is probed when enabled.
