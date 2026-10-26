# dhcp-client(8)

<!-- date: October 25, 2026 -->
<!-- os: Werewolf -->

## NAME

dhcp-client — obtain and maintain an IPv4 DHCP lease

## SYNOPSIS

**dhcp-client** **up** *interface*

**dhcp-client** **keep**

## DESCRIPTION

The **dhcp-client** utility configures an IPv4 address, routes, MTU, upstream DNS
resolvers and the assigned DNS domain. The **up** command attempts to obtain a lease
within 30 seconds. The **keep** command renews the recorded lease.

init(8) starts both modes before fence(8) removes network administration privileges
from later processes. The renewal process is not a runit service. It cannot be
restarted from an ordinary confined root shell.

An unprivileged engine parses DHCP packets as _dhcp. A separate _netcfg process
validates its fixed-size messages and applies leases with CAP_NET_ADMIN. Only the
latter may write network state. Classless static routes and DHCP domain option 15 are
supported. Malformed domains are ignored.

## FILES

- `/run/werewolf/network`

  Lease and resolver state shared with the boot network helpers.

## SEE ALSO

fence(8), iface-up(8), init(8), unwound(8)

## CAVEATS

An expired lease keeps its address until replaced. Renewals are broadcast;
duplicate-address probing is not performed. If the renewal process exits, renewals
stop. DHCP cannot authenticate the server; use static addressing on an untrusted LAN.
