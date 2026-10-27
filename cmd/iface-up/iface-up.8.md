# iface-up(8)

<!-- date: October 25, 2026 -->
<!-- os: Werewolf -->

## NAME

iface-up — bring up an interface with an optional IPv4 address and route

## SYNOPSIS

**iface-up** *interface* [*address/prefix* [*gateway*]]

## DESCRIPTION

The **iface-up** utility brings up *interface*. If supplied, it assigns the IPv4
address and prefix and installs the default gateway. A gateway outside the subnet
receives a host route first. Arguments are validated before any network change.

This boot helper is called by init(8) for loopback and static addressing. It keeps
only CAP_NET_ADMIN and restricts its system calls before configuring the interface.
It cannot restore network privileges removed by fence(8).

## EXIT STATUS

The **iface-up** utility exits 0 on success, and >0 if an error occurs.

## SEE ALSO

dhcp-client(8), fence(8), init(8)
