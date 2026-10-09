# fence

Built, 2026-10-06 (cmd/fence).

## Summary

A werewolf machine sends only what its form declares, receives only what
it serves or asked for, and lets only named users reach the metadata
server. Routing rules and Landlock, fixed in the image, enforce it.

## Background

A broken-into service should reach nothing its form did not declare; a
firewall root can reconfigure does not hold. The policy is form.yaml's
`net` (cmd/fence/README.md), by user; the build fails on a line it cannot
compile, or a service `listen` that no `net` line declares.

## Goals

- Default deny both ways, root included, that nothing after fence lifts.
- Files written only where a machine must, and run only from the image.

## Non-Goals

- Destinations (hosts), connection tracking, or rules between services.

## Detailed design

init's last step is `exec fence runit`: fence sets the rules, restricts
itself with Landlock, drops capabilities, and becomes runit, so every
process inherits it all. A lookup from `lo` marks sent traffic:

| Priority | Rule (IPv4 and IPv6) |
| --- | --- |
| 5 | sent with a `public` line's user, protocol and port to a non-public address: refuse |
| 10 | sent to this machine or over loopback: deliver |
| 100 | sent to the metadata server's TCP 80 (IPv6: AWS's fd00:ec2::254) by a user named: route |
| 101 | sent there by anyone else, or to Azure's wire server: refuse |
| 200 | sent as declared (user, protocol, port), from a served port, or ICMPv6: route |
| 299 | anything else sent: refuse (EACCES) |
| 300 | arriving at a served port, from a connected-to port or the metadata server's 80, or ICMP: deliver |
| 399 | anything else arriving by TCP, UDP, UDP-Lite, SCTP, DCCP, tunnel or IPsec: drop |
| 400 | the kernel's local rule, moved from 0 |

The kernel already refuses packets for ports nothing listens on, so this
is default deny with no work per packet: rules are read once per route
lookup. Each route-out rule has an unreachable twin, so a missing route
fails ENETUNREACH and clients try the next address; EACCES, final to
them, broke the updater on dual-stack names.

Landlock lets a process bind only the policy's ports (and 0), and connect
only to declared, served, loopback and metadata ports: rule 200 lets a
served port answer anyone, so a listener could otherwise reach anywhere.

### Files

The same Landlock ruleset holds every process's files, root's included:

| | Allowed | Refused to everyone |
| --- | --- | --- |
| Read | everywhere but `/dev` | `/dev`, but for the devices below and `/dev/input` |
| Write | `/run`, `/tmp`, `/var/tmp`, `/dev/shm`, `/data`; `null`, `zero`, `full`, `random`, `urandom`, `kmsg`; terminals; an image root's `/tmp`, `/run`, `/data` and `write` paths, each its own rule ([adhoc.md](adhoc.md)) | `/proc`, `/sys`, disks, the image |
| Execute | beneath `/usr` and `/oci` | anything written since boot |
| Make sockets, FIFOs; device nodes | `/run`, an image root's `/run` and `/tmp`; `/data` (`nodev`), for apk building a slot | elsewhere |
| Device ioctls | console, `tty*`, `hvc*`, ptys if the form allows `pty`, a PL061 GPIO chip | every other device |

So not even root can change a sysctl or write a disk beneath its
filesystem, or mount. Other reads stay open: the image holds no secrets,
and closing them would force exceptions for every program.

## Drawbacks

The rules are stateless: a packet forged from a port the machine connects
to (443, say) passes, but reaches only a socket that exists.

### Not covered

- **UDP listeners.** Landlock has TCP rules only; UDP hears what 300 admits.
- **Fragmented UDP.** Later fragments carry no ports and meet the drop;
  DNS, the one UDP declared, fits 512 bytes (no EDNS0) or retries on TCP.
- **Destinations.** `connect USER tcp/443` reaches any HTTPS server.

## Alternatives Considered

### BPF socket hooks, or nftables
BPF hooks need `bpf()` open at boot, which the seal shuts. nftables is
about 1 MB of userland and modules, and tracks every connection.

## Security Considerations

Without `CAP_NET_ADMIN` and `CAP_NET_RAW` (kept only if a form allows
them; none does) root cannot change the rules or send beneath them. The
domain is scoped (ABI 6): root cannot signal the broker or DHCP's renewal.

## Reliability Considerations

- **Fails closed:** any failed step, Landlock below ABI 4 included, exits;
  PID 1 dies, the kernel panics, and the last slot that worked boots.
- **Tested** each boot by posture: `network-ports`, `-bind`, `-outbound`,
  `-metadata`, `-inbound`, `-ipv6`, `files-system-writes`, `-device-reads`.
