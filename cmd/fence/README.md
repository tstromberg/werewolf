# fence

## Summary

fence sets the image's network and file policy, then execs runit. Every
process descends from it; root cannot loosen the policy before a reboot.

## Background

init installs the seal, starts the mount broker, DHCP renewal and stage0's
deadman outside fence's domain, then execs `fence runit`. DHCP keeps its
CAP_NET_ADMIN and packet socket; services inherit fence's restrictions.
fence reads `/usr/share/werewolf/net`, compiled from form.yaml's `net`, and
the detected resolvers: one entry per line, numbers only, `all` for every user;
a `connect` or `lookup` user may be a range, `FIRST-LAST` (`:people`).
    listen tcp 22
    listen tcp 5432 loopback
    connect 65536-1073741823 tcp 443 public
    connect 208 tcp 32402 loopback
    listen 207 udp 5353 lan
    connect 207 udp 5353 lan
    metadata 68

## Goals

- Default deny, both ways, for every user, from the image alone.
- No process after fence can change the rules, or send below them.
- Files are written only where a machine must write, and run only from `/usr`.

## Non-Goals

- Connection state, which policy-routing rules lack, and policy between
  local services, which leash's Landlock rules handle.

## Detailed design

1. **Policy-routing rules** for IPv4, and for IPv6 if the kernel has it (werewolf's
   kernel is built without it). Sent traffic passes only if its user declared the
   protocol and port (`connect`), as a reply from a served port (`listen`), as ICMPv6,
   or to the metadata server's TCP 80 for a user named in `metadata`. Anything else
   fails with EACCES. `dns UID` permits UDP and TCP 53 only to the detected IPv4
   resolvers, including GCP's metadata address; replies must come from those addresses
   to ephemeral ports. DHCP renewals revoke old DNS rules before granting new ones
   ([dns.md](../../docs/design/dns.md)). A `public` connect refuses private, loopback,
   link-local, shared, multicast and reserved addresses, blocking the local network and
   metadata server from URL fetchers. Azure's wire server is closed to all. Arrivals
   pass to served ports, from connected ports, or as ICMP. Denied TCP, UDP, other
   transports, tunnels and IPsec get no reply; other protocols get "unreachable". Local
   and loopback traffic normally pass. A TCP `loopback` connect permits its port only on
   127.0.0.1 and ::1, refusing other destinations before the local table; it grants no
   Internet egress or reply allowance. Private TCP ports drop arrivals before reply
   allowances, even if a daemon binds all interfaces; local traffic reaches them first.
   Allowed traffic with no route fails as "network unreachable", not EACCES, so clients
   try the next address. UDP `lan` restricts unicast to connected subnets detected at
   boot, plus mDNS's group on UDP 5353. Other ports add no multicast. Off-subnet unicast
   drops before reply allowances. Changing the address plan needs a reboot; no subnet
   means no incoming unicast grant. See [fence.md](../../docs/design/fence.md).
2. **Landlock**, for every process: TCP binds only to the policy's ports
   or 0, and connects only to declared, served, loopback and metadata
   ports. Files are readable anywhere but `/dev`; programs run only from
   `/usr` and `/oci`; writes go only to `/run`, `/tmp`, `/var/tmp`,
   `/dev/shm`, `/data` and binds under image roots; sockets and FIFOs only
   in `/run`, those roots' `/run` and `/tmp`, and declared writable shared
   directories on both sides of their binds. Read-only shares get no write
   grant. `/dev` allows only null, zero, full, random, urandom, kmsg, terminals,
   input devices and permitted ptys. No process may mount. Refusals are audited.
3. **The bounding set** loses CAP_NET_ADMIN and CAP_NET_RAW, unless a form
   allows them (`lib/allow.zig`: `netadmin`, `packet`; none does), and
   always CAP_SYS_ADMIN, which only Landlock needed. Root then cannot
   mount or configure a filesystem (fsconfig, CVE-2022-0185).

## Drawbacks

- Stateless: a broad `connect` admits replies by source port; `dns` also
  checks the resolver address and destination ephemeral port.
- Fragmented UDP replies are lost: later fragments carry no ports.

## Alternatives Considered

### netfilter or BPF
More to configure and more kernel to reach. Policy routing, Landlock and
the bounding set are built in; DHCP changes only resolver grants.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| Root removes the rules | That needs CAP_NET_ADMIN, gone after fence. No one can lift Landlock. |
| Raw or packet sockets below the rules | That needs CAP_NET_RAW, gone after fence. DHCP's engine holds the one packet socket, locked to DHCP replies. |
| A reply forged by its source port | Explicit private TCP ports drop arrivals before reply allowances. Other sockets remain **open, by design**, including kernel-picked ports; leash refuses `listen` unless promised. |
| Root signals the mount broker or DHCP | Landlock ABI 6 scoping blocks signals and abstract sockets out of the domain. |
| Root drives GPIO lines | No GPIO chip is open to anyone; the kernel's gpio-keys turns a power line into an input device. |

## Reliability Considerations

- **Fails closed:** any failed step exits 1; PID 1 dies, the kernel
  panics, and the machine comes back on the slot that last worked.
- **A malformed policy** is an error, never a guess; a rule two forms
  share is accepted (EEXIST), not fatal.
- **Tested:** posture checks each protection on every `make check` boot.
