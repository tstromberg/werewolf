# fence

## Summary

The machine's network and file policy, set once at boot from the image,
then `exec runit`, so every process on the machine descends from it and
none, root's included, can loosen it before a reboot.

## Background

A machine should send only what its form declares and receive only what it
serves or asked for, with no firewall to configure. init's last step is
`exec fence runit`, after the seal and after starting the two programs that
stay outside fence's domain: the mount broker, and DHCP's renewal. fence
reads only `/usr/share/werewolf/net`, which the build compiles from the
forms' `.net` files into the signed image.

## Goals

- Default deny, both ways, for every user, from the image alone.
- No process after fence can change the rules, or send below them.
- Files written only where a machine must write, and run only from `/usr`.

## Non-Goals

- Connection state: the kernel's routing rules have none.
- Policy between local services: each service's own Landlock (leash).

## Detailed design

1. **Policy-routing rules**, IPv4 and, where the form allows IPv6, IPv6;
   without the `ipv6` allowance the kernel has none. Sent traffic passes only if its
   user declared the protocol and port (`connect`), as a reply from a
   served port (`listen`), or to the metadata server for a user named;
   anything else gets EACCES. Arriving traffic passes to a served port,
   from a port the machine connects to, or as ICMP; TCP, UDP, the other
   transports, tunnels and IPsec are dropped unanswered.
2. **Landlock**, for every process: TCP binds only to the policy's ports or
   0; files read anywhere but `/dev`, which is closed even for reading but
   for the devices werewolf names, run only beneath `/usr`, written only in `/run`,
   `/tmp`, `/var/tmp`, `/dev/shm`, `/data` and terminals; device ioctls
   only on terminals and a VM's PL061 GPIO chip; no `mount`. Every refusal
   is audited, after exec too (`LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON`).
3. **The bounding set** loses CAP_NET_ADMIN and CAP_NET_RAW, unless a form
   allows them (none does), and CAP_SYS_ADMIN, always: its Landlock step
   needed it, and after boot only the mount broker, outside, mounts.
4. **exec** of PROGRAM.

## Drawbacks

- Stateless: a packet from TCP 443 or UDP 53 reaches any socket.
- Fragmented UDP replies are lost: later fragments carry no ports.

## Alternatives Considered

### netfilter or BPF
More to configure and more kernel to reach. Policy routing, Landlock and
the bounding set are built in, and nothing on the machine sets them again.

### A rule that drops every protocol arriving
It would drop ARP's local lookup too, and the machine would answer no one.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| Root removes the rules | That takes CAP_NET_ADMIN, gone after fence; Landlock no one can lift. |
| Raw or packet sockets below the rules | That takes CAP_NET_RAW, gone after fence; DHCP's engine holds the one packet socket, locked to DHCP replies. |
| A reply forged by its source port | **Open, by design:** it reaches any socket, including one listening on a port the kernel picked (`listen()` without `bind()`, unseen by Landlock). It takes code already running here; leash refuses `listen` to services that did not promise it. |
| Other IP protocols arriving | No handler exists once modules are closed; the kernel answers unreachable. |
| Root drives GPIO lines | Only a PL061 (`arm,pl061`), the chip a VM wires its power button to; real hardware's chips get no ioctls. |

## Reliability Considerations

- **Fails closed:** any step that fails exits 1; PID 1 dies, the kernel
  panics, and the machine returns on the slot that last worked.
- **A malformed policy** is an error, never a guess.
- **Tested:** posture checks each protection on every `make check` boot.
