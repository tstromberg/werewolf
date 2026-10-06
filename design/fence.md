# fence

Built, 2026-10-06.

A werewolf machine sends only the traffic its form declares, receives only
what it serves or asked for, and lets only the processes named reach the
cloud's metadata server. The policy is decided when the image is built and
cannot be changed on the machine. There is no firewall to configure, and
no BPF or netfilter: mechanisms built into the kernel enforce it.

## The policy

Each form may have a `forms/<name>.net`, read along the include chain as
modules are:

```
# The updater, as root: Wolfi, Alpine and git.kernel.org over HTTPS, and
# the names to find them.
connect root tcp/443 udp/53 tcp/53
```

| Line | Means |
| --- | --- |
| `listen tcp/PORT...` | a TCP port the machine serves |
| `connect USER\|all tcp/PORT udp/PORT icmp ...` | what processes running as USER, or anyone, may send |
| `metadata USER...` | a user who may reach the metadata server's port 80 |

Identity is the user a process runs as. Services with accounts of their
own (`_cloud`, `grype`, `nginx`) get exactly their own declarations;
everything running as root shares root's, until services are given users
of their own (shell-free.md).

The build compiles the lines, users to uids from the image's own
`/etc/passwd`, into `/usr/share/werewolf/net`, one entry a line:

```
connect 0 tcp 443
connect all udp 53
listen tcp 22
metadata 68
```

A line it cannot compile fails the build. The file is in the read-only
image, and with verified boot it is signed with the rest. It is the one
place the machine's network is written down: `posture` and the checks
read it too.

## Enforcement

init's last step is `exec /usr/lib/werewolf/fence /usr/bin/runit`. As root,
fence reads the policy and then:

1. **Sets policy-routing rules**, which the kernel consults on every route
   lookup, the same for IPv4 and IPv6, in this order:

   | Priority | Rule |
   | --- | --- |
   | 10 | sent here, to this machine or over loopback: deliver |
   | 100 | sent to 169.254.169.254 TCP 80 by a user named: route |
   | 101 | sent there by anyone else: refuse |
   | 200 | sent as declared (user, protocol, port), or from a served port: route; if there is no route, unreachable |
   | 299 | anything else sent: refuse (EACCES) |
   | 300 | arriving to a served port, from a port the machine connects to, from the metadata server's 80, or ICMP: deliver |
   | 399 | anything else arriving: drop, unanswered |
   | 400 | the kernel's own local rule, moved here from 0 |

   Locally sent traffic is told apart by its lookups coming from `lo`.
   DHCP's packet socket and ARP are below IP routing and unaffected; so is
   loopback. For IPv6, ICMPv6 passes both ways for everyone (neighbour
   discovery, router advertisements), and the metadata rules name AWS's
   fd00:ec2::254.

   Each rule that routes traffic out has a twin with the same match whose
   action is unreachable. Without it, allowed traffic with no route (IPv6
   on a network without IPv6) fell through to the refusal and got EACCES,
   which clients take as final, where they would have tried the next
   address after ENETUNREACH. That broke the updater on dual-stack names.
2. **Binds only declared ports.** It restricts itself with Landlock: a
   ruleset handling only `BIND_TCP`, allowing the policy's ports and port
   0, which some clients bind before connecting (busybox's `nc`).
3. **Becomes runit.** Landlock's restriction is inherited by every process
   that follows and cannot be lifted, by root or anyone, until reboot.

It logs one line, and fails closed: a step that fails exits 1, init is
PID 1, the kernel panics, and the machine comes back on the slot that last
worked.

```
fence: {"time":"2026-10-06T17:39:50Z","event":"fence","listen":[],"connect":["0 tcp 443","0 tcp 53","0 udp 53"],"metadata":[68]}
```

Binding and routing are the right places for this. The kernel already
refuses packets for ports nothing listens on, so allowing only declared
ports to be bound, and only declared traffic to arrive, is default-deny
inbound without inspecting packets or tracking connections. Rules are
consulted once per route lookup: once per TCP connection, once per
unconnected UDP datagram. Nothing is done per packet beyond what routing
does anyway.

The rules are stateless. A packet crafted to come from a port the machine
connects to (443, say) passes the inbound rules, but reaches only a
socket that exists: Landlock still stops anything binding an undeclared
port, so what could hear it is a client's own connection, or a socket
bound to port 0 by a process the seal has not stopped.

## Order with the seal

The routing rules can be changed by anyone holding
`CAP_NET_ADMIN`. The seal (lockdown.md) drops it from every process but the
DHCP client's parent, whose seccomp filter allows no netlink. So the seal
goes after fence's netlink step and before runit starts anything. Landlock
needs nothing from the seal.

## Checked

`posture` tests each protection on a running machine, and fails it where
it is missing, on any Linux:

| Check | Test |
| --- | --- |
| `network-ports` | listening TCP ports are the declared ones |
| `network-bind` | bind() of an undeclared port: EACCES |
| `network-outbound` | UDP connect() to 192.0.2.1:9, a route lookup that sends nothing: EACCES |
| `network-metadata` | TCP connect() to 169.254.169.254:80, one second at most: EACCES |
| `network-inbound` | the rules (RTM_GETRULE) drop arriving traffic before delivering it, and refuse undeclared sent traffic |
| `network-ipv6` | IPv6 is off, or its rules (AF_INET6) drop and refuse as IPv4's do |

Tested under QEMU, on aarch64:

- On the cloud form: every `posture` check above passes, and the config
  still arrives through `_cloud`.
- On the autoupdate form, as root: `apk` installs from Wolfi by name, TCP
  443 connects and DNS resolves, all declared; TCP 80 is refused. As `nobody`: TCP 443 is refused. `nc -l -p
  4444` as root: `bind: Permission denied`.
- On the sshd form: sshd serves port 22 from the host.

## Not covered

- **UDP listeners.** Landlock in Linux 6.18 has rules for TCP only. A UDP
  listener hears only what the inbound rules let arrive (replies from
  declared ports); the seal can refuse UDP sockets to processes not
  allowed them.
- **Raw and packet sockets** bypass routing and Landlock: they need
  `CAP_NET_RAW`, which the seal drops for all but the DHCP client's
  allowance.
- **Destinations.** Outbound rules name protocols and ports, not hosts:
  `connect root tcp/443` reaches any HTTPS server.

## Alternatives considered

- **BPF socket hooks** (cgroup `bind4/6`, `connect4/6`). Per-process and
  exact, and permanent once the seal forbids `bpf()`, but `bpf()` must be
  open at boot for werewolf's own programs, and BPF is what the seal is
  meant to shut.
- **nftables.** A real packet filter, but about 1 MB of userland and
  kernel modules, and stateful inbound filtering needs connection
  tracking, which costs memory and work on every packet.
