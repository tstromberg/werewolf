# fence

Built, 2026-10-06.

A werewolf machine sends only the traffic its form declares, receives only
what it serves or asked for, and lets only the processes named reach the
cloud's metadata server. The policy is decided when the image is built and
cannot be changed on the machine. There is no firewall to configure, and
no BPF or netfilter: mechanisms built into the kernel enforce it.

## The policy

Each form may have a `forms/<name>/form.yaml`, read along its chain of bases as
modules are:

```
# The updater's network half, as _update: Wolfi, Alpine and git.kernel.org
# over HTTPS, and the names to find them. Root has none.
connect _update tcp/443 udp/53 tcp/53
```

| Line | Means |
| --- | --- |
| `listen tcp/PORT...` | a TCP port the machine serves |
| `listen tcp/PORT... loopback` | a TCP port its own processes may bind and reach, and the network never does |
| `connect USER\|all tcp/PORT udp/PORT icmp ...` | what processes running as USER, or anyone, may send |
| `connect USER\|all tcp/PORT udp/PORT ... public` | the same, to public addresses alone |
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

A service that fetches from the internet on its users' behalf (a model
pull, a webhook, a feed) is the classic server-side request forgery
target: told to fetch `http://10.0.0.5/` or `http://[::1]:6379/`, it
would reach what only the machine should. `public` on a `connect` line
keeps its ports to public addresses: never loopback, private (10/8,
172.16/12, 192.168/16, fc00::/7), carrier-grade NAT, link-local (and so
the metadata server), benchmarking, multicast, reserved, or IPv4 hidden
in IPv6 (`::/96`, `64:ff9b::/96`). It takes no `icmp`, and compiles to
`connect 207 tcp 443 public`.

## Enforcement

init's last step is `exec /usr/lib/werewolf/fence /usr/bin/runit`. As root,
fence reads the policy and then:

1. **Sets policy-routing rules**, which the kernel consults on every route
   lookup, the same for IPv4 and IPv6, in this order:

   | Priority | Rule |
   | --- | --- |
   | 5 | sent by a user whose `connect` says `public`, on that protocol and port, to an address that is not public: refuse |
   | 10 | sent here, to this machine or over loopback: deliver |
   | 100 | sent to 169.254.169.254 TCP 80 by a user named: route |
   | 101 | sent there by anyone else: refuse |
   | 200 | sent as declared (user, protocol, port), or from a served port: route; if there is no route, unreachable |
   | 299 | anything else sent: refuse (EACCES) |
   | 300 | arriving to a served port, from a port the machine connects to, from the metadata server's 80, or ICMP: deliver |
   | 399 | anything else arriving by TCP, UDP, UDP-Lite, SCTP or DCCP: drop, unanswered |
   | 400 | the kernel's own local rule, moved here from 0 |

   Locally sent traffic is told apart by its lookups coming from `lo`.
   DHCP's packet socket and ARP are below IP routing and unaffected; so is
   loopback. For IPv6, ICMPv6 passes both ways for everyone (neighbour
   discovery, router advertisements), and the metadata rules name AWS's
   fd00:ec2::254.

   The drops name their protocols. A single rule dropping everything
   arriving also dropped ARP: to answer a request, the kernel asks the
   rules whether the address is local, with a lookup that has no protocol
   or port, and the blackhole answered first. The machine stopped
   answering for its address, and once its neighbours forgot it, nothing
   reached it, the served ports included. Other IP protocols reach the
   local table and, with no handler (modules are closed), get the
   kernel's "protocol unreachable".

   Each rule that routes traffic out has a twin with the same match whose
   action is unreachable. Without it, allowed traffic with no route (IPv6
   on a network without IPv6) fell through to the refusal and got EACCES,
   which clients take as final, where they would have tried the next
   address after ENETUNREACH. That broke the updater on dual-stack names.
2. **Binds, and connects, only declared ports.** It restricts itself with
   Landlock: a ruleset handling `BIND_TCP` and `CONNECT_TCP`. Binding is
   allowed to the policy's ports and port 0, which some clients bind
   before connecting (busybox's `nc`). Connecting is allowed to the ports
   the policy names for any user, to the served ports, which local
   clients reach over loopback, and to port 80 where some user may read
   the metadata server; the rules above decide which user and where to.
   This bounds what a process that may bind a served port can do from
   it: the rule that lets a server answer from its port names no user
   and no destination, and the kernel routes a connect from a bound port
   by the same lookup, so without it a listener, or whatever took its
   place, could connect anywhere.
3. **Becomes runit.** Landlock's restriction is inherited by every process
   that follows and cannot be lifted, by root or anyone, until reboot. On
   a kernel with Landlock ABI 6 the domain is scoped too: no process in
   it can signal, or reach the abstract UNIX socket of, a process outside
   it. Outside it are only what init started before fence, the mount
   broker, DHCP's renewal and stage0's deadman, so root cannot stop or
   kill them; the broker is asked on its path socket, which scoping does
   not touch, and the kernel ends the rest at reboot.

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
`CAP_NET_ADMIN`. fence drops it, and `CAP_NET_RAW`, from the bounding set
once its rules are set, so no process after it holds either. It drops
`CAP_SYS_ADMIN` too, which its Landlock restriction is the last to need:
the few mounts after boot are the mount broker's, started before fence. The one that
needs them, DHCP's renewal (`dhcp-client keep`), init starts before fence,
as it starts the mount broker: it keeps them, its parent's seccomp filter
allows no netlink, and its engine holds a packet socket it cannot remake.
The seal goes before both, and Landlock needs nothing from it.

## Files

The same Landlock ruleset holds every process's files, root's included,
from runit on:

| | Allowed | Refused to everyone |
| --- | --- | --- |
| Read | everywhere | |
| Write | `/run`, `/tmp`, `/var/tmp`, `/dev/shm`, `/data`; `/dev/null`, `zero`, `full`, `random`, `urandom`, `kmsg`; terminals | `/proc`, `/sys`, a disk itself, the image |
| Execute | beneath `/usr`, where every program and service link leads, and `/oci`, the image roots baked in beside it ([adhoc.md](adhoc.md)) | anything written since boot, wherever |
| Write, beneath an image root | its `/tmp`, `/run` and `/data`, and each path its service writes: the binds init made from its own places, listed by the build in `/usr/share/werewolf/oci`, each needing a rule of its own since Landlock judges a path by the mounts it crosses | the image |
| Make sockets, FIFOs | `/run` | elsewhere |
| Make device nodes | `/data`, which is `nodev`, for apk building a slot | elsewhere |
| Device ioctls | terminals: `/dev/console`, `/dev/ptmx`, `/dev/pts`, and every `tty*` and `hvc*` in `/dev` at boot | every other device |

Not even root can change a sysctl or a sysfs setting init left, or write
under a filesystem to its disk, until the machine reboots. A domain that
handles files also refuses `mount`, `umount` and `pivot_root` to every
process in it; the mounts werewolf makes after boot (an update's slot,
GRUB's environment, the ESP, shutdown) are made by `mount-broker`, which
init starts before it becomes fence, outside the domain, and which takes
a word, never a path ([pledge.md](pledge.md)).

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
| `files-system-writes` | opening a sysctl, a sysfs setting and the first disk for writing, without writing: EACCES |

Tested under QEMU, on aarch64:

- On the cloud form: every `posture` check above passes, and the config
  still arrives through `_cloud`.
- On the autoupdate form, when root still had `connect root`: `apk`
  installs from Wolfi by name, TCP 443 connects and DNS resolves, all
  declared; TCP 80 is refused. As `nobody`: TCP 443 is refused. `nc -l -p
  4444` as root: `bind: Permission denied`.
- On the autoupdate form now, where only `_update` may send: a whole
  update, apk's fetches and the CVE sources as `_update`, root offline.
- On the sshd form, with a static address and nothing sent first: sshd
  serves port 22 from the host. (The single drop-everything rule failed
  this: ARP went unanswered.)

## Not covered

- **UDP listeners.** Landlock in Linux 6.18 has rules for TCP only. A UDP
  listener hears only what the inbound rules let arrive (replies from
  declared ports); the seal can refuse UDP sockets to processes not
  allowed them.
- **Raw and packet sockets** bypass routing and Landlock: they need
  `CAP_NET_RAW`, which fence drops from every process after it. DHCP's
  renewal opened its packet socket before.
- **Fragmented UDP.** Arriving packets are routed before they are
  reassembled, and only a datagram's first fragment carries its ports, so
  the rest of a fragmented reply matches no allowance, meets the UDP drop,
  and the datagram is lost. No rule can tell a later fragment apart. It
  costs nothing today: the one UDP werewolf declares is DNS, and neither
  Zig's resolver nor glibc's asks for EDNS0 (no `options edns0` in
  resolv.conf), so answers stay within 512 bytes, and a truncated one is
  asked again over TCP 53, which is declared. A UDP service with large
  datagrams would need its fragments let through some other way.
- **Destinations.** Outbound rules name protocols and ports, not hosts:
  `connect root tcp/443` reaches any HTTPS server. `public` narrows a
  line to the internet, not to a host.

## Alternatives considered

- **BPF socket hooks** (cgroup `bind4/6`, `connect4/6`). Per-process and
  exact, and permanent once the seal forbids `bpf()`, but `bpf()` must be
  open at boot for werewolf's own programs, and BPF is what the seal is
  meant to shut.
- **nftables.** A real packet filter, but about 1 MB of userland and
  kernel modules, and stateful inbound filtering needs connection
  tracking, which costs memory and work on every packet.
