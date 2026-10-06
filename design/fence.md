# fence

Built, 2026-10-06.

A werewolf machine serves only the TCP ports its form declares, and only
the processes its form names may reach the cloud's metadata server. The
policy is decided when the image is built and cannot be changed on the
machine. There is no firewall to configure, and no BPF or netfilter: two
mechanisms built into the kernel enforce it.

## The policy

Each form may have a `forms/<name>.net`, read along the include chain as
modules are:

```
# sshd, for operators by key.
listen tcp/22
```

```
# The fetcher of cloud/cloud.zig, which takes the config from the user data.
metadata _cloud
```

| Line | Means |
| --- | --- |
| `listen tcp/PORT...` | a TCP port the machine serves |
| `metadata USER...` | a user who may reach the metadata server |

The build compiles them, users to uids from the image's own
`/etc/passwd`, into `/usr/share/werewolf/net`, one entry a line:

```
listen tcp 22
metadata 68
```

A line it cannot compile fails the build. The file is in the read-only
image, and with verified boot it is signed with the rest. It is the one
place the machine's ports are written down: the checks and `posture` read
it too.

When services declare themselves in service files (shell-free.md), their
`listen` lines join the form's: the machine-wide set is their union, and
each service's jail narrows it to the service's own.

## Enforcement

init's last step is `exec /usr/lib/werewolf/fence /usr/bin/runit`. As root,
fence reads the policy and then:

1. **Routes the metadata server away.** It adds policy-routing rules, for
   IPv4 and IPv6: for each allowed uid, TCP to the metadata server's port
   80 is routed as usual; after those, the same is refused
   (`FR_ACT_PROHIBIT`), so `connect()` fails at once with EACCES. The
   addresses are 169.254.169.254, which every cloud uses, and
   fd00:ec2::254, AWS's IPv6 one. UDP and other ports to them are left
   alone: on GCP the same address is the DNS server DHCP hands out.
2. **Binds only declared ports.** It restricts itself with Landlock: a
   ruleset handling only `BIND_TCP`, allowing the policy's ports. Port 0
   is not allowed: bind(0) and listen() would serve on a port the kernel
   picked. A client connecting without binding, as clients do, is
   untouched.
3. **Becomes runit.** Landlock's restriction is inherited by every process
   that follows and cannot be lifted, by root or anyone, until reboot.

It logs one line, and fails closed: a step that fails exits 1, init is
PID 1, the kernel panics, and the machine comes back on the slot that last
worked.

```
fence: {"time":"2026-10-06T17:13:39Z","event":"fence","listen":[22],"metadata":[]}
```

Binding is the right place to enforce what a machine serves: the kernel
already refuses packets for ports nothing listens on, so allowing only
declared ports to be bound is a default-deny inbound policy, without
inspecting packets or tracking connections, and costs nothing per packet.

## Order with the seal

The routing rules can be deleted by anyone holding `CAP_NET_ADMIN`. The
seal (lockdown.md) drops it from every process but the DHCP client's
parent, whose seccomp filter allows no netlink. So the seal goes after
fence's netlink step and before runit starts anything. Landlock needs
nothing from the seal.

## Tested

Under QEMU, on aarch64:

- `nc -l -p 4444` and `nc -l` as root, on the cloud and sshd forms:
  `bind: Permission denied`.
- sshd on the sshd form: listening on 22, over IPv4 and IPv6, and reached
  from the host.
- `wget http://169.254.169.254/...` as root: `Permission denied`, at once.
- The same as `_cloud`: answered. UDP to 169.254.169.254:53: sent.
- An outgoing connection elsewhere: made.

## Not covered

- **UDP.** Landlock in Linux 6.18 has rules for TCP only. Nothing werewolf
  runs listens on UDP; a process that would must be stopped by the seal
  until Landlock's UDP rules land upstream.
- **listen() without bind().** The kernel then picks a port, and Landlock
  sees no bind. Closing it needs Landlock's proposed listen right, or a
  packet filter.
- **Raw and packet sockets** bypass both: they need `CAP_NET_RAW`, which
  the seal drops for all but the DHCP client's allowance.
- **Where services connect**, beyond the metadata server, is each
  service's jail's business (shell-free.md), by port.

## Alternatives considered

- **BPF socket hooks** (cgroup `bind4/6`, `connect4/6`). Per-process and
  exact, and permanent once the seal forbids `bpf()`, but `bpf()` must be
  open at boot for werewolf's own programs, and BPF is what the seal is
  meant to shut.
- **nftables.** A real packet filter, but about 1 MB of userland and
  kernel modules, and inbound default-deny needs connection tracking,
  which costs memory and work on every packet.
