# Service forms

Proposed, 2026-10-07. Built: `caddy`, `valkey`, `openbao`, `step-ca`,
`wordpress`, `bastion` and `tailscale` (forms/NAME/README.md). `haproxy`,
`mariadb`, `wordpress-mariadb`, `unbound` and `wireguard` wait (below).
What follows them is [forms-catalog.md](forms-catalog.md).

## Summary

Forms for the services people most want on a machine that is hard to take
over. Each is `prod` (or a runtime form) plus one Wolfi package, run by
leash as its own user, with the safest defaults that leave it usable and
a check that tries the attack those defaults stop.

## Background

The runtime forms ([docs/forms.md](../forms.md)) run one application.
Daemons that hold keys, peers and data needed more: leash's `config`
lines and settings ([settings.md](settings.md)), and an `answering` check
for any protocol, both built; and two things still open:

- **UDP listeners.** fence and the build take `listen tcp` alone; unbound
  needs udp/53, wireguard udp/51820. Landlock cannot restrict a UDP bind,
  so fence's routing rules would be the whole guard.
- **Packages that bring a shell.** Wolfi's haproxy, unbound and mariadb
  ship bash and perl scripts that no form runs. `prune` drops a shell a
  dependency drags in ([docs/forms.md](../forms.md#files-a-form-leaves-out));
  a package's own scripts wait for Wolfi to split them out, as Chainguard
  does for `-oci-entrypoint`.

## Goals

- Each form passes posture, or fails only what its `weaknesses` excuse,
  and its check tries the attack its defaults are for.

## Non-Goals

- Vault (Wolfi's is 1.14.1, the last MPL release; OpenBao is its fork),
  and MySQL (MariaDB, below).
- Clustering, and MariaDB or Valkey serving other machines.

## Detailed design

**Defaults, for every form**: as secure as the common case allows; where
stricter would break what most run (a DNS server on every address, a
WordPress sending mail), stricter is a line in the form.

- **No unclaimed first boot**: installers and OpenBao's `init` run from
  the config before the service serves.
- **A missing secret parks the service** with one line naming the file:
  no self-signed certificate or default password. What the machine can
  make itself (a host key, an ACME certificate) is made once on `/data`.
- **State wants a disk**, but runs without one. Open: a console line on a
  RAM `/data` saying what a reboot loses. bastion stays down instead.
- **No control interface on the network** (off, or a 0700 socket), and
  **no `exec` promise** but for a daemon's own helpers, named by `run`
  (bastion's sshd); `make seal-learn` finds the rest of each pledge.
- **Its own ceiling under `memory`**, so it refuses work rather than dying.
- **Modern TLS** (1.2 at least), **security events on the console**, and
  **a check with an attack in it**.

**The forms that wait**, what each decides, and what it waits on:

| Form | Decides | Waits on |
| --- | --- | --- |
| `haproxy` | `-db`, no master-worker (its reloads re-execute haproxy); no external checks, Lua or stats socket; timeouts 5s connect, 30s client and server, 10s `http-request`, 1h `tunnel`; `del-header Proxy` (httpoxy); `maxconn` from its memory; `-nocaps`, as leash grants low ports | Wolfi splitting out `haproxy-dump-certs` and `haproxy-reload` |
| `unbound` | recursive and validating on every address, answering only loopback, RFC 1918, 100.64/10, ULA and link-local: no open resolver; no `private-address`, which breaks internal names in public DNS; a cloud's private zones by `forward-zone`; the trust anchor seeded from the image into `/data` (RFC 5011), since `unbound-anchor` needs the network first | `listen udp`; Wolfi splitting out `unbound-control-setup` |
| `mariadb` | 11.8, an LTS into 2028: Wolfi's MySQL is short-lived Innovation releases, whose one-way data-dictionary upgrades would leave a rolled-back slot unable to read its data; a new major is a new form. As `postgresql`: a socket, roles by `unix_socket`, `local_infile=0`, an empty `secure_file_priv`, no `FILE`, `SUPER` or `PROCESS` for applications | Wolfi splitting out its scripts; a Zig `mariadb-init`, as `pg-init`, in their place |
| `wordpress-mariadb` | `wordpress` `with` `mariadb`; a `db.php` that does nothing over SQLite's, since a form cannot remove a file; role `php` by `unix_socket`, all on its database, no `FILE` | `mariadb` |
| `wireguard` | the kernel's module, set up from `/run/config/wireguard/wg0.conf` by a Zig `wireguard-up` that init runs before fence, with `CAP_NET_ADMIN`; overlapping `AllowedIPs` refused, as they misroute a peer's traffic; fence forwards from `wg0` to declared networks (the tunnel's own only if peers may reach each other); no NAT, as fence uses no netfilter | `listen udp`; a `forward` allowance, since init sets `ip_forward=0`; forwarding rules in fence |

## Drawbacks

- fence names users, ports and `public`, not networks: bastion, haproxy,
  tailscale and WordPress's mail rely on their own destination lists.
- Open: which to publish. `tailscale` and `wireguard` need only config.

## Alternatives Considered

- **Fragments the daemon includes from `/run/config`**: the config tar
  would author the whole configuration, `PermitOpen any` included.
  Settings replaced them ([settings.md](settings.md)).
- **Cloud SSH keys for the bastion**: anyone with GCP's `setMetadata`
  could add a key at runtime; OS Login needs Google's NSS and PAM.
- **A kernel-routed Tailscale**: a tun device needs `CAP_NET_ADMIN`.
  Userspace networking keeps `tailscaled` a leashed user fence judges.

## Security Considerations

- An exploited daemon meets its own user, Landlock, its pledge, no shell
  and a read-only root; admin APIs are off or on a 0700 socket.
- Whoever holds the config tar can unseal OpenBao: the trust the tar
  already holds for `data.key`.

## Reliability Considerations

- werewolf reboots into every update: hence OpenBao's static seal, and
  MariaDB's LTS, so a rolled-back slot still reads the `/data` both share.
