# Greenbone - Hardened VM

Vulnerability management: [Greenbone](https://greenbone.github.io/docs/) gvmd and gsad, the scanner, and the community feed, behind Caddy, with PostgreSQL and Valkey. The form's manifest is [form.yaml](form.yaml).

## Security Posture

- gsad listens on loopback. Caddy is what the network sees. The scanner listens on loopback for gvmd.
- The administrator is `admin`. The password is the config's, applied at every start. `admin` / `admin` is refused.
- gvmd's socket is mode 0660, group `_oci-gvmd`. gvm-link keeps that group after it drops to `_glink`. The socket it gives gsad is mode 0660, group `_oci-gsad`. A command on it still needs the administrator password.
- The scanner is the one service that keeps `CAP_NET_RAW` and `CAP_NET_ADMIN`. gvmd, gsad, the feed, Valkey, PostgreSQL and Caddy do not.
- The feed cache is `/data/share/gvm`, owned by the feed, mode 02750. gvmd is in that group and may only read it. The scanner may write the plugin directory and only read the rest. Nothing else on the machine is in the group.
- PostgreSQL takes one role, over loopback. The scanner's routing prohibits its loopback except Valkey, so it cannot open that port.
- The image's bash runs one script, then the program. The host has no shell. rsync and Python stay inside the feed and scanner images.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
openssl rand -base64 18 >admin-password
howl create greenbone --with greenbone \
	--domain scan.home.arpa --admin-password admin-password
```

Open `https://scan.home.arpa` and sign in as `admin`. The password is in `admin-password`. Give the machine 8 GB. The feed cache is several gigabytes and the first sync takes a long time; the UI is up while it runs. Tasks and targets are in [Greenbone's documentation](https://greenbone.github.io/docs/).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -base64 18 >admin-password
howl create greenbone --with greenbone --on gcp --allow-from me \
	--domain scan.example.com --admin-password admin-password
```

Sign in at `https://scan.example.com`. A scan from this machine reaches the targets you name, including private addresses. Replies come back to the machine's own local ports. Its service ports stay closed unless this form listens on them.

### Importing data

The database starts empty. The feed fills the cache on `/data` from the community server. This form does not import a Greenbone dump.

### Known Quirks

- gvmd listens on a Unix socket, not a TCP port. gvm-link, as `_glink` in the group `_oci-gvmd`, copies it into gsad's directory. Both sockets are mode 0660.
- The scanner's socket is mode 0770 inside its own directory. gvmd uses loopback TCP, not that socket.
- The first feed sync is large. An 8 GiB disk is tight once PostgreSQL and the cache share it. A later sync keeps the last good copy when the server is unreachable.
- The database password is not a secret: the scanner cannot open the port, and no other leash names it.
- Twelve characters at least, and not `admin`.

### Network Exposure

- listen: tcp/80 tcp/443 *
- connect: the scanner, any TCP port, so a scan can reach a target; the feed, public tcp/873; the resolver
