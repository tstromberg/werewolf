# Loki - Hardened VM

[Grafana Loki](https://grafana.com/oss/loki/) takes logs over HTTPS. Caddy checks the
user and the password, then proxies to Loki on loopback. The form's manifest is
[form.yaml](form.yaml).

[Images, test status and download
instructions](https://dist.werewolf-linux.org/boot/v1/loki/index.html).

## Security Posture

- Loki and Caddy run as their own users. The root is read-only.
- The password is a file. It is not a flag, and it is not in the image.
- Loki listens on loopback. The only public ports are Caddy's.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
openssl rand -base64 24 >loki-password
howl create loki --with loki --domain logs.home.arpa --loki-user alloy --loki-password loki-password
```

Point a client at `https://logs.home.arpa` with that user and the password file.
Pushing logs is in [Loki's
documentation](https://grafana.com/docs/loki/latest/send-data/).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -base64 24 >loki-password
howl create loki --with loki --on gcp --allow-from me \
	--domain logs.example.com --loki-user alloy --loki-password loki-password
```

`--allow-from me` admits your address to ports 80 and 443. Use a name you control,
and point it at the machine.

### Importing data

This machine starts empty. History stays on the old server. There is no database to
import.

### Known Quirks

- The user is `--loki-user`. The password file has no newline requirement beyond what
  Caddy reads.
- Logs land on `/data`. An update replaces the image and keeps that disk.

### Network Exposure

- listen: tcp/80 *
- listen: tcp/443 *
