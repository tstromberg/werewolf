# Prometheus - Hardened VM

[Prometheus](https://prometheus.io) scrapes targets you name and serves its own UI. The form's manifest is [form.yaml](form.yaml).

[Images, test status and download instructions](https://dist.werewolf-linux.org/images/v1/prometheus/index.html).

## Security Posture

- Prometheus runs as its own user. The root is read-only. The TSDB is on `/data`.
- The admin password is a file. It is not a flag.
- Targets are addresses you pass. The form does not discover a network.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
openssl rand -base64 24 >metrics-password
howl create prometheus --with prometheus --targets 127.0.0.1:9090 \
	--admin grafana --admin-password metrics-password
```

Open `http://ADDRESS:9090` and sign in as `grafana`. Queries are in [Prometheus's documentation](https://prometheus.io/docs/prometheus/latest/querying/basics/).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -base64 24 >metrics-password
howl create prometheus --with prometheus --on gcp --allow-from me \
	--targets 10.0.0.5:9100 --admin grafana --admin-password metrics-password
```

`--allow-from me` admits your address to port 9090. Name each target `HOST:PORT`. Several are a comma-separated list.

### Importing data

This machine starts empty. History stays on the old server. There is no TSDB import.

### Known Quirks

- `--admin` is the user name. The password file is `--admin-password`.
- A target on this machine is `127.0.0.1:PORT`. A target elsewhere is that host's address.

### Network Exposure

- listen: tcp/9090 *
