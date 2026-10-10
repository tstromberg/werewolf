# Grafana

Dashboards and alerts: [Grafana](https://grafana.com) 13, from Grafana's own image, behind Caddy.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
mkdir -p config/grafana
openssl rand -base64 24 >config/grafana/admin-password
howl create dash --with grafana --on lima --config config \
	--base-url https://grafana.home.arpa
```

Sign in as `admin`. The password creates that user once, when the database is new. Change it later in Grafana.

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
mkdir -p config/grafana
openssl rand -base64 24 >config/grafana/admin-password
howl create dash --with grafana --on gcp --allow-from 0.0.0.0/0 \
	--config config --base-url https://grafana.example.com
```

Point the name at the machine. Add data sources and users in Grafana's own pages. On one machine, `--with grafana,prometheus` puts Prometheus at `127.0.0.1:9090`.

A key encrypts the credentials Grafana stores for data sources. The form makes one before the first start and keeps it at `/data/svc/grafana/secret-key`. To keep it across a new disk, put the same bytes in `config/grafana/secret-key`. A different key makes stored credentials unreadable.

### Known Quirks

- Sign-up and anonymous access are off. Usage reports and update checks are off.
- There is no plugin install from the network. A plugin is a program.
- The image is pinned by digest at each build, so a Grafana release follows the next machine image.
- Give the machine a couple of gigabytes. The first start migrates its database.

### Network Exposure

- tcp/80 and tcp/443, Caddy. Grafana is on loopback, and may reach Prometheus or Loki on the machine and HTTPS for a data source you add.
