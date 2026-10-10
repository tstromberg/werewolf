# Grafana

Dashboards and alerts: [Grafana](https://grafana.com) 13, from Grafana's own image, behind Caddy. The form's manifest is [form.yaml](form.yaml).

## Security Posture

The service runs as its own user. Landlock and seccomp hold it to the files and ports its manifest names. The root is read-only. An update replaces the image, and `/data` is what survives.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
mkdir -p config/grafana
openssl rand -base64 24 >config/grafana/admin-password
howl create grafana --with grafana --config config \
	--base-url https://grafana.home.arpa
```

Open `https://grafana.home.arpa` and sign in as `admin`. The password is in `config/grafana/admin-password`. It creates that user once, when the database is new. Data sources are in [Grafana's documentation](https://grafana.com/docs/grafana/latest/datasources/).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
mkdir -p config/grafana
openssl rand -base64 24 >config/grafana/admin-password
howl create grafana --with grafana --on gcp --allow-from me \
	--config config --base-url https://grafana.example.com
```

Sign in at `https://grafana.example.com`. On one machine, `--with grafana,prometheus` puts Prometheus at `127.0.0.1:9090`. A key encrypts stored data-source credentials. The form makes one at `/data/svc/grafana/secret-key`. To keep it across a new disk, put the same bytes in `config/grafana/secret-key`.

### Migrating data in

The database is SQLite in `/data`, and the host cannot write that directory. After the site is up, import a dashboard's JSON in the UI. History before that stays on the old server.

### Known Quirks

- Sign-up and anonymous access are off. Usage reports and update checks are off.
- There is no plugin install from the network. A plugin is a program.
- The image is pinned by digest at each build, so a Grafana release follows the next machine image.
- Give the machine a couple of gigabytes. The first start migrates its database.

### Network Exposure

- tcp/80 and tcp/443, Caddy. Grafana is on loopback, and may reach Prometheus or Loki on the machine and HTTPS for a data source you add.
