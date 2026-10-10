# NATS - Hardened VM

A message bus, with JetStream for what must be kept: [NATS](https://nats.io) 2.15. The form's manifest is [form.yaml](form.yaml).

## Security Posture

NATS runs as its own user. There is no shell. Landlock and seccomp hold it to port 4222 and to `/data/svc/nats`. The root is read-only.

- Nothing anonymous, and nothing plain. Clients use TLS.
- There are no routes, leaf nodes or gateways.
- Monitoring answers on loopback port 8222, and nowhere else.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
umask 077
mkdir -p config/nats
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 365 \
	-subj /CN=nats.home.arpa -keyout config/nats/tls.key -out config/nats/tls.crt
howl create nats --with nats --config config
```

`config/nats/users.conf` is an `authorization` block: each user, a bcrypt password (`htpasswd -nbB`), and the subjects that user may publish and subscribe to. Without it the server stays down. Clients use `tls://ADDRESS:4222`. JetStream is in [NATS's documentation](https://docs.nats.io/).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
umask 077
mkdir -p config/nats
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 365 \
	-subj /CN=nats.example.com -keyout config/nats/tls.key -out config/nats/tls.crt
howl create nats --with nats --on gcp --allow-from me --config config
```

`--allow-from me` admits your address to port 4222. Use a certificate clients already trust.

### Migrating data in

The server starts empty. Clients publish to the address howl prints. This form does not import a stream. JetStream's files are in `/data/svc/nats`, at most 8 GB, and the host cannot write that directory.

### Known Quirks

- Payloads are at most 1 MB. Connections are at most 1000.

### Network Exposure

tcp/4222
