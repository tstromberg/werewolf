# Gatus - Hardened VM

A status page for one service: [Gatus](https://gatus.io) 5. The form's manifest is [form.yaml](form.yaml).

## Security Posture

Gatus runs as its own user. There is no shell. Landlock and seccomp hold it to port 8080 and to `/data/svc/gatus`. The root is read-only.

- The page and its API are read-only. A write is refused.
- There is no login. Put Caddy, oauth2-proxy or a tailnet in front before you show the page past this machine.
- The Prometheus endpoint is off. It would tell anyone what is watched.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
howl create gatus --with gatus --target https://www.example.com/
```

Open `http://ADDRESS:8080`. Gatus asks the target every 60 seconds for a 200 within 2 seconds. History is in `/data/svc/gatus/data.db`. Endpoints and alerts are in [Gatus's documentation](https://gatus.io/).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
howl create gatus --with gatus --on gcp --allow-from me --target https://www.example.com/
```

`--allow-from me` admits your address to port 8080.

### Migrating data in

This machine starts empty. What it watches is `--target`. The history on the old server stays there. There is no database to import.

### Known Quirks

- More endpoints are a form of your own, with its `etc/gatus/config.yaml` over this one.

### Network Exposure

tcp/8080
