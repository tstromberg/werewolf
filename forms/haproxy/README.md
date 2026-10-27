# HAProxy - Hardened VM

[HAProxy](https://www.haproxy.org) 3.4 balances HTTP across backends you name, on one
leash. The form's manifest is [form.yaml](form.yaml).

[Images, test status and download
instructions](https://dist.werewolf-linux.org/boot/v1/haproxy/index.html).

## Security Posture

- HAProxy runs as its own user. The root is read-only. There is no control socket.
- A request is sent to the next backend that answers. `X-Forwarded-For` is added.
- A certificate serves HTTPS on port 443, and port 80 redirects to it. Without one,
  only port 80 answers.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
howl create haproxy --with haproxy --backends 127.0.0.1:8080
```

`--health PATH` checks with `GET PATH`. Without it, a TCP connect is enough. Backends
are names or IPv4 addresses, on port 80, 443, or 8080. Configuration is in [HAProxy's
documentation](https://docs.haproxy.org/).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
howl create haproxy --with haproxy --on gcp --allow-from me --backends 10.0.0.5:8080
```

`--allow-from me` admits your address to ports 80 and 443. Add `--tls-cert FILE
--tls-key FILE` for HTTPS.

### Importing data

This machine starts empty. What it must remember is in the create command. There is
no database to import.

### Known Quirks

- Several backends are a comma-separated list: `10.0.0.5:8080,10.0.0.6:8080`.

### Network Exposure

- listen: tcp/80 *
- listen: tcp/443 *
- connect: tcp/80 global
- connect: tcp/443 global
- connect: tcp/8080 global
