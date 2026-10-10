# cloudflared - Hardened VM

A machine that serves hostnames on the Internet with no port open to it: [cloudflared](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/). The form's manifest is [form.yaml](form.yaml).

## Security Posture

cloudflared runs as its own user. There is no shell. Landlock and seccomp hold it to Cloudflare's edge and to the origins its tunnel names. The root is read-only. Nothing listens on the network.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
printf '%s' 'eyJhIjoi...' >token
howl create cloudflared --with cloudflared --tunnel-token token
```

The token is a remotely managed tunnel, from the Cloudflare dashboard. It names the hostnames and the origins. Replace the placeholder before you create the machine. The token is an environment variable, not a file the service can read.

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
printf '%s' 'eyJhIjoi...' >token
howl create cloudflared --with cloudflared --on gcp --allow-from me --tunnel-token token
```

`--allow-from` opens no port: there is no listener. The tunnel connects out.

### Migrating data in

This machine starts empty. The tunnel's hostnames live in the Cloudflare dashboard, with the token. There is no database to import.

### Known Quirks

- `--no-autoupdate` is set. A new cloudflared arrives with the machine's next image.
- Metrics answer on loopback port 2000, and nowhere else.
