# Headscale - Hardened VM

A coordination server for Tailscale's clients, run by you:
[Headscale](https://github.com/juanfont/headscale) 0.29, behind Caddy. The form's
manifest is [form.yaml](form.yaml).

[Images, test status and download
instructions](https://dist.werewolf-linux.org/boot/v1/headscale/index.html).

## Security Posture

- The service runs as its own user, held to the files and ports its manifest names. The
  root is read-only. `/data` is what survives.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
howl create headscale --with headscale \
	--base-url https://hs.home.arpa
```

On a device, `tailscale up --login-server https://hs.home.arpa`. The node waits until
you approve it, or until you issue a pre-auth key. Caddy's own CA signs `.home.arpa`;
the device must trust that CA. Nodes and keys are in [Headscale's
documentation](https://headscale.net/stable/).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
howl create headscale --with headscale --on gcp --allow-from me \
	--base-url https://hs.example.com
```

Point `hs.example.com` at the address howl prints. Devices use `https://hs.example.com`
as the login server. OpenID, instead of approval, is a set of files under
`config/headscale/` passed with `--config`:

```text
mkdir -p config/headscale
echo https://accounts.example.com >config/headscale/oidc-issuer
echo headscale >config/headscale/oidc-client-id
openssl rand -base64 24 >config/headscale/oidc-client-secret
echo 'me@example.com' >config/headscale/oidc-allowed-users
howl create headscale --with headscale --on gcp --allow-from me \
	--config config --base-url https://hs.example.com
```

The OpenID client must allow `https://hs.example.com/oidc/callback`.

### Importing data

The database is in `/data`, and the host cannot write that directory. The network starts
empty. A node joins again with this machine's address. This form does not import a
Headscale database.

### Known Quirks

- gRPC and metrics are off. Clients use the one HTTPS port.
- The database and the keys are in `/data/svc/headscale`.
- Headscale fetches Tailscale's DERP map over HTTPS, so relayed connections work without
  you running a relay.
- A new Headscale release follows the next image. This form is 0.29.

### Network Exposure

- listen: tcp/80 *
- listen: tcp/443 *
