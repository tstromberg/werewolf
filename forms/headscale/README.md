# Headscale

A coordination server for Tailscale's clients, run by you: [Headscale](https://github.com/juanfont/headscale) 0.29, behind Caddy.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
howl create tailnet --with headscale --on lima \
	--base-url https://hs.home.arpa
```

On a device, `tailscale up --login-server https://hs.home.arpa`. The node waits until you approve it. Caddy's own CA signs `.home.arpa`; the device must trust that CA.

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
mkdir -p config/headscale
echo https://accounts.example.com >config/headscale/oidc-issuer
echo headscale >config/headscale/oidc-client-id
printf '%s' 'the client secret' >config/headscale/oidc-client-secret
echo 'me@example.com you@example.com' >config/headscale/oidc-allowed-users
howl create tailnet --with headscale --on gcp --allow-from 0.0.0.0/0 \
	--config config --base-url https://hs.example.com
```

Point the name at the machine. The OpenID client must allow `https://hs.example.com/oidc/callback`. An allowed user who signs in joins as that user. Without those files, a node needs a pre-auth key or your approval. Nobody joins unasked.

### Known Quirks

- gRPC and metrics are off. Clients use the one HTTPS port.
- The database and the keys are in `/data/svc/headscale`.
- Headscale fetches Tailscale's DERP map over HTTPS, so relayed connections work without you running a relay.
- A new Headscale release follows the next image. This form is 0.29.

### Network Exposure

- tcp/80 and tcp/443, Caddy. Headscale is on loopback, and may call the DERP map and, when you configure it, your OpenID provider.
