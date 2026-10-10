# Syncthing

Folders kept in sync with your other devices: [Syncthing](https://syncthing.net) 2.1, from its own image, the web interface behind Caddy.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
openssl rand -base64 24 >gui-password
howl create sync --with syncthing --on lima \
	--gui-user alice --gui-password gui-password
```

Without `--base-url`, Caddy serves the interface as plain HTTP on port 80. Use that only on a LAN or a tailnet: the password crosses the wire. The password is 12 to 72 bytes.

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -base64 24 >gui-password
howl create sync --with syncthing --on gcp --allow-from 0.0.0.0/0 \
	--base-url https://sync.example.com \
	--gui-user alice --gui-password gui-password
```

Point the name at the machine. Sign in as `alice`, add your other devices by their IDs, and share folders. New folders go under `/var/syncthing`, which is on `/data`.

### Known Quirks

- The interface can share any folder with anyone. Caddy lets in only the one user you named, and Syncthing itself listens on loopback.
- Local discovery and UPnP are off. Devices find each other through Syncthing's global discovery and relays, unless you set `--global-discovery false` or `--relays false`.
- Usage reports are off.
- QUIC uses UDP port 22000 beside TCP 22000. Open both.

### Network Exposure

- tcp/22000 and udp/22000, Syncthing, for your devices. tcp/80 and tcp/443, Caddy, for the interface.
