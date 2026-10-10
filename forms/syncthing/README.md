# Syncthing

Folders kept in sync with your other devices: [Syncthing](https://syncthing.net) 2.1, from its own image, the web interface behind Caddy. The form's manifest is [form.yaml](form.yaml).

## Security Posture

The service runs as its own user. Landlock and seccomp hold it to the files and ports its manifest names. The root is read-only. An update replaces the image, and `/data` is what survives.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
openssl rand -base64 18 >gui-password
howl create syncthing --with syncthing \
	--base-url https://sync.home.arpa \
	--gui-user alice --gui-password gui-password
```

Open `https://sync.home.arpa` and sign in as `alice`. The password is in `gui-password`. Devices and folders are in [Syncthing's documentation](https://docs.syncthing.net/). On a LAN that should stay plain HTTP, leave `--base-url` out and open `http://ADDRESS/`:

```text
howl create syncthing --with syncthing \
	--gui-user alice --gui-password gui-password
```

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -base64 18 >gui-password
howl create syncthing --with syncthing --on gcp --allow-from me \
	--base-url https://sync.example.com \
	--gui-user alice --gui-password gui-password
```

Sign in at `https://sync.example.com` as `alice`. Add your other devices by their IDs, and share folders. New folders go under `/var/syncthing`, which is on `/data`.

### Migrating data in

The other devices already hold the files. Add this machine to the folder after it is up. There is no dump to copy in.

### Known Quirks

- The interface can share any folder with anyone. Caddy lets in only the one user you named, and Syncthing itself listens on loopback.
- Local discovery and UPnP are off. Devices find each other through Syncthing's global discovery and relays, unless you set `--global-discovery false` or `--relays false`.
- Usage reports are off.
- QUIC uses UDP port 22000 beside TCP 22000. Open both.

### Network Exposure

- tcp/22000 and udp/22000, Syncthing, for your devices. tcp/80 and tcp/443, Caddy, for the interface.
