# Jellyfin

Your media, in a browser or an app: [Jellyfin](https://jellyfin.org) 12.2, behind Caddy. Media is copied in over ssh.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
openssl rand -base64 24 >jellyfin-password
howl create media --with jellyfin --on lima \
	--domain media.home.arpa --jellyfin-admin alice \
	--jellyfin-password jellyfin-password \
	--users.alice.keys "$(cat ~/.ssh/id_ed25519_sk.pub)" --users.alice.admin
```

The key must be a security key (`id_ed25519_sk`), except on Lima, which also takes a key file. Sign in at `https://media.home.arpa` as `alice`. The password is at least 12 bytes.

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -base64 24 >jellyfin-password
howl create media --with jellyfin --on gcp --allow-from 0.0.0.0/0 \
	--domain media.example.com --jellyfin-admin alice \
	--jellyfin-password jellyfin-password \
	--users.alice.keys "$(cat ~/.ssh/id_ed25519_sk.pub)" --users.alice.admin
```

Point the name at the machine, then copy the files. An admin's keys are also root's:

```sh
scp -r Movies root@media.example.com:/data/svc/jellyfin/media/
```

The library `Media` is that directory. Jellyfin scans it on its schedule, or at once from the dashboard.

### Known Quirks

- The setup wizard is finished before anyone can open the site.
- There is no shell you can type into for everyday use. ssh is there to copy files.
- Jellyfin does not fetch metadata from the internet.
- Transcoding is on the CPU. There is no GPU.

### Network Exposure

- tcp/80 and tcp/443, Caddy. tcp/22, ssh, for the people named in `--users`.

### Security Weaknesses

- ssh brings a small set of tools, including a shell, for the people who log in. .NET runs Jellyfin and compiles it as it runs. All of that is named in `form.yaml`.
