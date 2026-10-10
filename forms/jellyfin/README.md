# Jellyfin

Your media, in a browser or an app: [Jellyfin](https://jellyfin.org) 12.2, behind Caddy. Media is copied in over ssh. The form's manifest is [form.yaml](form.yaml).

## Security Posture

The service runs as its own user. Landlock and seccomp hold it to the files and ports its manifest names. The root is read-only. An update replaces the image, and `/data` is what survives.

- ssh brings a small set of tools, including a shell, for the people who log in. .NET runs Jellyfin and compiles it as it runs. All of that is named in `form.yaml`.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
openssl rand -base64 18 >jellyfin-password
howl create jellyfin --with jellyfin \
	--domain media.home.arpa --jellyfin-admin alice \
	--jellyfin-password jellyfin-password
```

Open `https://media.home.arpa` and sign in as `alice`. The password is in `jellyfin-password`. Copying media needs a security key, which a script cannot mint. Make one with `ssh-keygen -t ed25519-sk` and pass it:

```text
howl create jellyfin --with jellyfin \
	--domain media.home.arpa --jellyfin-admin alice \
	--jellyfin-password jellyfin-password \
	--users.alice.keys "$(cat ~/.ssh/id_ed25519_sk.pub)" --users.alice.admin
```

A key file is refused until `--sshd.pubkey-accepted-algorithms=ssh-ed25519,sk-ssh-ed25519@openssh.com`, and that is a posture weakness. Libraries are in [Jellyfin's documentation](https://jellyfin.org/docs/).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -base64 18 >jellyfin-password
howl create jellyfin --with jellyfin --on gcp --allow-from me \
	--domain media.example.com --jellyfin-admin alice \
	--jellyfin-password jellyfin-password
```

Sign in at `https://media.example.com`. Add `--users.NAME.keys` with a security key, and `--users.NAME.admin`, before you copy files. An admin key is also root's:

```text
scp -i ~/.ssh/id_ed25519_sk -r Movies root@media.example.com:/data/svc/jellyfin/media/
```

The library `Media` is that directory. Jellyfin scans it on its schedule, or at once from the dashboard.

### Migrating data in

Media comes in over the ssh this form publishes, as the cloud section shows. There is no database dump, and `--import` does not carry media.

### Known Quirks

- The setup wizard is finished before anyone can open the site.
- There is no shell you can type into for everyday use. ssh is there to copy files.
- Jellyfin does not fetch metadata from the internet.
- Transcoding is on the CPU. There is no GPU.

### Network Exposure

- tcp/80 and tcp/443, Caddy. tcp/22, ssh, for the people named in `--users`.
