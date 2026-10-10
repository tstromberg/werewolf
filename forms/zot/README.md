# zot

A registry for your own container images: [zot](https://zotregistry.dev) 2.1, behind Caddy. Everyone who is named can pull. Only the users you list can push or delete. The form's manifest is [form.yaml](form.yaml).

## Security Posture

The service runs as its own user. Landlock and seccomp hold it to the files and ports its manifest names. The root is read-only. An update replaces the image, and `/data` is what survives.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
openssl rand -base64 18 >ci-password
htpasswd -nbB ci "$(cat ci-password)" >htpasswd
howl create zot --with zot \
	--domain registry.home.arpa --htpasswd htpasswd --pushers ci
```

`docker login registry.home.arpa -u ci`, with the password in `ci-password`. Push and pull are in [zot's documentation](https://zotregistry.dev/latest/user-guides/user-guide/).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -base64 18 >ci-password
openssl rand -base64 18 >deploy-password
htpasswd -nbB ci "$(cat ci-password)" >htpasswd
htpasswd -nbB deploy "$(cat deploy-password)" >>htpasswd
howl create zot --with zot --on gcp --allow-from me \
	--domain registry.example.com --htpasswd htpasswd --pushers ci
```

Sign in at `registry.example.com`. `ci` pushes; `deploy` only pulls. Add a line and run create again to add a user. Images on `/data` stay.

### Migrating data in

This machine starts empty. Push images to the address howl prints. There is no registry to copy in.

### Known Quirks

- Anonymous pull and push are refused, including from the machine itself.
- Caddy serves `/v2/` and nothing else.
- zot cannot open a connection of its own.
- One copy of each blob is kept.

### Network Exposure

- tcp/80 and tcp/443, Caddy. zot is on loopback.
