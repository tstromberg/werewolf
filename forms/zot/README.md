# zot

A registry for your own container images: [zot](https://zotregistry.dev) 2.1, behind Caddy. Everyone who is named can pull. Only the users you list can push or delete.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
htpasswd -nB ci >htpasswd
howl create registry --with zot --on lima \
	--domain registry.home.arpa --htpasswd htpasswd --pushers ci
```

`htpasswd -nB` is bcrypt and asks for the password. Then `docker login registry.home.arpa -u ci`.

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
htpasswd -nB ci >htpasswd
htpasswd -nB deploy >>htpasswd
howl create registry --with zot --on gcp --allow-from 0.0.0.0/0 \
	--domain registry.example.com --htpasswd htpasswd --pushers ci
```

Point the name at the machine. `ci` pushes; `deploy` only pulls. Add a line and run create again to add a user. Images on `/data` stay.

### Known Quirks

- Anonymous pull and push are refused, including from the machine itself.
- Caddy serves `/v2/` and nothing else.
- zot cannot open a connection of its own.
- One copy of each blob is kept.

### Network Exposure

- tcp/80 and tcp/443, Caddy. zot is on loopback.
