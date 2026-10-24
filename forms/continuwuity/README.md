# Continuwuity - Hardened VM

A [Matrix](https://matrix.org) homeserver: [Continuwuity](https://continuwuity.org),
behind Caddy. The form's manifest is [form.yaml](form.yaml).

[Images, test status and download
instructions](https://dist.werewolf-linux.org/boot/v1/continuwuity/index.html).

## Security Posture

- Continuwuity and Caddy run as their own users. The root is read-only.
- Continuwuity listens on loopback. The public ports are Caddy's.
- Registration is closed. The administrator is created from the config, once.
- Federation reaches other servers on ports 443 and 8448. URL previews, the terminal
  admin console and Brotli/Zstd HTTP compression are omitted from the package.
- RocksDB keeps its storage codecs for existing data. Embedded static assets retain
  a separate pure-Rust Brotli implementation.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
openssl rand -base64 24 >admin-password
howl create continuwuity --with continuwuity \
	--domain matrix.home.arpa --admin alice --admin-password admin-password
```

Point a Matrix client at `https://matrix.home.arpa` and sign in as `alice`. Clients are
in [Matrix's documentation](https://matrix.org/ecosystem/clients/).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -base64 24 >admin-password
howl create continuwuity --with continuwuity --on gcp --allow-from me \
	--domain matrix.example.com --admin alice --admin-password admin-password
```

`--allow-from me` admits your address to ports 80 and 443. Point the name at the machine
before you create it. The name is the server name in every user id.

### Importing data

The database is RocksDB in `/data`. This form does not import one. Rooms already on
other servers are joined from a client after this one is up.

### Known Quirks

- The server name is stored in the database. A different name needs a new disk.
- The password file has no newline. A trailing newline is ignored.
- Further accounts are made from the admin room, not by registering.

### Network Exposure

- listen: tcp/80 *
- listen: tcp/443 *
- connect: tcp/443 global
- connect: tcp/8448 global
