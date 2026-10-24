# Mastodon - Hardened VM

[Mastodon](https://joinmastodon.org) for one server, with PostgreSQL, Valkey, and Caddy.

The application package omits optional OpenTelemetry exporters. libvips retains
Mastodon's JPEG, PNG, GIF and WebP formats, EXIF orientation and colour conversion;
other image loaders are omitted. FFmpeg retains media codecs but accepts only
local files and pipes, without network, device, display or font integrations.
The streaming server uses hardened Node without Brotli or Zstd. Other libraries
may retain their own codecs; this is not a claim that every native dependency is
Brotli-free.
The form's manifest is [form.yaml](form.yaml).

[Images, test status and download
instructions](https://dist.werewolf-linux.org/boot/v1/mastodon/index.html).

## Security Posture

- Each program runs as its own user. The root is read-only. `/data` is what survives.
- Sign-up is closed. The owner is created once, when the database is new.
- PostgreSQL and Valkey are on UNIX sockets. The host cannot reach them.

### Weaknesses

- Ruby and Node run Mastodon, which is what this form is for.
- PostgreSQL compiles costly queries to machine code with LLVM.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
openssl rand -base64 24 >owner-password
howl create mastodon --with mastodon \
	--domain social.home.arpa --owner alice --owner-email alice@example.com \
	--owner-password owner-password
```

Open `https://social.home.arpa` and sign in as the owner. The domain is the server's
name from then on. Administration is in [Mastodon's
documentation](https://docs.joinmastodon.org/).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -base64 24 >owner-password
howl create mastodon --with mastodon --on gcp --allow-from me \
	--domain social.example.com --owner alice --owner-email alice@example.com \
	--owner-password owner-password
```

`--allow-from me` admits your address to ports 80 and 443. Point the domain at the
machine before you create it.

### Importing data

`--import` streams `*.sql` into the `postgres` database, and one `dump.rdb` into Valkey,
once, while data is first made. Media and settings files are not on that disk. A cloud
cannot attach it. Delete the machine before a second import.

```sh
howl create mastodon --with mastodon --import ./dump \
	--domain social.home.arpa --owner alice --owner-email alice@example.com \
	--owner-password owner-password
```

### Known Quirks

- Give the machine 4 GB. The first boot migrates the database.
- The owner password is a file with no newline.

### Network Exposure

- listen: tcp/80 *
- listen: tcp/443 *
