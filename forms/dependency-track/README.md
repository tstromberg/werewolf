# Dependency-Track - Hardened VM

A bill-of-materials server: [Dependency-Track](https://dependencytrack.org) 5, the
API server and its frontend, behind Caddy, with PostgreSQL. The form's manifest is
[form.yaml](form.yaml).

[Images, test status and download
instructions](https://dist.werewolf-linux.org/boot/v1/dependency-track/index.html).

## Security Posture

- The API listens on loopback. Caddy is what the network sees.
- The published `admin` / `admin` password is replaced from the config before Caddy
  opens.
- PostgreSQL takes one role, over loopback, and only this service may connect.

### Weaknesses

- Java runs Dependency-Track, and the JVM compiles it as it runs. Both are named in
  `form.yaml`.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
openssl rand -base64 18 >admin-password
howl create dependency-track --with dependency-track \
	--domain bom.home.arpa --admin-password admin-password
```

Open `https://bom.home.arpa` and sign in as `admin`. The password is in
`admin-password`. Give the machine 3 GB. Projects and uploads are in [Dependency-Track's
documentation](https://docs.dependencytrack.org/).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -base64 18 >admin-password
howl create dependency-track --with dependency-track --on gcp \
	--allow-from me --domain bom.example.com --admin-password admin-password
```

Sign in at `https://bom.example.com`. There is no anonymous upload.

### Importing data

The database starts empty. Upload a bill of materials through the API. This form does
not import a database dump.

### Known Quirks

- The administrator password is set once. Changing the file later does not change it.
- The database password is not a secret: only this service can open the port.
- Twelve characters at least.

### Network Exposure

- listen: tcp/80 tcp/443 *
- connect: tcp/443 * and udp/53 tcp/53 *
