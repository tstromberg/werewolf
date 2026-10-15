# DFIR-IRIS - Hardened VM

Case management: [DFIR-IRIS](https://docs.dfir-iris.org/) 2.4, behind Caddy, with
PostgreSQL. The form's manifest is [form.yaml](form.yaml).

[Images, test status and download
instructions](https://dist.werewolf-linux.org/boot/v1/iris/index.html).

## Security Posture

- The web server listens on loopback. Caddy is what the network sees.
- The administrator is `administrator`. The password is the config's, not a published
  one.
- The secret key is generated on the machine, into `/data`, the first time it starts.
- PostgreSQL takes one role, over loopback, and only this service may connect.
- The image's bash runs one script, then gunicorn. The host has no shell.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
openssl rand -base64 18 >admin-password
howl create iris --with iris \
	--domain iris.home.arpa --admin-password admin-password
```

Open `https://iris.home.arpa` and sign in as `administrator`. The password is in
`admin-password`. Give the machine 2 GB. Cases are in [DFIR-IRIS's
documentation](https://docs.dfir-iris.org/).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -base64 18 >admin-password
howl create iris --with iris --on gcp --allow-from me \
	--domain iris.example.com --admin-password admin-password
```

Sign in at `https://iris.example.com`. There is no sign-up.

### Importing data

The database starts empty. This form does not import a case export.

### Known Quirks

- The schema is migrated before the server listens. A migration that fails does not
  serve.
- The administrator password is applied at every start, from the file.
- Background modules do not run. This machine is the web server.
- The database password is not a secret: only this service can open the port.
- Twelve characters at least, and not `admin`.

### Network Exposure

- listen: tcp/80 tcp/443 *
- connect: udp/53 tcp/53 *
