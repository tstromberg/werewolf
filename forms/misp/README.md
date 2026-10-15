# MISP - Hardened VM

Threat intelligence: [MISP](https://www.misp-project.org/) 2.5, its core, behind Caddy,
with MariaDB and Valkey. The form's manifest is [form.yaml](form.yaml).

[Images, test status and download
instructions](https://dist.werewolf-linux.org/boot/v1/misp/index.html).

## Security Posture

- PHP listens on loopback. Caddy is what the network sees. FastCGI is not published, and
  the supervisor control port is not open.
- The image's published passwords are not set: not `example`, not `redispassword`, not
  `passphrase`, not `supervisor`. Cake's published salt is replaced on the machine.
- The administrator password is the config's. The email is the setting's, not
  `admin@admin.test`.
- MariaDB and Valkey listen on loopback. Only this service may connect. Valkey has no
  password because nothing else can open the port.
- The image's bash runs one script, then misp-serve. That program starts PHP and one of
  each worker. The list is the binary. There is no Python and no supervisor socket. The
  host has no shell.
- Modules are not on this machine, and the process cannot reach them.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
openssl rand -base64 18 >admin-password
howl create misp --with misp \
	--domain misp.home.arpa \
	--base-url https://misp.home.arpa --admin-email admin@misp.home.arpa \
	--admin-password admin-password
```

Open `https://misp.home.arpa` and sign in as `admin@misp.home.arpa`. The password is in
`admin-password`. Give the machine 6 GB. Events and feeds are in [MISP's
documentation](https://www.misp-project.org/documentation/).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -base64 18 >admin-password
howl create misp --with misp --on gcp --allow-from me \
	--domain misp.example.com \
	--base-url https://misp.example.com --admin-email admin@misp.example.com \
	--admin-password admin-password
```

Point the name at the machine. Feeds are fetched from public addresses on 80 and 443.

### Importing data

The database starts empty. This form does not import a MISP dump.

### Known Quirks

- The database password is `misp`. It is not a secret, and it is not `example`.
- Twelve characters at least. A GPG key is made once, on `/data`. The passphrase is not
  put in the environment.
- MISP modules are not started. rsyslog is not started. A worker exiting restarts the
  service.

### Network Exposure

- listen: tcp/80 tcp/443 *
- connect: tcp/80 tcp/443 * and udp/53 tcp/53 *
