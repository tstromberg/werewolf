# Keycloak - Hardened VM

Single sign-on for a campus: [Keycloak](https://www.keycloak.org) 26.8, OpenID
Connect and SAML, with PostgreSQL and Caddy. The form's manifest is
[form.yaml](form.yaml).

[Images, test status and download
instructions](https://dist.werewolf-linux.org/boot/v1/keycloak/index.html).

## Security Posture

- The service runs as its own user, held to the files and ports its manifest names.
  The root is read-only. `/data` is what survives.

### Weaknesses

- Java runs Keycloak with native access for Infinispan's off-heap cache, scoped to
  that service. The JVM and PostgreSQL compile code as they run. These are named in
  `form.yaml`.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
mkdir -p config/keycloak
openssl rand -base64 18 >config/keycloak/admin-password
howl create keycloak --with keycloak --config config \
	--base-url https://sso.home.arpa --admin alice
```

Open `https://sso.home.arpa/admin` and sign in as `alice`. The password is in
`config/keycloak/admin-password`. Caddy's own CA signs `.home.arpa`. Realms and
clients are in [Keycloak's server
guide](https://www.keycloak.org/docs/latest/server_admin/).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
mkdir -p config/keycloak
openssl rand -base64 18 >config/keycloak/admin-password
howl create keycloak --with keycloak --on gcp --allow-from me \
	--config config --base-url https://sso.example.edu --admin alice
```

Sign in at `https://sso.example.edu/admin`. The password is in
`config/keycloak/admin-password`. Point the name at the machine with an A record.
Keycloak calls this first administrator temporary: make your own, or bring them from
your directory, then remove it. Realms, clients and a SAML federation are kept in
PostgreSQL.

### Importing data

PostgreSQL has no TCP port. `--import` attaches a directory of SQL. It is applied
once, in the `postgres` database, while the cluster is first made. See
[postgresql](../postgresql/README.md). `CREATE DATABASE` is not available there. A
cloud cannot attach the disk.

```sh
howl create keycloak --with keycloak --import ./dump
```

Files the application stores itself are not on that disk. Bring those through the
service after it is up.

### Known Quirks

- Every link and token names `--base-url`, even if a client sends another Host
  header.
- Health and metrics listen on loopback port 9180. Caddy does not forward them.
- One node. A second machine is not a cluster.
- Themes and providers of your own need a form on this one: `providers/` is in the
  read-only image.
- Kerberos is not built in.

### Network Exposure

- listen: tcp/80 *
- listen: tcp/443 *
