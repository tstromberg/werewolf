# Keycloak

Single sign-on for a campus: [Keycloak](https://www.keycloak.org) 26.8, OpenID Connect and SAML, with PostgreSQL and Caddy.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
openssl rand -base64 24 >admin-password
howl create sso --with keycloak --on lima \
	--base-url https://sso.home.arpa --admin alice \
	--admin-password admin-password
```

Sign in at `https://sso.home.arpa/admin` as `alice`. Caddy's own CA signs `.home.arpa`.

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -base64 24 >admin-password
howl create sso --with keycloak --on gcp --allow-from 0.0.0.0/0 \
	--base-url https://sso.example.edu --admin alice \
	--admin-password admin-password
```

Point `sso.example.edu` at the machine with an A record. Keycloak calls this first administrator temporary: make your own, or bring them from your directory, then remove it. Realms, clients and a SAML federation (eduGAIN, InCommon) are set in the admin console and kept in PostgreSQL.

### Known Quirks

- Every link and token names `--base-url`, even if a client sends another Host header.
- Health and metrics listen on loopback port 9180. Caddy does not forward them.
- One node. A second machine is not a cluster.
- Themes and providers of your own need a form on this one: `providers/` is in the read-only image.
- Kerberos is not built in.

### Network Exposure

- tcp/80 and tcp/443, Caddy. Keycloak can reach LDAP, mail submission and HTTPS, for a directory or an identity provider you configure.

### Security Weaknesses

- Java runs Keycloak, and the JVM and PostgreSQL compile code as they run. Both are named in `form.yaml`.
