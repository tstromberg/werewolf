# OpenLDAP - Hardened VM

A directory for the accounts a company already shares: [OpenLDAP](https://www.openldap.org) 2.6 on LDAPS alone. The form's manifest is [form.yaml](form.yaml).

[Images, test status and download instructions](https://dist.werewolf-linux.org/images/v1/openldap/index.html).

## Security Posture

- The service runs as its own user, held to the files and ports its manifest names. The root is read-only. `/data` is what survives.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
openssl rand -base64 18 >admin-password
openssl ecparam -name prime256v1 -genkey -noout -out ldap.key
openssl req -new -x509 -key ldap.key -out ldap.crt -days 30 -subj /CN=ldap.home.arpa
howl create openldap --with openldap \
	--domain ldap.home.arpa --admin admin --admin-password admin-password \
	--tls-cert ldap.crt --tls-key ldap.key
```

The first start makes `dc=ldap,dc=home,dc=arpa`. Add people with `ldapadd` over `ldaps://ADDRESS`, as `cn=admin,dc=ldap,dc=home,dc=arpa`. The password is in `admin-password`. Entries and schemas are in [OpenLDAP's administrator's guide](https://www.openldap.org/doc/admin26/).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -base64 18 >admin-password
openssl ecparam -name prime256v1 -genkey -noout -out ldap.key
openssl req -new -x509 -key ldap.key -out ldap.crt -days 30 -subj /CN=ldap.example.com
howl create openldap --with openldap --on gcp --allow-from me \
	--domain ldap.example.com --admin admin --admin-password admin-password \
	--tls-cert ldap.crt --tls-key ldap.key
```

Clients use `ldaps://ldap.example.com`. Use a certificate your CA signed for that name. The suffix is one `dc=` per label of `--domain`, and it cannot be renamed after the directory is made.

### Importing data

The directory starts empty. Load an LDIF with `ldapadd` against the ldaps port howl prints. The host cannot write `/data`.

### Known Quirks

- Anonymous bind and anonymous search are refused. So is a cleartext bind: port 389 is not open.
- Passwords are stored as Argon2id and are not returned in a search.
- There is no web UI. You add entries with `ldapadd` from a machine you trust.
- One server. Replication is not configured.

### Network Exposure

- listen: tcp/636 *
