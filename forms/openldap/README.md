# OpenLDAP

A directory for the accounts a company already shares: [OpenLDAP](https://www.openldap.org) 2.6 on LDAPS alone.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
openssl rand -base64 24 >ldap-admin-password
howl create ldap --with openldap --on lima \
	--domain example.com --admin admin --admin-password ldap-admin-password \
	--tls-cert ldap.crt --tls-key ldap.key
```

The first start makes `dc=example,dc=com`. Add people with `ldapadd` over `ldaps://`, as `cn=admin,dc=example,dc=com`. The password is at least 12 bytes.

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -base64 24 >ldap-admin-password
howl create ldap --with openldap --on gcp --allow-from 10.128.0.0/20 \
	--domain example.com --admin admin --admin-password ldap-admin-password \
	--tls-cert ldap.crt --tls-key ldap.key
```

Use a certificate your CA signed for the machine's name. The suffix is one `dc=` per label of `--domain`, and it cannot be renamed after the directory is made. Schemas are core, cosine, inetorgperson and nis, which is what SSSD and nslcd read.

### Known Quirks

- Anonymous bind and anonymous search are refused. So is a cleartext bind: port 389 is not open.
- Passwords are stored as Argon2id and are not returned in a search.
- There is no web UI. You add entries with `ldapadd` from a machine you trust.
- One server. Replication is not configured.

### Network Exposure

- tcp/636, LDAPS, for clients you allow.
