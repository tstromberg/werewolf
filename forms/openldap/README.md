# OpenLDAP

The `openldap` form is a company's directory: OpenLDAP 2.6, the
long-term release, serving LDAPS on :636 alone, its suffix from your
domain, nothing to anyone who has not bound, and passwords kept as
Argon2id hashes no one reads back, on one leash
([design/corporate.md](../../docs/design/corporate.md)).

## Run your own

```sh
openssl rand -base64 24 >ldap-admin-password    # its admin's; keep it
howl create ldap --with openldap --on gcp --allow-from 10.128.0.0/20 \
	--domain example.com --admin admin --admin-password ldap-admin-password \
	--tls-cert ldap.crt --tls-key ldap.key
```

slapd answers at `ldaps://ADDRESS` to `cn=admin,dc=example,dc=com` and
that password, with the certificate your CA (`step-ca`, say) issued for
the machine's name. The first start makes `dc=example,dc=com` and its
password policy; the admin adds the rest:

```sh
LDAPTLS_CACERT=ca.crt ldapadd -H ldaps://ldap.example.com -x \
	-D cn=admin,dc=example,dc=com -y ldap-admin-password -f people.ldif
```

| Flag | |
| --- | --- |
| `--domain NAME` | required. The suffix, a `dc=` for each label (RFC 2247); fixed once the directory is made |
| `--admin NAME` | its admin, `cn=NAME` under the suffix; `admin` if not given |
| `--admin-password FILE` | required. The admin's password, 12 bytes at least |
| `--tls-cert FILE`, `--tls-key FILE` | required. Its certificate and key, PEM |

The schemas are core, cosine, inetorgperson and nis: people, groups and
the POSIX accounts SSSD and nslcd read.

## How it is held

- **openldap-setup first.** [cmd/openldap-setup](cmd/openldap-setup/openldap-setup.zig)
  runs before slapd, on its leash: it writes `slapd.conf` in
  `/run/svc/openldap` from the settings, the admin's password as an
  Argon2id hash, and removes leash's copy of the password. On the first
  start it makes the base entry and the policy with slapadd, and marks
  the directory made with its suffix; a later start refuses another
  suffix, and refuses to make an empty directory over a lost one.
- **LDAPS alone.** Nothing on :389, so no password crosses the network
  in the clear; TLS 1.2 at least, and `security ssf=128` refuses any
  operation on a connection without it.
- **Nothing anonymous.** `disallow bind_anon` and `require authc`: an
  anonymous bind is refused, and so is every search before a bind.
- **Passwords hashed, never read.** `ppolicy_hash_cleartext` hashes a
  password a client sends in the clear, and `password-hash {ARGON2}`
  one changed by the password-modify operation (`ldappasswd`), with
  OWASP's Argon2id parameters. `userPassword` is readable by no one: a
  bind checks it, a user may replace their own.
- **A password policy.** `cn=password-policy` under the suffix, made
  once, the admin's to change: 12 characters at least, a password sent
  already hashed refused (its cost would be the sender's), and an
  account locked for 5 minutes after 10 failed binds in 5.
- **Bound users read.** Every entry is readable by whoever has bound; only
  the admin writes, but for a user's own password.
- **Its config database is no one's.** `cn=config` answers no one, the
  admin neither; the configuration is the image's and the settings'.
- **Its limits.** 500 entries a search, 60 s; 512 MiB under leash.

## Drawbacks

- One server: no replication (syncprov) to a second.
- The admin (the rootdn) is not locked out: it is the policy's
  exception, so keep its password long and random.
- Indexes are the image's: one a later image adds is built by slapd as
  entries change, not over those already there.

## Checked

`make check-openldap` boots it with its test config ([test/config](test/config)):
the admin binds over LDAPS, adds a person with a password in the clear
and finds them; the password is stored as an Argon2id hash, and the
admin's in `slapd.conf`, whose copy is gone; the person binds and reads
entries but no password; a password sent hashed is refused; `cn=config`
answers not even the admin. Then the attacks: an anonymous search is
refused at its bind, and so is one bound by a name without a password;
nothing answers plain LDAP on :389. slapd logs each refusal on the console.
`make check-shellfree-openldap` boots it as it ships, with no config:
slapd parks, saying it has no admin password, before anything is
written or bound.
